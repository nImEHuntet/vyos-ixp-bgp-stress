"""Sampling, convergence detection, and failure predicates.

Sampling
--------
A background thread writes one JSON object per interval to a JSONL file. Every
field is sourced from a command that is cheap enough to poll — see `dut.py` for
why `show bgp ... statistics` and full-table dumps are excluded.

Convergence
-----------
There is no single "converged" flag to read. FRR's own operational definition,
the one `bgp update-delay` uses, is: every configured non-shutdown peer has sent
an explicit or implicit End-of-RIB (the first keepalive after Established counts
as implicit). Read-only mode ending is the closest thing to a first-class event.

Absent that, this module requires three conditions to hold together for
`stable_samples` consecutive samples:

1. `failedPeers == 0` and the established count matches what was configured.
2. `tableVersion` unchanged.
3. Total `pfxRcd` unchanged.

`tableVersion` is the stronger of the last two and the reason it is tracked
separately: FRR bumps it on every table change, so a withdraw-plus-announce pair
that leaves the prefix count identical still moves the version. A prefix-count
plateau alone gives false positives during a mid-convergence lull.

Those three are still not enough, and T2 is why. Immediately after loading
2,800,920 paths, this module reported **converged in 1.0 s**: all 149 sessions
Established, pfxRcd complete, and `tableVersion` reading 50 for three
consecutive samples. At that same moment bgpd was pinned at 100% of one core,
its RSS was growing ~9.5 MB/s, `tableVersion` had not started moving yet (it
later climbed ~15k/s), and zebra had installed **136** routes into the kernel
against a BGP RIB of 2,552,093. The control plane looked finished before the
data plane had started.

So convergence additionally requires the router to be *quiet*, not just
*consistent*:

4. bgpd below `busy_cpu_pct` of one core.
5. zebra's dataplane queue empty and its install count no longer moving.
6. the FIB within `fib_min_ratio` of the BGP RIB — because traffic follows the
   FIB, and a router with every session up and two million prefixes not yet
   installed is black-holing them.

`require_quiet=False` restores the old behaviour for comparison.

Predicates
----------
Break-it mode needs a machine-checkable definition of "too far". These encode the
documented FRR failure modes rather than guesses:

* `SENDQ_STUCK_WARN` / `_PROPER` — bgpd cannot drain its own send queue. At two
  holdtimes it kills the session itself. Non-configurable, undocumented in the
  FRR user guide, and the most likely first failure at scale.
* zebra netlink `recvmsg overrun` — the socket is invalidated and zebra restarts
  itself.
* FIB backpressure — dataplane queue at its limit, or non-zero route update
  errors.
* Daemon restart — detected by PID change, which catches watchdog restarts and
  crashes that leave no log line.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .dut import Dut

CLK_TCK = 100.0  # Linux USER_HZ; /proc/<pid>/stat times are in these units


# ---------------------------------------------------------------------------
# sampling
# ---------------------------------------------------------------------------


#: Per-peer detail is written into every sample only while the peer count is
#: small enough that it does not dominate samples.jsonl. Above this, only the
#: not-established list is kept (which is what alerting needs anyway).
PER_PEER_SAMPLE_LIMIT = 64
NOT_ESTABLISHED_CAP = 25


def bgp_peer_node(summary: Optional[Dict]) -> Optional[Dict]:
    """Return the dict that actually holds `peers`.

    FRR nests per-VRF when 'all' is used; a single-AFI query puts the peers at
    the top level. Tolerate both shapes so callers never have to.
    """
    if not isinstance(summary, dict):
        return None
    if "peers" in summary:
        return summary
    for v in summary.values():
        if isinstance(v, dict) and "peers" in v:
            return v
    return None


def bgp_peer_state(summary: Optional[Dict], peer: str) -> Optional[str]:
    """State string for one neighbour, or None if that neighbour is absent.

    `peer` must be the *neighbour's* address as FRR keys it — i.e. the
    simulated speaker's address, never the DUT's own fabric address.
    """
    node = bgp_peer_node(summary)
    if not node:
        return None
    peers = node.get("peers")
    if not isinstance(peers, dict):
        return None
    p = peers.get(peer)
    if not isinstance(p, dict):
        return None
    return str(p.get("state", "")) or None


def _summarise_bgp(summary: Optional[Dict],
                   full_detail: bool = False) -> Dict[str, Any]:
    """Reduce `show bgp <afi> unicast summary json` to scalar metrics."""
    out: Dict[str, Any] = {
        "read_ok": True,
        "peers": 0, "established": 0, "failed": None, "table_version": None,
        "rib_count": None, "rib_memory": None, "peer_memory": None,
        "pfx_rcd_total": 0, "pfx_snt_total": 0, "max_pfx_rcd": 0,
        "not_established": [], "per_peer": None,
    }
    if not isinstance(summary, dict):
        # The query failed — vtysh timed out, or bgpd's main thread was too busy
        # to answer. That is NOT "zero peers with zero prefixes", and recording
        # it as such is the same mistake as H-18: an absent measurement written
        # down as a measured absence.
        #
        # On the T2 run this happened for 45 of 2,392 address-family reads
        # (1.9%), every one of them while bgpd sat at ~100% of one core. Each
        # produced a sample reading `peers: 0, established: 0, pfx_rcd_total: 0,
        # table_version: null`, which reset the convergence tracker (so
        # "post-chaos re-convergence: 1260 s, converged=False" may be an
        # artefact rather than a result) and corrupted every peak, final and
        # drift figure derived from those fields. The telemetry became least
        # reliable exactly when the DUT was most loaded, which is when it
        # matters. See FINDINGS.md H-43.
        out["read_ok"] = False
        return out

    node = bgp_peer_node(summary) or summary

    out["table_version"] = node.get("tableVersion")
    out["rib_count"] = node.get("ribCount")
    out["rib_memory"] = node.get("ribMemory")
    out["peer_memory"] = node.get("peerMemory")
    if node.get("failedPeers") is not None:
        out["failed"] = node.get("failedPeers")

    peers = node.get("peers") or {}
    if isinstance(peers, dict):
        out["peers"] = len(peers)
        detail: Dict[str, Any] = {}
        for addr, p in peers.items():
            if not isinstance(p, dict):
                continue
            state = str(p.get("state", ""))
            if state.lower() == "established":
                out["established"] += 1
            elif full_detail or len(out["not_established"]) < NOT_ESTABLISHED_CAP:
                out["not_established"].append(f"{addr}={state or '?'}")
            rcd = p.get("pfxRcd") or 0
            snt = p.get("pfxSnt") or 0
            if isinstance(rcd, int):
                out["pfx_rcd_total"] += rcd
                out["max_pfx_rcd"] = max(out["max_pfx_rcd"], rcd)
            if isinstance(snt, int):
                out["pfx_snt_total"] += snt
            # The cap keeps a 2 s poll cheap, but it also means that at T3
            # scale (154 sessions) *every* sample carried `per_peer: null`. On
            # run 1 the settle phase ended with 75 IPv6 sessions in Active and
            # not one record of which sessions, since when, or how many times
            # they had dropped — so the outage could not be attributed to
            # either side from the run's own data. Callers that are taking a
            # one-shot snapshot (end of run, failed convergence) pass
            # full_detail=True and get all of them. See FINDINGS.md H-57.
            if full_detail or len(peers) <= PER_PEER_SAMPLE_LIMIT:
                detail[addr] = {
                    "state": state,
                    "pfx_rcd": rcd if isinstance(rcd, int) else None,
                    "pfx_snt": snt if isinstance(snt, int) else None,
                    # Connection counters expose flaps that a 2 s poll misses
                    # entirely: two samples can both read Established across a
                    # reset, but connectionsDropped will have moved.
                    "conn_est": p.get("connectionsEstablished"),
                    "conn_drop": p.get("connectionsDropped"),
                }
        if detail:
            out["per_peer"] = detail
    if out["failed"] is None:
        out["failed"] = max(0, out["peers"] - out["established"])
    return out


@dataclass
class Sampler:
    dut: Dut
    path: str
    interval: float = 2.0
    # Heavier scrapes run every Nth sample to keep the poll cheap.
    slow_every: int = 5
    #: Floor for the journal window. The window actually used is the time that
    #: has elapsed since the previous log read plus `log_window_margin_s`,
    #: because a fixed window shorter than the slow-sample cadence leaves a
    #: blind gap between consecutive reads. At the shipped T3 settings
    #: (interval 3.0 s, slow_every 5) the cadence is 15 s and this was "-10s":
    #: one second in three was never read at all. That is how T3 run 1 recorded
    #: `daemon_unresponsive: 0` while the journal contained three
    #: `bgpd state -> unresponsive` lines. See FINDINGS.md H-56.
    log_window: str = "-10s"
    log_window_margin_s: float = 2.0

    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: Optional[threading.Thread] = field(default=None, init=False)
    _t0: float = field(default=0.0, init=False)
    _n: int = field(default=0, init=False)
    #: (ticks, clock, pid) per daemon. The pid is part of the key because a
    #: restart resets the tick counter — see _cpu_pct.
    _prev_proc: Dict[str, Tuple] = field(default_factory=dict, init=False)
    #: Count of samples whose computed CPU% exceeded threads*100, which is
    #: physically impossible and therefore a measurement bug, not a finding.
    cpu_pct_impossible: int = field(default=0, init=False)
    latest: Dict[str, Any] = field(default_factory=dict, init=False)
    #: monotonic clock at the end of the previous log read.
    _last_log_read: Optional[float] = field(default=None, init=False)
    _fh: Any = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def start(self) -> None:
        # Validate here rather than discovering it inside the sampling thread,
        # where the TypeError surfaces as a bare thread traceback while the real
        # problem scrolls past underneath.
        if self.interval is None or float(self.interval) <= 0:
            raise ValueError(
                f"Sampler.interval must be a positive number, got "
                f"{self.interval!r}. Callers should resolve it via "
                f"runner.sample_interval()."
            )
        self.interval = float(self.interval)
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._fh = open(self.path, "a", buffering=1, encoding="utf-8")
        self._t0 = time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Always safe to call, including after a failed or partial start."""
        self._stop.set()
        if self._thread is not None:
            try:
                interval = float(self.interval) if self.interval else 2.0
            except (TypeError, ValueError):
                interval = 2.0
            self._thread.join(timeout=interval * 3 + 30)
            if self._thread.is_alive():
                # Daemon thread, so this does not block exit; say so rather than
                # hanging silently.
                print("warning: telemetry thread did not stop within its timeout")
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def thread_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def event(self, kind: str, /, payload: Optional[Dict[str, Any]] = None,
              **kw) -> None:
        """Record a harness-initiated event on the same timeline as the samples.

        `kind` is positional-only for the same reason as `Ctx.log`: callers
        expand dicts into this, and a `kind` key in one of them would otherwise
        be a TypeError at the call site (H-24). `payload` generalises that fix
        to every other key — see `Ctx.log` and FINDINGS.md H-58.
        """
        merged: Dict[str, Any] = dict(payload or {})
        merged.update(kw)
        if "kind" in merged:
            merged.setdefault("event_kind", merged.pop("kind"))
        rec = {"t": round(time.monotonic() - self._t0, 3), "wall": time.time(),
               "kind": kind, **merged}
        self._emit(rec)

    def _emit(self, rec: Dict[str, Any]) -> None:
        with self._lock:
            if self._fh:
                self._fh.write(json.dumps(rec, default=str) + "\n")

    def _cpu_pct(self, name: str, ticks: int, now: float,
                 threads: Optional[int] = None,
                 pid: Optional[int] = None) -> Optional[float]:
        """CPU% between two /proc reads.

        `now` MUST be the clock taken next to the /proc read, not the timestamp
        at the top of `sample()`. Using the latter made the reported percentage
        depend on how long the *rest* of the sample took: the tick delta spans
        (read_n - read_n-1) while the divisor was (top_n - top_n-1), and on a
        slow sample the heavy scrapes push read_n several seconds past top_n.
        At T1 that produced a reported bgpd max of 526.98% for a process with 4
        threads — a physical impossibility, since 4 threads cap at 400%. See
        FINDINGS.md H-21.

        A value above threads*100 is still reported, but flagged, because
        clamping silently would hide a future instance of the same class of bug.
        """
        prev = self._prev_proc.get(name)
        self._prev_proc[name] = (ticks, now, pid)
        if not prev:
            return None
        # A PID change means the tick counter belongs to a different process, so
        # the delta is meaningless — and negative, because the new process
        # starts from zero. T2 reported bgpd at **-1547.13%** on the sample
        # after watchfrr restarted it. Reset the baseline instead.
        if len(prev) > 2 and pid is not None and prev[2] != pid:
            return None
        dt = now - prev[1]
        if dt <= 0:
            return None
        pct = round(100.0 * (ticks - prev[0]) / CLK_TCK / dt, 2)
        if pct < 0:
            # Belt and braces: a negative CPU% is never a measurement.
            self.cpu_pct_impossible += 1
            return None
        if threads and pct > threads * 100 * 1.02:
            self.cpu_pct_impossible += 1
        return pct

    def sample(self) -> Dict[str, Any]:
        now = time.monotonic()
        slow = (self._n % self.slow_every == 0)
        self._n += 1

        rec: Dict[str, Any] = {
            "t": round(now - self._t0, 3), "wall": time.time(), "kind": "sample",
        }

        if not self.dut.alive():
            rec["dut_down"] = True
            self._emit(rec)
            self.latest = rec
            return rec

        rec["bgp"] = {
            "ipv4": _summarise_bgp(self.dut.bgp_summary("ipv4")),
            "ipv6": _summarise_bgp(self.dut.bgp_summary("ipv6")),
        }

        proc = self.dut.proc_stats()
        # Clock taken next to the /proc read, so the CPU divisor matches the
        # interval the tick delta actually covers.
        proc_at = time.monotonic()
        pr: Dict[str, Any] = {}
        for name, st in proc.items():
            pr[name] = {
                "pid": st["pid"], "rss_mb": round(st["rss_kb"] / 1024.0, 1),
                "threads": st["threads"],
                "cpu_pct": self._cpu_pct(name, st["utime"] + st["stime"],
                                         proc_at, st.get("threads"),
                                         st.get("pid")),
            }
        rec["proc"] = pr
        rec["proc_read_lag_s"] = round(proc_at - now, 3)
        if self.cpu_pct_impossible:
            rec["cpu_pct_impossible"] = self.cpu_pct_impossible

        if slow:
            rec["zebra"] = self.dut.zebra_stats()
            rec["dplane"] = self.dut.dplane_stats()
            rec["cgroup_mem_mb"] = (
                round(self.dut.cgroup_mem() / 1048576.0, 1)
                if self.dut.cgroup_mem() else None
            )
            # Cover the whole span since the previous read. A small overlap
            # (log_window_margin_s) is deliberate: double-counting a line at a
            # window edge inflates a count, while a gap loses the one line that
            # explains the run.
            nowm = time.monotonic()
            floor_s = abs(float(str(self.log_window).strip("-s") or 10))
            if self._last_log_read is None:
                span = floor_s
            else:
                span = max(floor_s,
                           nowm - self._last_log_read + self.log_window_margin_s)
            since = f"-{int(math.ceil(span))}s"
            rec["logs"] = self.dut.log_counts(since)
            rec["log_window_s"] = round(span, 1)
            self._last_log_read = time.monotonic()

        self._emit(rec)
        self.latest = rec
        return rec

    def _loop(self) -> None:
        try:
            interval = float(self.interval)
        except (TypeError, ValueError):
            interval = 2.0
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.sample()
            except Exception as exc:  # never let telemetry kill the run
                self._emit({"t": round(time.monotonic() - self._t0, 3),
                            "kind": "sampler_error", "error": repr(exc)})
            elapsed = time.monotonic() - t0
            self._stop.wait(max(0.1, interval - elapsed))


# ---------------------------------------------------------------------------
# convergence
# ---------------------------------------------------------------------------


@dataclass
class ConvergenceTracker:
    """Detects a stable table across consecutive samples."""

    expected_sessions_v4: int = 0
    expected_sessions_v6: int = 0
    stable_samples: int = 3
    require_all_established: bool = True
    #: A single bgpd thread above this is still working, whatever the table
    #: counters say. 100% of one core sustained is the signature of an
    #: update-generation or FIB-install backlog.
    busy_cpu_pct: float = 60.0
    #: Retained for callers that set it; the FIB ratio itself is evaluated
    #: against `show ip route summary` in runner._fib_agrees(), not here.
    #: See FINDINGS.md H-52 for why the sampled counters cannot answer it.
    fib_min_ratio: float = 0.95
    #: Set False to get the old table-counters-only behaviour.
    require_quiet: bool = True

    _streak: int = field(default=0, init=False)
    _last_key: Optional[Tuple] = field(default=None, init=False)
    _last_installs: Optional[int] = field(default=None, init=False)
    #: Whether the current stable streak has actually *seen* a FIB observation.
    #: zebra and dplane counters only ride on every `slow_every`-th sample, so a
    #: three-sample streak can easily contain none — and treating "absent" as
    #: "satisfied" reintroduces exactly the hole this gate exists to close.
    _fib_seen: bool = field(default=False, init=False)
    #: Why the most recent sample was not accepted, for the caller to report.
    reason: Optional[str] = field(default=None, init=False)

    @staticmethod
    def read_failed(rec: Dict[str, Any]) -> bool:
        """True when either address family's summary read did not succeed.

        A failed read must neither confirm nor deny convergence: it carries no
        information. Previously it was recorded as all-zeros, which *reset* the
        stable streak — so under load, where these reads fail, the tracker could
        be prevented from ever converging by its own telemetry.
        """
        b = rec.get("bgp") or {}
        return any((b.get(a) or {}).get("read_ok") is False
                   for a in ("ipv4", "ipv6"))

    def _key(self, rec: Dict[str, Any]) -> Optional[Tuple]:
        b = rec.get("bgp")
        if not b:
            return None
        v4, v6 = b.get("ipv4", {}), b.get("ipv6", {})
        return (v4.get("table_version"), v4.get("pfx_rcd_total"),
                v6.get("table_version"), v6.get("pfx_rcd_total"))

    def sessions_ok(self, rec: Dict[str, Any]) -> bool:
        b = rec.get("bgp")
        if not b:
            return False
        v4, v6 = b.get("ipv4", {}), b.get("ipv6", {})
        if (v4.get("failed") or 0) or (v6.get("failed") or 0):
            return False
        if not self.require_all_established:
            return True
        if self.expected_sessions_v4 and v4.get("established", 0) < self.expected_sessions_v4:
            return False
        if self.expected_sessions_v6 and v6.get("established", 0) < self.expected_sessions_v6:
            return False
        return True

    def busy(self, rec: Dict[str, Any]) -> Optional[str]:
        """Is the DUT still visibly working? Returns the reason, or None.

        Table counters alone are not enough, and T2 showed why. On
        2026-08-21 11:33, immediately after loading 2,800,920 paths,
        `converge` reported **converged in 1.0 s**: all 149 sessions were
        Established, pfxRcd was complete at 2,251,132, and `tableVersion` read
        50 for three consecutive samples, so the key was stable. Meanwhile:

          * bgpd was pinned at 100.0-101.4% CPU — one full core, continuously,
            for as long as it was sampled;
          * bgpd RSS was growing ~9.5 MB/s (4,411 -> 4,786 MB over 36 s);
          * `tableVersion` had not started moving yet, and later climbed from
            746,811 to 1,275,781 in 36 s (~15k/s);
          * zebra had installed **136** routes into the FIB against a BGP RIB of
            2,552,093. Minutes later it was at 664,557 installs, 185% CPU and
            2.6 GB RSS.

        So the control plane looked finished while the data plane had not
        started. Every measurement taken from that baseline — flap recovery,
        commit latency, convergence after churn — would have been taken against
        a router that was already saturated, and "converged in 1.0 s" would have
        been reported as a result.

        Traffic follows the FIB, so a router whose FIB is two million routes
        behind its RIB is not converged in any sense a user would recognise.
        """
        proc = (rec.get("proc") or {}).get("bgpd") or {}
        cpu = proc.get("cpu_pct")
        if isinstance(cpu, (int, float)) and cpu >= self.busy_cpu_pct:
            return f"bgpd at {cpu:.0f}% CPU"

        dp = rec.get("dplane") or {}
        depth = dp.get("queue_depth")
        if isinstance(depth, int) and depth > 0:
            return f"zebra dataplane queue depth {depth}"

        z = rec.get("zebra") or {}
        installs = z.get("route_installs")
        if isinstance(installs, int):
            prev, self._last_installs = self._last_installs, installs
            if prev is not None and installs != prev:
                return f"zebra still installing routes ({prev} -> {installs})"
            # A *stable* install counter is a real data-plane observation:
            # zebra is quiescent. That, and only that, is what this flag means.
            #
            # It used to also compare `installs` against bgpd's `rib_count` as
            # a FIB-completeness ratio. Both halves of that comparison were the
            # wrong quantity. `route_installs` is zebra's **cumulative** count
            # of install operations since the daemon started, so it rises
            # without bound as routes churn — on T3 run 1 it finished at
            # 13,890,066 against a 5,783,732-entry RIB, a "fib_lag" of
            # -8,106,334. And `rib_count` is bgpd's *RIB entries* figure from
            # `show bgp summary`, which counts BGP table nodes, not installable
            # best paths: 4,891,343 v4 entries for 2,445,625 actual v4 routes.
            # The ratio was therefore ~50% for the whole of a warmup in which
            # the FIB was 100% installed, and would later pass for the wrong
            # reason once churn pushed the counter past the threshold.
            #
            # FIB completeness is now decided only by zebra's own
            # `show ip route summary` (Dut.route_summary), via
            # runner._fib_agrees(). See FINDINGS.md H-52.
            if prev is not None:
                self._fib_seen = True
        return None

    def feed(self, rec: Dict[str, Any]) -> bool:
        """Returns True on the sample where convergence is first confirmed."""
        if rec.get("kind") != "sample":
            # A timeline event, not a measurement. Do not reset, and do not
            # overwrite a real reason with "no sample" — the caller prints it.
            return False
        self.reason = None
        if rec.get("dut_down"):
            self._streak = 0
            self.reason = "the DUT container is not running"
            return False
        if self.read_failed(rec):
            # No information. Hold the streak rather than breaking it, and say
            # why, so a run that cannot be measured is distinguishable from a
            # router that will not settle.
            self.reason = "a BGP summary read failed (DUT too busy to answer)"
            return False
        if self.require_quiet:
            why = self.busy(rec)
            if why:
                self._streak = 0
                self.reason = why
                return False
        key = self._key(rec)
        if key is None or None in key[:1]:
            self._streak = 0
            self._last_key = key
            return False
        if not self.sessions_ok(rec):
            self._streak = 0
            self._last_key = key
            self.reason = "not all sessions established"
            return False
        if key == self._last_key:
            self._streak += 1
        else:
            self._streak = 1
            self._fib_seen = False
        self._last_key = key
        if self._streak < self.stable_samples:
            if self.reason is None:
                self.reason = (f"stabilising "
                               f"({self._streak}/{self.stable_samples} samples)")
            return False
        if self.require_quiet and not self._fib_seen:
            # Counters are stable and bgpd is idle, but no sample in this streak
            # carried a FIB reading, so the FIB has not been checked at all.
            # Keep waiting rather than confirming on an unexamined data plane.
            self.reason = "waiting for a FIB reading (arrives on slow samples)"
            return False
        return True

    def reset(self) -> None:
        self._streak = 0
        self._last_key = None
        self._last_installs = None
        self._fib_seen = False
        self.reason = None


def wait_for_convergence(sampler: Sampler, tracker: ConvergenceTracker,
                         timeout_s: float, poll: float = 1.0,
                         on_sample: Optional[Callable[[Dict], None]] = None
                         ) -> Tuple[bool, float, Dict[str, Any]]:
    """Block until the table settles or `timeout_s` elapses.

    Returns (converged, seconds, last_sample). A False here in break-it mode is
    a result, not an error: it means the DUT could not settle at this scale
    within budget.
    """
    tracker.reset()
    t0 = time.monotonic()
    last: Dict[str, Any] = {}
    while time.monotonic() - t0 < timeout_s:
        rec = sampler.latest
        if rec and rec is not last:
            last = rec
            if on_sample:
                on_sample(rec)
            if tracker.feed(rec):
                # `elapsed` below is deliberately back-dated to the first sample
                # of the stable streak: it answers "when did the table settle",
                # not "how long was this call". It is NOT a wall-clock duration
                # and must not be used as one — doing exactly that clipped the
                # start of every log window in the exercise (FINDINGS.md H-38).
                # Back-date to the first sample of the stable streak.
                elapsed = time.monotonic() - t0 - (tracker.stable_samples - 1) * sampler.interval
                return True, max(0.0, elapsed), rec
        time.sleep(poll)
    return False, time.monotonic() - t0, last


# ---------------------------------------------------------------------------
# failure predicates
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    code: str
    detail: str
    severity: str = "fail"       # fail | warn
    evidence: Dict[str, Any] = field(default_factory=dict)
    #: What makes this violation *the same* as an earlier one, for
    #: `check_new`'s once-per-run suppression. Defaults to (code, severity),
    #: which is right for a standing condition ("bgpd RSS over budget") and
    #: wrong for a repeatable discrete event. T3 run 1 restarted bgpd three
    #: times — 503 -> 178177 -> 198291 -> 240636, each one a separate watchfrr
    #: kill with its own multi-minute outage — and reported exactly one,
    #: because all three shared the key ("bgpd_restarted", "fail"). Set this to
    #: something that varies per occurrence when each occurrence is a result.
    #: See FINDINGS.md H-55.
    dedup: Optional[str] = None

    def key(self) -> Tuple:
        return (self.code, self.severity, self.dedup)

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.detail}"


@dataclass
class Budgets:
    convergence_s: float = 120.0
    bgpd_rss_mb: float = 8192.0
    zebra_rss_mb: float = 4096.0
    commit_s: float = 120.0
    #: How far the FIB may lag the BGP RIB, as a fraction, before it is a
    #: finding. Traffic follows the FIB: a router with every session
    #: Established and two million routes not yet installed is black-holing.
    fib_min_ratio: float = 0.95
    #: How long that lag may persist before it stops being "still loading" and
    #: becomes "not keeping up".
    fib_lag_grace_s: float = 300.0
    max_failed_peers: int = 0
    max_dplane_errors: int = 0
    allow_sendq_warn: bool = True     # a warn is informative, not fatal

    @classmethod
    def from_profile(cls, d: Optional[Dict]) -> "Budgets":
        d = d or {}
        return cls(
            convergence_s=float(d.get("convergence_s", 120)),
            bgpd_rss_mb=float(d.get("bgpd_rss_mb", 8192)),
            zebra_rss_mb=float(d.get("zebra_rss_mb", 4096)),
            commit_s=float(d.get("commit_s", 120)),
            fib_min_ratio=float(d.get("fib_min_ratio", 0.95)),
            fib_lag_grace_s=float(d.get("fib_lag_grace_s", 300)),
            max_failed_peers=int(d.get("max_failed_peers", 0)),
            max_dplane_errors=int(d.get("max_dplane_errors", 0)),
            allow_sendq_warn=bool(d.get("allow_sendq_warn", True)),
        )


class PredicateSet:
    """Evaluates samples against budgets and tracks daemon restarts.

    Two things it must NOT do, both learned from a run whose FAIL verdict was
    entirely self-inflicted:

    1. Fault the DUT for an impairment the harness itself applied. The scenario
       mix is 40% `peer_flap` by weight, so with `max_failed_peers: 0` checked
       unconditionally the run could never pass: every deliberate flap tripped
       `failed_peers_ipv4` and `failed_peers_ipv6`. Call `impair_begin()` /
       `impair_end()` around a deliberate impairment and the peer-count
       predicate is suppressed for its duration plus a recovery grace window.
       What replaces it is the assertion that actually matters — a flapped peer
       must come *back*, which `ConvergenceTracker` and the flap-recovery
       measurement already cover.

    2. Treat a monotonic high-water mark as a live measurement. zebra's
       `queue_max` from `show zebra dplane` is the maximum depth since the
       daemon started, so once the initial table load pushed it to the limit it
       stayed there and re-fired on every subsequent sample, timestamped
       wherever the sampler happened to be. It is now reported once, as an
       observation, only if it moves during the run.
    """

    def __init__(self, budgets: Budgets):
        self.b = budgets
        self._pids: Dict[str, int] = {}
        #: How many times each daemon has been seen to change PID.
        self._restarts: Dict[str, int] = {}
        #: `t` of the most recent sample whose log window carried the watchfrr
        #: "unresponsive" signature.
        self._unresponsive_at: Optional[float] = None
        self._seen: set = set()
        self._impair_until: float = -1.0
        self._impaired: bool = False
        self._impair_grace_s: float = 30.0
        #: When the FIB first fell behind the RIB, so a transient load window
        #: can be told apart from a router that is not keeping up.
        self._fib_lag_since: Optional[float] = None
        #: Daemons an event has announced it is about to restart on purpose.
        #: Without this, `dut_bgpd_restart` — whose entire job is to restart
        #: bgpd — reports `[fail] bgpd_restarted` against itself.
        self._expect_restart: set = set()
        self._dplane_qmax_baseline: Optional[int] = None

    # -- deliberate-impairment window ------------------------------------

    def impair_begin(self, reason: str = "") -> None:
        """Suppress peer-count faults: the harness is taking a peer down."""
        self._impaired = True
        self._impair_reason = reason

    def impair_end(self, grace_s: Optional[float] = None) -> None:
        """Impairment lifted; keep suppressing for a recovery grace window."""
        self._impaired = False
        self._impair_until = time.monotonic() + (
            self._impair_grace_s if grace_s is None else float(grace_s))

    @property
    def peer_faults_suppressed(self) -> bool:
        return self._impaired or time.monotonic() < self._impair_until

    @staticmethod
    def read_failed(rec: Dict[str, Any]) -> bool:
        b = rec.get("bgp") or {}
        return any((b.get(a) or {}).get("read_ok") is False
                   for a in ("ipv4", "ipv6"))

    def expect_daemon_restart(self, name: str) -> None:
        """Tell the predicate set that the next restart of `name` is deliberate.

        Consumed by the first PID change observed for that daemon, so it cannot
        mask a second, unintended restart later in the run.
        """
        self._expect_restart.add(name)

    #: How long after watchfrr logs "unresponsive" a PID change is still
    #: attributable to it.
    #:
    #: 300 s was a guess and it was too short. Measured, unresponsive-to-back-up:
    #: run 2 gave 228 s, 362 s and 238 s; run 3 gave 177 s and 365 s. The PID
    #: change is only *detected* once the new bgpd is up and the sampler reads
    #: /proc, so the gap to attribute across is the whole sequence, and
    #: run 3's second restart came in at 338 s — just past the window, so it
    #: was reported as `watchdog_kill: false` for a kill the journal names
    #: explicitly. See FINDINGS.md H-62.
    #:
    #: 600 s covers every sequence observed with headroom. The risk of being
    #: generous is mislabelling an unrelated restart as a watchdog kill within
    #: 10 minutes of one; the risk of being tight is denying a kill that
    #: happened, which has now happened twice.
    WATCHDOG_ATTRIBUTION_S: float = 600.0

    def _note_watchdog(self, rec: Dict[str, Any]) -> None:
        """Called on every sample, not only on ones that show a PID change."""
        if (rec.get("logs") or {}).get("daemon_unresponsive"):
            self._unresponsive_at = rec.get("t")

    def _watchdog_recent(self, rec: Dict[str, Any]) -> bool:
        t = rec.get("t")
        if self._unresponsive_at is None or t is None:
            return False
        return (t - self._unresponsive_at) <= self.WATCHDOG_ATTRIBUTION_S

    def check(self, rec: Dict[str, Any]) -> List[Violation]:
        self._note_watchdog(rec)
        v: List[Violation] = []
        if rec.get("kind") != "sample":
            return v

        if self.read_failed(rec):
            # The measurement failed; there is nothing to judge. Faulting the
            # DUT for a read the harness could not complete is the H-13 mistake
            # in a new costume — and on T2 these reads returned "0 peers", which
            # would have looked like a total outage.
            v.append(Violation(
                "telemetry_read_failed",
                "a BGP summary read did not complete — bgpd's main thread was "
                "too busy to answer vtysh. The sample carries no data; it is "
                "not evidence of zero peers.",
                severity="warn", evidence={"t": rec.get("t")}))
            return v
        if rec.get("dut_down"):
            v.append(Violation("dut_container_down",
                               "the DUT container is no longer running",
                               evidence={"t": rec.get("t")}))
            return v

        # --- session health
        suppressed = self.peer_faults_suppressed
        for afi in ("ipv4", "ipv6"):
            b = (rec.get("bgp") or {}).get(afi) or {}
            failed = b.get("failed") or 0
            if failed > self.b.max_failed_peers and not suppressed:
                v.append(Violation(
                    f"failed_peers_{afi}",
                    f"{failed} {afi} peer(s) not established "
                    f"(budget {self.b.max_failed_peers})",
                    evidence={"failed": failed, "peers": b.get("peers"),
                              "established": b.get("established"), "t": rec.get("t")},
                ))

        # --- FIB versus RIB. The measurement that matters most for "did this
        # cause an outage": traffic follows the FIB. At T2 the DUT held all 149
        # sessions Established with a 2,552,093-entry BGP RIB and **136** routes
        # installed in the kernel, and nothing in `show bgp summary` said so.
        # See FINDINGS.md H-40.
        #
        # This used to be computed here from the sampled counters, as
        # `zebra.route_installs / sum(bgp[afi].rib_count)`. Neither side is the
        # quantity the sentence claims. `route_installs` is cumulative install
        # *operations* since zebra started; `rib_count` is bgpd's BGP-table-node
        # count, not installable best paths. On T3 run 1 that produced
        # "3,049,967 of 5,821,556 RIB entries installed in the FIB (52%) ...
        # 2,771,589 prefixes are not reachable" at a moment when zebra's own
        # summary read 2,445,625 of 2,445,625 installed. The violation is now
        # raised from `feed_fib()`, which the runner calls with the parsed
        # output of `show ip route summary`. See FINDINGS.md H-52.
        # --- memory
        proc = rec.get("proc") or {}
        for name, budget in (("bgpd", self.b.bgpd_rss_mb), ("zebra", self.b.zebra_rss_mb)):
            st = proc.get(name)
            if st and st.get("rss_mb") and st["rss_mb"] > budget:
                v.append(Violation(
                    f"{name}_rss_exceeded",
                    f"{name} RSS {st['rss_mb']} MB exceeds budget {budget} MB",
                    evidence={"rss_mb": st["rss_mb"], "t": rec.get("t")},
                ))

        # --- daemon restarts (catches crashes that log nothing)
        for name, st in proc.items():
            pid = st.get("pid")
            if pid is None:
                continue
            prev = self._pids.get(name)
            if prev is not None and pid != prev:
                # Three cases, and they are not the same result:
                #  - the harness restarted it on purpose (`dut_bgpd_restart`),
                #    which is an exercise step, not a finding;
                #  - watchfrr killed it for missing a liveness ping, which is
                #    the T2 finding and deserves to say so by name;
                #  - it died for some other reason, which is the generic case.
                expected = name in self._expect_restart
                # watchfrr declares a daemon unresponsive, waits its full
                # 90 s grace, and only then sends SIGTERM — so the
                # "unresponsive" line and the PID change are 90-160 s apart,
                # and the sampled log window is a few seconds wide. Looking
                # only at the current sample's counts therefore reported
                # `watchdog_kill: false` for a kill the journal named
                # explicitly. Remember when the signature was last seen and
                # allow for the grace period. See FINDINGS.md H-56.
                watchdog = self._watchdog_recent(rec)
                if expected:
                    self._expect_restart.discard(name)
                    detail = (f"{name} PID changed {prev} -> {pid}, as the "
                              f"running event intended")
                    sev = "info"
                elif watchdog:
                    detail = (f"{name} PID changed {prev} -> {pid} after "
                              f"watchfrr logged it unresponsive — the daemon "
                              f"was killed by its own supervisor for missing a "
                              f"liveness ping, not by a crash. VyOS runs "
                              f"watchfrr with --timeout=90 and {name}'s main "
                              f"thread is single-threaded.")
                    sev = "fail"
                else:
                    detail = (f"{name} PID changed {prev} -> {pid}; the daemon "
                              f"restarted or crashed")
                    sev = "fail"
                self._restarts[name] = self._restarts.get(name, 0) + 1
                nth = self._restarts[name]
                v.append(Violation(
                    f"{name}_restarted",
                    f"{detail} (restart #{nth} of this run)", severity=sev,
                    dedup=f"{prev}->{pid}",
                    evidence={"old_pid": prev, "new_pid": pid, "nth": nth,
                              "expected": expected, "watchdog_kill": watchdog,
                              "watchdog_seen_at_s": self._unresponsive_at,
                              "t": rec.get("t")},
                ))
            self._pids[name] = pid
        for name in ("bgpd", "zebra"):
            if name in self._pids and name not in proc:
                v.append(Violation(f"{name}_gone",
                                   f"{name} is no longer running",
                                   evidence={"t": rec.get("t")}))

        # --- documented FRR failure modes, from the log scrape
        logs = rec.get("logs") or {}
        if logs.get("sendq_stuck_proper"):
            v.append(Violation(
                "sendq_stuck_proper",
                "bgpd terminated a session after 2x holdtime without send-queue "
                "progress (EC_BGP_SENDQ_STUCK_PROPER). This threshold is hardcoded "
                "in bgp_packet.c and is not configurable. The DUT is past the point "
                "where it can keep up with its own update generation.",
                evidence={"count": logs["sendq_stuck_proper"], "t": rec.get("t")},
            ))
        if logs.get("sendq_stuck_warn"):
            v.append(Violation(
                "sendq_stuck_warn",
                "bgpd made no send-queue progress for one holdtime "
                "(EC_BGP_SENDQ_STUCK_WARN) — the leading indicator that the main "
                "thread is saturating. Session teardown follows at 2x holdtime.",
                severity="warn" if self.b.allow_sendq_warn else "fail",
                evidence={"count": logs["sendq_stuck_warn"], "t": rec.get("t")},
            ))
        if logs.get("netlink_overrun") or logs.get("zebra_recvmsg_overrun"):
            v.append(Violation(
                "netlink_overrun",
                "zebra reported a netlink receive-buffer overrun. The socket is "
                "invalidated and zebra restarts itself. Check the applied buffer "
                "with `show zebra` ('Kernel socket buffer size') rather than "
                "net.core.rmem_max — zebra uses SO_RCVBUFFORCE, which bypasses "
                "that sysctl when it holds CAP_NET_ADMIN.",
                evidence={"t": rec.get("t")},
            ))
        if logs.get("bgpd_crash"):
            v.append(Violation("bgpd_crash", "crash/assert signature in the DUT log",
                               evidence={"t": rec.get("t")}))
        if logs.get("optmem"):
            v.append(Violation(
                "optmem_exhausted",
                "sockopt_tcp_signature failure: the kernel's option memory is "
                "exhausted. FRR documents this at several-hundred-peer scale with "
                "TCP-MD5; raise net.core.optmem_max.",
                evidence={"t": rec.get("t")},
            ))

        # --- FIB backpressure
        dp = rec.get("dplane") or {}
        if dp:
            errs = dp.get("route_update_errors", 0)
            if errs > self.b.max_dplane_errors:
                v.append(Violation(
                    "dplane_route_errors",
                    f"zebra dataplane reported {errs} route update error(s) — routes "
                    f"are failing to install in the kernel FIB",
                    evidence={"errors": errs, "t": rec.get("t")},
                ))
            limit, qmax = dp.get("queue_limit"), dp.get("queue_max")
            if limit and qmax:
                # `queue_max` is a high-water mark since zebra started, not a
                # current depth. Latch the first value seen as the baseline and
                # only report if it moves, otherwise a limit reached during the
                # initial table load re-fires on every sample for the rest of
                # the run at a meaningless timestamp.
                if self._dplane_qmax_baseline is None:
                    self._dplane_qmax_baseline = qmax
                    if qmax >= limit:
                        v.append(Violation(
                            "dplane_queue_saturated_before_run",
                            f"zebra's dataplane route-update queue had already "
                            f"reached its limit ({qmax}/{limit}) before this run "
                            f"started — queue_max is a high-water mark since "
                            f"zebra started, so this happened during table load, "
                            f"not during chaos. Raise it with `zebra dplane "
                            f"limit` if FIB install rate is the bottleneck "
                            f"rather than bgpd. VyOS does not expose "
                            f"`zebra dplane limit` (vyos.dev/T5454).",
                            severity="warn",
                            evidence={"queue_max": qmax, "limit": limit,
                                      "t": rec.get("t")},
                        ))
                elif qmax > self._dplane_qmax_baseline:
                    self._dplane_qmax_baseline = qmax
                    if qmax >= limit:
                        v.append(Violation(
                            "dplane_queue_saturated",
                            f"dataplane route-update queue high-water mark rose "
                            f"to its limit during the run ({qmax}/{limit}). "
                            f"VyOS does not expose `zebra dplane limit` "
                            f"(vyos.dev/T5454), so this is a platform "
                            f"constraint rather than something to tune around: "
                            f"if the FIB install rate is the bottleneck rather "
                            f"than bgpd, that is the finding.",
                            severity="warn",
                            evidence={"queue_max": qmax, "limit": limit,
                                      "t": rec.get("t")},
                        ))
            if dp.get("updates_skipped"):
                v.append(Violation(
                    "dplane_updates_skipped",
                    f"{dp['updates_skipped']} dataplane update(s) skipped",
                    severity="warn", evidence={"t": rec.get("t")},
                ))
        return v

    def feed_fib(self, summary: Dict[str, Any],
                 t: Optional[float] = None) -> List[Violation]:
        """Judge FIB completeness from zebra's own `show ip route summary`.

        `summary` is one `Dut.route_summary()` result. This is the only source
        that can answer the question: bgpd's counters cannot (H-52), and the
        answer decides whether traffic works, so a missing or unparsable
        summary is reported as a measurement gap rather than passed over.
        """
        out: List[Violation] = []
        afi = summary.get("afi") or "ipv4"
        if not summary.get("ok"):
            out.append(Violation(
                "fib_state_unreadable",
                f"zebra could not answer `show {'ip' if afi == 'ipv4' else 'ipv6'} "
                f"route summary` for {afi}, so FIB completeness is unmeasured "
                f"for this check — not zero, unmeasured.",
                severity="warn", dedup=f"fib_state_unreadable:{afi}",
                evidence={"afi": afi, "error": summary.get("error"), "t": t},
            ))
            return out
        routes, fib = summary.get("bgp_routes"), summary.get("bgp_fib")
        if routes is None:
            out.append(Violation(
                "fib_summary_unrecognised",
                f"`show route summary` for {afi} carried no BGP row this "
                f"harness recognises (looked for {list(Dut.BGP_ROUTE_SOURCES)}, "
                f"found {sorted(summary.get('sources') or {})}). FIB "
                f"completeness is unmeasured.",
                severity="warn", dedup=f"fib_summary_unrecognised:{afi}",
                evidence={"afi": afi, "sources": sorted(summary.get("sources") or {}),
                          "t": t},
            ))
            return out
        if not routes:
            return out
        ratio = fib / routes
        key = f"fib_behind_rib:{afi}"
        if ratio < self.b.fib_min_ratio:
            if self._fib_lag_since is None:
                self._fib_lag_since = t or 0.0
            held = (t or 0.0) - self._fib_lag_since
            sev = "fail" if held > self.b.fib_lag_grace_s else "warn"
            out.append(Violation(
                "fib_behind_rib",
                f"zebra holds {routes:,} {afi} BGP routes and has installed "
                f"{fib:,} of them in the FIB ({ratio:.0%}), for {held:.0f}s. "
                f"Traffic follows the FIB: BGP is up and {routes - fib:,} "
                f"prefixes are not reachable.",
                severity=sev, dedup=f"{key}:{sev}",
                evidence={"afi": afi, "routes": routes, "fib": fib,
                          "ratio": round(ratio, 4), "held_s": round(held, 1),
                          "t": t},
            ))
        else:
            self._fib_lag_since = None
        return out

    def check_new(self, rec: Dict[str, Any]) -> List[Violation]:
        """Only violations not already reported, so a run does not spam."""
        out = []
        for viol in self.check(rec):
            key = viol.key()
            if key not in self._seen:
                self._seen.add(key)
                out.append(viol)
        return out
