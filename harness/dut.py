"""Driver for the VyOS device under test.

Everything goes through `docker exec` rather than SSH, deliberately:

* The harness always runs on the containerlab host, so the container is directly
  reachable and `docker exec` has no dependency on the DUT's own firewall,
  routing, or sshd state.
* The template sets `firewall ipv4 input filter default-action drop` and the
  DUT is about to be deliberately overloaded. An SSH control channel would be
  the first thing to become unreliable — exactly when telemetry matters most.
* Config is applied via `vbash` + `script-template`, which is VyOS's own
  documented mechanism for scripting configuration
  (docs.vyos.io/configuration/command-scripting).

Command choices are constrained by what FRR actually exposes:

* `show bgp ... summary json` **has** JSON and carries instance-level
  `tableVersion`, `ribCount`, `ribMemory`, `peerMemory`, `failedPeers` plus
  per-peer `pfxRcd`/`pfxSnt`. This is the polling primitive.
* `show bgp ipv4 unicast json` dumps the entire table. At a million prefixes
  that is gigabytes per sample — **never poll it**; `tableVersion` from the
  summary gives the same settling signal for free.
* `show bgp ... statistics` is a synchronous full-table walk on bgpd's main
  thread (`event_execute` on `bm->master`), measured at over a second per call
  on a large table. Polling it perturbs the very thing being measured, so it is
  available here as an explicit one-shot only.
* `show bgp memory` has no JSON. `show memory json` does — prefer the latter.
* `show event cpu` (renamed from `show thread cpu` in FRR 10.0, alias dropped in
  10.2) has no JSON and must be scraped.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


class DutError(RuntimeError):
    pass


class CommitTimeout(DutError):
    pass


@dataclass
class RunResult:
    rc: int
    out: str
    err: str
    seconds: float

    @property
    def ok(self) -> bool:
        return self.rc == 0


# ---------------------------------------------------------------------------
# docker invocation
# ---------------------------------------------------------------------------
#
# The harness shells out to `docker` for everything. On a host where the invoking
# user is not in the `docker` group that fails with a permission error that has
# nothing to do with BGP, so resolve the working form once and reuse it. Detection
# is cached because it runs before every single command otherwise, and the
# telemetry sampler is on a 2-second interval.

_DOCKER: Optional[List[str]] = None


def docker_cmd() -> List[str]:
    """['docker'] if that works, else ['sudo','-n','docker'], else ['docker']."""
    global _DOCKER
    if _DOCKER is not None:
        return _DOCKER
    for argv in (["docker"], ["sudo", "-n", "docker"]):
        try:
            p = subprocess.run(argv + ["info"], capture_output=True, timeout=25)
            if p.returncode == 0:
                _DOCKER = argv
                return _DOCKER
        except (OSError, subprocess.SubprocessError):
            continue
    # Nothing worked. Return the plain form so the real error surfaces to the
    # caller rather than being masked here.
    _DOCKER = ["docker"]
    return _DOCKER


def docker_available() -> Tuple[bool, str]:
    argv = docker_cmd()
    try:
        p = subprocess.run(argv + ["info"], capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot execute {' '.join(argv)}: {exc}"
    if p.returncode == 0:
        return True, " ".join(argv)
    return False, (p.stderr or p.stdout).strip()[-300:]


def _run(argv: List[str], timeout: float, input_: Optional[str] = None) -> RunResult:
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           input=input_)
        return RunResult(p.returncode, p.stdout, p.stderr, time.monotonic() - t0)
    except subprocess.TimeoutExpired as exc:
        return RunResult(124, exc.stdout or "", f"timeout after {timeout}s",
                         time.monotonic() - t0)
    except OSError as exc:
        return RunResult(127, "", f"could not execute {argv[0]}: {exc}",
                         time.monotonic() - t0)


@dataclass
class Dut:
    container: str
    vtysh_timeout: float = 30.0
    commit_timeout: float = 180.0
    user: str = "admin"

    # ---- plumbing --------------------------------------------------------

    def exec(self, cmd: str, timeout: Optional[float] = None,
             input_: Optional[str] = None) -> RunResult:
        return _run(docker_cmd() + ["exec", "-i", self.container, "sh", "-c", cmd],
                    timeout or self.vtysh_timeout, input_)

    def alive(self) -> bool:
        r = _run(docker_cmd() + ["inspect", "-f", "{{.State.Running}}", self.container], 15)
        return r.ok and r.out.strip() == "true"

    # ---- FRR operational -------------------------------------------------

    def vtysh(self, cmd: str, timeout: Optional[float] = None) -> RunResult:
        """Run one vtysh command.

        Uses vtysh directly rather than VyOS op-mode because op-mode wraps vtysh
        anyway (`src/op_mode/vtysh_wrapper.sh`) and strips JSON tokens: `json` does
        not appear anywhere in VyOS's BGP op-mode definitions, so
        `show bgp summary json` is not a valid *VyOS* command even though it is a
        valid *FRR* one.
        """
        return self.exec(f"vtysh -c {shlex.quote(cmd)}", timeout)

    def vtysh_json(self, cmd: str, timeout: Optional[float] = None) -> Optional[Any]:
        r = self.vtysh(cmd, timeout)
        if not r.ok or not r.out.strip():
            return None
        try:
            return json.loads(r.out)
        except json.JSONDecodeError:
            # FRR occasionally prefixes warnings before the JSON body
            i = r.out.find("{")
            if i < 0:
                return None
            try:
                return json.loads(r.out[i:])
            except json.JSONDecodeError:
                return None

    def bgp_summary(self, afi: str = "ipv4") -> Optional[Dict]:
        return self.vtysh_json(f"show bgp {afi} unicast summary json")

    def bgp_neighbor_json(self, peer: str) -> Optional[Dict]:
        return self.vtysh_json(f"show bgp neighbors {peer} json")

    def lookup_prefix(self, prefix: str, afi: str = "ipv4") -> Optional[Dict]:
        """Single-prefix lookup — cheap, unlike a full table dump."""
        return self.vtysh_json(f"show bgp {afi} unicast {prefix} json")

    def memory(self, daemon: str = "bgpd") -> Optional[Dict]:
        return self.vtysh_json(f"show memory {daemon} json")

    def table_statistics(self, afi: str = "ipv4") -> Optional[Dict]:
        """One-shot only.

        `show bgp <afi> unicast statistics` walks the whole table synchronously on
        bgpd's main thread. Do not put this on a polling interval — it competes
        with UPDATE processing and can itself push the send queue toward the
        2x-holdtime teardown threshold.
        """
        return self.vtysh_json(f"show bgp {afi} unicast statistics json", timeout=120)

    # ---- scraped (no JSON available) ------------------------------------

    _RE_ZEBRA_ROUTES = re.compile(
        r"^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
    _RE_RCVBUF = re.compile(r"Kernel socket buffer size\s*\|?\s*(\d+)")

    def zebra_stats(self) -> Dict[str, Any]:
        """Scrape `show zebra`. No JSON support in any FRR release to date."""
        r = self.vtysh("show zebra")
        out: Dict[str, Any] = {"raw_ok": r.ok}
        if not r.ok:
            return out
        m = self._RE_RCVBUF.search(r.out)
        if m:
            # The actual applied netlink buffer. zebra defaults to 4 MiB on Linux
            # and sets it with SO_RCVBUFFORCE, which bypasses net.core.rmem_max —
            # so this value, not the sysctl, is the one that matters.
            out["netlink_rcvbuf"] = int(m.group(1))
        installs = removals = 0
        for line in r.out.splitlines():
            m = self._RE_ZEBRA_ROUTES.match(line)
            if m and m.group(1) not in ("VRF",):
                installs += int(m.group(2))
                removals += int(m.group(3))
        out["route_installs"] = installs
        out["route_removals"] = removals
        return out

    _DPLANE_KEYS = {
        "Route updates:": "route_updates",
        "Route update errors:": "route_update_errors",
        "Route update queue limit:": "queue_limit",
        "Route update queue depth:": "queue_depth",
        "Route update queue max:": "queue_max",
        "Route updates skipped:": "updates_skipped",
        "Dplane update yields:": "update_yields",
        "Nexthop updates:": "nexthop_updates",
        "Nexthop update errors:": "nexthop_update_errors",
    }

    def dplane_stats(self) -> Dict[str, int]:
        """Scrape `show zebra dplane`.

        `queue_max` against `queue_limit` (default 200) is the FIB-install
        backpressure signal; `update_yields` shows the dataplane pthread being
        preempted.
        """
        r = self.vtysh("show zebra dplane detailed")
        out: Dict[str, int] = {}
        if not r.ok:
            return out
        for line in r.out.splitlines():
            s = line.strip()
            for prefix, key in self._DPLANE_KEYS.items():
                if s.startswith(prefix):
                    tail = s[len(prefix):].strip().split()
                    if tail and tail[0].isdigit():
                        out[key] = int(tail[0])
                    break
        return out

    _RE_EVENT = re.compile(
        r"^\s*([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$")

    def event_cpu(self) -> Dict[str, Dict[str, int]]:
        """Scrape `show event cpu` for main-thread hot spots.

        Renamed from `show thread cpu` in FRR 10.0 (deprecated alias removed in
        10.2), so both spellings are tried. Keepalive generation never appears
        here: the keepalives pthread deliberately has no threadmaster.

        `max_us` on main-thread rows is the number that matters — a long
        main-thread stall is what starves the send queue.
        """
        r = self.vtysh("show event cpu")
        if not r.ok or "Unknown command" in (r.out + r.err):
            r = self.vtysh("show thread cpu")
        out: Dict[str, Dict[str, int]] = {}
        if not r.ok:
            return out
        for line in r.out.splitlines():
            m = self._RE_EVENT.match(line)
            if not m:
                continue
            try:
                total_cpu, runs = m.group(1), int(m.group(2))
                cpu_max = int(m.group(4))
                func = m.group(8).strip()
            except (ValueError, IndexError):
                continue
            out[func] = {"runs": runs, "max_us": cpu_max}
        return out

    # ---- process-level ---------------------------------------------------

    PROC_SCRIPT = (
        "for p in $(pidof bgpd zebra staticd frr-exporter 2>/dev/null); do "
        "n=$(cat /proc/$p/comm 2>/dev/null) || continue; "
        "rss=$(awk '/VmRSS/{print $2}' /proc/$p/status 2>/dev/null); "
        "cpu=$(awk '{print $14\" \"$15}' /proc/$p/stat 2>/dev/null); "
        "th=$(awk '/Threads/{print $2}' /proc/$p/status 2>/dev/null); "
        "echo \"$n $p ${rss:-0} ${cpu:-0 0} ${th:-0}\"; done"
    )

    def proc_stats(self) -> Dict[str, Dict[str, int]]:
        """Per-daemon RSS (kB), CPU ticks and thread count, straight from /proc.

        RSS is the number that matters for an OOM verdict. FRR's own
        `show memory` reports `count x sizeof(struct)` accounting, which excludes
        allocator overhead and is not RSS.
        """
        r = self.exec(self.PROC_SCRIPT, timeout=20)
        out: Dict[str, Dict[str, int]] = {}
        if not r.ok:
            return out
        for line in r.out.strip().splitlines():
            f = line.split()
            if len(f) < 6:
                continue
            try:
                out[f[0]] = {
                    "pid": int(f[1]), "rss_kb": int(f[2]),
                    "utime": int(f[3]), "stime": int(f[4]), "threads": int(f[5]),
                }
            except ValueError:
                continue
        return out

    def cgroup_mem(self) -> Optional[int]:
        """Container memory usage in bytes (cgroup v2, then v1)."""
        r = self.exec(
            "cat /sys/fs/cgroup/memory.current 2>/dev/null || "
            "cat /sys/fs/cgroup/memory/memory.usage_in_bytes 2>/dev/null", timeout=10)
        try:
            return int(r.out.strip().splitlines()[0])
        except (ValueError, IndexError):
            return None

    # ---- logs ------------------------------------------------------------

    # Error codes that mark the documented FRR-at-scale failure modes.
    LOG_PATTERNS = {
        # These two matched the *C enum names* (EC_BGP_SENDQ_STUCK_WARN /
        # _PROPER), which FRR never prints — flog_err/flog_warn emit the numeric
        # code as "[EC 33554461]" plus the message text. Verified against
        # bgpd/bgp_packet.c in 10.5.2, which logs:
        #   "%pBP has not made any SendQ progress for 1 holdtime (%us), peer
        #    overloaded?"                                      (flog_warn)
        #   "%pBP has not made any SendQ progress for 2 holdtimes (%jds),
        #    terminating session"                              (flog_err)
        # So the two most important detectors in the table — the only signal for
        # FRR's hardcoded 2x-holdtime teardown — could not have matched anything
        # ever, at any scale. Neither is debug-gated. See FINDINGS.md H-30.
        "sendq_stuck_warn": r"SendQ progress for 1 holdtime",
        "sendq_stuck_proper": r"SendQ progress for 2 holdtime",
        "netlink_overrun": "recvmsg overrun",
        # Same class of mistake, and this one is also unreachable on Linux:
        # EC_ZEBRA_RECVMSG_OVERRUN is raised from two places, and the only one
        # that is not netlink is zebra/kernel_socket.c ("routing socket
        # overrun"), which is the BSD routing-socket path and is not compiled on
        # Linux. `netlink_overrun` below is the Linux one and its text was
        # already right. Keeping this key repointed at the real string rather
        # than deleting it, so "never fired" for it means "correct, not
        # applicable" instead of "unexplained".
        "zebra_recvmsg_overrun": r"routing socket overrun",
        # "Maximum-prefix" only appears in the *restart-timer* messages
        # ("Maximum-prefix restart timer started/expired"), which are emitted
        # solely when `maximum-prefix ... restart <min>` is configured — it is
        # not. The actual trip and threshold lines, both zlog_info and neither
        # debug-gated (bgpd/bgp_route.c bgp_maximum_prefix_overflow), are:
        #   "%MAXPFXEXCEED: No. of IPv4 Unicast prefix received from
        #    <peer> 181 exceed, limit 50"
        #   "%MAXPFX: No. of IPv4 Unicast prefix received from <peer>
        #    reaches 45, max 50"
        # `%MAXPFX` is a prefix of `%MAXPFXEXCEED`, so one pattern covers both
        # and `maxprefix_exceeded` separates the trip from the warning.
        # See FINDINGS.md H-30.
        "maxprefix": r"%MAXPFX",
        "maxprefix_exceeded": r"%MAXPFXEXCEED",
        # Two independent sources for this. The FSM line
        # ("[FSM] Hold timer expire for ...") is gated on
        # `debug bgp neighbor-events`; the NOTIFICATION line is not, because
        # holdtime expiry makes FRR *send* a 4/0 notification and
        # bgp_notify_print spells the code out as "(Hold Timer Expired)" at
        # zlog_info. So this fires without any debug as long as
        # log-neighbor-changes is on (see neighbor_changes_state()).
        "holdtime_expire": r"Hold Timer Expired|Hold timer expire",
        # Both of these were matching things that are not BGP notifications at
        # all. Verified against a full `make exercise` log:
        #   "sending NOTIFICATION" matched zebra's YANG northbound error
        #     "NB_OP_CHANGE: oper_walk_done: ERROR: Error sending notification
        #      message for path: /frr-vrf:lib/vrf[name=\"default\"]/state"
        #   "NOTIFICATION" matched bgpd's shutdown memory dump
        #     "bgpd: memstats:  BGP Notification Message : 4 * (variably sized)"
        # `dut_bgpd_restart` was therefore reported as having fired
        # notification_sent and notification_any when neither had anything to do
        # with BGP. Anchor on bgpd plus the BGP wording. See FINDINGS.md H-26.
        # All three notification patterns were guesses at FRR's wording and all
        # three were wrong, which is the whole of the "all three counters read 0
        # across two runs, which is still unexplained" note in the exercise
        # report. bgpd/bgp_debug.c bgp_notify_print() emits, at zlog_info:
        #   "%NOTIFICATION: sent to neighbor <host> 6/2 (Cease/...) 0 bytes"
        #   "%NOTIFICATION: received from neighbor <host> 6/2 (...) 0 bytes"
        # The old patterns required the verb *before* the word NOTIFICATION
        # ("sending NOTIFICATION"), and `notification_any` required
        # "NOTIFICATION" followed immediately by a digit. Neither shape exists.
        # The leading `%` is what separates these from bgpd's shutdown memstats
        # line "BGP Notification Message : 4 * (variably sized)", so it is the
        # anchor rather than the daemon name. Gated on
        # `debug bgp neighbor-events` OR log-neighbor-changes — the latter is
        # config, not debug, and survives a bgpd restart.
        # See FINDINGS.md H-30.
        "notification_sent": r"%NOTIFICATION[^:]*: sent to neighbor",
        "notification_recv": r"%NOTIFICATION[^:]*: received from neighbor",
        "bgpd_crash": "bgpd.*(Segmentation|assert|crash|aborting)",
        "optmem": "sockopt_tcp_signature",
        # bgp_fsm.c logs session up/down at zlog_info under
        # BGP_FLAG_LOG_NEIGHBOR_CHANGES, with the reset reason appended from
        # peer_down_str[]:
        #   "%ADJCHANGE: neighbor <peer> in vrf default Down BGP Notification received"
        #   "%ADJCHANGE: neighbor <peer> in vrf default Up"
        # The old pattern ("Notification received") is a substring of the real
        # reason "BGP Notification received", so it would have matched — but
        # only for that one reason out of 47, and only with log-neighbor-changes
        # on. Match the ADJCHANGE tag itself and the direction.
        "peer_down": r"%ADJCHANGE:.* Down ",
        "peer_up": r"%ADJCHANGE:.* Up\b",
        # enforce-first-as. FRR 10.0 turned this ON by default
        # (FRR_CFG_DEFAULT_BOOL(BGP_ENFORCE_FIRST_AS) in bgpd/bgp_vty.c, guarded
        # by match_version "< 9.1"), and since FRR 7.4 a violation is
        # treat-as-withdraw rather than a NOTIFICATION
        # (bgp_attr_aspath_check returns BGP_ATTR_PARSE_WITHDRAW). So the routes
        # vanish while the session stays Established and nothing in
        # `show bgp summary` says why. This counter is the only cheap signal.
        # Log string, verbatim from bgpd/bgp_attr.c:
        #   "%s incorrect first AS (must be %u)"
        "attr_first_as": "incorrect first AS",
        # Martian next-hop. Verbatim from bgpd/bgp_attr.c in FRR 10.5.2:
        #   flog_err(EC_BGP_ATTR_MARTIAN_NH, "Martian nexthop %pI4", ...)
        # flog_err, so it is unconditional, not debug-gated. This was missing,
        # which is why a run that reset the session 1,130 times reported
        # notification_sent=0 and showed only unrelated AS_PATH lines: nothing
        # in LOG_PATTERNS matched the actual cause. See FINDINGS.md H-8.
        "martian_nexthop": "Martian nexthop",
        # FRR's OWN saturation detector, and the single most important signal in
        # this whole table. lib/event.c warns when a scheduled event runs later
        # than `--event-warn` / the default threshold:
        #   "CPU starvation: {...} getting executed %ldms late, warning threshold %ldms"
        # Observed at T1 (42 sessions, 90,830 paths) at 4,535-5,181 ms late on
        # bgp_generate_updgrp_packets and update_subgroup_merge_check_thread_cb —
        # i.e. bgpd's main thread blocked for over five seconds. This pattern was
        # absent, so the T1 report showed `attr_withdraw: 2` and nothing else
        # while FRR was logging exactly the thing the whole exercise is looking
        # for. See FINDINGS.md H-20.
        "cpu_starvation": "CPU starvation",
        # Companion: FRR also warns when a single event *runs* too long.
        # Companion: FRR also warns when a single event *runs* too long. The
        # old pattern was invented; lib/event.c and lib/vty.c actually log
        #   "CPU HOG: task %s (%lx) ran for %lums (cpu time %lums)"
        #   "CPU HOG: command took %lums (cpu time %lums): %s"
        #   "STARVATION: task %s (%lx) ran for %lums (cpu time %lums)"
        # (EC_LIB_SLOW_THREAD_CPU / _WALL). Note this is a different detector
        # from `cpu_starvation` above, which is the *scheduling delay* warning
        # (EC_LIB_STARVE_THREAD, "CPU starvation: ... getting executed Nms
        # late") and is the one already observed at T1.
        # "STARVATION:" needs the task/command qualifier: matching is
        # case-insensitive, so a bare "STARVATION:" also swallows every
        # "CPU starvation:" line and the two detectors stop being distinct.
        "event_slow": r"CPU HOG:|STARVATION: (task|command)",
        # A peer dropping the TCP connection. Expected during a deliberate flap,
        # but at scale it is also how a send-queue teardown and an OOM-killed
        # generator look, and neither was matched by anything here.
        "read_packet_error": r"bgp_read_packet error",
        # The two patterns below assume FRR words its notification log lines
        # "sending NOTIFICATION" / "received NOTIFICATION". That has NOT been
        # confirmed against 10.5.2 — a run with 1,130 confirmed session resets
        # left both at 0 — so treat a zero here as "unknown", not "no
        # notifications". `notification_any` is the version-independent counter;
        # prefer it.
        # Deliberately still broad, but scoped to bgpd and to the uppercase
        # protocol spelling so memstats' "BGP Notification Message" cannot match.
        "notification_any": r"%NOTIFICATION",
        # Companion line on every treat-as-withdraw, bgpd/bgp_packet.c:
        #   "%pBP rcvd UPDATE with errors in attr(s)!! Withdrawing route."
        "attr_withdraw": r"errors in attr\(s\)",
        # bgpd losing its unix-socket connection to zebra. Seen unprompted in
        # the 2026-08-21 exercise rerun, immediately after a bgpd restart
        # (PID 456 -> 39183), and previously uncounted by anything here:
        #   [EC 100663299] buffer_write: write error on fd 19: Broken pipe
        #   [EC 100663302] zclient_send_message: buffer_write failed to
        #                  zclient fd 19, closing
        # While this is broken bgpd cannot install or resolve anything through
        # zebra, so the RIB and the FIB silently diverge — `show bgp` looks
        # healthy and the kernel has nothing. It is exactly the class of
        # failure the log detectors exist for.
        "zebra_conn_lost": r"zclient_send_message: buffer_write failed|buffer_write: write error",
        # The failure mode T2 actually produced, and which `bgpd_crash` could
        # never have caught because bgpd did not crash — its own supervisor
        # killed it. watchfrr pings each daemon and, past `--timeout` (VyOS
        # ships `--timeout=90`), declares it dead:
        #   [EC 268435457] bgpd state -> unresponsive : no response yet to ping
        #                  sent 90 seconds ago
        #   Forked background command [pid 71630]: watchfrr.sh restart bgpd
        #   bgpd[504]: Terminating on signal
        # bgpd's main thread is single-threaded for UPDATE parsing, bestpath,
        # policy evaluation and update generation, so at 2.8M paths under churn
        # it can legitimately be busy for longer than 90 s — and then the
        # platform kills a working daemon. See FINDINGS.md R-2.
        "daemon_unresponsive": r"state -> unresponsive|no response yet to ping",
        # The restart that follows, and its own failure to finish in time.
        "daemon_watchdog_restart": r"watchfrr\.sh restart|restart \w+ process \d+ terminated due to signal",
        # Consequence of the above: every nexthop registration bgpd tries to
        # push afterwards fails. Ten of these followed the broken pipe.
        #   [EC 33554500] sendmsg_nexthop: zclient_send_message() failed
        "nexthop_reg_fail": r"sendmsg_nexthop",
    }

    #: FRR's config writer prints enforce-first-as *inverted* when the default is
    #: on: at the default it prints nothing, and `no neighbor X enforce-first-as`
    #: means it has been explicitly disabled (bgp_vty.c, bgp_config_write_peer).
    #: So "no output" here means enforcement is ACTIVE, not absent.
    def enforce_first_as_state(self) -> Dict[str, Any]:
        """What the DUT's running FRR config says about enforce-first-as."""
        r = self.vtysh("show running-config")
        if not r.ok:
            return {"ok": False, "error": (r.err or r.out or "")[:200]}
        lines = [l.strip() for l in r.out.splitlines()
                 if "enforce-first-as" in l]
        disabled = [l for l in lines if l.startswith("no ")]
        enabled = [l for l in lines if not l.startswith("no ")]
        return {"ok": True,
                "explicitly_disabled": len(disabled),
                "explicitly_enabled": len(enabled),
                "lines": lines[:40],
                # No line at all for a neighbour == FRR default == ON (>= 10.0).
                "default_applies": not lines}

    #: Cached result of "does journalctl work in this container".
    _journal_ok: Optional[bool] = field(default=None, init=False, repr=False)
    #: True when the last log read could NOT be time-bounded, so its counts
    #: cover whatever was in /var/log/messages rather than the asked-for window.
    log_window_unbounded: bool = field(default=False, init=False, repr=False)
    #: Raw tail of the last `show debugging bgp`, so a False in
    #: bgp_debugs_active() can be told apart from a parse failure.
    debug_show_raw: str = field(default="", init=False, repr=False)
    #: Which readback command actually worked, or None if none did.
    debug_show_cmd: Optional[str] = field(default=None, init=False, repr=False)

    #: FRR logs BGP session events only under these debugs. Verified empirically:
    #: a full `make exercise` — 17 events including four peer-flap modes, a
    #: blackhole held for 2.5x holdtime, and a bgpd restart — produced ZERO
    #: occurrences of "went from", "Hold Timer", "Maximum-prefix",
    #: "bgp_read_packet" or any real NOTIFICATION line. bgpd's only output was
    #: attribute-parse errors. Session state changes, holdtime expiry and
    #: notification send/receive are all behind `debug bgp neighbor-events`
    #: (bgp_fsm.c and bgp_packet.c gate them on
    #: BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)), so eight detectors were
    #: structurally unable to fire. See FINDINGS.md H-27.
    BGP_DEBUGS = ("debug bgp neighbor-events",)

    #: FRR's log *destinations* have their own severity floor, applied after the
    #: debug flag is consulted: `zlog_debug()` output is discarded before it
    #: reaches syslog unless the syslog destination is itself set to
    #: `debugging`. So arming `debug bgp neighbor-events` is necessary but not
    #: sufficient — both halves have to be true for a single line to appear.
    #: Which of the two halves was missing in the 2026-08-21 run has NOT been
    #: established; this code now sets both and then proves the chain
    #: end-to-end with `verify_log_pipeline()` rather than assuming either.
    LOG_LEVEL_CMD = "log syslog debugging"

    @staticmethod
    def _cap(r: "RunResult", n: int = 600) -> Dict[str, Any]:
        """A capturable summary of a vtysh call, for evidence in the report."""
        return {"rc": r.rc,
                "out": (r.out or "").strip()[-n:],
                "err": (r.err or "").strip()[-n:]}

    def enable_bgp_debugs(self, extra: Sequence[str] = (),
                          set_log_level: bool = True) -> Dict[str, Any]:
        """Arm the FRR debugs the log detectors need, and prove they took.

        Three things went wrong with the previous version, all of them silent:

        1. It only tried the CONFIG_NODE form
           (`vtysh -c 'configure terminal' -c 'debug bgp neighbor-events'`),
           reported `armed=True` from vtysh's exit status alone, and the very
           next call to `bgp_debugs_active()` returned False. vtysh's exit
           status says the command was accepted, not that the flag is set.
        2. It never touched the log destination's severity floor, so even a
           correctly set flag can produce no output (see LOG_LEVEL_CMD).
        3. It was called exactly once, before the first event. Terminal debugs
           live in the daemon's memory, so `dut_bgpd_restart` drops them, and a
           VyOS commit runs frr-reload which can drop the config-node form.
           Everything after step 12 of the exercise plan was unarmed regardless.

        Now: set the severity floor, try the ENABLE_NODE form first (it sets the
        term flag directly and frr-reload cannot touch it), verify, fall back to
        the CONFIG_NODE form, verify again, and return the raw vtysh output of
        every step so a failure is visible instead of inferred. `ok` means the
        debug is *active*, not that vtysh exited 0. See FINDINGS.md H-27.
        """
        cmds = list(self.BGP_DEBUGS) + list(extra)
        args = " ".join(f"-c {shlex.quote(c)}" for c in cmds)
        raw: Dict[str, Any] = {}

        # `bgp log-neighbor-changes` is config rather than a debug: it survives a
        # bgpd restart and an frr-reload, it logs at info, and it is what unlocks
        # %ADJCHANGE and %NOTIFICATION (bgp_debug.c checks
        # BGP_DEBUG(neighbor_events) || BGP_FLAG_LOG_NEIGHBOR_CHANGES). The
        # template already carries `set protocols bgp parameters
        # log-neighbor-changes` and it is in the generated base config, so this
        # is normally a no-op that confirms rather than changes.
        nbr = self.enable_neighbor_changes()
        raw["log_neighbor_changes"] = {"ok": nbr.get("ok"),
                                       "asn": nbr.get("asn"),
                                       "error": nbr.get("error")}

        if set_log_level:
            raw["log_level"] = self._cap(self.exec(
                "vtysh -c 'configure terminal' -c "
                + shlex.quote(self.LOG_LEVEL_CMD), timeout=30))

        # ENABLE_NODE only, deliberately. TERM_DEBUG_ON sets an in-process flag
        # that does not appear in `show running-config`, so frr-reload cannot see
        # it and cannot remove it. The CONFIG_NODE form does appear there, and a
        # single VyOS commit then wipes it — which is exactly what happened on
        # 2026-08-21: FSM lines stop at the first policy_churn commit and never
        # come back, so maxprefix_trip, blackhole_peer, gr_event and
        # dut_bgpd_restart all ran blind. FRR prints
        # "BGP neighbor-events debugging is on" from the enable node, and that
        # echo is authoritative — more so than a readback command this build may
        # not implement.
        r1 = self.exec(f"vtysh {args}", timeout=30)
        raw["enable_node"] = self._cap(r1)
        echoed = "debugging is on" in (r1.out or "").lower()
        active = self.bgp_debugs_active()
        via = "enable_node"

        if not (echoed or all(active.values())):
            # Last resort. Note in the return value that this form is fragile:
            # it will be removed by the next commit's frr-reload.
            r2 = self.exec(f"vtysh -c 'configure terminal' {args}", timeout=30)
            raw["config_node"] = self._cap(r2)
            active = self.bgp_debugs_active()
            via = "config_node (fragile: frr-reload removes this on the next "
            via += "VyOS commit)"

        ok = bool(echoed or all(active.values()))
        raw["readback_cmd"] = getattr(self, "debug_show_cmd", None)
        raw["readback"] = self.debug_show_raw
        if not ok:
            raw["show_logging"] = self._cap(self.vtysh("show logging"))

        return {"ok": ok,
                "sent_ok": bool(r1.ok),
                "echoed": echoed,
                "commands": cmds,
                "active": active,
                "neighbor_changes": bool(nbr.get("ok")),
                "via": via,
                "raw": raw}

    def rearm_bgp_debugs(self) -> Dict[str, bool]:
        """Cheap re-arm: enable-node form only, trusting FRR's own echo.

        Called before every exercise event. A VyOS commit runs frr-reload, and a
        bgpd restart drops in-process state, so the flag cannot be assumed to
        survive from one event to the next.
        """
        args = " ".join(f"-c {shlex.quote(c)}" for c in self.BGP_DEBUGS)
        r = self.exec(f"vtysh {args}", timeout=30)
        if "debugging is on" in (r.out or "").lower():
            return {c: True for c in self.BGP_DEBUGS}
        return self.bgp_debugs_active()

    #: Per-daemon syslog severity, from `show logging`. FRR consults the debug
    #: flag first and the *destination's* severity floor second, so a correctly
    #: armed debug still produces nothing if the floor is above it.
    LOG_LEVEL_RE = re.compile(
        r"Logging configuration for (\w+):\s*\n\s*Syslog logging: level (\w+)",
        re.IGNORECASE)

    def logging_state(self) -> Dict[str, Any]:
        """The syslog severity each daemon is currently logging at.

        This is the measurement that explains the 2026-08-21 18:40 run. The
        debug was armed and stayed armed — `show debugging` said so before and
        after every event — and yet bgpd emitted no debug and no *info* lines
        after the first `policy_churn` commit, while continuing to emit warnings
        and errors. Two peers demonstrably left Established during
        `maxprefix_trip` and a session demonstrably dropped during
        `blackhole_peer`; neither produced a single log line. The flag was on and
        the floor had moved. See FINDINGS.md H-39.
        """
        r = self.vtysh("show logging")
        levels = {d.lower(): lvl.lower()
                  for d, lvl in self.LOG_LEVEL_RE.findall(r.out or "")}
        return {"ok": r.ok, "levels": levels,
                "bgpd": levels.get("bgpd"),
                "debug_reaches_log": levels.get("bgpd") == "debugging"}

    #: `show ip route summary` prints one line per route source plus a Totals
    #: line, with RIB and FIB counts side by side:
    #:     Route Source         Routes               FIB  (vrf default)
    #:     bgp                  2251132              2251132
    ROUTE_SUMMARY_RE = re.compile(
        r"^\s*(\S+)\s+(\d+)\s+(\d+)\s*$", re.MULTILINE)

    #: Every row name `show ip route summary` uses for a BGP-learned route.
    #: FRR 10.5.2 emits `ebgp` and `ibgp` (zebra/zebra_vty.c, ZEBRA_ROUTE_BGP
    #: is split by `is_ibgp`); older builds emit a single `bgp`. All three are
    #: summed, so this reads correctly on either.
    BGP_ROUTE_SOURCES = ("bgp", "ebgp", "ibgp")

    def route_summary(self, afi: str = "ipv4") -> Dict[str, Any]:
        """RIB and FIB counts per route source, straight from zebra.

        This is the authoritative answer to "how much of the BGP table is
        actually installed", and it is the number that decides whether traffic
        works. `show bgp summary` cannot answer it: at T2 it reported all 149
        sessions Established with 2,251,132 prefixes received while zebra had
        installed 136 routes (FINDINGS.md H-40).

        Deliberately NOT sampled on every tick — zebra walks the table to
        produce it, which is not something to do every two seconds against
        millions of routes. One shot at convergence time is the right cost.
        """
        cmd = ("show ip route summary" if afi == "ipv4"
               else "show ipv6 route summary")
        r = self.vtysh(cmd, timeout=120)
        out: Dict[str, Any] = {"ok": r.ok, "afi": afi, "sources": {}}
        if not r.ok:
            out["error"] = (r.err or r.out or "")[:200]
            return out
        for src, routes, fib in self.ROUTE_SUMMARY_RE.findall(r.out or ""):
            key = src.lower()
            if key in ("route", "totals"):
                if key == "totals":
                    out["total_routes"] = int(routes)
                    out["total_fib"] = int(fib)
                continue
            out["sources"][key] = {"routes": int(routes), "fib": int(fib)}
        # FRR does **not** print a single `bgp` row. `show ip route summary`
        # splits BGP by peer type:
        #
        #     Route Source         Routes               FIB  (vrf default)
        #     ebgp                 2445625              2445625
        #     ibgp                 0                    0
        #
        # Reading only `sources["bgp"]` therefore returned None on every real
        # FRR build, and `runner._fib_agrees()` turns None into "zebra has no
        # BGP routes at all — the FIB is empty". On T3 run 1 that string was
        # printed 160 times over the full 2,400 s warmup against a FIB that was
        # 2,445,625/2,445,625 installed, and the run recorded
        # `initial_converged: false`. Sum every BGP-bearing row, and say which
        # rows were found so a future rename is visible rather than silent.
        # See FINDINGS.md H-51.
        rows = {k: v for k, v in out["sources"].items()
                if k in self.BGP_ROUTE_SOURCES}
        out["bgp_source_rows"] = sorted(rows)
        if rows:
            out["bgp_routes"] = sum(v["routes"] for v in rows.values())
            out["bgp_fib"] = sum(v["fib"] for v in rows.values())
            if out["bgp_routes"]:
                out["bgp_fib_ratio"] = round(
                    out["bgp_fib"] / out["bgp_routes"], 4)
        else:
            out["bgp_routes"] = None
            out["bgp_fib"] = None
        return out

    #: `show bgp summary` prints a read-only-mode block while `update-delay` is
    #: configured, and it is the only place FRR reports the four timestamps that
    #: decompose a cold start. Measured on T3 (154 sessions, 4.8M paths):
    #:
    #:     Read-only mode update-delay limit: 300 seconds
    #:                        Establish wait: 60 seconds
    #:       First neighbor established: 2026/08/28 12:55:41.944
    #:               Best-paths resumed: 2026/08/28 13:00:41.944
    #:             zebra update resumed: 2026/08/28 13:03:52.908
    #:             peers update resumed: 2026/08/28 13:03:53.541
    UPDATE_DELAY_RE = {
        "limit_s": re.compile(r"update-delay limit:\s*(\d+)", re.I),
        "establish_wait_s": re.compile(r"Establish wait:\s*(\d+)", re.I),
        "first_established": re.compile(r"First neighbor established:\s*(\S+ \S+)"),
        "bestpath_resumed": re.compile(r"Best-paths resumed:\s*(\S+ \S+)"),
        "zebra_resumed": re.compile(r"zebra update resumed:\s*(\S+ \S+)"),
        "peers_resumed": re.compile(r"peers update resumed:\s*(\S+ \S+)"),
    }

    def update_delay_state(self, afi: str = "ipv4") -> Dict[str, Any]:
        """Decompose the cold start: read-only, bestpath, FIB install, advertise.

        `bgp update-delay` holds bestpath, FIB install and advertisement until
        every peer has sent End-of-RIB or the limit expires. That is correct
        behaviour and it is why a freshly-loaded DUT can sit at 0% CPU with an
        empty FIB and `PfxSnt 0` looking broken — but the *duration* is a
        first-class result, because the same sequence runs after every bgpd
        restart. It is what turns a watchdog kill (R-2) into a multi-minute
        forwarding outage rather than a blip.

        Returns the four timestamps plus the intervals between them, so the
        cold start is recorded instead of being noticed by eye.
        """
        r = self.vtysh(f"show bgp {afi} unicast summary")
        out: Dict[str, Any] = {"ok": r.ok, "afi": afi}
        if not r.ok:
            out["error"] = (r.err or r.out or "")[:200]
            return out
        text = r.out or ""
        for key, rx in self.UPDATE_DELAY_RE.items():
            m = rx.search(text)
            if m:
                out[key] = int(m.group(1)) if key.endswith("_s") else m.group(1)
        stamps: Dict[str, float] = {}
        for key in ("first_established", "bestpath_resumed", "zebra_resumed",
                    "peers_resumed"):
            v = out.get(key)
            if not v:
                continue
            try:
                stamps[key] = datetime.strptime(
                    v, "%Y/%m/%d %H:%M:%S.%f").timestamp()
            except ValueError:
                continue
        if "first_established" in stamps:
            t0 = stamps["first_established"]
            for key, label in (("bestpath_resumed", "readonly_s"),
                               ("zebra_resumed", "to_fib_s"),
                               ("peers_resumed", "to_advertise_s")):
                if key in stamps:
                    out[label] = round(stamps[key] - t0, 1)
            if {"bestpath_resumed", "zebra_resumed"} <= stamps.keys():
                out["bestpath_and_fib_s"] = round(
                    stamps["zebra_resumed"] - stamps["bestpath_resumed"], 1)
            # Hitting the limit exactly means not every peer sent End-of-RIB in
            # time — the cap fired rather than the condition being satisfied.
            lim = out.get("limit_s")
            if lim and out.get("readonly_s") is not None:
                out["limit_expired"] = abs(out["readonly_s"] - lim) < 2.0
        return out

    def local_asn(self) -> Optional[int]:
        """The DUT's local ASN, from FRR's running config."""
        r = self.vtysh("show running-config")
        m = re.search(r"^router bgp (\d+)", r.out or "", re.MULTILINE)
        if m:
            return int(m.group(1))
        j = self.bgp_summary("ipv4") or {}
        try:
            return int(j.get("as"))
        except (TypeError, ValueError):
            return None

    def neighbor_changes_state(self) -> Dict[str, Any]:
        """Whether `bgp log-neighbor-changes` is on, from the running config.

        This is a *config* flag, not a debug, and it is what unlocks the
        info-level session record: bgp_fsm.c emits
        `%ADJCHANGE: neighbor <peer> in vrf default Down <reason>` under
        BGP_FLAG_LOG_NEIGHBOR_CHANGES, and bgp_debug.c's bgp_notify_print()
        emits the `%NOTIFICATION:` lines when *either* that flag or
        `debug bgp neighbor-events` is set. Unlike a terminal debug it survives
        both a bgpd restart and an frr-reload, so it is the better primary
        source for six of the detectors that had never fired.
        """
        r = self.vtysh("show running-config")
        out = r.out or ""
        on = bool(re.search(r"^\s*bgp log-neighbor-changes", out, re.MULTILINE))
        off = bool(re.search(r"^\s*no bgp log-neighbor-changes", out,
                             re.MULTILINE))
        return {"ok": r.ok, "enabled": on, "explicitly_disabled": off,
                "asn": None}

    def enable_neighbor_changes(self) -> Dict[str, Any]:
        """Turn on `bgp log-neighbor-changes` via vtysh and confirm it took.

        Normally a no-op that confirms rather than changes: the template carries
        `set protocols bgp parameters log-neighbor-changes` and it is in the
        generated base config, so VyOS has already committed it. Done in FRR
        rather than as a VyOS commit because a commit on a loaded table costs
        tens of seconds.
        """
        asn = self.local_asn()
        if asn is None:
            return {"ok": False, "error": "could not determine local ASN",
                    "asn": None}
        r = self.exec("vtysh -c 'configure terminal' "
                      f"-c 'router bgp {asn}' -c 'bgp log-neighbor-changes'",
                      timeout=30)
        st = self.neighbor_changes_state()
        st["asn"] = asn
        return {"ok": bool(st["enabled"]), "asn": asn,
                "was": st, "vtysh": self._cap(r)}

    #: Readback commands, in order of preference. `show debugging bgp` is what
    #: FRR's own bgp_debug.c installs, and it is what this code asked for — but
    #: on VyOS 1.5.1 vtysh it comes back `% Unknown command: show debugging bgp`.
    #: That one unknown command caused the whole cascade: the readback said "not
    #: active" even though the debug was on, so arming fell through to the
    #: CONFIG_NODE form, which lands in the running config, which means the next
    #: VyOS commit's frr-reload sees a line the generated frr.conf does not have
    #: and issues `no debug bgp neighbor-events` — clearing the term flag with
    #: it. Every event after the first policy_churn ran unarmed. See H-34.
    DEBUG_SHOW_CMDS = ("show debugging", "show debugging bgp")

    def bgp_debugs_active(self) -> Dict[str, bool]:
        """Which of BGP_DEBUGS FRR currently reports as on.

        Tries each readback in DEBUG_SHOW_CMDS and skips any that the build does
        not implement, instead of treating "unknown command" as "not enabled".
        """
        out = ""
        used = None
        for cmd in self.DEBUG_SHOW_CMDS:
            r = self.vtysh(cmd)
            text = (r.out or "")
            if not r.ok or "unknown command" in text.lower():
                continue
            out, used = text.lower(), cmd
            break
        self.debug_show_raw = (out or "").strip()[-600:]
        self.debug_show_cmd = used
        res: Dict[str, bool] = {}
        for c in self.BGP_DEBUGS:
            topic = c.lower().replace("debug bgp ", "").strip()
            variants = {topic, topic.replace("-", " "), topic.replace(" ", "-")}
            res[c] = (any(f"{v} debugging is on" in out for v in variants)
                      or any(v in out for v in variants))
        return res

    def verify_log_pipeline(self, peer: str, wait_s: float = 8.0
                           ) -> Dict[str, Any]:
        """Reset one session and report which log *severity* actually arrives.

        This is the measurement that closes out sixteen never-fired detectors.
        A single session reset produces, in FRR 10.5.2, one line at each of
        three severities:

          debug  "<peer> fd N went from Established to Clearing ..."
                 (bgp_fsm.c, gated on `debug bgp neighbor-events`)
          info   "%ADJCHANGE: neighbor <peer> in vrf default Down <reason>"
                 (bgp_fsm.c, gated on `bgp log-neighbor-changes`)
          info   "%NOTIFICATION: sent to neighbor <peer> 6/... (Cease/...)"
                 (bgp_debug.c, gated on either of the two above)

        Every detector this project has ever *seen* fire — attr_withdraw,
        martian_nexthop, cpu_starvation — is flog_err or flog_warn. Every
        detector that has never fired is info or debug, or had a wrong pattern.
        That is consistent with a severity floor somewhere below bgpd rather
        than with a missing flag, but the two have never been told apart. This
        does tell them apart: `tier_reached` names the lowest severity that made
        it all the way to the reader.
        """
        self.vtysh(f"clear bgp {peer}", timeout=30)
        time.sleep(wait_s)
        window = f"-{int(wait_s) + 8}s"
        rx = (r"went from|%ADJCHANGE|%NOTIFICATION|Notification|"
              r"bgp_read_packet|SendQ progress")
        lines = self.log_since(window, extra_grep=rx)

        def hit(pat: str) -> List[str]:
            return [l for l in lines if re.search(pat, l, re.IGNORECASE)]

        fsm = hit(r"went from")                     # debug
        adj = hit(r"%ADJCHANGE")                    # info
        note = hit(r"%NOTIFICATION")                # info
        tier = ("debug" if fsm else
                "info" if (adj or note) else
                "warn_or_err_only")
        return {"ok": bool(fsm or adj or note),
                "peer": peer,
                "matched": len(lines),
                "fsm_debug_lines": len(fsm),
                "adjchange_lines": len(adj),
                "notification_lines": len(note),
                "tier_reached": tier,
                "sample": [l[-220:] for l in (fsm + adj + note or lines)[:6]],
                "window_unbounded": self.log_window_unbounded}

    def log_since(self, since: str = "-30s", extra_grep: Optional[str] = None
                  ) -> List[str]:
        """Log lines within `since`, matched in Python rather than in shell.

        The previous implementation chained the fallback with `||`:

            journalctl --since '-10s' ... | grep -Ei PAT || \
            tail -n 4000 /var/log/messages | grep -Ei PAT || true

        `grep` exits 1 when it matches nothing, which is the *normal* case for a
        quiet 10-second window — so every quiet sample fell through to the
        fallback, which has **no time bound at all**. The effect was total and
        silent: 62 consecutive slow samples in one 600 s run each reported
        exactly `martian_nexthop: 332, attr_withdraw: 447`, a constant carried
        over from a `make probe` run the previous day. The log signatures are the
        primary failure detector at scale (`SENDQ_STUCK`, netlink overrun,
        maxprefix, holdtime expiry), so this meant the harness could not see a
        new one at all. See FINDINGS.md H-18.

        Now: journalctl is used when it works, its exit status distinguishes
        "unusable" from "nothing matched", and matching happens here. When the
        fallback is used, `log_window_unbounded` is set so callers can say so
        rather than quietly trusting a number that spans the whole file.
        """
        pat = extra_grep or "|".join(self.LOG_PATTERNS.values())
        rx = re.compile(pat, re.IGNORECASE)
        self.log_window_unbounded = False

        if self._journal_ok is not False:
            r = self.exec(
                f"journalctl --since {shlex.quote(since)} --no-pager -o cat",
                timeout=30)
            if r.ok:
                self._journal_ok = True
                return [l for l in r.out.splitlines() if l.strip() and rx.search(l)]
            self._journal_ok = False

        r = self.exec("tail -n 4000 /var/log/messages 2>/dev/null || true",
                      timeout=30)
        self.log_window_unbounded = True
        return [l for l in r.out.splitlines() if l.strip() and rx.search(l)]

    def _log_since_legacy(self, since: str, extra_grep: Optional[str]) -> List[str]:
        """Retained only so the old shell form is documented, never called."""
        pat = extra_grep or "|".join(self.LOG_PATTERNS.values())
        cmd = (
            f"journalctl --since '{since}' --no-pager -o cat 2>/dev/null "
            f"| grep -Ei {shlex.quote(pat)} || "
            f"tail -n 4000 /var/log/messages 2>/dev/null | grep -Ei {shlex.quote(pat)} || true"
        )
        r = self.exec(cmd, timeout=30)
        return [l for l in r.out.splitlines() if l.strip()]

    def log_counts(self, since: str = "-30s") -> Dict[str, int]:
        """Counts within `since`. Adds `_window_unbounded` when it is not.

        The flag matters: a count taken over an unbounded window is a historical
        total, not a rate, and summing it across samples is meaningless. Callers
        and the report must be able to tell the difference.
        """
        lines = self.log_since(since)
        counts: Dict[str, int] = {k: 0 for k in self.LOG_PATTERNS}
        for line in lines:
            for key, pat in self.LOG_PATTERNS.items():
                if re.search(pat, line, re.IGNORECASE):
                    counts[key] += 1
        if self.log_window_unbounded:
            counts["_window_unbounded"] = 1
        return counts

    # ---- configuration ---------------------------------------------------

    CONFIG_WRAPPER = (
        "source /opt/vyatta/etc/functions/script-template\n"
        "configure\n"
        "{body}\n"
        "commit\n"
        "exit\n"
    )

    def configure(self, lines: List[str], save: bool = False,
                  timeout: Optional[float] = None) -> RunResult:
        """Apply set/delete commands and commit, timing the commit.

        Commit latency is itself a first-class result: on a router holding a full
        table, a policy change forces a full re-evaluation, and a commit that
        takes minutes is an operational finding whether or not BGP stays up.
        """
        body = [l for l in lines
                if l.strip() and not l.strip().startswith("#")]
        if not body:
            return RunResult(0, "", "", 0.0)
        script = self.CONFIG_WRAPPER.format(body="\n".join(body))
        if save:
            script = script.replace("commit\nexit\n", "commit\nsave\nexit\n")
        r = _run(docker_cmd() + ["exec", "-i", self.container, "/bin/vbash", "-s"],
                 timeout or self.commit_timeout, input_=script)
        if r.rc == 124:
            raise CommitTimeout(
                f"commit did not finish within {timeout or self.commit_timeout}s "
                f"({len(body)} command(s))"
            )
        self.reassert_logging()
        return r

    def reassert_logging(self) -> Dict[str, Any]:
        """Put the FRR log level and debugs back after a VyOS commit.

        A commit runs `frr-reload.py`, which diffs FRR's running config against
        the frr.conf VyOS generates and removes anything it does not find there.
        `log syslog debugging` is *config*, so it goes — and with it every
        info-level and debug-level line, silently, mid-run.

        Measured: on the 2026-08-21 18:40 run, bgpd logged debug, info, warning
        and error up to 18:45:05, the first commit landed at 18:45:31, and from
        then on the log contains only warnings and errors. `maxprefix_trip`
        tripped two peers off the table at 18:46:42 and `blackhole_peer` dropped
        a session inside one holdtime, and neither logged anything at all. Both
        were read as "the DUT did not do it" for three runs.

        The enable-node debug flag itself survives frr-reload (it is in-process,
        H-34) — it is the destination floor that moves. So this is called from
        `configure()`, which is the only thing in the harness that commits, and
        therefore the only place the floor can be lost.
        """
        out: Dict[str, Any] = {}
        out["level"] = self._cap(self.exec(
            "vtysh -c 'configure terminal' -c " + shlex.quote(self.LOG_LEVEL_CMD),
            timeout=30))
        args = " ".join(f"-c {shlex.quote(c)}" for c in self.BGP_DEBUGS)
        out["debugs"] = self._cap(self.exec(f"vtysh {args}", timeout=30))
        st = self.logging_state()
        out["bgpd_level"] = st.get("bgpd")
        out["ok"] = bool(st.get("debug_reaches_log"))
        return out

    def configure_file(self, path: str, **kw) -> RunResult:
        with open(path, "r", encoding="utf-8") as fh:
            return self.configure(fh.read().splitlines(), **kw)

    def reset_bgp(self, target: str = "all", soft: Optional[str] = None,
                  afi: Optional[str] = None) -> RunResult:
        """VyOS spells this `reset`, not `clear`.

        Its op-mode wrapper rewrites `reset bgp` to `clear bgp` before handing it
        to vtysh; since we go straight to vtysh, use FRR's spelling.
        """
        cmd = "clear bgp"
        if afi:
            cmd += f" {afi} unicast"
        cmd += f" {target}"
        if soft:
            cmd += " soft" + (f" {soft}" if soft in ("in", "out") else "")
        return self.vtysh(cmd, timeout=120)

    def restart_bgpd(self) -> RunResult:
        """Restart bgpd only. Exercises the DUT's own graceful-restart path."""
        return self.exec("systemctl restart frr || /usr/lib/frr/frrinit.sh restart",
                         timeout=180)

    def version(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        r = self.vtysh("show version")
        if r.ok:
            out["frr"] = r.out.strip().splitlines()[0] if r.out.strip() else ""
        r = self.exec("cat /etc/os-release 2>/dev/null | head -4", timeout=15)
        if r.ok:
            for line in r.out.splitlines():
                if line.startswith("PRETTY_NAME="):
                    out["vyos"] = line.split("=", 1)[1].strip('"')
        r = self.exec("uname -r", timeout=15)
        if r.ok:
            out["kernel"] = r.out.strip()
        return out

    def kernel_route_counts(self) -> Dict[str, int]:
        """FIB size as the kernel sees it — the other half of convergence.

        IPv4 has no configurable FIB ceiling in modern kernels
        (`net.ipv4.route.max_size` has been a no-op since 3.6), so IPv4 failure
        shows up as memory pressure. IPv6 `max_size` was a real ceiling until it
        was deprecated in kernel 6.3, so whether it binds depends on `uname -r`.
        """
        r = self.exec(
            "echo v4=$(ip -4 route show | wc -l); "
            "echo v6=$(ip -6 route show | wc -l); "
            "echo v6max=$(sysctl -n net.ipv6.route.max_size 2>/dev/null || echo -1); "
            "echo v6gc=$(sysctl -n net.ipv6.route.gc_thresh 2>/dev/null || echo -1)",
            timeout=120)
        out: Dict[str, int] = {}
        for line in r.out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    out[k.strip()] = int(v.strip())
                except ValueError:
                    pass
        return out
