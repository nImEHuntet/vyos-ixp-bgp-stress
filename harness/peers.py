"""Drivers for the simulated-peer side: GoBGP and ExaBGP.

GoBGP
-----
One `gobgpd` per session, each bound to its own address via `local-address-list`
so many coexist on port 179 in one container. Control is via the `gobgp` CLI
against that process's own gRPC port.

Flap primitives, in increasing severity — which one you pick determines what is
actually being tested:

| primitive        | mechanism                                    | what it exercises |
|------------------|----------------------------------------------|-------------------|
| `softreset_in`   | `gobgp neighbor X softresetin`               | route-refresh / the DUT's soft-reconfiguration inbound |
| `admin_down`     | `gobgp neighbor X disable`                   | clean teardown, then a full re-advertisement |
| `notification`   | `gobgp neighbor X shutdown --reason ...`     | Cease NOTIFICATION with Administrative Shutdown and an RFC 8203 shutdown communication |
| `process_kill`   | `SIGINT` to gobgpd                           | GR helper path — gobgpd does *not* send NOTIFICATION on SIGINT/SIGKILL, so the DUT enters graceful-restart helper mode |
| `process_term`   | `SIGTERM` to gobgpd                          | the opposite: gobgpd *does* notify, so GR is not triggered |
| `blackhole`      | drop port 179 in the peer netns              | holdtime expiry, and the DUT's send-queue behaviour with a peer that stops reading |

That last one is the important one for limit-finding. FRR tears a session down
when its send queue makes no progress for `2 x holdtime` — hardcoded, not
configurable, and absent from the FRR user documentation. `blackhole` is how you
reach it deliberately instead of stumbling into it.

ExaBGP
------
Driven by writing text commands into the FIFO that the generated `nasty.py`
helper reads. The helper is responsible for draining ExaBGP's ACK stream; if it
did not, the pipe would fill and the session would stall in a way that looks
exactly like a DUT fault.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .dut import RunResult, _run, docker_cmd
from .model import Session


# ---------------------------------------------------------------------------
# process detection inside peer containers
# ---------------------------------------------------------------------------
#
# `pgrep -f <pattern>` cannot be used here. The harness reaches into containers
# with `docker exec ... sh -c "<command>"`, so the shell's own command line
# contains the pattern, and pgrep matches it. The effect was silent and total:
# gobgpd_pid() always returned a PID, the runner concluded every generator was
# already running, started none of them, and every MRT injection then failed
# against a gobgpd that did not exist.
#
# The bracket trick (`[g]obgpd`) fixes the immediate shell but not ancestors whose
# command lines may also contain the pattern. Matching on the resolved executable
# via /proc/<pid>/exe is immune to argv contamination altogether, so that is what
# is used. Verified three ways: no match when nothing runs despite the pattern
# being in the shell's argv, a correct match against a real process, and no
# cross-match between two sessions.

_SCAN = (
    'for d in /proc/[0-9]*; do '
    'e=$(readlink "$d/exe" 2>/dev/null) || continue; '
    'case "$e" in {exe}) ;; *) continue ;; esac; '
    'c=$(tr "\\0" " " < "$d/cmdline" 2>/dev/null); '
    'case "$c" in {cmd}) echo "${{d#/proc/}}" ;; esac; '
    'done'
)


def proc_scan(exe_glob: str, cmd_glob: str = "*") -> str:
    """A shell snippet printing PIDs whose exe and cmdline match the globs."""
    return _SCAN.format(exe=exe_glob, cmd=cmd_glob)


# ---------------------------------------------------------------------------
# peer-side socket state
# ---------------------------------------------------------------------------
#
# T3 run 1 ended with 75 of 154 IPv6 sessions in `Active` on the DUT and stayed
# that way for a full hour, with bgpd at 0.4% CPU. `Active` means the DUT is
# trying to open a TCP connection and getting nothing back. From the DUT alone
# that is equally consistent with:
#
#   * the far-end speaker being dead or no longer listening on v6, and
#   * the DUT's own connect attempts failing.
#
# Nothing in the run could tell those apart, so the largest number the run
# produced could not be reported to anyone. See FINDINGS.md R-8 and H-57.
#
# The discriminator is the TCP state on the *peer* side, and it is read from
# /proc rather than from `ss` or `netstat` because those are not present in
# every generator image and a missing binary would turn the answer back into a
# guess. /proc/net/tcp{,6} is in every Linux container.
#
#   LISTEN on the peer's address, no ESTABLISHED  -> the peer is up and waiting;
#                                                    the DUT's SYNs are not
#                                                    arriving or are refused
#   SYN_SENT                                      -> the peer is dialling and
#                                                    the DUT is not answering
#   nothing at all on :179 for that family        -> the peer's speaker is gone
#                                                    (lab-side, not a DUT result)
#
#: /proc/net/tcp state codes. Hex, as the kernel prints them.
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

BGP_PORT = 179


def _addr_from_proc(hexaddr: str) -> Optional[str]:
    """Decode one /proc/net/tcp{,6} address field.

    The kernel writes each 32-bit word of the address in host byte order, so on
    a little-endian host every word is byte-reversed relative to network order.
    8 hex digits is IPv4, 32 is IPv6.
    """
    try:
        if len(hexaddr) == 8:
            return str(ipaddress.IPv4Address(
                struct.pack("<I", int(hexaddr, 16))))
        if len(hexaddr) == 32:
            raw = b"".join(struct.pack("<I", int(hexaddr[i:i + 8], 16))
                           for i in range(0, 32, 8))
            return str(ipaddress.IPv6Address(raw))
    except (ValueError, struct.error, ipaddress.AddressValueError):
        return None
    return None


def parse_proc_net_tcp(text: str, port: int = BGP_PORT) -> List[Dict[str, Any]]:
    """Rows of /proc/net/tcp and /proc/net/tcp6 touching `port`.

    Pure function of its input so it can be tested against a captured file
    rather than against a running container — the rule this project arrived at
    the hard way in H-51.
    """
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or not f[0].endswith(":"):
            continue
        try:
            lhex, lport = f[1].rsplit(":", 1)
            rhex, rport = f[2].rsplit(":", 1)
            lp, rp = int(lport, 16), int(rport, 16)
        except ValueError:
            continue
        if port not in (lp, rp):
            continue
        out.append({
            "local": _addr_from_proc(lhex), "lport": lp,
            "remote": _addr_from_proc(rhex), "rport": rp,
            "state": TCP_STATES.get(f[3].upper(), f[3]),
        })
    return out


@dataclass
class PeerFleet:
    """Executes commands inside peer containers."""

    clab_prefix: str
    timeout: float = 60.0
    #: container -> ["198.51.96.15/20", "2001:db8:1::f/64", ...], from the
    #: inventory. Used to put back what a link flap removed (H-59). None means
    #: `restore_addrs` cannot act and will say so rather than pretend.
    expected_addrs: Optional[Dict[str, Any]] = None

    def cname(self, container: str) -> str:
        return f"{self.clab_prefix}-{container}"

    def exec(self, container: str, cmd: str,
             timeout: Optional[float] = None) -> RunResult:
        return _run(docker_cmd() + ["exec", "-i", self.cname(container), "sh", "-c", cmd],
                    timeout or self.timeout)

    def exec_detached(self, container: str, cmd: str) -> RunResult:
        return _run(docker_cmd() + ["exec", "-d", self.cname(container), "sh", "-c", cmd], 30)

    # -- gobgp -------------------------------------------------------------

    def gobgp(self, s: Session, args: str, timeout: Optional[float] = None) -> RunResult:
        return self.exec(s.container, f"gobgp -p {s.api_port} {args}", timeout)

    def gobgp_json(self, s: Session, args: str) -> Optional[object]:
        r = self.gobgp(s, args + " -j")
        if not r.ok or not r.out.strip():
            return None
        try:
            return json.loads(r.out)
        except json.JSONDecodeError:
            return None

    def start_gobgpd(self, s: Session, log_level: str = "info") -> RunResult:
        """Launch one gobgpd for this session.

        `--cpus 1` keeps a generator process from stealing the cores the DUT needs;
        the whole point is to bottleneck the DUT, not the harness.
        """
        cmd = (
            f"gobgpd -f /etc/gobgp/{s.sid}.toml "
            f"--api-hosts 127.0.0.1:{s.api_port} "
            f"-l {log_level} --pprof-disable --cpus 1 "
            f">/var/log/gobgpd-{s.sid}.log 2>&1"
        )
        return self.exec_detached(s.container, cmd)

    def gobgpd_pid(self, s: Session) -> Optional[int]:
        """PID of the gobgpd serving this session, or None.

        Matches on the executable, not the command line — see the note above
        `PeerFleet` for why pgrep is unusable through `docker exec`.
        """
        r = self.exec(s.container,
                      proc_scan("*/gobgpd", f"*{s.sid}.toml*") + " | head -1",
                      timeout=30)
        try:
            return int(r.out.strip().splitlines()[0])
        except (ValueError, IndexError):
            return None

    def exabgp_pids(self, container: str) -> List[int]:
        """PIDs of exabgp in a container.

        ExaBGP is a Python console script, so its exe resolves to the interpreter;
        match the interpreter plus `exabgp` in argv. The invoking shell's exe is
        /bin/sh, so it cannot match.
        """
        r = self.exec(container, proc_scan("*/python*", "*exabgp*"), timeout=30)
        out = []
        for line in r.out.strip().splitlines():
            try:
                out.append(int(line.strip()))
            except ValueError:
                continue
        return out

    def generator_pids(self, container: str) -> Dict[str, List[int]]:
        """Every generator process in a container, by kind."""
        g = self.exec(container, proc_scan("*/gobgpd"), timeout=30)
        gp = []
        for line in g.out.strip().splitlines():
            try:
                gp.append(int(line.strip()))
            except ValueError:
                continue
        return {"gobgpd": gp, "exabgp": self.exabgp_pids(container)}

    def gobgpd_log(self, s: Session, lines: int = 40) -> str:
        r = self.exec(s.container,
                      f"tail -n {lines} /var/log/gobgpd-{s.sid}.log 2>/dev/null || true",
                      timeout=30)
        return r.out.strip()

    def exabgp_log(self, container: str, lines: int = 40) -> str:
        r = self.exec(container,
                      f"tail -n {lines} /var/log/exabgp.log 2>/dev/null || true",
                      timeout=30)
        return r.out.strip()

    def inject_mrt(self, s: Session, only_best: bool = True,
                   count: Optional[int] = None,
                   timeout: float = 900.0) -> RunResult:
        """Bulk-load this session's table.

        `--only-best` matters a lot: on a real full-table MRT, omitting it has been
        reported to cost ~16.8 GiB for 820k received paths versus ~3 GiB with it,
        because every peer's view in the dump is loaded rather than just the best
        path. Both figures are from a GoBGP issue report, not an official
        benchmark, but the direction is not in doubt.

        Internally `gobgp mrt inject` streams via AddPathStream, which is why this
        is used instead of a loop over `gobgp global rib add` (one gRPC connection
        per prefix).
        """
        mrt = self.mrt_path(s)
        args = f"mrt inject global {mrt}"
        if count:
            args += f" {count}"
        if only_best:
            args += " --only-best"
        return self.gobgp(s, args, timeout=timeout)

    def file_size_in_container(self, container: str, path: str) -> Optional[int]:
        """Size of `path` as the container sees it, or None if it is not there.

        Exists because a bind mount can go stale. If whatever produced the host
        directory replaces it (a regenerate that recreates the directory, or a
        file-sync agent resolving a conflict by swapping it out), the running
        container keeps the *old* inode: the host directory is full and the
        container's view is empty. Docker reports nothing; the only symptom is
        the consumer failing to open a file that visibly exists on the host.
        """
        r = self.exec(container,
                      f"wc -c < {shlex.quote(path)} 2>/dev/null || echo MISSING",
                      timeout=30)
        out = (r.out or "").strip()
        if not out or "MISSING" in out:
            return None
        try:
            return int(out.split()[0])
        except (ValueError, IndexError):
            return None

    def mrt_path(self, s: Session) -> str:
        return s.mrt or f"/mrt/{s.sid}.mrt"

    def rib_add(self, s: Session, prefix: str, afi: str = "ipv4",
                attrs: str = "") -> RunResult:
        return self.gobgp(s, f"global rib add -a {afi} {prefix} {attrs}".strip())

    def rib_del(self, s: Session, prefix: str, afi: str = "ipv4") -> RunResult:
        return self.gobgp(s, f"global rib del -a {afi} {prefix}")

    def rib_del_all(self, s: Session, afi: str = "ipv4") -> RunResult:
        return self.gobgp(s, f"global rib del all -a {afi}", timeout=300)

    def rib_batch(self, s: Session, ops: Sequence[str],
                  timeout: float = 600.0) -> RunResult:
        """Apply many rib add/del operations in one container shell.

        Still one gRPC connection per `gobgp` invocation — that is a GoBGP CLI
        limitation, not something this harness can fix — but batching into a single
        `docker exec` removes the per-call container round trip, which dominates
        at small batch sizes.
        """
        script = "\n".join(f"gobgp -p {s.api_port} {o}" for o in ops)
        return self.exec(s.container, script, timeout=timeout)

    def peer_state(self, s: Session) -> Optional[List[Dict]]:
        return self.gobgp_json(s, "neighbor")

    # -- flap primitives ---------------------------------------------------

    def _neighbor_addrs(self, s: Session, dut_v4: str, dut_v6: str) -> List[str]:
        out = []
        if s.v4:
            out.append(dut_v4)
        if s.v6:
            out.append(dut_v6)
        return out

    def flap(self, s: Session, dut_v4: str, dut_v6: str, mode: str,
             reason: str = "vyos-ixp-stress") -> List[RunResult]:
        """Take a session down. See the table in this module's docstring."""
        res: List[RunResult] = []
        addrs = self._neighbor_addrs(s, dut_v4, dut_v6)

        if s.engine == "exabgp":
            for a in addrs:
                res.append(self.exabgp_send(s, f"neighbor {a} teardown 6"))
            return res

        if mode == "admin_down":
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} disable"))
        elif mode == "notification":
            # Cease NOTIFICATION, Administrative Shutdown subcode, plus an
            # RFC 8203 shutdown communication.
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} shutdown --reason {shlex.quote(reason)}"))
        elif mode == "reset":
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} reset"))
        elif mode == "softreset_in":
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} softresetin"))
        elif mode == "softreset_out":
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} softresetout"))
        elif mode == "process_kill":
            # SIGINT: gobgpd does NOT send NOTIFICATION, so the DUT should engage
            # its graceful-restart helper procedure.
            pid = self.gobgpd_pid(s)
            if pid:
                res.append(self.exec(s.container, f"kill -INT {pid}"))
        elif mode == "process_term":
            # SIGTERM: gobgpd DOES notify first, so GR is not triggered. The
            # contrast with process_kill isolates GR behaviour.
            pid = self.gobgpd_pid(s)
            if pid:
                res.append(self.exec(s.container, f"kill -TERM {pid}"))
        elif mode == "blackhole":
            res.append(self.blackhole(s, on=True))
        elif mode == "link_down":
            res.append(self.exec(s.container, "ip link set eth1 down"))
        else:
            raise ValueError(f"unknown flap mode: {mode}")
        return res

    def unflap(self, s: Session, dut_v4: str, dut_v6: str, mode: str) -> List[RunResult]:
        res: List[RunResult] = []
        addrs = self._neighbor_addrs(s, dut_v4, dut_v6)
        if s.engine == "exabgp":
            return res  # ExaBGP re-establishes on its own
        if mode in ("admin_down", "notification"):
            for a in addrs:
                res.append(self.gobgp(s, f"neighbor {a} enable"))
        elif mode in ("process_kill", "process_term"):
            # Restarting gobgpd gives back the SESSION but not the TABLE: a fresh
            # gobgpd has an empty RIB, so the peer re-establishes and advertises
            # nothing. `converge` then reports success (all sessions up) while the
            # DUT silently holds fewer prefixes for the rest of the run.
            #
            # Measured on t0-smoke: after `peer_flap mode=process_kill` hit the
            # route-server session, prefix drift went to -1000 v4 / -400 v6 and
            # stayed there through all six subsequent events. Any run containing
            # process_kill, process_term or gr_event loses that peer's whole
            # contribution from that point on. See FINDINGS.md H-25.
            res.append(self.start_gobgpd(s))
            res.append(self.reinject_after_restart(s))
        elif mode == "blackhole":
            res.append(self.blackhole(s, on=False))
        elif mode == "link_down":
            res.append(self.exec(s.container, "ip link set eth1 up"))
            # Bringing the link up is not enough. Linux flushed every global
            # IPv6 address on it when it went down, and does not put them back.
            # `prepare.sh` now sets keep_addr_on_down=1 so this should be a
            # no-op — but "should be" is how T3 lost 75 sessions twice, so the
            # addresses are read back and restored here as well. See
            # FINDINGS.md H-59.
            res.extend(self.restore_addrs(s.container))
        return res

    #: How `expected_addrs` describes one container. Written out because the
    #: shape is the whole point: the *interface* is part of the answer, and
    #: assuming `eth1` is what broke run 3 (H-61).
    #:     {"iface": "eth1.200", "parent": "eth1",
    #:      "cidrs": ["203.0.112.17/20", "2001:db8:2::11/64", ...]}

    def _addr_plan(self, container: str) -> Optional[Dict[str, Any]]:
        plan = (self.expected_addrs or {}).get(container)
        if not plan:
            return None
        if isinstance(plan, list):        # tolerate the old bare-list shape
            return {"iface": "eth1", "parent": "eth1", "cidrs": plan}
        return plan

    def addrs_on(self, container: str, iface: str) -> Set[str]:
        """Bare addresses currently configured on one interface."""
        have: Set[str] = set()
        for flag in ("-4", "-6"):
            r = self.exec(container,
                          f"ip {flag} -o addr show dev {iface} 2>/dev/null "
                          f"| awk '{{print $4}}' || true", timeout=30)
            have |= {l.strip().split("/")[0] for l in (r.out or "").splitlines()
                     if l.strip()}
        return have

    def container_v6_addrs(self, container: str, iface: Optional[str] = None
                           ) -> List[str]:
        """Global IPv6 addresses currently on the container's peering iface."""
        plan = self._addr_plan(container)
        dev = iface or (plan or {}).get("iface") or "eth1"
        r = self.exec(container,
                      f"ip -6 -o addr show dev {dev} scope global 2>/dev/null "
                      f"| awk '{{print $4}}' || true", timeout=30)
        return [l.strip() for l in (r.out or "").splitlines() if l.strip()]

    def restore_addrs(self, container: str, iface: Optional[str] = None
                      ) -> List[RunResult]:
        """Put back what a link-down removed, on the interface it belongs to.

        Also *removes* any expected address that has appeared on the parent
        interface when it belongs on a VLAN child. That is not tidiness: two
        interfaces in one namespace holding the same address and the same
        connected prefix leaves the egress choice to the kernel, and run 3 lost
        five sessions to it. See FINDINGS.md H-61.
        """
        out: List[RunResult] = []
        plan = self._addr_plan(container)
        if not plan:
            return out
        dev = iface or plan["iface"]
        parent = plan.get("parent") or dev
        have = self.addrs_on(container, dev)
        stray = self.addrs_on(container, parent) if parent != dev else set()
        for cidr in plan["cidrs"]:
            addr = cidr.split("/")[0]
            flag = "-6" if ":" in addr else "-4"
            if addr not in have:
                out.append(self.exec(
                    container, f"ip {flag} addr replace {cidr} dev {dev}",
                    timeout=30))
            if addr in stray:
                out.append(self.exec(
                    container, f"ip {flag} addr del {cidr} dev {parent}",
                    timeout=30))
        return out

    def addrs_missing(self, container: str, iface: Optional[str] = None
                      ) -> List[str]:
        """Expected addresses absent from the peering interface.

        Checked on the interface the inventory names, never on a guess. The
        H-61 verification passed because it looked at `eth1` — the same wrong
        interface the repair had written to. A check that shares the bug's
        assumption is not a check.
        """
        plan = self._addr_plan(container)
        if not plan:
            return []
        dev = iface or plan["iface"]
        have = self.addrs_on(container, dev)
        return [c for c in plan["cidrs"] if c.split("/")[0] not in have]

    def addrs_misplaced(self, container: str) -> List[str]:
        """Expected addresses sitting on the parent instead of the VLAN child."""
        plan = self._addr_plan(container)
        if not plan:
            return []
        dev, parent = plan["iface"], plan.get("parent") or plan["iface"]
        if parent == dev:
            return []
        on_parent = self.addrs_on(container, parent)
        return [c for c in plan["cidrs"] if c.split("/")[0] in on_parent]

    def reinject_after_restart(self, s: Session, wait_s: float = 20.0,
                               only_best: bool = True) -> RunResult:
        """Reload this session's MRT table into a freshly restarted gobgpd.

        Waits for the gRPC API to answer before injecting, because a gobgpd that
        has only just been exec'd will refuse the connection and the injection
        would fail silently into a discarded RunResult.
        """
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            if self.gobgp(s, "global rib summary -a ipv4", timeout=10).ok:
                break
            time.sleep(1.0)
        return self.inject_mrt(s, only_best=only_best)

    def kill_generators(self, container: str, signal: str = "TERM") -> int:
        """Signal every generator process in a container. Returns the count."""
        pids = self.generator_pids(container)
        allp = pids["gobgpd"] + pids["exabgp"]
        if allp:
            self.exec(container, f"kill -{signal} {' '.join(str(p) for p in allp)} "
                                 f"2>/dev/null; true", timeout=30)
        return len(allp)

    #: The one place the ExaBGP launch command lives. It used to be inline in
    #: runner._start_generators only, which meant nothing else could restart the
    #: process without duplicating it.
    EXABGP_SERVER_CMD = ("exabgp --env-file /etc/exabgp/exabgp.env server "
                         "/etc/exabgp/exabgp.conf >/var/log/exabgp.log 2>&1")

    def start_exabgp(self, container: str) -> RunResult:
        return self.exec_detached(container, self.EXABGP_SERVER_CMD)

    def restart_exabgp(self, container: str, wait_s: float = 8.0) -> bool:
        """Kill and relaunch ExaBGP so its Adj-RIB-Out is provably empty.

        Needed because withdrawing a route by prefix does not reliably clear a
        route that was announced with a hand-encoded generic attribute: after the
        malformed suite withdrew all its cases, the DUT log still showed
        unknown-attribute (153/155) and 6-byte-AS_PATH-segment lines on every
        reconnect, i.e. some cases were still being advertised. Restarting is the
        only way to guarantee a clean slate, and the process re-reads its boot
        file on start so the baseline table comes back on its own.
        """
        pids = self.exabgp_pids(container)
        if pids:
            self.exec(container,
                      f"kill -TERM {' '.join(str(x) for x in pids)} 2>/dev/null; true",
                      timeout=30)
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline and self.exabgp_pids(container):
                time.sleep(0.5)
        self.start_exabgp(container)
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            if self.exabgp_pids(container):
                return True
            time.sleep(0.5)
        return bool(self.exabgp_pids(container))

    def blackhole(self, s: Session, on: bool) -> Dict[str, Any]:
        """Silently drop BGP to/from the DUT without touching the session state.

        This is the primitive that reaches FRR's send-queue teardown and, before
        that, a plain holdtime expiry: the DUT hears nothing from the peer for a
        full holdtime.

        It used to end in `2>/dev/null; true`, return the RunResult, and be
        ignored by the caller — so an image without `iptables` produced rc 0, no
        rules, no impairment, and a green `blackhole_peer` row. That is what
        happened on 2026-08-21: the event ran for 75.3 s against a 30 s holdtime
        and FRR logged **no** session transition and **no** hold-timer expiry,
        which is impossible if BGP was actually being dropped. Now the rules are
        counted back and the result says whether the impairment exists.
        """
        action = "-I" if on else "-D"
        chains = (("iptables", "INPUT", "--dport"), ("iptables", "INPUT", "--sport"),
                  ("iptables", "OUTPUT", "--dport"), ("iptables", "OUTPUT", "--sport"),
                  ("ip6tables", "INPUT", "--dport"), ("ip6tables", "OUTPUT", "--dport"))
        cmd = "; ".join(f"{t} {action} {c} -p tcp {d} 179 -j DROP"
                        for t, c, d in chains)
        r = self.exec(s.container, f"({cmd}) 2>&1; true")
        have = self.exec(s.container,
                         "command -v iptables >/dev/null 2>&1 && echo yes || echo no")
        installed = self.blackhole_rules(s)
        return {"applied": on,
                "rc": r.rc,
                "iptables_present": (have.out or "").strip() == "yes",
                "rules_installed": installed,
                "effective": (installed > 0) if on else (installed == 0),
                "output": (r.out or "").strip()[-300:]}

    def blackhole_rules(self, s: Session) -> int:
        """How many BGP DROP rules are actually installed in the peer's netns."""
        r = self.exec(s.container,
                      "(iptables -S 2>/dev/null; ip6tables -S 2>/dev/null) "
                      "| grep -c -- '179 -j DROP' || true")
        try:
            return int((r.out or "0").strip().splitlines()[-1])
        except (ValueError, IndexError):
            return 0

    def netem(self, container: str, iface: str = "eth1", delay_ms: int = 0,
              loss_pct: float = 0.0, jitter_ms: int = 0,
              reorder_pct: float = 0.0, clear: bool = False) -> RunResult:
        """Impair the peering path.

        Latency and loss change convergence behaviour qualitatively, not just
        quantitatively: with loss on the peering LAN, TCP retransmits stall the
        UPDATE stream, which is a different failure shape from CPU saturation and
        is easy to mistake for one.
        """
        if clear:
            return self.exec(container, f"tc qdisc del dev {iface} root 2>/dev/null; true")
        parts = [f"tc qdisc replace dev {iface} root netem"]
        if delay_ms:
            parts.append(f"delay {delay_ms}ms" + (f" {jitter_ms}ms" if jitter_ms else ""))
        if loss_pct:
            parts.append(f"loss {loss_pct}%")
        if reorder_pct:
            parts.append(f"reorder {reorder_pct}% 50")
        return self.exec(container, " ".join(parts))

    def netem_active(self, container: str, iface: str = "eth1") -> Dict[str, Any]:
        """Read the qdisc back, so a missing `tc` cannot pass as an impairment.

        Same class of problem as `blackhole()`: the apply command's exit status
        was never checked by the caller, and a peer image without `tc` (or an
        iface named something else) would leave the path unimpaired while the
        event reported success. `netem` has never produced an observable effect
        in any run so far, which is consistent with either "40 ms and 1% loss is
        simply not enough to matter at this scale" or "it was never applied" —
        and those two have never been told apart.
        """
        r = self.exec(container, f"tc qdisc show dev {iface} 2>&1 || true")
        out = (r.out or "").strip()
        return {"active": "netem" in out.lower(),
                "qdisc": out[-300:],
                "tc_present": "not found" not in out.lower()}

    # -- exabgp ------------------------------------------------------------

    EXABGP_FIFO = "/run/exabgp-cmd"

    def exabgp_send(self, s: Session, line: str) -> RunResult:
        return self.exec(
            s.container,
            f"printf '%s\\n' {shlex.quote(line)} > {self.EXABGP_FIFO}",
            timeout=30,
        )

    def exabgp_send_many(self, s: Session, lines: Iterable[str],
                         timeout: float = 300.0) -> RunResult:
        """Write a batch of commands into the helper's FIFO in one shot."""
        body = "\n".join(lines)
        if not body:
            return RunResult(0, "", "", 0.0)
        return _run(
            docker_cmd() + ["exec", "-i", self.cname(s.container), "sh", "-c",
                            f"cat > {self.EXABGP_FIFO}"],
            timeout, input_=body + "\n",
        )

    def exabgp_helper_log(self, target: Union[Session, str],
                          lines: int = 200) -> str:
        """The process helper's own log — where ACK errors and the boot count surface.

        Accepts either a Session or a bare container name. The sibling methods
        are split: `exabgp_log`/`exabgp_pids` take a container name (there is one
        ExaBGP process per container, not per session) while `gobgpd_log` takes a
        Session. This one used to take only a Session and silently relied on
        `.container`, so a container-name caller died with
        `AttributeError: 'str' object has no attribute 'container'`.
        """
        container = target if isinstance(target, str) else target.container
        r = self.exec(container,
                      f"tail -n {lines} /run/exabgp-helper.log 2>/dev/null || true",
                      timeout=30)
        return r.out

    # -- peer-side forensics ----------------------------------------------

    def bgp_sockets(self, container: str) -> Dict[str, Any]:
        """Every TCP socket on port 179 inside a peer container.

        Read from /proc/net/tcp and /proc/net/tcp6 so it works in any image.
        """
        r = self.exec(container,
                      "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || true",
                      timeout=30)
        if not r.ok:
            return {"ok": False, "error": (r.err or r.out or "")[:200]}
        socks = parse_proc_net_tcp(r.out)
        return {
            "ok": True,
            "sockets": socks,
            "listen": sorted({x["local"] for x in socks
                              if x["state"] == "LISTEN" and x["local"]}),
            "established": sorted({f"{x['local']}->{x['remote']}" for x in socks
                                   if x["state"] == "ESTABLISHED"}),
        }

    def container_addrs(self, container: str) -> List[str]:
        """Addresses currently configured in the container.

        An IPv6 session that will not come up because the peer no longer has
        the address is a lab fault, and it is invisible from the DUT.
        """
        r = self.exec(container,
                      "ip -o addr show 2>/dev/null | "
                      "awk '{print $2\" \"$4}' || true", timeout=30)
        return [l.strip() for l in (r.out or "").splitlines() if l.strip()]

    def container_snapshot(self, container: str,
                           log_lines: int = 60) -> Dict[str, Any]:
        """One container's side of the story, for attributing a stuck session."""
        snap: Dict[str, Any] = {"container": container}
        try:
            snap["pids"] = self.generator_pids(container)
        except Exception as exc:
            snap["pids_error"] = repr(exc)
        try:
            snap["sockets"] = self.bgp_sockets(container)
        except Exception as exc:
            snap["sockets"] = {"ok": False, "error": repr(exc)}
        try:
            snap["addrs"] = self.container_addrs(container)
        except Exception as exc:
            snap["addrs_error"] = repr(exc)
        try:
            snap["netem"] = self.netem_active(container)
        except Exception as exc:
            snap["netem_error"] = repr(exc)
        try:
            snap["exabgp_log_tail"] = self.exabgp_log(container, log_lines)
            snap["exabgp_helper_tail"] = self.exabgp_helper_log(
                container, log_lines)
        except Exception as exc:
            snap["log_error"] = repr(exc)
        alive = snap.get("pids") or {}
        snap["speakers_alive"] = sum(len(v) for v in alive.values() if v)
        return snap

    def session_socket_state(self, s: Session, dut_v4: Optional[str],
                             dut_v6: Optional[str],
                             sockets: Dict[str, Any]) -> Dict[str, Any]:
        """What the peer's own kernel says about this one session.

        The verdict strings are deliberately about *evidence*, not blame:
        `no_socket_for_family` says the peer is not even trying, which points
        away from the DUT; `listening_no_connection` says it is waiting and
        nothing arrived, which points at the DUT or the path.
        """
        out: Dict[str, Any] = {"sid": s.sid, "engine": s.engine,
                               "container": s.container}
        if not sockets.get("ok"):
            out["verdict"] = "unreadable"
            out["error"] = sockets.get("error")
            return out
        rows = sockets.get("sockets") or []
        for afi, local, dut in (("ipv4", s.v4, dut_v4), ("ipv6", s.v6, dut_v6)):
            if not local:
                continue
            match = [x for x in rows
                     if x["local"] == local and x["remote"] == dut] or \
                    [x for x in rows
                     if x["remote"] == local and x["local"] == dut]
            if match:
                state = match[0]["state"]
                verdict = ("established" if state == "ESTABLISHED"
                           else f"socket_{state.lower()}")
            else:
                family_rows = [x for x in rows
                               if (":" in (x["local"] or "")) == (afi == "ipv6")]
                listening = [x for x in family_rows if x["state"] == "LISTEN"]
                if not family_rows:
                    verdict = "no_socket_for_family"
                elif listening:
                    verdict = "listening_no_connection"
                else:
                    verdict = "no_socket_for_session"
            out[afi] = {"local": local, "dut": dut, "verdict": verdict}
        return out

    def fleet_snapshot(self, sessions: Sequence[Session],
                       dut_addrs: Any, why: str = "",
                       workers: int = 8) -> Dict[str, Any]:
        """The peer half of a stuck-session investigation.

        `dut_addrs` is a callable taking a Session and returning
        `(dut_v4, dut_v6)` — `Ctx.dut_addrs` satisfies it.

        Containers are visited concurrently because a docker exec round trip
        dominates: 24 containers x 5 commands serially is minutes, and this runs
        at the end of a run and on every failed convergence.
        """
        containers = sorted({s.container for s in sessions})
        snaps: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for c, snap in zip(containers,
                               pool.map(self.container_snapshot, containers)):
                snaps[c] = snap

        per_session = []
        for s in sessions:
            try:
                d4, d6 = dut_addrs(s)
            except Exception:
                d4 = d6 = None
            socks = (snaps.get(s.container) or {}).get("sockets") or {}
            per_session.append(
                self.session_socket_state(s, d4, d6, socks))

        counts: Dict[str, int] = {}
        for row in per_session:
            for afi in ("ipv4", "ipv6"):
                v = (row.get(afi) or {}).get("verdict")
                if v:
                    counts[f"{afi}:{v}"] = counts.get(f"{afi}:{v}", 0) + 1
        dead = [c for c, sn in snaps.items() if not sn.get("speakers_alive")]
        return {
            "why": why,
            "containers": snaps,
            "sessions": per_session,
            "verdict_counts": counts,
            "containers_with_no_speaker": dead,
        }

