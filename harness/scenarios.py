"""The chaos engine: the scenario catalogue and its scheduler.

Every event is a callable that mutates the lab and returns a record for the
timeline. The scheduler draws from a weighted mix with a seeded RNG, so a run is
reproducible: same profile plus same seed replays the same sequence of events at
the same offsets.

Why this particular set of events
---------------------------------
A real IXP-connected router does not fail because of one big thing. It fails
because several ordinary things overlap: a peer flaps while an operator is
committing a policy change while a route server re-advertises. The event mix is
built so those overlaps happen on their own, and so each individual event
isolates a different part of the pipeline:

* `peer_flap` — session churn. The `mode` chooses what is really being tested;
  see the table in `peers.py`.
* `churn` — RIB churn without session churn, in four flavours:
  - `flap_same`   withdraw then re-announce the same prefixes (classic flap)
  - `walk`        announce fresh NLRI, withdraw older NLRI (table growth/decay)
  - `attr_churn`  re-announce identical prefixes with different attributes.
                  Prefix count never changes, so `pfxRcd` stays flat while
                  `tableVersion` moves — this is the case that exposes bestpath
                  and update-group cost independently of RIB size.
  - `withdraw_storm` mass withdrawal, the case an FRR maintainer comment records
                  as having taken "40+ seconds" of main-thread CPU.
* `policy_churn` — config changes on the DUT itself, applied and reverted, with
  commit latency recorded. On a router holding a full table this forces a full
  policy re-evaluation and is the single most disruptive routine operation.
* `soft_clear` — `clear bgp ... soft in`, which re-runs import policy against the
  stored Adj-RIB-In. The template sets `soft-reconfiguration inbound` on every
  peer-group, so this path is always available and always costs memory.
* `blackhole_peer` — the deliberate route to FRR's send-queue teardown.
* `gr_event` — graceful restart, contrasting SIGINT (no NOTIFICATION, GR engages)
  with SIGTERM (NOTIFICATION sent, GR does not).
* `netem` — latency and loss on the peering LAN, which produces a failure shape
  that is easy to mistake for CPU saturation.
* `maxprefix_trip` — drives a peer past its limit and back, verifying teardown
  and recovery.
* `probe_check` — asserts the policy pipeline is still correct *while* under load.
* `malformed_burst` — the RFC 7606 suite, injected mid-chaos.
* `dut_bgpd_restart` — the DUT's own restart path, including update-delay.
"""

from __future__ import annotations

import itertools
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import policyprobe, routegen, telemetry
from .dut import CommitTimeout, Dut
from .model import Inventory, Session
from .peers import PeerFleet
from .telemetry import Sampler


@dataclass
class Ctx:
    inv: Inventory
    dut: Dut
    fleet: PeerFleet
    sampler: Sampler
    plan: routegen.PrefixPlan
    build_dir: str
    rng: random.Random
    dry_run: bool = False
    # monotonic offsets used by the `walk` churn mode, per session
    walk_offset: Dict[str, int] = field(default_factory=dict)
    #: Set by `run` so events can declare "this outage is mine, do not fault the
    #: DUT for it". Without this the peer-count predicate turns every deliberate
    #: flap into a failure and the run can never pass. See FINDINGS.md H-13.
    preds: Optional[Any] = None
    #: Why the last `_converge` call did not converge, or None. Set by the
    #: runner so a command can report the blocker rather than just False —
    #: at T2 the blocker was "bgpd at 100% CPU" and "FIB is behind the RIB",
    #: neither of which appears in `show bgp summary`.
    last_convergence_reason: Optional[str] = None
    #: Violations raised outside the per-sample predicate loop — currently the
    #: FIB-completeness verdict, which can only be taken from
    #: `show ip route summary` at a convergence decision, not from a sample.
    #: The runner drains this into the run's violation list.
    violations: List[Any] = field(default_factory=list)

    def impair(self, on: bool, reason: str = "", grace_s: Optional[float] = None):
        if self.preds is None:
            return
        if on:
            self.preds.impair_begin(reason)
        else:
            self.preds.impair_end(grace_s)

    def dut_addrs(self, s: Session) -> Tuple[str, str]:
        f = self.inv.fabrics[s.fabric]
        return str(f.dut_v4), str(f.dut_v6)

    def log(self, kind: str, /, payload: Optional[Dict[str, Any]] = None,
            **kw) -> Dict[str, Any]:
        """Record a timeline event.

        `kind` is **positional-only** — note the `/`. Without it, any caller
        expanding a dict that happens to contain a `kind` key dies with
        `TypeError: Ctx.log() got multiple values for argument 'kind'`, raised at
        the call site before the body runs, so no amount of defensive code inside
        the function can help. `cmd_exercise` built a per-event row keyed `kind`
        and expanded it, and the very first step of the very first run crashed.
        See FINDINGS.md H-24.

        `payload` is the same lesson learned a second time, and generalised.
        Positional-only `kind` fixes exactly one key; **any** key shared between
        an expanded dict and an explicit keyword raises the same TypeError at
        the call site. T3 run 2 died on
        `ctx.log("fib_state", afi=afi, **route_summary(afi))` — because
        `route_summary` returns a dict that already contains `afi`. It had been
        dead code until the H-51 fix made that branch reachable, and then it
        killed the command one line after printing
        `ipv4 FIB: 2,445,625 of 2,445,625 (100.0%)`. See FINDINGS.md H-58.

        So: pass a dict as `payload` instead of expanding it. Explicit keywords
        win over payload keys, and nothing can collide.
        """
        merged: Dict[str, Any] = dict(payload or {})
        merged.update(kw)
        if "kind" in merged:
            merged.setdefault("event_kind", merged.pop("kind"))
        rec = {"kind": kind, **merged}
        self.sampler.event(kind, **merged)
        return rec

    def pick(self, n: int = 1, role: Optional[str] = None,
             engine: Optional[str] = None) -> List[Session]:
        pool = [s for s in self.inv.sessions if s.flappable]
        if role:
            pool = [s for s in pool if s.role == role]
        if engine:
            pool = [s for s in pool if s.engine == engine]
        if not pool:
            return []
        return self.rng.sample(pool, min(n, len(pool)))


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------


def ev_peer_flap(ctx: Ctx, mode: str = "admin_down", count: int = 1,
                 down_s: Sequence[int] = (5, 30), **_) -> Dict[str, Any]:
    targets = ctx.pick(count)
    if not targets:
        return ctx.log("skipped", reason="no flappable sessions", event="peer_flap")
    lo, hi = (down_s if isinstance(down_s, (list, tuple)) else (down_s, down_s))[:2]
    hold = ctx.rng.uniform(float(lo), float(hi))
    sids = [s.sid for s in targets]
    addrs_lost: Dict[str, List[str]] = {}
    addrs_stray: Dict[str, List[str]] = {}
    ctx.log("peer_flap_down", mode=mode, sessions=sids, hold_s=round(hold, 1))
    if not ctx.dry_run:
        ctx.impair(True, reason=f"peer_flap {mode} {sids}")
        try:
            for s in targets:
                v4, v6 = ctx.dut_addrs(s)
                ctx.fleet.flap(s, v4, v6, mode)
            time.sleep(hold)
            for s in targets:
                v4, v6 = ctx.dut_addrs(s)
                ctx.fleet.unflap(s, v4, v6, mode)
            # A link flap takes the whole container's interface down, and Linux
            # flushes its global IPv6 addresses when it does. `unflap` restores
            # them; this proves it, because two full T3 runs ended with 75
            # sessions dead from exactly this and nothing said a word.
            # See FINDINGS.md H-59.
            if mode == "link_down":
                for c in sorted({s.container for s in targets}):
                    gone = ctx.fleet.addrs_missing(c)
                    if gone:
                        addrs_lost[c] = gone
                    # An address on the parent instead of the VLAN child is
                    # just as fatal as a missing one, and it is what run 3
                    # actually produced (H-61). Check both.
                    stray = ctx.fleet.addrs_misplaced(c)
                    if stray:
                        addrs_stray[c] = stray
        finally:
            # The grace window has to cover re-establish plus full
            # re-advertisement, which the flap-recovery measurement puts at a
            # p95 of ~32 s and a max of ~46 s on this profile.
            ctx.impair(False, grace_s=60.0)
    rec: Dict[str, Any] = {"mode": mode, "sessions": sids}
    if mode == "link_down":
        rec["containers_flapped"] = sorted({s.container for s in targets})
        rec["addresses_still_missing"] = addrs_lost
        rec["addresses_on_wrong_iface"] = addrs_stray
        if addrs_lost or addrs_stray:
            # Not an impairment the DUT caused, and not one the harness meant
            # to leave behind. Name it so it cannot be read as a DUT result.
            bits = []
            if addrs_lost:
                bits.append(f"{sum(len(v) for v in addrs_lost.values())} "
                            f"address(es) missing on "
                            f"{len(addrs_lost)} container(s)")
            if addrs_stray:
                bits.append(f"{sum(len(v) for v in addrs_stray.values())} "
                            f"address(es) left on the parent interface instead "
                            f"of the VLAN child on "
                            f"{len(addrs_stray)} container(s) — two interfaces "
                            f"holding one address makes the kernel's egress "
                            f"choice decide whether the session works")
            rec["peer_flap_ineffective"] = (
                "link flap left the lab broken: " + "; and ".join(bits)
                + ". Every session using them is unreliable for the rest of "
                  "the run, and it is the harness's fault, not the DUT's")
    return ctx.log("peer_flap_up", payload=rec)


def ev_blackhole_peer(ctx: Ctx, count: int = 1, hold_s: int = 0, **_) -> Dict[str, Any]:
    """Silently stop reading BGP, and verify the silence is real.

    `hold_s` defaults to 2.5x the peer's holdtime so the run reaches both FRR's
    hold-timer expiry and, if the DUT is advertising, the send-queue teardown at
    2x holdtime.

    The 2026-08-21 run held this for 75.3 s against a 30 s holdtime and FRR
    logged nothing at all — no FSM transition, no hold-timer expiry, no
    NOTIFICATION — while the debug was armed and log-neighbor-changes was on.
    That is not possible if BGP was being dropped, so the impairment itself was
    not in place: `blackhole()` ended in `2>/dev/null; true` and nobody looked at
    what it returned, so a peer image without `iptables` produced a green row and
    no outage. Verify and report instead of assuming. See FINDINGS.md H-33.
    """
    targets = ctx.pick(count, engine="gobgp")
    if not targets:
        return ctx.log("skipped", reason="no gobgp sessions", event="blackhole_peer")
    s = targets[0]
    ht = s.timers.get("holdtime", 90)
    hold = hold_s or int(ht * 2.5)
    ctx.log("blackhole_on", session=s.sid, hold_s=hold, holdtime=ht,
            note="expect a hold-timer expiry at ~1x holdtime, and — only if the "
                 "DUT is advertising to this peer — 'has not made any SendQ "
                 "progress for 1 holdtime' then '... for 2 holdtimes, "
                 "terminating session' (the EC symbol names are never printed)")
    if ctx.dry_run:
        return ctx.log("blackhole_off", session=s.sid, dry_run=True)

    def peer_state() -> Dict[str, Any]:
        return {
            "ipv4": telemetry.bgp_peer_state(ctx.dut.bgp_summary("ipv4"),
                                             s.v4 or ""),
            "ipv6": telemetry.bgp_peer_state(ctx.dut.bgp_summary("ipv6"),
                                             s.v6 or ""),
        }

    # How much the DUT is actually sending this peer decides whether the
    # send-queue path is even reachable: a queue with nothing in it never backs
    # up. At an IXP the DUT advertises almost nothing, so pfx_snt near zero is
    # the expected — and disqualifying — case.
    summ = ctx.dut.bgp_summary("ipv4") or {}
    node = telemetry.bgp_peer_node(summ) or {}
    snt = ((node.get("peers") or {}).get(s.v4 or "") or {}).get("pfxSnt")

    state_before = peer_state()
    ctx.impair(True, reason=f"blackhole {s.sid}")
    applied = held = None
    try:
        applied = ctx.fleet.blackhole(s, on=True)
        if not applied.get("effective"):
            # Do not burn 75 s on an impairment that is not in place, and do not
            # report the resulting silence as a DUT result.
            ctx.fleet.blackhole(s, on=False)
            return ctx.log(
                "blackhole_ineffective", session=s.sid,
                iptables_present=applied.get("iptables_present"),
                rules_installed=applied.get("rules_installed"),
                output=applied.get("output"),
                reason="no BGP DROP rules are installed in the peer netns, so "
                       "the DUT is not being blackholed; the previous run's "
                       "silent pass here was this",
                event="blackhole_peer")
        # Mid-hold sample, just past one holdtime: this is where the hold timer
        # should already have fired.
        time.sleep(min(hold, ht + 5))
        held = peer_state()
        time.sleep(max(0.0, hold - (ht + 5)))
    finally:
        cleared = ctx.fleet.blackhole(s, on=False)
        ctx.impair(False, grace_s=60.0)

    return ctx.log("blackhole_off", session=s.sid, holdtime=ht, hold_s=hold,
                   rules_installed=applied.get("rules_installed") if applied else None,
                   iptables_present=applied.get("iptables_present") if applied else None,
                   rules_after_clear=cleared.get("rules_installed"),
                   dut_pfx_snt_to_peer=snt,
                   sendq_path_reachable=bool(snt),
                   state_before=state_before,
                   state_at_1x_holdtime=held,
                   dropped_within_holdtime=bool(
                       held and state_before.get("ipv4") == "Established"
                       and held.get("ipv4") != "Established"))


def _session_prefixes(ctx: Ctx, s: Session, fraction: float, offset: int = 0
                      ) -> Tuple[List[str], List[str]]:
    n4 = max(1, int(s.prefixes_v4 * fraction)) if s.prefixes_v4 else 0
    n6 = max(1, int(s.prefixes_v6 * fraction)) if s.prefixes_v6 else 0
    v4 = list(itertools.islice(
        ctx.plan.session_v4(s.nlri_slot, s.prefixes_v4, offset), n4)) if n4 else []
    v6 = list(itertools.islice(
        ctx.plan.session_v6(s.nlri_slot, s.prefixes_v6, offset), n6)) if n6 else []
    return v4, v6


def ev_churn(ctx: Ctx, mode: str = "flap_same", fraction: float = 0.25,
             count: int = 1, settle_s: float = 2.0, **_) -> Dict[str, Any]:
    targets = ctx.pick(count)
    if not targets:
        return ctx.log("skipped", reason="no sessions", event="churn")

    total = 0
    for s in targets:
        if s.engine == "gobgp":
            total += _churn_gobgp(ctx, s, mode, fraction, settle_s)
        else:
            total += _churn_exabgp(ctx, s, mode, fraction, settle_s)
    return ctx.log("churn", mode=mode, sessions=[s.sid for s in targets],
                   fraction=fraction, prefixes=total)


def _churn_gobgp(ctx: Ctx, s: Session, mode: str, fraction: float,
                 settle_s: float) -> int:
    off = ctx.walk_offset.get(s.sid, 0)
    v4, v6 = _session_prefixes(ctx, s, fraction, off)
    n = len(v4) + len(v6)
    if ctx.dry_run or n == 0:
        return n

    if mode == "withdraw_storm":
        ops = [f"global rib del -a ipv4 {p}" for p in v4]
        ops += [f"global rib del -a ipv6 {p}" for p in v6]
        ctx.fleet.rib_batch(s, ops)
        time.sleep(settle_s)
        # restore from the MRT rather than re-adding one prefix at a time
        ctx.fleet.inject_mrt(s)
        return n

    if mode == "flap_same":
        ops = [f"global rib del -a ipv4 {p}" for p in v4]
        ops += [f"global rib del -a ipv6 {p}" for p in v6]
        ctx.fleet.rib_batch(s, ops)
        time.sleep(settle_s)
        ops = [f"global rib add -a ipv4 {p} nexthop {s.v4} aspath {s.asn},3356,15169"
               for p in v4]
        ops += [f"global rib add -a ipv6 {p} nexthop {s.v6} aspath {s.asn},6939,20000"
                for p in v6]
        ctx.fleet.rib_batch(s, ops)
        return n

    if mode == "attr_churn":
        # Same NLRI, different MED and large-community. Prefix count is unchanged,
        # so pfxRcd stays flat while tableVersion moves.
        med = ctx.rng.randrange(1, 5000)
        lc = ctx.rng.randrange(1, 9999)
        ops = [f"global rib add -a ipv4 {p} nexthop {s.v4} med {med} "
               f"aspath {s.asn},3356,15169 large-community {s.asn}:0:{lc}" for p in v4]
        ops += [f"global rib add -a ipv6 {p} nexthop {s.v6} med {med} "
                f"aspath {s.asn},6939,20000 large-community {s.asn}:0:{lc}" for p in v6]
        ctx.fleet.rib_batch(s, ops)
        return n

    if mode == "walk":
        # Advertise a fresh window, withdraw the previous one: net table size is
        # stable but every prefix is new, which is the worst case for the
        # nexthop cache and for update-group churn.
        new_off = off + max(1, len(v4) or len(v6))
        nv4, nv6 = _session_prefixes(ctx, s, fraction, new_off)
        ops = [f"global rib add -a ipv4 {p} nexthop {s.v4} aspath {s.asn},3356,15169"
               for p in nv4]
        ops += [f"global rib add -a ipv6 {p} nexthop {s.v6} aspath {s.asn},6939,20000"
                for p in nv6]
        ops += [f"global rib del -a ipv4 {p}" for p in v4]
        ops += [f"global rib del -a ipv6 {p}" for p in v6]
        ctx.fleet.rib_batch(s, ops)
        ctx.walk_offset[s.sid] = new_off
        return len(nv4) + len(nv6) + n

    raise ValueError(f"unknown churn mode: {mode}")


def _churn_exabgp(ctx: Ctx, s: Session, mode: str, fraction: float,
                  settle_s: float) -> int:
    off = ctx.walk_offset.get(s.sid, 0)
    v4, v6 = _session_prefixes(ctx, s, fraction, off)
    n = len(v4) + len(v6)
    if ctx.dry_run or n == 0:
        return n
    dv4, dv6 = ctx.dut_addrs(s)
    lines: List[str] = []
    if mode in ("flap_same", "withdraw_storm"):
        lines += list(routegen.exabgp_announce_batches(v4, s.v4, [], neighbor=dv4,
                                                       withdraw=True))
        lines += list(routegen.exabgp_announce_batches(v6, s.v6, [], neighbor=dv6,
                                                       withdraw=True))
        ctx.fleet.exabgp_send_many(s, lines)
        time.sleep(settle_s)
        lines = []
    med = ctx.rng.randrange(1, 5000) if mode == "attr_churn" else 50
    if v4:
        lines += list(routegen.exabgp_announce_batches(
            v4, s.v4, [s.asn, 3356, 15169], med=med, neighbor=dv4, batch=200))
    if v6:
        lines += list(routegen.exabgp_announce_batches(
            v6, s.v6, [s.asn, 6939, 20000], med=med, neighbor=dv6, batch=200))
    ctx.fleet.exabgp_send_many(s, lines)
    return n


def ev_policy_churn(ctx: Ctx, fragments: Sequence[str] = (), hold_s: float = 15.0,
                    revert: bool = True, **_) -> Dict[str, Any]:
    """Apply a config fragment, hold, revert. Commit latency is the metric.

    The revert is now in a `finally` and its failure is a first-class result,
    because on the T2 run the absence of both cost 72 minutes of unusable data.
    Two single-command commits exceeded the 360 s timeout:

        maxprefix-squeeze  apply   -> CommitTimeout, 1 command
        pg-routemap-swap   revert  -> CommitTimeout, 1 command

    On the old code path a `CommitTimeout` on the apply returned immediately and
    the revert never ran, so `ixp1-peer4` stayed clamped at maximum-prefix 2,500
    against 5,000 announced for the rest of the run: all 80 ixp1-bilat IPv4
    sessions were torn down and stayed down, drift -400,000 (= 80 x 5,000), and
    every measurement afterwards was taken against a lab the harness had broken
    and could not un-break. See FINDINGS.md H-42.

    `config_left_modified` is the flag that says the DUT is no longer in the
    state the profile describes. `run` treats it as fatal.
    """
    import os
    pool = list(fragments) or ["localpref-flip", "community-retag", "prefixlist-grow"]
    name = ctx.rng.choice(pool)
    cdir = os.path.join(ctx.build_dir, "dut", "churn")
    apply_p = os.path.join(cdir, f"{name}.apply.conf")
    revert_p = os.path.join(cdir, f"{name}.revert.conf")
    if not os.path.exists(apply_p):
        return ctx.log("skipped", reason=f"no fragment {name}", event="policy_churn")

    ctx.log("policy_churn_apply_start", fragment=name)
    if ctx.dry_run:
        return ctx.log("policy_churn_done", fragment=name, dry_run=True)

    applied: Dict[str, Any] = {}
    apply_timed_out = False
    try:
        r = ctx.dut.configure_file(apply_p)
        applied = {"rc": r.rc, "commit_s": round(r.seconds, 2)}
        if not r.ok:
            applied["stderr"] = (r.err or r.out)[-400:]
        ctx.log("policy_churn_applied", payload=applied, fragment=name)
        time.sleep(hold_s)
    except CommitTimeout as exc:
        # The apply may have partially landed — VyOS commits are not atomic from
        # the outside once the timeout fires — so the revert must still be tried.
        apply_timed_out = True
        applied = {"error": str(exc)}
        ctx.log("policy_churn_commit_timeout", fragment=name, error=str(exc),
                note="apply timed out; still attempting the revert so the DUT "
                     "does not stay modified")
    finally:
        rev: Dict[str, Any] = {}
        if revert:
            try:
                r2 = ctx.dut.configure_file(revert_p)
                rev = {"rc": r2.rc, "commit_s": round(r2.seconds, 2)}
                if not r2.ok:
                    rev["stderr"] = (r2.err or r2.out)[-400:]
            except CommitTimeout as exc:
                rev = {"error": str(exc)}

    left_modified = bool(revert and rev.get("error"))
    return ctx.log("policy_churn_reverted" if not left_modified
                   else "policy_churn_left_modified",
                   fragment=name, applied=applied, reverted=rev,
                   apply_timed_out=apply_timed_out,
                   config_left_modified=left_modified,
                   note=None if not left_modified else
                   f"the revert of `{name}` did not complete, so the DUT is no "
                   f"longer in the state the profile describes and every "
                   f"measurement after this point is against a different "
                   f"router. This is a harness-induced change, not a DUT "
                   f"result.")


def ev_soft_clear(ctx: Ctx, target: str = "all", direction: str = "in",
                  afi: Optional[str] = None, **_) -> Dict[str, Any]:
    """Re-run import policy against the stored Adj-RIB-In.

    Cheap to trigger, expensive to service: it re-evaluates policy for every
    stored path. The template enables `soft-reconfiguration inbound` on every
    peer-group, which is what makes this possible and what pays for it in memory.
    """
    ctx.log("soft_clear_start", target=target, direction=direction, afi=afi)
    if ctx.dry_run:
        return ctx.log("soft_clear_done", dry_run=True)
    r = ctx.dut.reset_bgp(target=target, soft=direction, afi=afi)
    return ctx.log("soft_clear_done", rc=r.rc, seconds=round(r.seconds, 2))


def ev_maxprefix_trip(ctx: Ctx, hold_s: float = 25.0, **_) -> Dict[str, Any]:
    """Squeeze a peer-group's maximum-prefix below the offered table, then restore.

    Previously a one-line delegation to `ev_policy_churn`, which meant the only
    evidence that anything happened was a log signature — and the log pattern it
    depended on was wrong (it matched the `restart` timer messages, which VyOS
    cannot configure, instead of `%MAXPFXEXCEED`). The event therefore reported
    "ok, recovered" whether or not the limit had ever tripped.

    FRR does re-evaluate the limit the moment it is lowered:
    `peer_maximum_prefix_set` (bgpd/bgpd.c) calls
    `bgp_maximum_prefix_overflow(peer, afi, safi, 1)` — `always=1` — for the
    peer and again for every peer-group member, so no new UPDATE is needed. What
    is *not* guaranteed is recovery: the template's `maximum-prefix` is a bare
    limit, since VyOS exposes no `warning-only`, `restart` or `threshold`
    sub-option, so teardown is the only behaviour and re-raising the limit may
    or may not bring the peer back without an explicit reset.

    So sample the peers directly, mid-hold, and record it: which peers left
    Established, what their prefix counts were, and whether raising the limit
    was enough on its own.
    """
    import os
    name = "maxprefix-squeeze"
    cdir = os.path.join(ctx.build_dir, "dut", "churn")
    apply_p = os.path.join(cdir, f"{name}.apply.conf")
    revert_p = os.path.join(cdir, f"{name}.revert.conf")
    if not os.path.exists(apply_p):
        return ctx.log("skipped", reason=f"no fragment {name}",
                       event="maxprefix_trip")
    if ctx.dry_run:
        return ctx.log("maxprefix_trip_done", fragment=name, dry_run=True)

    def snap() -> Dict[str, Any]:
        summ = ctx.dut.bgp_summary("ipv4")
        node = telemetry.bgp_peer_node(summ) or {}
        peers = node.get("peers") or {}
        return {p: {"state": str(v.get("state", "")),
                    "pfx": v.get("pfxRcd")}
                for p, v in peers.items() if isinstance(v, dict)}

    before = snap()
    ctx.log("maxprefix_trip_start", fragment=name, peers=len(before))
    apply_timed_out = False
    try:
        r = ctx.dut.configure_file(apply_p)
        applied = {"rc": r.rc, "commit_s": round(r.seconds, 2)}
    except CommitTimeout as exc:
        # Do NOT return here. On T2 this exact path returned immediately, the
        # revert never ran, and `ixp1-peer4` stayed clamped at maximum-prefix
        # 2,500 against 5,000 announced for the remaining 72 minutes: all 80
        # ixp1-bilat IPv4 sessions torn down, drift -400,000, and the whole rest
        # of the run measured against a lab the harness had broken. The squeeze
        # is the one fragment where not reverting is guaranteed to keep sessions
        # down, so the revert has to be attempted whatever the apply did.
        # See FINDINGS.md H-42.
        apply_timed_out = True
        applied = {"error": str(exc)}
        ctx.log("maxprefix_trip_commit_timeout", fragment=name, error=str(exc),
                note="apply timed out; continuing to the revert so the limit "
                     "is not left clamped")

    # Confirm the limit is actually in place before judging anything. On the
    # 2026-08-21 run this event fired no %MAXPFXEXCEED at all, and the only DUT
    # log line in its window was `bgp_read_packet error: Connection reset by
    # peer` at the exact second of the apply commit — i.e. VyOS's frr-reload
    # bounced the peer-group's sessions rather than adjusting a live limit. A
    # peer that is still reconnecting cannot exceed a prefix limit, so a silent
    # "no trip" here says nothing about the DUT.
    limit_re = re.compile(
        r"peer-group\s+(\S+).*maximum-prefix\s+'?(\d+)'?", re.IGNORECASE)
    rc = ctx.dut.vtysh("show running-config")
    limits_now = sorted(set(limit_re.findall(rc.out or "")))

    time.sleep(2.0)
    during_early = snap()

    # Wait for the bounced sessions to come back, because the trip can only
    # happen once the peer re-advertises. Bounded by the hold so the event does
    # not run away.
    deadline = time.monotonic() + max(hold_s, 30.0)
    reestablished_after = None
    while time.monotonic() < deadline:
        cur = snap()
        back = [p for p in before
                if before[p].get("state") == "Established"
                and cur.get(p, {}).get("state") == "Established"]
        if len(back) == len([p for p in before
                             if before[p].get("state") == "Established"]):
            reestablished_after = round(
                max(hold_s, 30.0) - (deadline - time.monotonic()), 1)
            break
        time.sleep(2.0)
    time.sleep(max(0.0, hold_s - 2.0))
    during_late = snap()

    def dropped(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
        return sorted(p for p, v in b.items()
                      if a.get(p, {}).get("state") == "Established"
                      and v.get("state") != "Established")

    tripped = sorted(set(dropped(before, during_early))
                     | set(dropped(before, during_late)))
    # Direct, log-independent confirmation from FRR's own per-neighbour state.
    nbr = ctx.dut.vtysh("show bgp neighbors")
    limit_text = [l.strip() for l in (nbr.out or "").splitlines()
                  if "prefix" in l.lower() and "limit" in l.lower()][:6]

    try:
        r2 = ctx.dut.configure_file(revert_p)
        rev = {"rc": r2.rc, "commit_s": round(r2.seconds, 2)}
    except CommitTimeout as exc:
        # The limit is still clamped. Say so loudly: everything measured after
        # this point is against a DUT the harness has modified and cannot
        # restore, which `run` treats as fatal.
        return ctx.log("maxprefix_trip_left_modified", fragment=name,
                       applied=applied, apply_timed_out=apply_timed_out,
                       error=str(exc), config_left_modified=True,
                       note="the maximum-prefix squeeze could not be reverted, "
                            "so the peer-group is still clamped below what its "
                            "members announce and those sessions will stay "
                            "down. Harness-induced, not a DUT result.")

    time.sleep(8.0)
    after_revert = snap()
    still_down = [p for p in tripped
                  if after_revert.get(p, {}).get("state") != "Established"]
    needed_clear = False
    if still_down:
        # Raising the limit was not enough. This is the operationally
        # interesting outcome, so record that it was needed rather than
        # quietly clearing and reporting a clean recovery.
        ctx.dut.reset_bgp(target="all")
        needed_clear = True
        time.sleep(10.0)
        after_revert = snap()

    return ctx.log("maxprefix_trip_done", fragment=name,
                   applied=applied, reverted=rev,
                   peergroup_limits_after_apply=limits_now,
                   all_peers_reestablished_after_s=reestablished_after,
                   apply_timed_out=apply_timed_out,
                   peers_before=len(before),
                   tripped=tripped,
                   tripped_count=len(tripped),
                   max_pfx_before=max([v.get("pfx") or 0
                                       for v in before.values()] or [0]),
                   still_down_after_revert=still_down,
                   needed_explicit_clear=needed_clear,
                   established_after=sum(
                       1 for v in after_revert.values()
                       if v.get("state") == "Established"),
                   neighbor_limit_lines=limit_text)

def ev_netem(ctx: Ctx, delay_ms: int = 20, jitter_ms: int = 5, loss_pct: float = 0.5,
             duration_s: float = 30.0, count: int = 1, **_) -> Dict[str, Any]:
    targets = ctx.pick(count)
    if not targets:
        return ctx.log("skipped", reason="no sessions", event="netem")
    containers = sorted({s.container for s in targets})
    ctx.log("netem_on", containers=containers, delay_ms=delay_ms,
            jitter_ms=jitter_ms, loss_pct=loss_pct, duration_s=duration_s)
    if ctx.dry_run:
        return ctx.log("netem_off", containers=containers, dry_run=True)
    applied: Dict[str, Any] = {}
    for c in containers:
        ctx.fleet.netem(c, delay_ms=delay_ms, jitter_ms=jitter_ms,
                        loss_pct=loss_pct)
        # Read the qdisc back. An image without `tc`, or a different iface name,
        # leaves the path clean while the event reports success — the same defect
        # that made blackhole_peer a silent no-op. See FINDINGS.md H-33.
        applied[c] = ctx.fleet.netem_active(c)
    effective = [c for c, v in applied.items() if v.get("active")]
    if not effective:
        for c in containers:
            ctx.fleet.netem(c, clear=True)
        return ctx.log("netem_ineffective", containers=containers,
                       detail=applied,
                       reason="no netem qdisc is present after applying it, so "
                              "the peering path was never impaired",
                       event="netem")
    time.sleep(duration_s)
    for c in containers:
        ctx.fleet.netem(c, clear=True)
    return ctx.log("netem_off", containers=containers,
                   impaired=effective,
                   qdiscs={c: v.get("qdisc") for c, v in applied.items()})


def ev_gr_event(ctx: Ctx, mode: str = "process_kill", down_s: float = 20.0,
                **_) -> Dict[str, Any]:
    """Restart a peer process to exercise graceful restart.

    `process_kill` (SIGINT) makes gobgpd exit *without* a NOTIFICATION, so the DUT
    should enter GR helper mode and hold the peer's routes as stale.
    `process_term` (SIGTERM) makes gobgpd notify first, so GR must not engage.
    Running both and diffing the DUT's behaviour is how you confirm GR is actually
    working rather than assumed.
    """
    targets = ctx.pick(1, engine="gobgp")
    if not targets:
        return ctx.log("skipped", reason="no gobgp sessions", event="gr_event")
    s = targets[0]
    v4, v6 = ctx.dut_addrs(s)
    ctx.log("gr_event_down", session=s.sid, mode=mode,
            expect="GR helper engaged" if mode == "process_kill"
                   else "NOTIFICATION sent, GR not engaged")
    if not ctx.dry_run:
        ctx.fleet.flap(s, v4, v6, mode)
        time.sleep(down_s)
        ctx.fleet.unflap(s, v4, v6, mode)
        time.sleep(3)
        ctx.fleet.inject_mrt(s)
    gr = None
    if not ctx.dry_run:
        gr = ctx.dut.vtysh_json(f"show bgp neighbors {v4} graceful-restart json")
    return ctx.log("gr_event_up", session=s.sid, mode=mode,
                   graceful_restart=gr if isinstance(gr, dict) else None)


def ev_dut_bgpd_restart(ctx: Ctx, **_) -> Dict[str, Any]:
    """Restart FRR on the DUT.

    Exercises the DUT side of graceful restart and, if configured, `update-delay`
    read-only mode. Also worth watching for the documented VyOS issue class
    "FRRouting Configuration Loss on Abnormal Service Restart" — verify the BGP
    config is still present afterwards.
    """
    ctx.log("dut_bgpd_restart_start")
    if ctx.dry_run:
        return ctx.log("dut_bgpd_restart_done", dry_run=True)
    # Tell the predicate set this one is deliberate, or the event reports
    # `[fail] bgpd_restarted` against itself. Consumed by the first PID change
    # observed, so it cannot mask a second, unintended restart later.
    if ctx.preds is not None and hasattr(ctx.preds, "expect_daemon_restart"):
        for d in ("bgpd", "zebra", "staticd"):
            ctx.preds.expect_daemon_restart(d)
    t0 = time.monotonic()
    r = ctx.dut.restart_bgpd()
    # confirm the config survived the restart
    time.sleep(5)
    summary = ctx.dut.bgp_summary("ipv4")
    peers = len((summary or {}).get("peers", {}) or {}) if summary else 0
    return ctx.log("dut_bgpd_restart_done", rc=r.rc,
                   seconds=round(time.monotonic() - t0, 2),
                   peers_after=peers,
                   config_survived=peers > 0)


def ev_probe_check(ctx: Ctx, announce: bool = True, settle_s: float = 15.0,
                   withdraw: bool = True, **_) -> Dict[str, Any]:
    """Assert the policy pipeline is still correct, under load.

    It must ANNOUNCE the probes before looking them up. The first version built
    the probe list with empty peer addresses and went straight to
    `lookup_prefix`, so as the `run` command's "final policy check" it queried 18
    prefixes that nothing had announced. Every lookup came back empty, which the
    grader read as "reject": the 14 probes that expect a reject passed
    vacuously, and the 4 that expect an accept were reported as failures. The
    giveaway was `bogon-v6-doc-rfc9637` "passing" in that check while being a
    confirmed template defect everywhere else. See FINDINGS.md H-14.
    """
    exa = [x for x in ctx.inv.sessions if x.engine == "exabgp"]
    if not exa:
        return ctx.log("skipped", reason="no exabgp session to announce from",
                       event="probe_check")
    sess = exa[0]
    dv4, dv6 = ctx.dut_addrs(sess)
    probes = policyprobe.build_probes(
        ctx.inv.dut_asn, ctx.inv.profile["own"]["supernet4"],
        ctx.inv.profile["own"]["supernet6"], sess.v4 or "", sess.v6 or "",
        peer_asn=sess.asn)
    results = []
    if not ctx.dry_run:
        if announce:
            ctx.fleet.exabgp_send_many(sess, [
                l for l in policyprobe.probe_announce_commands(
                    probes, sess.v4 or "", sess.v6 or "", dv4, dv6,
                    peer_asn=sess.asn) if not l.startswith("#")])
            time.sleep(settle_s)
        for p in probes:
            afi = "ipv4" if p.afi == "ipv4" else "ipv6"
            got = ctx.dut.lookup_prefix(p.prefix, afi)
            present = bool(got and got.get("paths"))
            verdict = "accept" if present else "reject"
            row = {
                "pid": p.pid, "prefix": p.prefix, "expect": p.expect,
                "observed": verdict, "pass": verdict == p.expect,
            }
            if verdict != p.expect and p.template_defect:
                row["template_defect"] = p.template_defect
                row["classification"] = "template-defect-confirmed"
            elif verdict != p.expect:
                row["classification"] = "unexpected"
            if present and isinstance(got, dict):
                paths = got.get("paths") or []
                if paths:
                    # FRR emits LOCAL_PREF as "locPrf" (bgp_route.c,
                    # json_object_int_add(json_path, "locPrf", ...)). Reading
                    # "localPref" returned None for every accepted route, which
                    # silently disabled the local-preference half of the tagging
                    # assertions - the probes looked like they were checking
                    # local-pref and were not. Accept both spellings.
                    row["local_pref"] = (paths[0].get("locPrf")
                                         if paths[0].get("locPrf") is not None
                                         else paths[0].get("localPref"))
                    row["large_community"] = (
                        (paths[0].get("largeCommunity") or {}).get("string"))
            results.append(row)
    if not ctx.dry_run and announce and withdraw:
        ctx.fleet.exabgp_send_many(
            sess, policyprobe.probe_withdraw_commands(probes, dv4, dv6,
                                                       sess.v4, sess.v6))
    failed = [r for r in results if not r["pass"]]
    defects = [r for r in failed if r.get("template_defect")]
    return ctx.log("probe_check", total=len(results),
                   failures=len(failed),
                   template_defects=len(defects),
                   unexplained=len(failed) - len(defects),
                   announced=bool(announce and not ctx.dry_run),
                   results=results)


def ev_malformed_burst(ctx: Ctx, withdraw_after_s: float = 20.0, **_) -> Dict[str, Any]:
    """Inject the RFC 7606 suite from an ExaBGP peer and check the session survives."""
    targets = [s for s in ctx.inv.sessions if s.engine == "exabgp"]
    if not targets:
        return ctx.log("skipped", reason="no exabgp sessions", event="malformed_burst")
    s = targets[0]
    dv4, dv6 = ctx.dut_addrs(s)
    cases = policyprobe.build_malformed(s.v4 or "", s.v6 or "", ctx.inv.dut_asn,
                                       peer_asn=s.asn)
    lines = policyprobe.malformed_announce_commands(cases, dv4, dv6, s.v4, s.v6)
    ctx.log("malformed_burst_start", session=s.sid, cases=len(cases))
    if ctx.dry_run:
        return ctx.log("malformed_burst_done", dry_run=True)

    before4 = ctx.dut.bgp_summary("ipv4")
    before6 = ctx.dut.bgp_summary("ipv6")
    state_before = {
        "ipv4": telemetry.bgp_peer_state(before4, s.v4 or ""),
        "ipv6": telemetry.bgp_peer_state(before6, s.v6 or ""),
    }
    ctx.fleet.exabgp_send_many(s, [l for l in lines if not l.startswith("#")])
    time.sleep(withdraw_after_s)

    results = []
    for m in cases:
        afi = "ipv4" if m.afi == "ipv4" else "ipv6"
        got = ctx.dut.lookup_prefix(m.prefix, afi)
        present = bool(got and got.get("paths"))
        ok = (m.expect_route == "either"
              or (m.expect_route == "present" and present)
              or (m.expect_route == "absent" and not present))
        results.append({"mid": m.mid, "prefix": m.prefix,
                        "expect_route": m.expect_route,
                        "present": present, "pass": ok, "tags": list(m.tags)})

    # The session surviving is the primary assertion: RFC 7606 exists precisely to
    # stop attribute errors from resetting sessions. Both address families are
    # checked because the suite touches both, and because a v4-only reset (or a
    # v4-only AFI/SAFI disable, RFC 7606 section 4) is a distinct outcome.
    after4 = ctx.dut.bgp_summary("ipv4")
    after6 = ctx.dut.bgp_summary("ipv6")
    state_after = {
        "ipv4": telemetry.bgp_peer_state(after4, s.v4 or ""),
        "ipv6": telemetry.bgp_peer_state(after6, s.v6 or ""),
    }
    session_kept = _state_is_established(state_after["ipv4"])
    # A reset that has already completed by the time we look shows up only in the
    # connection counters, not in `state`.
    drops = {}
    for afi, (b, a, addr) in {"ipv4": (before4, after4, s.v4),
                              "ipv6": (before6, after6, s.v6)}.items():
        pb = _peer_field(b, addr or "", "connectionsDropped")
        pa = _peer_field(a, addr or "", "connectionsDropped")
        drops[afi] = None if (pb is None or pa is None) else pa - pb
    # `incorrect first AS` is FRR's enforce-first-as rejection (default ON since
    # FRR 10.0, treat-as-withdraw not reset). It silently removes every route in
    # this suite whose AS_PATH does not start with the peer's own ASN, so it must
    # be reported alongside the route checks or the results read as policy denies.
    window = f"-{int(withdraw_after_s) + 15}s"
    logs = ctx.dut.log_counts(since=window)
    # Counters alone were not enough to explain the first observed reset loop:
    # attr_withdraw fired 6,791 times and notification_sent stayed at 0, which
    # cannot both be true of a session that dropped 1,123 times. Keep raw lines
    # so the actual reason is in the artefact rather than needing another run.
    raw = ctx.dut.log_since(window, extra_grep=MALFORMED_LOG_GREP)
    ctx.fleet.exabgp_send_many(
        s, policyprobe.malformed_withdraw_commands(cases, dv4, dv6, s.v4, s.v6))
    return ctx.log("malformed_burst_done", session=s.sid,
                   peer_v4=s.v4, peer_v6=s.v6,
                   session_established_after=session_kept,
                   state_before=state_before, state_after=state_after,
                   connections_dropped_delta=drops,
                   dut_log_counts=logs,
                   dut_log_sample=_dedup_log(raw, 40),
                   route_checks=results,
                   failures=len([r for r in results if not r["pass"]]))


#: Broad on purpose. The counters in Dut.LOG_PATTERNS are curated for sampling;
#: this is for post-mortem, where missing the one line that explains a reset
#: costs a whole run.
MALFORMED_LOG_GREP = (
    "NOTIFICATION|Unrecognized|unrecognized|malformed|MALFORMED"
    "|attribute|attr|Cease|went from|Established|Idle|Clearing|Connect"
    "|bgp_stop|error|Error|reset|closing|EOF|hold|Hold"
)


def _dedup_log(lines: Sequence[str], limit: int) -> List[Dict[str, Any]]:
    """Collapse repeated log lines to `{count, line}`, keeping the first `limit`.

    A reset loop produces thousands of identical lines; the information is in
    the distinct set and their multiplicities, not the volume.
    """
    counts: Dict[str, int] = {}
    order: List[str] = []
    for raw in lines:
        # Drop the leading timestamp/host so repeats actually collapse.
        key = raw.strip()
        parts = key.split(": ", 1)
        key = parts[1] if len(parts) == 2 and len(parts[0]) < 80 else key
        if key not in counts:
            order.append(key)
        counts[key] = counts.get(key, 0) + 1
    return [{"count": counts[k], "line": k[:400]} for k in order[:limit]]


def ev_malformed_isolate(ctx: Ctx, settle_s: float = 3.0,
                         only: Optional[Sequence[str]] = None,
                         fresh_session: bool = True,
                         **_) -> Dict[str, Any]:
    """Announce each malformed case alone and record whether the session drops.

    The burst variant answers "did the session survive the suite". It cannot say
    *which* case broke it, and when one case triggers a reset loop the other
    nineteen results become meaningless: routes appear or vanish depending on
    where the reconnect landed. That is exactly what was observed on VyOS 1.5.1 /
    FRR 10.5.2 — connectionsDropped moved by 1,123 across a 20 s burst.

    So: one case at a time, `connectionsDropped` sampled either side, withdrawn
    before the next. Costs len(cases) * (settle_s + a few RTT), which is minutes
    rather than hours, and turns "5 unexplained" into a named case.
    """
    targets = [s for s in ctx.inv.sessions if s.engine == "exabgp"]
    if not targets:
        return ctx.log("skipped", reason="no exabgp sessions",
                       event="malformed_isolate")
    s = targets[0]
    dv4, dv6 = ctx.dut_addrs(s)
    # Naming cases explicitly overrides the default tag exclusion: the whole
    # point of isolation mode is to reproduce one case on demand, including the
    # martian next-hop pair that the burst suite now skips (see
    # policyprobe.EXCLUDED_TAGS).
    cases = policyprobe.build_malformed(
        s.v4 or "", s.v6 or "", ctx.inv.dut_asn, peer_asn=s.asn,
        exclude_tags=() if only else policyprobe.EXCLUDED_TAGS)
    if only:
        wanted = set(only)
        cases = [m for m in cases if m.mid in wanted]
    ctx.log("malformed_isolate_start", session=s.sid, cases=len(cases),
            settle_s=settle_s)
    if ctx.dry_run:
        return ctx.log("malformed_isolate_done", dry_run=True)

    # Start from a provably empty Adj-RIB-Out. Withdrawing by prefix does not
    # reliably clear a route announced with a hand-encoded generic attribute:
    # after the burst withdrew all its cases, the DUT log still carried
    # unknown-attribute (153/155) and 6-byte-AS_PATH-segment lines on every
    # reconnect, so those cases were still being advertised and their log lines
    # were landing in whichever case was under test. Restarting ExaBGP removes
    # the ambiguity; the process re-reads its boot file, so the baseline table
    # comes back by itself.
    restarted = None
    if fresh_session:
        restarted = ctx.fleet.restart_exabgp(s.container)
        ctx.log("malformed_isolate_restart", container=s.container,
                ok=restarted)
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            st4 = telemetry.bgp_peer_state(ctx.dut.bgp_summary("ipv4"), s.v4 or "")
            if _state_is_established(st4):
                break
            time.sleep(2.0)

    rows: List[Dict[str, Any]] = []
    for m in cases:
        afi = "ipv4" if m.afi == "ipv4" else "ipv6"
        addr = (s.v4 if afi == "ipv4" else s.v6) or ""
        nb = dv4 if afi == "ipv4" else dv6

        before = ctx.dut.bgp_summary(afi)
        drops_before = _peer_field(before, addr, "connectionsDropped")
        # Let the session settle back to Established before measuring, otherwise
        # a previous case's reset is attributed to this one.
        waited = 0.0
        while (_state_is_established(telemetry.bgp_peer_state(before, addr))
               is not True) and waited < 30.0:
            time.sleep(2.0)
            waited += 2.0
            before = ctx.dut.bgp_summary(afi)
            drops_before = _peer_field(before, addr, "connectionsDropped")

        sel = policyprobe.neighbor_selector(nb, s.v4 if m.afi == "ipv4" else s.v6)
        ctx.fleet.exabgp_send(s, f"{sel} announce route {m.prefix} {m.attrs}")
        time.sleep(settle_s)

        after = ctx.dut.bgp_summary(afi)
        drops_after = _peer_field(after, addr, "connectionsDropped")
        state = telemetry.bgp_peer_state(after, addr)
        delta = (None if (drops_before is None or drops_after is None)
                 else drops_after - drops_before)
        got = ctx.dut.lookup_prefix(m.prefix, afi)
        present = bool(got and got.get("paths"))

        reset = bool(delta) if delta is not None else None
        # Grade it here. The first version recorded route_present and never
        # compared it to expect_route, so the one pass with clean per-case data
        # produced no verdicts at all — the whole point of isolating.
        session_ok = (None if reset is None
                      else (True if m.expect_session == "reset-tolerated"
                            else not reset))
        route_ok = (m.expect_route == "either"
                    or (m.expect_route == "present" and present)
                    or (m.expect_route == "absent" and not present))
        row = {
            "mid": m.mid, "prefix": m.prefix, "afi": afi,
            "expect_session": m.expect_session, "expect_route": m.expect_route,
            "state_after": state, "connections_dropped_delta": delta,
            "route_present": present,
            "resets_session": reset,
            "session_pass": session_ok,
            "route_pass": route_ok,
            "pass": bool(session_ok) and route_ok,
            "tags": list(m.tags),
        }
        if reset and m.expect_session == "up":
            row["classification"] = ("implementation-defect-confirmed"
                                     if m.known_defect else "rfc7606-violation")
            if m.known_defect:
                row["known_defect"] = m.known_defect
        elif reset:
            row["classification"] = "reset-tolerated"
        elif not row["pass"]:
            row["classification"] = "unexpected"
        if delta:
            window = f"-{int(settle_s) + 5}s"
            # `log_sample` is every reset-relevant line in the window and may
            # still contain residue from other traffic on the session. When the
            # case declares the line it should produce, grep for that
            # specifically and record it separately - that is the decisive
            # evidence, and it must not be left for a human to spot in a haystack.
            row["log_sample"] = _dedup_log(
                ctx.dut.log_since(window, extra_grep=MALFORMED_LOG_GREP), 12)
            if m.expect_log:
                hits = ctx.dut.log_since(window, extra_grep=m.expect_log)
                row["expect_log"] = m.expect_log
                row["expect_log_found"] = bool(hits)
                row["expect_log_lines"] = _dedup_log(hits, 4)
        rows.append(row)
        ctx.log("malformed_isolate_case", **row)
        ctx.fleet.exabgp_send(s, f"{sel} withdraw route {m.prefix}")
        time.sleep(1.0)

    offenders = [r["mid"] for r in rows if r["resets_session"]]
    return ctx.log("malformed_isolate_done", session=s.sid,
                   exabgp_restarted=restarted,
                   cases=len(rows), offenders=offenders, results=rows)


def _peer_field(summary: Optional[Dict], peer: str, field_name: str):
    node = telemetry.bgp_peer_node(summary)
    if not node:
        return None
    p = (node.get("peers") or {}).get(peer)
    if not isinstance(p, dict):
        return None
    v = p.get(field_name)
    return v if isinstance(v, int) else None


def _peer_established(summary: Optional[Dict], peer: str) -> Optional[bool]:
    """True/False for one neighbour, None if that neighbour is not in the table.

    `peer` MUST be the simulated speaker's own address (Session.v4 / .v6).
    FRR keys `show bgp <afi> unicast summary json` by *neighbour* address, so
    passing the DUT's fabric address here returns None for every peer, which
    silently disables the caller's assertion. That was a real bug: see
    FINDINGS.md, harness defect H-1.
    """
    return _state_is_established(telemetry.bgp_peer_state(summary, peer))


def _state_is_established(state: Optional[str]) -> Optional[bool]:
    if state is None:
        return None
    return state.lower() == "established"


# ---------------------------------------------------------------------------
# registry + scheduler
# ---------------------------------------------------------------------------

EVENTS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "peer_flap": ev_peer_flap,
    "blackhole_peer": ev_blackhole_peer,
    "churn": ev_churn,
    "policy_churn": ev_policy_churn,
    "soft_clear": ev_soft_clear,
    "maxprefix_trip": ev_maxprefix_trip,
    "netem": ev_netem,
    "gr_event": ev_gr_event,
    "dut_bgpd_restart": ev_dut_bgpd_restart,
    "probe_check": ev_probe_check,
    "malformed_burst": ev_malformed_burst,
    "malformed_isolate": ev_malformed_isolate,
}


@dataclass
class Scheduler:
    """Weighted random event scheduler with a seeded RNG."""

    ctx: Ctx
    events: Sequence[Dict[str, Any]]
    min_gap_s: float = 3.0
    max_gap_s: float = 20.0

    def __post_init__(self) -> None:
        self._spec: List[Tuple[int, Dict[str, Any]]] = []
        for e in self.events:
            kind = e.get("kind")
            if kind not in EVENTS:
                raise ValueError(
                    f"unknown scenario event '{kind}'. Known: {sorted(EVENTS)}")
            self._spec.append((int(e.get("weight", 1)), e))
        if not self._spec:
            raise ValueError("scenario declares no events")
        self._total = sum(w for w, _ in self._spec)

    def draw(self) -> Dict[str, Any]:
        r = self.ctx.rng.randrange(self._total)
        acc = 0
        for w, e in self._spec:
            acc += w
            if r < acc:
                return e
        return self._spec[-1][1]

    def run_one(self) -> Dict[str, Any]:
        spec = dict(self.draw())
        kind = spec.pop("kind")
        spec.pop("weight", None)
        fn = EVENTS[kind]
        t0 = time.monotonic()
        try:
            rec = fn(self.ctx, **spec)
        except Exception as exc:
            rec = self.ctx.log("event_error", event=kind, error=repr(exc))
        rec["event_kind"] = kind
        rec["event_seconds"] = round(time.monotonic() - t0, 2)
        return rec

    def sleep_gap(self) -> float:
        gap = self.ctx.rng.uniform(self.min_gap_s, self.max_gap_s)
        time.sleep(gap)
        return gap
