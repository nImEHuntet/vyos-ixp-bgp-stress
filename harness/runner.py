"""CLI entry point.

    python -m harness.runner <subcommand> --build build/<profile> [options]

Subcommands
-----------
    status      what is running, and the DUT's versions
    config      push the generated DUT configuration (base, neighbors, instrument)
    bringup     start every generator and load its table
    converge    wait for the table to settle and report how long it took
    probe       one-shot policy-probe + malformed-attribute report
    run         warm up, converge, then run the chaos schedule for `duration_s`
    ramp        break-it mode: scale up in waves until a predicate trips
    teardown    stop generators and clear impairments

`containerlab deploy` and `containerlab destroy` are deliberately left to the
Makefile and the runbook: they need root and they are the one step where a human
should see the output.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from . import generate, model, policyprobe, routegen, scenarios, telemetry
from .dut import CommitTimeout, Dut, docker_available, docker_cmd
from .model import Inventory, Session
from .peers import PeerFleet
from .scenarios import Ctx, Scheduler
from .telemetry import Budgets, ConvergenceTracker, PredicateSet, Sampler, Violation


# ---------------------------------------------------------------------------
# context assembly
# ---------------------------------------------------------------------------


def _require_docker() -> None:
    """Fail with an actionable message rather than a wall of docker errors."""
    ok, detail = docker_available()
    if not ok:
        raise SystemExit(
            f"error: cannot reach the Docker daemon ({detail}).\n"
            f"       The harness drives the lab through `docker exec`. Either add\n"
            f"       your user to the docker group, or run this target under sudo."
        )


def load_build(build_dir: str) -> Tuple[Inventory, Dict]:
    inv_path = os.path.join(build_dir, "inventory.json")
    if not os.path.exists(inv_path):
        raise SystemExit(
            f"{inv_path} not found. Run `python -m harness.generate <profile> "
            f"--template <template.md>` first."
        )
    with open(inv_path, "r", encoding="utf-8") as fh:
        invj = json.load(fh)
    inv = model.load(invj["profile_path"])
    return inv, invj


def make_plan(invj: Dict) -> routegen.PrefixPlan:
    nl = invj["nlri"]
    return routegen.PrefixPlan(
        v4_first_octets=generate.expand_octets(nl["v4_first_octets"]),
        v4_len=int(nl.get("v4_len", 24)),
        v6_base=nl.get("v6_base", "3fff::/20"),
        v6_len=int(nl.get("v6_len", 48)),
        seed=int(nl.get("seed", 1)),
        contested_fraction=float(nl.get("contested_fraction", 0.10)),
        contested_pool_v4=int(nl.get("contested_pool_v4", 20000)),
        contested_pool_v6=int(nl.get("contested_pool_v6", 5000)),
    )


def make_ctx(args, inv: Inventory, invj: Dict, results_dir: str,
             sampler: Sampler) -> Ctx:
    prefix = args.clab_prefix or f"clab-{inv.name}"
    return Ctx(
        inv=inv,
        dut=Dut(container=f"{prefix}-{inv.dut['name']}",
                commit_timeout=float(invj.get("budgets", {}).get("commit_s", 180)) * 2),
        fleet=PeerFleet(clab_prefix=prefix,
                        expected_addrs=expected_container_addrs(inv)),
        sampler=sampler,
        plan=make_plan(invj),
        build_dir=args.build,
        rng=random.Random(int(invj.get("scenario", {}).get("seed", 1))),
        dry_run=args.dry_run,
    )


def expected_session_counts(inv: Inventory) -> Tuple[int, int]:
    return (len([s for s in inv.sessions if s.v4]),
            len([s for s in inv.sessions if s.v6]))


DEFAULT_SAMPLE_INTERVAL = 2.0


def sample_interval(args, invj: Optional[Dict] = None) -> float:
    """Resolve the telemetry interval: CLI flag, then profile, then default.

    `--interval` defaults to None so that "not given" is distinguishable from an
    explicit value, which means every call site has to resolve it. Three of them
    passed None straight through to the Sampler, whose loop then evaluated
    `self.interval - elapsed` and raised TypeError inside the sampling thread —
    visible only as a thread traceback, with the real failure (no generators
    started) scrolling past underneath it. Resolution lives here now so it cannot
    drift between subcommands.
    """
    if getattr(args, "interval", None):
        return float(args.interval)
    if invj:
        v = (invj.get("scenario") or {}).get("sample_interval_s")
        if v:
            return float(v)
    return DEFAULT_SAMPLE_INTERVAL


def new_sampler(ctx_dut: Dut, results_dir: str, interval: float) -> Sampler:
    os.makedirs(results_dir, exist_ok=True)
    if not interval or float(interval) <= 0:
        raise ValueError(f"sample interval must be positive, got {interval!r}")
    return Sampler(dut=ctx_dut, path=os.path.join(results_dir, "samples.jsonl"),
                   interval=float(interval))


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------


def cmd_status(args) -> int:
    inv, invj = load_build(args.build)
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}")
    fleet = PeerFleet(clab_prefix=prefix,
                      expected_addrs=expected_container_addrs(inv))

    ok, detail = docker_available()
    print(f"docker        : {'via ' + detail if ok else 'UNAVAILABLE — ' + detail}")
    if not ok:
        print("\n  The harness drives everything through docker exec. Either add your")
        print("  user to the docker group (newgrp docker) or run these targets with")
        print("  sudo. Nothing else will work until this does.")
        return 1
    print(f"lab           : {inv.name}")
    print(f"clab prefix   : {prefix}")
    t = inv.totals()
    print(f"sessions      : {t['sessions']} in {t['containers']} containers")
    print(f"paths planned : v4 {t['paths_v4']:,}  v6 {t['paths_v6']:,}")
    print(f"DUT container : {dut.container}  running={dut.alive()}")
    if not dut.alive():
        print("\nDUT is not running. Deploy the lab first (make deploy).")
        return 1

    for k, v in dut.version().items():
        print(f"  {k:<12}: {v}")
    print(f"  kernel routes: {dut.kernel_route_counts()}")
    z = dut.zebra_stats()
    if z.get("netlink_rcvbuf"):
        print(f"  netlink rcvbuf (applied): {z['netlink_rcvbuf']} bytes")

    for afi in ("ipv4", "ipv6"):
        s = telemetry._summarise_bgp(dut.bgp_summary(afi))
        print(f"  bgp {afi}: peers={s['peers']} established={s['established']} "
              f"failed={s['failed']} pfxRcd={s['pfx_rcd_total']:,} "
              f"tableVersion={s['table_version']}")

    running = 0
    for cname, c in inv.containers.items():
        pids = fleet.generator_pids(cname)
        n = len(pids["gobgpd"]) + len(pids["exabgp"])
        running += n
        want = len(c.sessions) if c.engine == "gobgp" else 1
        flag = "" if n >= want else "   <-- expected " + str(want)
        print(f"  {cname:<28} {c.engine:<7} procs={n}/{want}{flag}")
    print(f"\ngenerator processes running: {running}")
    if running == 0:
        # Without this note the BGP line above reads as a fault. It is not: the
        # DUT holds a neighbour stanza per session from `make config`, so with no
        # generators started every session is legitimately Active/Connect.
        print("  No generators are running, so every BGP session being down is the")
        print("  expected state at this point. `make bringup` starts them.")
    elif running and any(
            (b.get("established") or 0) == 0
            for b in (telemetry._summarise_bgp(dut.bgp_summary(a))
                      for a in ("ipv4", "ipv6"))):
        print("  Generators are running but no session is Established — that IS a")
        print("  fault. Check the peering-LAN addressing (make prepare) and the")
        print("  gobgpd logs.")

    # Bind-mount health. A running process with an unreadable table looks
    # identical to a healthy one until injection fails, so show it here.
    print("\nMRT tables as the containers see them:")
    bad = 0
    for s in inv.sessions:
        if s.engine != "gobgp":
            continue
        cpath = fleet.mrt_path(s)
        seen = fleet.file_size_in_container(s.container, cpath)
        hpath = None if s.mrt else os.path.join(args.build, "mrt", f"{s.sid}.mrt")
        host = os.path.getsize(hpath) if hpath and os.path.exists(hpath) else None
        ok_ = seen is not None and (host is None or seen == host)
        bad += 0 if ok_ else 1
        print(f"  {s.sid:<22} container={'MISSING' if seen is None else f'{seen:,}':>12}"
              f"  host={'MISSING' if host is None else f'{host:,}':>12}"
              f"  {'ok' if ok_ else 'MISMATCH'}")
    if bad:
        print(f"\n  {bad} container(s) cannot see their MRT table. The bind mount is")
        print("  stale: build/<profile>/mrt was replaced after `containerlab deploy`.")
        print("  Redeploy (make destroy && make deploy), and keep build/ out of any")
        print("  file-sync agent covering this repo (a .stignore ships in the repo).")
    return 0


def cmd_config(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}", commit_timeout=args.commit_timeout)
    if not dut.alive():
        print(f"error: {dut.container} is not running", file=sys.stderr)
        return 1

    files = ["00-base.conf", "10-neighbors.conf", "20-instrument.conf"]
    if args.only:
        files = [f for f in files if args.only in f]

    total = 0.0
    for fn in files:
        path = os.path.join(args.build, "dut", fn)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l for l in fh.read().splitlines()
                     if l.strip() and not l.strip().startswith("#")]
        print(f"-- {fn}: {len(lines)} command(s) ... ", end="", flush=True)
        if args.dry_run:
            print("(dry run)")
            continue
        try:
            r = dut.configure(lines, save=args.save)
        except CommitTimeout as exc:
            print(f"COMMIT TIMEOUT\n{exc}", file=sys.stderr)
            return 1
        total += r.seconds
        if r.ok:
            print(f"committed in {r.seconds:.1f}s")
        else:
            print(f"FAILED (rc={r.rc}) in {r.seconds:.1f}s")
            tail = (r.err or r.out).strip().splitlines()[-25:]
            print("\n".join("    " + l for l in tail), file=sys.stderr)
            if not args.keep_going:
                return 1
    print(f"\ntotal commit time: {total:.1f}s")

    vp = os.path.join(args.build, "dut", "VERIFY-ON-IMAGE.md")
    if os.path.exists(vp):
        print(f"note: review {vp} — it lists commands whose availability is "
              f"release-dependent.")
    return 0


def _check_mrt_visible(ctx: Ctx, gobgp_sessions: List[Session]) -> List[str]:
    """Confirm each container can actually see its MRT file before injecting.

    A bind mount is a snapshot of an inode, not a live path lookup. If the host
    directory behind `mrt:/mrt:ro` is *replaced* after `containerlab deploy` —
    by a regenerate that recreates the directory, or by a file-sync agent
    resolving a conflict by swapping it out — the running container keeps
    pointing at the old, now-unlinked directory. The host directory is full, the
    container's view is empty, and Docker reports nothing. The only symptom used
    to be gobgp's own message:

        failed to open file: open /mrt/<sid>.mrt: no such file or directory

    which reads like a generation bug and sends you looking in the wrong place.
    Checking here turns it into a named diagnosis with the host side quoted.

    Returns the sids that cannot be injected.
    """
    bad: List[str] = []
    for s in gobgp_sessions:
        cpath = ctx.fleet.mrt_path(s)
        seen = ctx.fleet.file_size_in_container(s.container, cpath)
        # A session with an explicit `mrt:` in the profile points at a file the
        # operator mounted themselves (a real RouteViews dump, say). There is no
        # generated host-side counterpart to compare sizes against, so the only
        # assertion available is that the container can read it at all.
        hpath = None if s.mrt else os.path.join(ctx.build_dir, "mrt",
                                                f"{s.sid}.mrt")
        host = (os.path.getsize(hpath)
                if hpath and os.path.exists(hpath) else None)
        if seen is not None and (host is None or seen == host):
            continue
        bad.append(s.sid)
        print(f"  !! {s.sid}: {s.container} cannot see its MRT table.")
        print(f"       in container : {cpath} -> "
              f"{'MISSING' if seen is None else f'{seen:,} bytes'}")
        if hpath:
            print(f"       on host      : {hpath} -> "
                  f"{'MISSING' if host is None else f'{host:,} bytes'}")
        else:
            print(f"       host side    : external MRT declared in the profile "
                  f"({s.mrt}); mount it into {s.container} yourself")
        ctx.log("mrt_not_visible", session=s.sid, container=s.container,
                container_path=cpath, container_bytes=seen,
                host_path=hpath, host_bytes=host, external=bool(s.mrt))
    external = [s_.sid for s_ in gobgp_sessions if s_.mrt and s_.sid in bad]
    if external:
        print(f"\n  {len(external)} of these declare an EXTERNAL MRT via `mrt:` in the")
        print("  profile. Nothing generates or mounts those for you — that is the")
        print("  deferred T3 gap, not a stale bind mount. To use a real dump you need")
        print("  all three of:")
        print("    1. the file present on the host and bound into each peer container")
        print("       at the path the profile names;")
        print("    2. it decompressed — `gobgp mrt inject` reads raw MRT, not .bz2/.gz;")
        print("    3. per-address-family injection with `--nexthop <peer-addr>` plus")
        print("       `--no-ipv4` / `--no-ipv6`, because a collector dump's next-hops")
        print("       point at the collector's peers, not at this lab's peering LAN.")
        print("  Until (3) exists in the harness, a real dump will load but every path")
        print("  will be unreachable. See FINDINGS.md H-28.")
    remaining = [x for x in bad if x not in set(external)]
    if remaining:
        print("\n  The MRT files exist on the host but the containers are mounting a")
        print("  different (replaced) directory. A bind mount holds the inode it was")
        print("  created with, so anything that recreates build/<profile>/mrt after")
        print("  `containerlab deploy` detaches every peer container from it.")
        print("  Confirm with:")
        print(f"    docker exec {ctx.fleet.cname(gobgp_sessions[0].container)} ls -la /mrt")
        print(f"    ls -la {os.path.join(ctx.build_dir, 'mrt')}")
        print(f"    docker inspect -f '{{{{json .Mounts}}}}' "
              f"{ctx.fleet.cname(gobgp_sessions[0].container)}")
        print("  Fix: redeploy (make destroy && make deploy) so the mounts are")
        print("  recreated against the current directory. If a file-sync agent")
        print("  covers this repo, exclude build/ from it - generated artefacts")
        print("  under a running container's bind mounts will keep doing this.")
    return bad


_BOOT_RE = re.compile(r"sent (\d+) boot commands")


def _boot_commands_sent(helper_log: str) -> Optional[int]:
    """How many boot commands the ExaBGP helper reported sending.

    None means it has not said yet (still starting, or the log is unreachable);
    0 means it explicitly announced nothing, which is a failure.
    """
    if not helper_log:
        return None
    if "BOOT-MISSING" in helper_log or "BOOT-EMPTY" in helper_log:
        return 0
    hits = _BOOT_RE.findall(helper_log)
    return int(hits[-1]) if hits else None


def _start_generators(ctx: Ctx, sessions: List[Session], inject: bool,
                      only_best: bool, prefix_cap: Optional[int] = None) -> Dict:
    """Start every generator, then confirm it is actually running.

    The confirmation step is not decoration. Previously a generator that failed to
    start was indistinguishable from one that started fine, because the only
    evidence was an MRT injection failure several steps later. Now a process that
    does not appear gets its log tail printed immediately.
    """
    started, injected, failed = 0, 0, []
    exa_containers = set()
    gobgp_sessions = [s for s in sessions if s.engine == "gobgp"]

    for s in gobgp_sessions:
        if ctx.fleet.gobgpd_pid(s) is None:
            ctx.fleet.start_gobgpd(s)
            started += 1
    for s in sessions:
        if s.engine == "exabgp":
            exa_containers.add(s.container)

    for c in sorted(exa_containers):
        n = len(ctx.fleet.exabgp_pids(c))
        if n == 0:
            # No copy step here. The per-container boot file is bound straight to
            # generate.EXABGP_BOOT_PATH by build_topology. The previous version
            # copied boot-<c>.txt to a fixed name inside the container, but
            # /etc/exabgp/run is mounted :ro, so the copy always failed and
            # `|| true` swallowed it: the fleet came up Established announcing
            # nothing, and `converge` still reported success.
            ctx.fleet.start_exabgp(c)
            started += 1

    if started:
        time.sleep(max(5.0, min(30.0, started * 0.4)))

    # Confirm what actually came up before trying to load tables into it.
    for s in gobgp_sessions:
        if ctx.fleet.gobgpd_pid(s) is None:
            failed.append(s.sid)
            log = ctx.fleet.gobgpd_log(s)
            print(f"  !! gobgpd for {s.sid} is not running. Log tail:")
            for line in (log.splitlines() or ["    (log is empty or missing)"])[-12:]:
                print(f"       {line}")
            ctx.log("gobgpd_start_failed", session=s.sid, log=log[-1500:])
    for c in sorted(exa_containers):
        if not ctx.fleet.exabgp_pids(c):
            failed.append(c)
            log = ctx.fleet.exabgp_log(c)
            print(f"  !! exabgp in {c} is not running. Log tail:")
            for line in (log.splitlines() or ["    (log is empty or missing)"])[-12:]:
                print(f"       {line}")
            ctx.log("exabgp_start_failed", container=c, log=log[-1500:])
            continue
        # Running is not the same as announcing. The helper logs exactly how many
        # boot commands it sent, or why it sent none; surface that here rather
        # than letting a silent empty table reach `converge`.
        hlog = ctx.fleet.exabgp_helper_log(c)
        sent = _boot_commands_sent(hlog)
        if sent is None:
            print(f"  ?? exabgp in {c} started but the helper has not reported a "
                  f"boot count yet. Helper log tail:")
            for line in (hlog.splitlines() or ["    (log is empty or missing)"])[-8:]:
                print(f"       {line}")
            ctx.log("exabgp_boot_unknown", container=c, log=hlog[-1500:])
        elif sent == 0:
            failed.append(f"{c} (announced nothing)")
            print(f"  !! exabgp in {c} announced 0 prefixes. Helper log tail:")
            for line in (hlog.splitlines() or ["    (log is empty or missing)"])[-8:]:
                print(f"       {line}")
            ctx.log("exabgp_boot_empty", container=c, log=hlog[-1500:])
        else:
            print(f"  exabgp {c}: {sent} boot command(s) sent")
            ctx.log("exabgp_boot_sent", container=c, commands=sent)

    # Arm the FRR debugs the session-level log detectors depend on. Without
    # `debug bgp neighbor-events` FRR logs no state transitions, no holdtime
    # expiry and no NOTIFICATIONs at all, so those detectors cannot fire.
    dbg = ctx.dut.enable_bgp_debugs()
    if dbg["ok"]:
        print(f"  FRR debugs armed   : {', '.join(dbg['commands'])} "
              f"(via {dbg['via']})")
    else:
        print(f"  !! FRR debugs did not take: `show debugging bgp` reports "
              f"{dbg['active']} after sending them (sent_ok={dbg['sent_ok']}). "
              f"The FSM transition lines will be absent.")
    print(f"  log-neighbor-changes: {dbg['neighbor_changes']}"
          + ("" if dbg["neighbor_changes"] else
             "  !! %ADJCHANGE / %NOTIFICATION detectors will stay silent"))
    ctx.log("frr_debugs", **dbg)

    if inject:
        stale = _check_mrt_visible(ctx, [s for s in sessions if s.engine == "gobgp"])
        if stale:
            failed.extend(stale)
        for s in sessions:
            if s.engine != "gobgp":
                continue
            if s.sid in stale:
                continue
            r = ctx.fleet.inject_mrt(s, only_best=only_best, count=prefix_cap)
            if r.ok:
                injected += 1
            else:
                ctx.log("mrt_inject_failed", session=s.sid,
                        rc=r.rc, err=(r.err or r.out)[-300:])
    return {"started": started, "injected": injected,
            "failed": failed, "gobgp_sessions": len(gobgp_sessions),
            "exabgp_containers": len(exa_containers)}


def cmd_bringup(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    results_dir = args.results or os.path.join(args.build, "results",
                                               time.strftime("%Y%m%dT%H%M%S"))
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}")
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    if not dut.alive():
        print(f"error: {dut.container} is not running", file=sys.stderr)
        return 1

    sampler.start()
    try:
        print(f"starting generators for {len(inv.sessions)} session(s) ...")
        st = _start_generators(ctx, list(inv.sessions), inject=not args.no_inject,
                               only_best=not args.all_paths)
        print(f"  processes started : {st['started']}")
        print(f"  gobgpd expected   : {st['gobgp_sessions']}")
        print(f"  exabgp containers : {st['exabgp_containers']}")
        print(f"  MRT tables loaded : {st['injected']}/{st['gobgp_sessions']}")
        if st["failed"]:
            print(f"  FAILED to start   : {', '.join(st['failed'])}")
        sampler.event("bringup_complete", **st)
    finally:
        sampler.stop()
    print(f"\ntelemetry: {os.path.join(results_dir, 'samples.jsonl')}")
    if st.get("failed"):
        print("\nSome generators did not start; their logs are above. Nothing after "
              "this will work until they do.")
        return 1
    if not args.no_inject and st["injected"] < st["gobgp_sessions"]:
        print(f"\nOnly {st['injected']} of {st['gobgp_sessions']} MRT table(s) "
              f"loaded. Check `make status` and the gobgpd logs.")
        return 1
    return 0


def _accounting(ctx: Ctx, inv: Inventory) -> Dict[str, Dict[str, int]]:
    """Announced vs accepted, per address family.

    A run that ends holding more prefixes than the profile announced is not a
    capacity result, it is a harness leak — and "IPv6 paths received (peak)" is a
    headline number in the report, so it has to be checked rather than admired.
    Observed once: 680 announced, 804 accepted at the end of a chaos run whose
    only prefix-moving events were `churn`.
    """
    out: Dict[str, Dict[str, int]] = {}
    for afi, want in (("ipv4", sum(x.prefixes_v4 for x in inv.sessions if x.v4)),
                      ("ipv6", sum(x.prefixes_v6 for x in inv.sessions if x.v6))):
        got = telemetry._summarise_bgp(ctx.dut.bgp_summary(afi))["pfx_rcd_total"]
        out[afi] = {"announced": want, "accepted": got, "drift": got - want}
    return out


def expected_container_addrs(inv: Inventory) -> Dict[str, Dict[str, Any]]:
    """container -> {"iface": <where the addresses live>, "cidrs": [...]}.

    The interface matters and is not always `eth1`. On a VLAN-backed fabric
    `prepare.sh` puts the addresses on `eth1.<vlan>`; ixp2 in the T3 profile is
    VLAN 200, ixp1 is untagged.

    The first version of this returned bare CIDRs and `restore_addrs()`
    defaulted to `eth1`, so the H-59 repair put every ixp2 address on the
    *parent* interface — untagged — while the real ones sat on `eth1.200`. Two
    interfaces in one netns then held the same address and the same connected
    prefix, and the kernel's egress choice between them decided whether the
    session worked. Five sessions in the container that was link-flapped twice
    ended the run with the DUT in `Connect` and the peer in `SYN_RECV`: the
    DUT's tagged SYN arrived, the peer's SYN-ACK left untagged, and the
    handshake never completed. See FINDINGS.md H-61.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for cname, c in inv.containers.items():
        fab = inv.fabrics[c.fabric]
        iface = c.iface if fab.vlan is None else f"{c.iface}.{fab.vlan}"
        cidrs: List[str] = []
        for sess in c.sessions:
            if sess.v4:
                cidrs.append(f"{sess.v4}/{fab.v4_net.prefixlen}")
            if sess.v6:
                cidrs.append(f"{sess.v6}/{fab.v6_net.prefixlen}")
        out[cname] = {"iface": iface, "parent": c.iface, "cidrs": cidrs}
    return out


def _fib_agrees(dut: Dut, last: Dict[str, Any], min_ratio: float = 0.95
                ) -> Tuple[bool, str, Dict[str, Any]]:
    """Ask zebra whether the BGP table is actually installed.

    Returns (agrees, why-not, per-afi detail). `show ip route summary` is
    authoritative and cheap enough to run once per convergence decision; the
    sampled `route_installs` counter is neither — it is a cumulative count of
    install operations, not a FIB size (FINDINGS.md H-52).

    A summary this code cannot *read* is treated as agreement and reported in
    the detail, because refusing to converge on a missing diagnostic is worse
    than the problem. That rule was already here; what was missing was that
    "no `bgp` row" is a parser limitation, not an empty FIB. FRR splits BGP
    into `ebgp` and `ibgp` rows, so `bgp_routes` came back None on every real
    build and this function answered "the FIB is empty" forever. T3 run 1 spent
    its entire 2,400 s warmup in that loop against a FIB that was
    2,445,625/2,445,625 installed. See FINDINGS.md H-51.
    """
    b = last.get("bgp") or {}
    detail: Dict[str, Any] = {}
    verdict: Tuple[bool, str] = (True, "")
    for afi in ("ipv4", "ipv6"):
        rib_bgp = (b.get(afi) or {}).get("rib_count") or 0
        if not rib_bgp:
            continue
        rs = dut.route_summary(afi)
        routes, fib = rs.get("bgp_routes"), rs.get("bgp_fib")
        detail[afi] = {"ok": rs.get("ok"), "bgp_routes": routes,
                       "bgp_fib": fib, "ratio": rs.get("bgp_fib_ratio"),
                       "rows": rs.get("bgp_source_rows"),
                       "sources": sorted(rs.get("sources") or {}),
                       "bgpd_rib_count": rib_bgp, "summary": rs}
        if not rs.get("ok") or routes is None:
            # Unmeasured, not zero. Say so in the record; do not block.
            detail[afi]["unmeasured"] = (
                "route summary unreadable" if not rs.get("ok")
                else f"no recognised BGP row in {sorted(rs.get('sources') or {})}")
            continue
        if routes and fib is not None and fib < routes * min_ratio:
            if verdict[0]:
                verdict = (False, f"{afi} FIB has {fib:,} of {routes:,} BGP "
                                  f"routes installed ({fib / routes:.0%})")
    return verdict[0], verdict[1], detail


def _snapshot_peers(ctx: Ctx, why: str) -> Dict[str, Any]:
    """One-shot full per-peer state, for the moments that need attributing.

    The sampler caps per-peer detail at PER_PEER_SAMPLE_LIMIT so a 2 s poll
    stays cheap, which at T3 scale means every sample carries `per_peer: null`.
    T3 run 1 finished its 3,600 s settle with 75 IPv6 sessions in Active and no
    record of *which* sessions, when each went down, or how many times it had
    flapped — so "the DUT would not re-establish them" and "the far ends were
    gone" were indistinguishable from the run's own data. Take the full picture
    at the moments where that question gets asked. See FINDINGS.md H-57.
    """
    snap: Dict[str, Any] = {"why": why}
    for afi in ("ipv4", "ipv6"):
        b = telemetry._summarise_bgp(ctx.dut.bgp_summary(afi), full_detail=True)
        pp = b.pop("per_peer", None) or {}
        snap[afi] = {
            **{k: v for k, v in b.items() if k != "not_established"},
            "not_established": b.get("not_established"),
            "down": {a: d for a, d in pp.items()
                     if str(d.get("state", "")).lower() != "established"},
            "flap_counts": {a: d.get("conn_drop") for a, d in pp.items()
                            if d.get("conn_drop")},
        }

    # The DUT half alone cannot attribute a session stuck in Active — that is
    # what R-8 ran into. Take the peer half at the same instant.
    try:
        snap["fleet"] = ctx.fleet.fleet_snapshot(
            ctx.inv.sessions, ctx.dut_addrs, why=why)
    except Exception as exc:
        snap["fleet_error"] = repr(exc)

    ctx.log("peer_snapshot", **snap)

    fl = snap.get("fleet") or {}
    counts = fl.get("verdict_counts") or {}
    interesting = {k: v for k, v in counts.items()
                   if not k.endswith(":established")}
    if interesting or fl.get("containers_with_no_speaker"):
        print(f"   peer-side state ({why}):")
        for k in sorted(interesting):
            print(f"      {k:<40} {interesting[k]}")
        dead = fl.get("containers_with_no_speaker") or []
        if dead:
            print(f"      containers with no live speaker: {', '.join(dead)}")
        print("      `listening_no_connection` points at the DUT or the path; "
              "`no_socket_for_family` points at the generator.")
    return snap

def _converge(ctx: Ctx, inv: Inventory, budgets: Budgets, timeout: float,
              progress_every: float = 20.0) -> Tuple[bool, float, Dict]:
    e4, e6 = expected_session_counts(inv)
    tracker = ConvergenceTracker(expected_sessions_v4=e4, expected_sessions_v6=e6,
                                 stable_samples=3)
    # Progress, because a silent 21-minute wait looks exactly like a hang.
    # On T2 run 3 the post-chaos settle had a 1,260 s timeout and printed
    # nothing at all; the operator reasonably assumed it had broken and
    # interrupted it, losing the final accounting. Say what is blocking and
    # what the counts are, roughly every `progress_every` seconds.
    started = time.monotonic()
    state = {"next": started + progress_every}

    def _tick(rec: Dict[str, Any]) -> None:
        nowt = time.monotonic()
        if nowt < state["next"]:
            return
        state["next"] = nowt + progress_every
        b = rec.get("bgp") or {}
        v4 = b.get("ipv4") or {}
        v6 = b.get("ipv6") or {}
        print(f"      [{nowt - started:5.0f}s/{timeout:.0f}s] "
              f"v4 {v4.get('established')}/{v4.get('peers')} "
              f"v6 {v6.get('established')}/{v6.get('peers')} — "
              f"{tracker.reason or 'stabilising'}", flush=True)

    # The sampled counters are a cheap gate; zebra's own route summary is the
    # authority. T3 converged in 34 s with `zebra rss=13.8 MB`, `tableVersion=50`
    # against a 4,891,343-entry RIB, and **no bgp line in the route summary at
    # all** — the FIB was completely empty and the sampled gate had been
    # satisfied by a reading it could not actually evaluate. So: when the
    # tracker is happy, ask zebra directly, and if zebra disagrees keep waiting
    # with whatever time is left. See FINDINGS.md H-50.
    deadline = started + timeout
    ok = False
    secs, last = 0.0, {}
    fib_detail: Dict[str, Any] = {}
    # The reason the *loop* rejected the last candidate, kept separately from
    # `tracker.reason`. The tracker's reason is overwritten by the very next
    # sample fed to it, so assigning the FIB verdict to it and then re-entering
    # `wait_for_convergence` guaranteed the recorded `blocked_by` was whatever
    # the final sample happened to say. T3 run 1 logged
    # `blocked_by: "stabilising (2/3 samples)"` for a run whose console printed
    # the real reason 160 times. See FINDINGS.md H-53.
    sticky: Optional[str] = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ok, secs, last = telemetry.wait_for_convergence(
            ctx.sampler, tracker, remaining, on_sample=_tick)
        if not ok:
            break
        fib_ok, fib_why, fib_detail = _fib_agrees(
            ctx.dut, last, min_ratio=budgets.fib_min_ratio)
        # Whatever the verdict, this is the only real FIB reading the run gets;
        # let the predicates judge it and put the numbers on the timeline.
        for afi in ("ipv4", "ipv6"):
            d = fib_detail.get(afi) or {}
            if d.get("summary") and ctx.preds is not None:
                for viol in ctx.preds.feed_fib(d["summary"], t=last.get("t")):
                    if viol.key() in ctx.preds._seen:
                        continue
                    ctx.preds._seen.add(viol.key())
                    ctx.violations.append(viol)
                    print(f"   !! [{viol.severity}] {viol.code}: {viol.detail}",
                          flush=True)
        if fib_ok:
            break
        ok = False
        sticky = fib_why
        print(f"      [{time.monotonic() - started:5.0f}s/{timeout:.0f}s] "
              f"counters say settled, zebra disagrees — {fib_why}", flush=True)
        tracker.reset()
    wall_s = round(time.monotonic() - started, 2)
    # Why it did not converge is as much a result as whether it did: at T2 the
    # answer was "bgpd at 100% CPU" and "FIB is behind the RIB", neither of which
    # is visible in `show bgp summary`.
    b = last.get("bgp") or {}
    rib = sum((b.get(a) or {}).get("rib_count") or 0 for a in ("ipv4", "ipv6"))
    reason = None if ok else (sticky or tracker.reason)
    ctx.last_convergence_reason = reason
    if not ok:
        # A convergence that failed is exactly the moment the per-peer picture
        # is needed, and it is the one the sampler cannot give (H-57).
        try:
            _snapshot_peers(ctx, f"convergence failed: {reason}")
        except Exception as exc:      # never let diagnostics kill the run
            ctx.log("peer_snapshot_failed", error=repr(exc))
    ctx.log("convergence", converged=ok,
            # `secs` is the tracker's back-dated streak figure and is only
            # meaningful when it converged. When it did not, the number that
            # describes what happened is how long the caller actually waited.
            seconds=round(secs, 2) if ok else wall_s,
            streak_seconds=round(secs, 2), waited_s=wall_s,
            budget_s=budgets.convergence_s,
            within_budget=ok and secs <= budgets.convergence_s,
            blocked_by=reason, last_sample_reason=tracker.reason,
            rib_count=rib,
            fib={a: {k: v for k, v in (fib_detail.get(a) or {}).items()
                     if k != "summary"} for a in fib_detail})
    return ok, (secs if ok else wall_s), last


def cmd_converge(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    budgets = Budgets.from_profile(invj.get("budgets"))
    results_dir = args.results or os.path.join(args.build, "results",
                                               time.strftime("%Y%m%dT%H%M%S"))
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}")
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    sampler.start()
    try:
        timeout = args.timeout or max(budgets.convergence_s * 4, 120)
        print(f"waiting up to {timeout:.0f}s for the table to settle ...")
        ok, secs, last = _converge(ctx, inv, budgets, timeout)
        b = (last.get("bgp") or {})
        print(f"\nconverged        : {ok}")
        if not ok:
            print(f"blocked by       : "
                  f"{ctx.last_convergence_reason or 'unknown'}")
        print(f"seconds          : {secs:.1f}   (budget {budgets.convergence_s})")
        # Ask zebra directly rather than inferring from the sampled counters.
        # `route_installs` is a cumulative install count that only rides on slow
        # samples; `show ip route summary` is the authoritative RIB-vs-FIB
        # figure, and it is the one that decides whether traffic works.
        for afi in ("ipv4", "ipv6"):
            rs = dut.route_summary(afi)
            if not rs.get("ok") or rs.get("bgp_routes") is None:
                rows = ', '.join(sorted(rs.get('sources') or {})) or 'none'
                why = rs.get('error') or (
                    f"no recognised BGP row (rows present: {rows})")
                print(f"{afi + ' FIB':<17}: unmeasured ({why})")
                continue
            ratio = rs.get("bgp_fib_ratio")
            print(f"{afi + ' FIB':<17}: {rs['bgp_fib']:,} of "
                  f"{rs['bgp_routes']:,} BGP routes installed"
                  + (f" ({ratio:.1%})" if ratio is not None else "")
                  + ("" if (ratio or 0) >= 0.99 else
                     "   <-- traffic follows the FIB, not the RIB"))
            # `payload=`, never `**rs`: route_summary() returns a dict that
            # already contains `afi`, and expanding it alongside `afi=afi`
            # raises TypeError at the call site. See FINDINGS.md H-58.
            ctx.log("fib_state",
                    payload={k: v for k, v in rs.items() if k != "sources"})

        # Decompose the cold start. Measured on T3: 300 s held in read-only mode
        # (the update-delay limit *expiring*, not every peer sending EoR), then
        # 191 s of bestpath and FIB install, then advertisement 0.6 s later —
        # 491.6 s from first session up to forwarding. The same sequence runs
        # after every bgpd restart, which is what turns a watchdog kill into a
        # multi-minute outage rather than a blip.
        ud = dut.update_delay_state()
        if ud.get("to_advertise_s") is not None:
            print(f"cold start        : {ud['to_advertise_s']:.0f}s from first "
                  f"session to advertising "
                  f"(read-only {ud.get('readonly_s')}s"
                  + (" — limit expired, not all peers sent EoR"
                     if ud.get("limit_expired") else "")
                  + f", bestpath+FIB {ud.get('bestpath_and_fib_s')}s)")
        ctx.log("update_delay", **ud)
        for afi in ("ipv4", "ipv6"):
            s = b.get(afi) or {}
            print(f"{afi:<17}: established={s.get('established')}/{s.get('peers')} "
                  f"pfxRcd={s.get('pfx_rcd_total', 0):,} "
                  f"tableVersion={s.get('table_version')} "
                  f"ribCount={s.get('rib_count')}")
        proc = last.get("proc") or {}
        for name in ("bgpd", "zebra"):
            if name in proc:
                print(f"{name:<17}: rss={proc[name]['rss_mb']} MB "
                      f"cpu={proc[name].get('cpu_pct')}% "
                      f"threads={proc[name]['threads']}")
        return 0 if ok else 2
    finally:
        sampler.stop()


def cmd_peers(args) -> int:
    """Per-peer accounting: what each speaker announced vs what the DUT accepted.

    `converge` only asserts that sessions came up. A session can be Established
    while every route it sent was silently dropped — FRR's enforce-first-as
    rejection is treat-as-withdraw, so the peer stays up, `pfxRcd` reads 0 and
    nothing in `show bgp summary` explains it. This is the command that catches
    that class of failure, and any other announced-vs-accepted shortfall.
    """
    _require_docker()
    inv, invj = load_build(args.build)
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}")

    summ = {afi: dut.bgp_summary(afi) for afi in ("ipv4", "ipv6")}
    node = {afi: telemetry.bgp_peer_node(summ[afi]) or {} for afi in summ}
    peers = {afi: (node[afi].get("peers") or {}) for afi in node}

    rows, shortfall_v4, shortfall_v6 = [], 0, 0
    # `advertised` (pfxSnt) is in the same summary response and costs nothing
    # extra, and it is the column that exposed template defect 12: the DUT was
    # announcing 760,518 IPv6 prefixes — its entire v6 RIB — across two transit
    # sessions, because `transit4`/`transit6` have an import route-map and no
    # export route-map at all. The template's own comment says an export policy
    # "needs to be added"; with none, FRR's default eBGP behaviour announces
    # everything eligible, which at an IXP means leaking the exchange's full
    # table to your upstream.
    print(f"{'session':<22} {'role':<13} {'afi':<5} {'addr':<24} "
          f"{'state':<12} {'announced':>9} {'accepted':>9} {'delta':>8} "
          f"{'advertised':>11}")
    print("-" * 126)
    for s in inv.sessions:
        for afi, addr, announced in (("ipv4", s.v4, s.prefixes_v4),
                                     ("ipv6", s.v6, s.prefixes_v6)):
            if not addr:
                continue
            p = peers[afi].get(addr)
            if not isinstance(p, dict):
                state, acc, snt = "ABSENT", None, None
            else:
                state = str(p.get("state", "?"))
                acc = p.get("pfxRcd")
                acc = acc if isinstance(acc, int) else None
                snt = p.get("pfxSnt")
                snt = snt if isinstance(snt, int) else None
            delta = None if acc is None else acc - announced
            if delta is not None and delta < 0:
                if afi == "ipv4":
                    shortfall_v4 -= delta
                else:
                    shortfall_v6 -= delta
            rows.append({"sid": s.sid, "role": s.role, "engine": s.engine,
                         "afi": afi, "addr": addr, "state": state,
                         "announced": announced, "accepted": acc,
                         "delta": delta, "advertised": snt})
            print(f"{s.sid:<22} {s.role:<13} {afi:<5} {addr:<24} "
                  f"{state:<12} {announced:>9,} "
                  f"{('-' if acc is None else format(acc, ',')):>9} "
                  f"{('-' if delta is None else format(delta, '+,')):>8} "
                  f"{('-' if snt is None else format(snt, ',')):>11}")

    print(f"\nshortfall: ipv4={shortfall_v4:,} prefix(es), ipv6={shortfall_v6:,}")
    print("note: `announced` is what the profile told the speaker to originate. "
          "A peer that is Established with accepted=0 sent routes the DUT threw "
          "away without tearing the session down.")

    # A peer being advertised more than the DUT's own address space is a route
    # leak, and at an IXP it is the most consequential policy mistake available.
    leaky = sorted((r for r in rows if (r.get("advertised") or 0) > 1000),
                   key=lambda r: -(r["advertised"] or 0))
    if leaky:
        print(f"\nfull-table export to {len(leaky)} peer(s) — the DUT is "
              f"advertising more than its own space:")
        for r in leaky[:10]:
            print(f"  {r['sid']:<22} {r['afi']:<5} {r['addr']:<24} "
                  f"advertised {r['advertised']:>11,}")
        print("  At an IXP you announce your own prefixes, not the exchange's "
              "table. Check the peer-group's\n  export route-map: template "
              "defect 12 is that `transit4`/`transit6` have none at all.")

    efa = dut.enforce_first_as_state()
    print("\nenforce-first-as (FRR default is ON from 10.0; violation is "
          "treat-as-withdraw, not a reset)")
    if not efa.get("ok"):
        print(f"  could not read running-config: {efa.get('error')}")
    elif efa.get("default_applies"):
        print("  no enforce-first-as line in the running config, and FRR prints "
              "this setting inverted: no line == ENABLED. Any peer whose AS_PATH "
              "does not begin with its own ASN will have every route silently "
              "withdrawn. Route-server fleets (RFC 7947, no self-prepend) are "
              "exactly this case.")
    else:
        print(f"  explicitly disabled on {efa['explicitly_disabled']} neighbour(s), "
              f"explicitly enabled on {efa['explicitly_enabled']}")
        for l in efa["lines"][:10]:
            print(f"    {l}")

    logs = dut.log_counts(since=args.since)
    interesting = {k: v for k, v in logs.items() if v}
    print(f"\nDUT log counters (since {args.since}): "
          f"{interesting or 'all zero'}")
    if logs.get("attr_first_as"):
        print("  -> `incorrect first AS` is present: enforce-first-as IS "
              "rejecting updates on this box. That is the cause of any "
              "Established-but-accepted=0 row above.")

    out = None
    if args.results:
        os.makedirs(args.results, exist_ok=True)
        out = os.path.join(args.results, "peers.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"rows": rows, "shortfall_v4": shortfall_v4,
                       "shortfall_v6": shortfall_v6,
                       "enforce_first_as": efa, "log_counts": logs}, fh, indent=2)
        print(f"\nwritten: {out}")
    return 0 if not (shortfall_v4 or shortfall_v6) else 2


def cmd_probe(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    results_dir = args.results or os.path.join(args.build, "results",
                                               time.strftime("%Y%m%dT%H%M%S"))
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}")
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    sampler.start()
    try:
        exa = [s for s in inv.sessions if s.engine == "exabgp"]
        if not exa:
            print("error: this profile has no ExaBGP fleet; probes need one.",
                  file=sys.stderr)
            return 1
        s = exa[0]
        dv4, dv6 = ctx.dut_addrs(s)
        probes = policyprobe.build_probes(
            inv.dut_asn, inv.profile["own"]["supernet4"],
            inv.profile["own"]["supernet6"], s.v4 or "", s.v6 or "",
            peer_asn=s.asn)
        print(f"announcing {len(probes)} probe prefix(es) from {s.sid} ...")
        if not args.dry_run:
            ctx.fleet.exabgp_send_many(s, [
                l for l in policyprobe.probe_announce_commands(
                    probes, s.v4 or "", s.v6 or "", dv4, dv6,
                peer_asn=s.asn) if not l.startswith("#")])
            time.sleep(args.settle)

        res = scenarios.ev_probe_check(ctx)
        rows = res.get("results", [])
        print(f"\n{'probe':<26} {'expect':<7} {'got':<7} {'verdict'}")
        print("-" * 78)
        defects, unexpected = [], []
        for r in rows:
            mark = "pass" if r["pass"] else r.get("classification", "FAIL")
            print(f"{r['pid']:<26} {r['expect']:<7} {r['observed']:<7} {mark}")
            if not r["pass"]:
                (defects if r.get("template_defect") else unexpected).append(r)

        # Withdraw the policy probes before the malformed phase. Leaving them
        # announced contaminated the evidence: `bogon-asn-zero` carries AS 0, so
        # every ExaBGP reconnect during a reset loop re-announced it and FRR
        # logged "Malformed AS path, AS number is 0" once per reconnect. Those
        # lines then got attributed to whichever malformed case was under test,
        # pointing at the wrong attribute entirely. See FINDINGS.md H-9.
        if not args.keep_probes:
            ctx.fleet.exabgp_send_many(
                s, policyprobe.probe_withdraw_commands(probes, dv4, dv6, s.v4, s.v6))
            time.sleep(min(5.0, args.settle))

        mal = scenarios.ev_malformed_burst(ctx, withdraw_after_s=args.settle)
        print(f"\nRFC 7606 suite: session established afterwards = "
              f"{mal.get('session_established_after')}")
        drops = mal.get("connections_dropped_delta") or {}
        print(f"  session state    : before={mal.get('state_before')} "
              f"after={mal.get('state_after')}")
        print(f"  connections dropped during the burst: {drops}")
        reset = any(bool(v) for v in drops.values())
        for r in mal.get("route_checks", []):
            if not r["pass"]:
                print(f"  unexpected: {r['mid']} expected route "
                      f"{r['expect_route']}, present={r['present']}")
        if reset:
            print("\n  The session was reset during the burst. Every route check "
                  "above is\n  therefore unreliable: whether a prefix is present "
                  "depends on where the\n  reconnect happened to land, not on how "
                  "the DUT handled the attribute.")
            for row in (mal.get("dut_log_sample") or [])[:12]:
                print(f"    x{row['count']:<5} {row['line'][:150]}")
        mal_iso = None
        if reset and not args.no_isolate:
            print(f"\nisolating {'' if args.isolate_only else 'each '}"
                  f"malformed case to find which one resets the session ...")
            if not args.no_restart:
                print("  restarting ExaBGP first so its Adj-RIB-Out is empty "
                      "(withdrawals do not reliably clear hand-encoded attributes)")
            mal_iso = scenarios.ev_malformed_isolate(
                ctx, settle_s=args.isolate_settle,
                fresh_session=not args.no_restart,
                only=args.isolate_only.split(",") if args.isolate_only else None)
            rows_i = mal_iso.get("results", [])
            print(f"\n{'case':<32} {'session':<16} {'state after':<12} "
                  f"{'reset':<6} {'route':<9} {'want':<8} {'verdict'}")
            print("-" * 108)
            for row in rows_i:
                verdict = ("pass" if row["pass"]
                           else row.get("classification", "FAIL"))
                print(f"{row['mid']:<32} {row['expect_session']:<16} "
                      f"{str(row['state_after']):<12} "
                      f"{str(row['resets_session']):<6} "
                      f"{('present' if row['route_present'] else 'absent'):<9} "
                      f"{row['expect_route']:<8} {verdict}")
            for row in rows_i:
                if row.get("expect_log") is not None:
                    mark = "FOUND" if row["expect_log_found"] else "NOT FOUND"
                    print(f"    [{row['mid']}] expected log "
                          f"{row['expect_log']!r}: {mark}")
                    for l in (row.get("expect_log_lines") or [])[:3]:
                        print(f"        x{l['count']:<4} {l['line'][:140]}")
                for l in (row.get("log_sample") or [])[:6]:
                    print(f"    [{row['mid']}] (window) x{l['count']:<4} "
                          f"{l['line'][:130]}")

            known = [r for r in rows_i
                     if r.get("classification") == "implementation-defect-confirmed"]
            viol = [r for r in rows_i
                    if r.get("classification") == "rfc7606-violation"]
            tol = [r["mid"] for r in rows_i
                   if r.get("classification") == "reset-tolerated"]
            unexp = [r for r in rows_i if r.get("classification") == "unexpected"]
            if tol:
                print(f"\n  conformant resets (RFC 4271 permits or requires a "
                      f"NOTIFICATION here): {', '.join(tol)}")
            if known:
                print(f"\n  confirmed implementation defects : {len(known)}")
                for r in known:
                    print(f"    - {r['mid']}: {r['known_defect'][:400]}")
            if viol:
                print(f"\n  RFC 7606 violation, not yet traced to source : "
                      f"{', '.join(r['mid'] for r in viol)}")
                print("    Read the log_sample lines above, then confirm against "
                      "the receiver's source before reporting.")
            if unexp:
                print(f"\n  unexpected (route present/absent disagrees with the "
                      f"expectation, session fine): "
                      f"{', '.join(r['mid'] for r in unexp)}")
            print(f"\n  isolated cases passing : "
                  f"{len([r for r in rows_i if r['pass']])}/{len(rows_i)}")

        print(f"\nconfirmed template defects : {len(defects)}")
        for r in defects:
            print(f"  - {r['pid']}: {r['template_defect'][:160]}")
        print(f"unexplained probe failures : {len(unexpected)}")

        out = os.path.join(results_dir, "probes.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"probes": rows, "malformed": mal,
                       "malformed_isolated": mal_iso,
                       "not_achievable_with_exabgp":
                           policyprobe.NOT_ACHIEVABLE_WITH_EXABGP}, fh, indent=2)
        print(f"\nwritten: {out}")
        return 0 if not unexpected else 2
    finally:
        sampler.stop()


def cmd_run(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    scen = invj.get("scenario", {})
    budgets = Budgets.from_profile(invj.get("budgets"))
    results_dir = args.results or os.path.join(args.build, "results",
                                               time.strftime("%Y%m%dT%H%M%S"))
    prefix = args.clab_prefix or f"clab-{inv.name}"
    # 4x the budget, not 2x. The timeout exists to stop the harness hanging
    # forever, not to enforce the budget — the budget is what the *measurement*
    # is compared against. At T2 the 2x timeout (360 s) fired on a commit that
    # legitimately took 343 s, the exception skipped the revert, and the run
    # spent its remaining 72 minutes measuring a lab the harness had clamped.
    # A latency that exceeds the budget is a finding; a timeout is a lost
    # measurement plus a broken lab. See FINDINGS.md H-42.
    dut = Dut(container=f"{prefix}-{inv.dut['name']}",
              commit_timeout=max(600.0, budgets.commit_s * 4))
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    if not dut.alive():
        print(f"error: {dut.container} is not running", file=sys.stderr)
        return 1

    duration = args.duration or float(scen.get("duration_s", 600))
    warmup = args.warmup if args.warmup is not None else float(scen.get("warmup_s", 60))
    preds = PredicateSet(budgets)
    ctx.preds = preds          # so deliberate impairments suppress peer faults
    violations: List[Violation] = []
    events: List[Dict] = []

    sampler.start()
    meta = {
        "lab": inv.name, "started": time.time(),
        "versions": dut.version(), "totals": inv.totals(),
        "budgets": asdict(budgets), "scenario": scen,
        "duration_s": duration, "warmup_s": warmup,
    }
    sampler.event("run_start", **meta)
    try:
        print(f"== warmup / initial convergence (up to {warmup + budgets.convergence_s:.0f}s)")
        conv_ok, conv_s, last = _converge(
            ctx, inv, budgets, warmup + budgets.convergence_s)
        print(f"   converged={conv_ok} in {conv_s:.1f}s")
        meta["initial_convergence_s"] = round(conv_s, 2)
        meta["initial_converged"] = conv_ok
        meta["initial_convergence_blocked_by"] = ctx.last_convergence_reason
        if not conv_ok:
            print(f"   blocked by: {ctx.last_convergence_reason or 'unknown'}")
        while ctx.violations:
            violations.append(ctx.violations.pop(0))

        # Baseline the table before chaos so end-of-run drift can be split into
        # "this run leaked it" and "the lab was already dirty". Observed once: a
        # +124 IPv6 drift inherited whole from the previous run because the lab
        # had not been redeployed in between, which the end-of-run figure alone
        # could not distinguish from a fresh leak.
        meta["accounting_at_start"] = _accounting(ctx, inv)
        a0 = meta["accounting_at_start"]
        if any(a0[x]["drift"] for x in ("ipv4", "ipv6")):
            print(f"   note: the table already differs from the profile before "
                  f"chaos begins — ipv4 {a0['ipv4']['drift']:+,}, "
                  f"ipv6 {a0['ipv6']['drift']:+,}. Redeploy for a clean baseline.")

        sched = Scheduler(ctx, scen.get("events", []),
                          min_gap_s=float(scen.get("min_gap_s", 3)),
                          max_gap_s=float(scen.get("max_gap_s", 20)))

        print(f"== chaos for {duration:.0f}s")
        t0 = time.monotonic()
        n = 0
        while time.monotonic() - t0 < duration:
            rec = sched.run_one()
            events.append(rec)
            n += 1
            elapsed = time.monotonic() - t0
            print(f"   [{elapsed:6.0f}s] {rec.get('event_kind'):<18} "
                  f"{rec.get('event_seconds', 0):>5.1f}s  #{n}")

            # An event that could not undo its own config change means the DUT
            # is no longer the router the profile describes, and nothing
            # measured after this point means anything. This is an unconditional
            # stop, not gated on --stop-on-violation, because it is a harness
            # fault rather than a DUT result.
            #
            # T2 is why: `maxprefix-squeeze` hit a 360 s CommitTimeout on its
            # apply, never reverted, and left `ixp1-peer4` clamped at
            # maximum-prefix 2,500 against 5,000 announced. All 80 ixp1-bilat
            # IPv4 sessions were torn down at t=391 and stayed down for the
            # remaining 72 minutes: 19 of 20 flap-recovery measurements came
            # back None, the drift figure read -400,000, and the FAIL verdict
            # was against a lab the harness had broken. See FINDINGS.md H-44.
            if rec.get("config_left_modified"):
                meta["aborted"] = True
                meta["aborted_at_s"] = round(elapsed, 1)
                meta["aborted_reason"] = (
                    f"{rec.get('event_kind')} could not revert its config "
                    f"change ({rec.get('fragment')}); the DUT no longer matches "
                    f"the profile, so the run stops here rather than measuring "
                    f"a lab the harness broke")
                sampler.event("run_aborted", **{
                    k: meta[k] for k in ("aborted_at_s", "aborted_reason")})
                print(f"   !! ABORT: {meta['aborted_reason']}")
                break

            # `_converge` raises FIB violations outside this loop (they need a
            # `show ip route summary`, which is not sampled); take them here so
            # they land in the same ordered list as everything else.
            while ctx.violations:
                violations.append(ctx.violations.pop(0))
            for viol in preds.check_new(sampler.latest or {}):
                violations.append(viol)
                print(f"   !! {viol}")
                if viol.severity == "fail" and "first_hard_failure" not in meta:
                    # Mark it even when the run continues, so the report can
                    # separate measurements taken before the DUT broke from
                    # those taken after — they are not the same experiment.
                    meta["first_hard_failure"] = {
                        "code": viol.code, "at_s": round(elapsed, 1),
                        "detail": viol.detail}
                    print(f"      ^ first hard failure at {elapsed:.0f}s; "
                          f"measurements after this point describe a degraded "
                          f"router")
                if args.stop_on_violation and viol.severity == "fail":
                    sampler.event("stopping_on_violation", code=viol.code)
                    raise KeyboardInterrupt
            sched.sleep_gap()

        settle_timeout = max(budgets.convergence_s * 3, 180)
        print(f"\n== post-chaos re-convergence (up to {settle_timeout:.0f}s; "
              f"progress every 20s)")
        ctx.log("post_chaos_settle_start")
        ok2, secs2, last2 = _converge(ctx, inv, budgets, settle_timeout)
        meta["post_chaos_converged"] = ok2
        meta["post_chaos_convergence_s"] = round(secs2, 2)
        meta["post_chaos_blocked_by"] = ctx.last_convergence_reason
        while ctx.violations:
            violations.append(ctx.violations.pop(0))
        print(f"   converged={ok2} in {secs2:.1f}s"
              + ("" if ok2 else f" — blocked by: "
                                f"{ctx.last_convergence_reason or 'unknown'}"))

        print("\n== prefix accounting (announced vs accepted)")
        acct = _accounting(ctx, inv)
        meta["accounting"] = acct
        try:
            meta["final_peer_snapshot"] = _snapshot_peers(ctx, "end of run")
        except Exception as exc:
            ctx.log("peer_snapshot_failed", error=repr(exc))
        base = meta.get("accounting_at_start") or {}
        for afi in ("ipv4", "ipv6"):
            a = acct[afi]
            b0 = (base.get(afi) or {}).get("drift")
            this_run = None if b0 is None else a["drift"] - b0
            a["drift_inherited"] = b0
            a["drift_this_run"] = this_run
            flag = "" if a["drift"] == 0 else "   <-- DRIFT"
            extra = ("" if this_run is None
                     else f" (inherited {b0:+,}, this run {this_run:+,})")
            print(f"   {afi}: announced={a['announced']:,} "
                  f"accepted={a['accepted']:,} drift={a['drift']:+,}"
                  f"{extra}{flag}")
        if any(acct[a]["drift"] for a in ("ipv4", "ipv6")):
            print("   The table does not hold what the profile announced. `walk`")
            print("   churn advertises fresh NLRI and withdraws older NLRI, so a")
            print("   positive drift means withdrawals are not landing; run")
            print("   `make peers` for the per-peer breakdown.")
            if all((acct[a].get("drift_this_run") or 0) == 0
                   for a in ("ipv4", "ipv6")):
                print("   All of it was already present before this run started —")
                print("   the lab was not reset. Redeploy for a clean baseline.")

        print("\n== final policy check")
        pc = scenarios.ev_probe_check(ctx, settle_s=args.probe_settle)
        meta["final_probe_failures"] = pc.get("failures")
        meta["final_probe_unexplained"] = pc.get("unexplained")
        meta["final_probe_template_defects"] = pc.get("template_defects")
        print(f"   {pc.get('total')} probe(s): "
              f"{pc.get('template_defects')} confirmed template defect(s), "
              f"{pc.get('unexplained')} unexplained")
        events.append(pc)

    except KeyboardInterrupt:
        print("\ninterrupted — collecting final state")
        meta["interrupted"] = True
    finally:
        for viol in preds.check(sampler.latest or {}):
            if viol not in violations:
                violations.append(viol)
        meta["finished"] = time.time()
        meta["violations"] = [asdict(v) for v in violations]
        meta["events"] = events
        sampler.event("run_end", violations=len(violations))
        sampler.stop()
        with open(os.path.join(results_dir, "run.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, default=str)

    fails = [v for v in violations if v.severity == "fail"]
    print(f"\n{'=' * 70}")
    print(f"events run     : {len(events)}")
    print(f"violations     : {len(fails)} fail, {len(violations) - len(fails)} warn")
    for v in violations:
        print(f"  {v}")
    print(f"results        : {results_dir}")
    print(f"next           : python -m analysis.analyze {results_dir}")
    return 0 if not fails else 3


def cmd_ramp(args) -> int:
    _require_docker()
    """Break-it mode.

    Scales in waves without redeploying the lab: sessions are started in batches
    and the per-session prefix count is raised by injecting progressively more of
    each MRT table (`gobgp mrt inject global <file> <count>`). After each step the
    table must re-converge inside budget and no predicate may trip. The first step
    that fails is the answer to "how far can this be pushed", and the reason it
    failed is the more useful half.
    """
    inv, invj = load_build(args.build)
    scen = invj.get("scenario", {})
    ramp = scen.get("ramp", {}) or {}
    budgets = Budgets.from_profile(invj.get("budgets"))
    results_dir = args.results or os.path.join(args.build, "results",
                                               "ramp-" + time.strftime("%Y%m%dT%H%M%S"))
    prefix = args.clab_prefix or f"clab-{inv.name}"
    # 4x the budget, not 2x. The timeout exists to stop the harness hanging
    # forever, not to enforce the budget — the budget is what the *measurement*
    # is compared against. At T2 the 2x timeout (360 s) fired on a commit that
    # legitimately took 343 s, the exception skipped the revert, and the run
    # spent its remaining 72 minutes measuring a lab the harness had clamped.
    # A latency that exceeds the budget is a finding; a timeout is a lost
    # measurement plus a broken lab. See FINDINGS.md H-42.
    dut = Dut(container=f"{prefix}-{inv.dut['name']}",
              commit_timeout=max(600.0, budgets.commit_s * 4))
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    if not dut.alive():
        print(f"error: {dut.container} is not running", file=sys.stderr)
        return 1

    step_peers = int(args.step_peers or ramp.get("step_peers", 10))
    step_prefixes = int(args.step_prefixes or ramp.get("step_prefixes", 25000))
    max_steps = int(args.max_steps or ramp.get("max_steps", 40))
    preds = PredicateSet(budgets)
    ctx.preds = preds          # so deliberate impairments suppress peer faults

    ordered = sorted(inv.sessions, key=lambda s: (s.role != "route-server", s.sid))
    steps: List[Dict] = []
    started: List[Session] = []

    sampler.start()
    sampler.event("ramp_start", step_peers=step_peers, step_prefixes=step_prefixes,
                  max_steps=max_steps, versions=dut.version())
    verdict = "completed-all-steps"
    try:
        for i in range(1, max_steps + 1):
            wave = ordered[len(started):len(started) + step_peers]
            cap = step_prefixes * i
            if not wave and i > 1:
                # no more peers to add; keep raising the prefix cap on the ones we have
                wave = []
            started.extend(wave)
            if not started:
                verdict = "no-sessions"
                break

            print(f"\n== step {i}: {len(started)} session(s), "
                  f"prefix cap {cap:,}/session")
            sampler.event("ramp_step_start", step=i, sessions=len(started),
                          prefix_cap=cap)
            st = _start_generators(ctx, wave, inject=False, only_best=True)
            # (re)inject with the higher cap on every started session
            for s in started:
                if s.engine == "gobgp":
                    ctx.fleet.inject_mrt(s, only_best=True, count=cap)

            e4 = len([s for s in started if s.v4])
            e6 = len([s for s in started if s.v6])
            tracker = ConvergenceTracker(expected_sessions_v4=e4,
                                         expected_sessions_v6=e6, stable_samples=3)
            ok, secs, last = telemetry.wait_for_convergence(
                sampler, tracker, budgets.convergence_s * 3)

            new_v = preds.check_new(sampler.latest or {})
            b4 = (last.get("bgp") or {}).get("ipv4") or {}
            b6 = (last.get("bgp") or {}).get("ipv6") or {}
            proc = last.get("proc") or {}
            row = {
                "step": i, "sessions": len(started), "prefix_cap": cap,
                "converged": ok, "convergence_s": round(secs, 2),
                "pfx_rcd_v4": b4.get("pfx_rcd_total"),
                "pfx_rcd_v6": b6.get("pfx_rcd_total"),
                "rib_count_v4": b4.get("rib_count"),
                "established_v4": b4.get("established"),
                "failed_v4": b4.get("failed"),
                "bgpd_rss_mb": (proc.get("bgpd") or {}).get("rss_mb"),
                "zebra_rss_mb": (proc.get("zebra") or {}).get("rss_mb"),
                "bgpd_cpu_pct": (proc.get("bgpd") or {}).get("cpu_pct"),
                "dplane": last.get("dplane"),
                "violations": [asdict(v) for v in new_v],
            }
            steps.append(row)
            sampler.event("ramp_step_done", **row)
            print(f"   converged={ok} in {secs:.1f}s  "
                  f"pfxRcd v4={row['pfx_rcd_v4']:,} " if row['pfx_rcd_v4'] else "")
            print(f"   bgpd rss={row['bgpd_rss_mb']} MB cpu={row['bgpd_cpu_pct']}% "
                  f"zebra rss={row['zebra_rss_mb']} MB")

            hard = [v for v in new_v if v.severity == "fail"]
            if hard:
                verdict = "predicate-failed"
                print("\n   !! LIMIT REACHED")
                for v in hard:
                    print(f"      {v}")
                break
            if not ok:
                verdict = "convergence-budget-exceeded"
                print(f"\n   !! LIMIT REACHED: did not converge within "
                      f"{budgets.convergence_s * 3:.0f}s")
                break
            for v in new_v:
                print(f"   (warn) {v}")
    except KeyboardInterrupt:
        verdict = "interrupted"
    finally:
        summary = {
            "lab": inv.name, "verdict": verdict, "steps": steps,
            "versions": dut.version(), "budgets": asdict(budgets),
            "last_good_step": steps[-2] if verdict != "completed-all-steps" and len(steps) > 1
                              else (steps[-1] if steps else None),
        }
        sampler.event("ramp_end", verdict=verdict, steps=len(steps))
        sampler.stop()
        with open(os.path.join(results_dir, "ramp.json"), "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"verdict: {verdict} after {len(steps)} step(s)")
    lg = summary.get("last_good_step")
    if lg:
        print(f"last step within budget: {lg['sessions']} sessions, "
              f"{lg.get('pfx_rcd_v4') or 0:,} v4 paths received, "
              f"converged in {lg.get('convergence_s')}s, "
              f"bgpd RSS {lg.get('bgpd_rss_mb')} MB")
    print(f"results: {results_dir}")
    return 0


#: Every event kind, cheapest first, with the log signature each one exists to
#: provoke. Ordering matters: `dut_bgpd_restart` is last because it restarts the
#: daemon, and `blackhole_peer` is late because it deliberately runs for
#: 2.5x holdtime.
#:
#: The `expect_logs` column is the whole point. Eight of these detectors had
#: never been observed matching a real event after two full chaos runs, because
#: five event kinds had never executed: T0 and T1 between them ran only churn,
#: peer_flap, policy_churn, probe_check and soft_clear. A pattern that has never
#: fired is a pattern that might not work — H-18 and H-20 were both exactly that.
EXERCISE_PLAN: List[Dict[str, Any]] = [
    {"kind": "probe_check", "args": {}, "expect_logs": []},
    {"kind": "soft_clear", "args": {"target": "all", "direction": "in"},
     "expect_logs": []},
    {"kind": "churn", "args": {"mode": "flap_same", "fraction": 0.2},
     "expect_logs": []},
    {"kind": "churn", "args": {"mode": "walk", "fraction": 0.2},
     "expect_logs": [],
     "note": "watch the accounting delta: the unexplained walk leak (H-16) "
             "followed walk on a route-server fleet"},
    {"kind": "churn", "args": {"mode": "attr_churn", "fraction": 0.3},
     "expect_logs": []},
    {"kind": "churn", "args": {"mode": "withdraw_storm", "fraction": 0.3},
     "expect_logs": []},
    {"kind": "netem", "args": {"delay_ms": 40, "jitter_ms": 10,
                               "loss_pct": 1.0, "duration_s": 30},
     "expect_logs": []},
    {"kind": "peer_flap", "args": {"mode": "admin_down", "down_s": [5, 6]},
     "expect_logs": ["notification_recv", "peer_down", "peer_up"],
     "note": "gobgp `neighbor disable` sends a clean Cease NOTIFICATION, so the "
             "DUT should log a received notification — NOT a TCP reset. The "
             "earlier `read_packet_error` expectation here was simply wrong"},
    {"kind": "peer_flap", "args": {"mode": "notification"},
     "expect_logs": ["notification_recv", "notification_any", "peer_down"],
     "note": "these three read 0 across two runs because all three patterns "
             "were wrong: FRR logs `%NOTIFICATION: received from neighbor ...`, "
             "not `received NOTIFICATION`, and the counters are gated on "
             "log-neighbor-changes (config) rather than only on a debug"},
    {"kind": "peer_flap", "args": {"mode": "process_kill"},
     "expect_logs": [],
     "note": "SIGINT: gobgpd does NOT notify, so the DUT should enter "
             "graceful-restart helper mode"},
    {"kind": "peer_flap", "args": {"mode": "process_term"},
     "expect_logs": ["notification_recv", "notification_any"],
     "note": "SIGTERM: gobgpd DOES notify, so GR should not engage"},
    {"kind": "policy_churn", "args": {}, "expect_logs": []},
    {"kind": "malformed_burst", "args": {"withdraw_after_s": 15},
     "expect_logs": ["attr_withdraw"],
     "note": "martian_nexthop is no longer expected: the two cases that "
             "provoke E-4 are excluded from the suite by default "
             "(policyprobe.EXCLUDED_TAGS). E-4 is a confirmed FRR <= 10.6.x "
             "defect fixed in 10.7.0 and unfixable on VyOS 1.5.1, so firing it "
             "every burst bought a known result at the cost of a real session "
             "reset inside the measurement window"},
    {"kind": "maxprefix_trip", "args": {},
     "expect_logs": ["maxprefix", "maxprefix_exceeded"],
     "note": "the old pattern matched only `Maximum-prefix restart timer`, "
             "which VyOS cannot configure; the real trip line is "
             "`%MAXPFXEXCEED` at info level. The event now also records the "
             "peers that actually left Established, independently of the log"},
    {"kind": "blackhole_peer", "args": {},
     "expect_logs": ["holdtime_expire", "peer_down"],
     "note": "the sendq expectations were dropped from this row on purpose: "
             "FRR's send-queue teardown needs a queue that cannot drain, and at "
             "an IXP the DUT advertises almost nothing (pfx_snt 0 in every T0 "
             "sample), so there is nothing to queue. The event now records "
             "`dut_pfx_snt_to_peer` and `sendq_path_reachable` so that is a "
             "recorded fact rather than an unexplained zero. What MUST happen is "
             "a hold-timer expiry at 1x holdtime — and it did not on "
             "2026-08-21, because the impairment was never applied (H-33)"},
    {"kind": "gr_event", "args": {"mode": "process_kill"}, "expect_logs": []},
    {"kind": "dut_bgpd_restart", "args": {},
     "expect_logs": ["peer_up", "zebra_conn_lost"],
     "note": "restarts bgpd; the PID-change detector is what catches a crash "
             "that logs nothing, and it has never been exercised either"},
]


def cmd_exercise(args) -> int:
    """Run every event kind once and report which log detectors actually fired.

    This is not a stress test. It is a test of the *harness* against the DUT:
    does each event do what it claims, does the lab recover afterwards, and do
    the log signatures each event exists to provoke actually match. Two full
    chaos runs left five event kinds and eight detectors completely unexercised,
    and every code path exercised for the first time in this project so far has
    turned up a defect.
    """
    _require_docker()
    inv, invj = load_build(args.build)
    budgets = Budgets.from_profile(invj.get("budgets"))
    results_dir = args.results or os.path.join(
        args.build, "results", time.strftime("%Y%m%dT%H%M%S") + "-exercise")
    prefix = args.clab_prefix or f"clab-{inv.name}"
    dut = Dut(container=f"{prefix}-{inv.dut['name']}",
              commit_timeout=budgets.commit_s * 4)
    if not dut.alive():
        print(f"error: {dut.container} is not running", file=sys.stderr)
        return 1
    sampler = new_sampler(dut, results_dir, sample_interval(args, invj))
    ctx = make_ctx(args, inv, invj, results_dir, sampler)
    preds = PredicateSet(budgets)
    ctx.preds = preds

    wanted = set(args.only.split(",")) if args.only else None
    plan = [p for p in EXERCISE_PLAN
            if wanted is None or p["kind"] in wanted]
    print(f"exercising {len(plan)} event(s) against {inv.name} "
          f"({inv.totals()['paths_total']:,} paths)")
    print("this validates the harness, not the DUT's capacity\n")

    sampler.start()
    rows: List[Dict[str, Any]] = []
    dbg: Dict[str, Any] = {"ok": None, "reason": "not reached"}
    pipe: Dict[str, Any] = {"ok": None, "reason": "not reached"}
    try:
        ok0, _, _ = _converge(ctx, inv, budgets, budgets.convergence_s * 2)
        if not ok0:
            print("warning: the lab was not converged before starting; results "
                  "for the first few events will be noisy")
        base = _accounting(ctx, inv)

        # Arming is now verified twice: once by asking bgpd what it thinks is on
        # (`show debugging bgp`), and once end-to-end by resetting a session and
        # looking for the transition line the debug exists to emit. The previous
        # version trusted vtysh's exit status, printed armed=True, and ran
        # seventeen events with every session-level detector structurally dead.
        dbg = dut.enable_bgp_debugs()
        active = dbg["active"]
        print(f"FRR debugs: {dbg['commands']} active={active} "
              f"via={dbg['via']} sent_ok={dbg['sent_ok']}")
        print(f"bgp log-neighbor-changes: {dbg['neighbor_changes']} "
              f"(config, not a debug: unlocks %ADJCHANGE and %NOTIFICATION "
              f"at info level)")
        if not dbg["ok"]:
            print("  WARNING: `debug bgp neighbor-events` is not active, so the "
                  "FSM transition lines\n  cannot be produced. Raw vtysh "
                  "output:")
            for k, v in dbg["raw"].items():
                print(f"    {k}: {v}")

        # Always probe, even when the debug did not take: log-neighbor-changes
        # alone is enough for six of the detectors, and the probe is what tells
        # a missing flag apart from a severity floor further down the chain.
        probe_peer = next((x.v4 for x in inv.sessions if x.v4), None)
        if probe_peer:
            pipe = dut.verify_log_pipeline(probe_peer)
            print(f"log pipeline: reset {pipe['peer']} -> "
                  f"tier={pipe['tier_reached']} "
                  f"fsm={pipe['fsm_debug_lines']} "
                  f"adjchange={pipe['adjchange_lines']} "
                  f"notification={pipe['notification_lines']}")
            if pipe["tier_reached"] == "warn_or_err_only":
                print("  WARNING: a real session reset produced no info- or "
                      "debug-level line at the reader.\n  Every session-level "
                      "zero below is a false negative, and the break is the "
                      "log\n  path (destination severity / syslog / journal), "
                      "not the detector patterns.")
            elif pipe["tier_reached"] == "info":
                print("  note: info-level lines arrive but debug-level do not. "
                      "%ADJCHANGE, %NOTIFICATION,\n  %MAXPFX and SendQ "
                      "detectors are live; the FSM 'went from' line is not.")
            for l in pipe["sample"][:3]:
                print(f"    sample: {l}")
            # The probe reset is a real outage; let it settle so it cannot be
            # blamed on the first event.
            _converge(ctx, inv, budgets, budgets.convergence_s * 2)

        for i, step in enumerate(plan, 1):
            kind, ev_args = step["kind"], dict(step["args"])
            fn = scenarios.EVENTS.get(kind)
            if fn is None:
                rows.append({"event": kind, "status": "no such event"})
                continue
            print(f"[{i:2}/{len(plan)}] {kind:<20} "
                  f"{'(' + step['args'].get('mode', '') + ')' if step['args'].get('mode') else '':<16}",
                  end="", flush=True)
            # Re-arm before every event. Terminal debugs live in bgpd's
            # memory, so `dut_bgpd_restart` clears them, and a VyOS commit runs
            # frr-reload which can drop the config-node form — everything after
            # step 12 was silently unarmed. Recorded per row so a missing
            # signature can be told apart from a dead detector.
            armed_now = dut.rearm_bgp_debugs()
            t0 = time.monotonic()
            status, err = "ok", None
            rec: Dict[str, Any] = {}
            try:
                rec = fn(ctx, **ev_args) or {}
                kind = str(rec.get("kind") or "")
                if kind == "skipped":
                    status = "skipped: " + str(rec.get("reason"))
                elif kind.endswith("_ineffective"):
                    # The event determined its own impairment was not in place.
                    # That is a harness fault, not a DUT result, and it must not
                    # read as `ok` — `blackhole_peer` reported ok for two runs
                    # while nothing was ever blackholed (H-33).
                    status = "INEFFECTIVE: " + str(rec.get("reason"))
            except Exception as exc:                      # noqa: BLE001
                status, err = "ERROR", f"{type(exc).__name__}: {exc}"
            secs = time.monotonic() - t0

            # Recovery first, then read the logs over the event's REAL elapsed
            # wall time.
            #
            # This window has now been wrong twice, in opposite directions.
            # First it was `event + 20s`, which reached back into the previous
            # step (H-29). Then it was `event + rec_s + 3`, which looked right
            # and was not: `wait_for_convergence` deliberately **back-dates** its
            # return value —
            #
            #     elapsed = now - t0 - (stable_samples - 1) * sampler.interval
            #
            # — because it wants "when did the table actually settle", not "how
            # long was I in this function". With stable_samples=3 and a 2s
            # interval that is 4 seconds of real time unaccounted for, plus the
            # poll loop's own sleep, and it can return 0.0 for a call that took
            # six seconds. So the window started several seconds after the event
            # did, and consistently clipped the beginning — where notifications,
            # session-down lines and attribute errors all are. Measured effect on
            # the 2026-08-21 18:15 run: `peer_flap/admin_down` logged
            # `%ADJCHANGE ... Down` at 18:17:30 and `... Up` at 18:17:42, and the
            # harness saw only the Up. Every notification detector regressed to
            # zero while the DUT had logged them correctly.
            #
            # A reported metric is not a duration. Measure the clock.
            rec_ok, rec_s, _ = _converge(ctx, inv, budgets,
                                         max(args.recover, budgets.convergence_s))
            elapsed = time.monotonic() - t0
            # Read the flag back AFTER the event too. Whether a VyOS commit
            # inside an event wipes the enable-node debug has been ambiguous for
            # two runs: the events that commit (policy_churn, maxprefix_trip)
            # produced no session transitions either way, so absence of log
            # lines proved nothing. before/after turns that into a fact.
            armed_after = dut.bgp_debugs_active()
            # The debug flag being on is only half of it: FRR checks the flag,
            # then the log destination's severity floor. A VyOS commit removes
            # `log syslog debugging` (it is config, so frr-reload drops it) and
            # every info and debug line disappears while `show debugging` still
            # says the debug is on. Record the floor next to the flag.
            log_level_after = dut.logging_state()
            window = max(3, int(math.ceil(elapsed)) + 3)
            logs = dut.log_counts(since=f"-{window}s")
            fired = sorted(k for k, v in logs.items()
                           if v and not k.startswith("_"))
            expect = step.get("expect_logs") or []
            missing = [k for k in expect if k not in fired]
            acct = _accounting(ctx, inv)
            drift = {a: acct[a]["accepted"] - base[a]["accepted"]
                     for a in ("ipv4", "ipv6")}

            # `preds` was constructed and handed to Ctx purely so events could
            # suppress their own impairments — nothing ever evaluated it, so the
            # PID-change daemon-restart check (the only detector for a crash that
            # logs nothing, and the whole point of the dut_bgpd_restart step)
            # never ran in this command. Evaluate it per event, after recovery,
            # so a deliberate outage is already over.
            viols = [{"code": v.code, "severity": v.severity,
                      "detail": v.detail} for v in preds.check_new(
                          sampler.latest or {})]

            # Field is `event`, not `kind`: `Ctx.log` writes its own `kind`
            # and a collision here is a TypeError at runtime.
            row = {"event": kind, "mode": ev_args.get("mode"),
                   "seconds": round(secs, 1), "status": status, "error": err,
                   "logs_fired": fired, "logs_expected": expect,
                   "logs_missing": missing, "log_window_s": window,
                   "elapsed_s": round(elapsed, 1),
                   "recovered": rec_ok, "recover_s": round(rec_s, 1),
                   "prefix_drift_vs_baseline": drift,
                   "debugs_active": armed_now,
                   "debugs_active_after": armed_after,
                   "bgpd_log_level_after": log_level_after.get("bgpd"),
                   "debug_reaches_log_after":
                       log_level_after.get("debug_reaches_log"),
                   "predicate_violations": viols,
                   # The event's own return value. Without this, the only
                   # evidence an event gathered about itself lived in
                   # samples.jsonl, which is tens of MB at T1+ — so
                   # `maxprefix_trip` and `blackhole_peer` could not be
                   # diagnosed from exercise.json at all. Log-independent
                   # fields are the whole point of those two events.
                   "event_record": {k: v for k, v in rec.items()
                                    if k not in ("kind",)},
                   "note": step.get("note")}
            rows.append(row)
            ctx.log("exercise_step", **row)
            flag = ("ERROR" if status == "ERROR"
                    else "INEFFECTIVE" if status.startswith("INEFFECTIVE")
                    else "no-recover" if not rec_ok
                    else "logs-missing" if missing else "ok")
            print(f" {secs:6.1f}s  recover={rec_s:5.1f}s  {flag}")
            if err:
                print(f"          {err}")
            time.sleep(args.gap)
    finally:
        sampler.stop()

    print(f"\n{'event':<22} {'mode':<14} {'status':<10} {'recovered':<10} "
          f"{'signatures fired'}")
    print("-" * 108)
    for r in rows:
        print(f"{r['event']:<22} {str(r.get('mode') or ''):<14} "
              f"{str(r.get('status'))[:10]:<10} "
              f"{str(r.get('recovered')):<10} "
              f"{','.join(r.get('logs_fired') or []) or '-'}")

    errs = [r for r in rows if r.get("status") == "ERROR"]
    ineff = [r for r in rows
             if str(r.get("status") or "").startswith("INEFFECTIVE")]
    norec = [r for r in rows if r.get("recovered") is False]
    miss = [r for r in rows if r.get("logs_missing")]
    drifted = [r for r in rows
               if any((r.get("prefix_drift_vs_baseline") or {}).values())]
    never = sorted(set(dut.LOG_PATTERNS)
                   - {k for r in rows for k in (r.get("logs_fired") or [])})

    print(f"\nevents run          : {len(rows)}")
    print(f"errored             : {len(errs)}"
          + (f" -> {', '.join(r['event'] for r in errs)}" if errs else ""))
    print(f"failed to recover   : {len(norec)}"
          + (f" -> {', '.join(r['event'] for r in norec)}" if norec else ""))
    if ineff:
        print(f"impairments that were never in place : {len(ineff)}")
        for r in ineff:
            print(f"  {r['event']}: {r['status']}")
        print("  These rows are harness faults, not DUT results.")
    print(f"expected signatures missing : {len(miss)}")
    for r in miss:
        print(f"  {r['event']}"
              f"{'/' + r['mode'] if r.get('mode') else ''}: "
              f"expected {r['logs_missing']}, fired {r['logs_fired'] or 'none'}")
        if r.get("note"):
            print(f"      note: {r['note']}")
    if drifted:
        print(f"prefix drift        : {len(drifted)} event(s) left the table "
              f"different from the baseline")
        for r in drifted:
            print(f"  {r['event']}/{r.get('mode')}: "
                  f"{r['prefix_drift_vs_baseline']}")
    vio = [r for r in rows if r.get("predicate_violations")]
    if vio:
        print(f"predicate violations: {len(vio)} event(s)")
        for r in vio:
            for v in r["predicate_violations"]:
                print(f"  {r['event']}/{r.get('mode')}: "
                      f"[{v['severity']}] {v['code']}: {v['detail']}")
    else:
        print("predicate violations: none "
              "(includes the PID-change daemon-restart check)")

    unarmed = [r for r in rows
               if not all((r.get("debugs_active") or {"x": False}).values())]
    floor = [r for r in rows if r.get("debug_reaches_log_after") is False]
    if floor:
        print(f"events that ended with the log floor above debugging: "
              f"{len(floor)} -> {', '.join(r['event'] for r in floor)}")
        print("  the debug flag can be on and still produce nothing: FRR checks "
              "the flag, then the\n  destination severity. Session-level zeroes "
              "on those rows are false negatives.")
    lost = [r for r in rows
            if all((r.get("debugs_active") or {"x": False}).values())
            and not all((r.get("debugs_active_after") or {"x": False}).values())]
    if lost:
        print(f"events that LOST the debug while running: {len(lost)} -> "
              f"{', '.join(r['event'] for r in lost)}")
        print("  the enable-node flag is supposed to be invisible to "
              "frr-reload; if a committing event clears it, that assumption is "
              "wrong and those rows' session-level zeroes are false negatives.")
    if unarmed:
        print(f"events run with debugs NOT armed: {len(unarmed)} -> "
              f"{', '.join(r['event'] for r in unarmed)}")
        print("  session-level zeroes for those rows are false negatives, "
              "not results.")

    print(f"\ndetectors still never observed firing ({len(never)}):")
    print(f"  {', '.join(never) or 'none — every pattern has matched at least once'}")
    print("\nA detector that has never fired is unproven, not absent. Trigger it "
          "deliberately\nbefore relying on it at T3/T4, where it is the only "
          "thing standing between\na real limit and a silent pass.")

    out = os.path.join(results_dir, "exercise.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"lab": inv.name, "versions": dut.version(),
                   "debugs": dbg, "log_pipeline": pipe, "rows": rows,
                   "detectors_never_fired": never}, fh, indent=2)
    print(f"\nwritten: {out}")
    return 0 if not (errs or norec or ineff) else 2


def cmd_teardown(args) -> int:
    _require_docker()
    inv, invj = load_build(args.build)
    prefix = args.clab_prefix or f"clab-{inv.name}"
    fleet = PeerFleet(clab_prefix=prefix,
                      expected_addrs=expected_container_addrs(inv))
    for cname, c in inv.containers.items():
        fleet.netem(cname, clear=True)
        for s in c.sessions:
            if s.engine == "gobgp":
                fleet.blackhole(s, on=False)
        n = fleet.kill_generators(cname)
        print(f"  stopped {cname} ({n} process(es))")
    print("generators stopped and impairments cleared "
          "(the lab itself is still deployed; use `make destroy`).")
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="harness.runner",
                                 description="VyOS IXP BGP stress harness")
    ap.add_argument("--build", required=True, help="build/<profile> directory")
    ap.add_argument("--clab-prefix", default=None,
                    help="containerlab container prefix (default clab-<lab>)")
    ap.add_argument("--results", default=None, help="results directory")
    ap.add_argument("--interval", type=float, default=None,
                    help="telemetry sample interval, seconds")
    ap.add_argument("--dry-run", action="store_true",
                    help="log what would happen without touching the lab")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(fn=cmd_status)

    p = sub.add_parser("config")
    p.add_argument("--only", help="substring filter, e.g. 'neighbors'")
    p.add_argument("--save", action="store_true", help="also `save` after commit")
    p.add_argument("--keep-going", action="store_true")
    p.add_argument("--commit-timeout", type=float, default=300.0)
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("bringup")
    p.add_argument("--no-inject", action="store_true",
                   help="start processes but do not load MRT tables")
    p.add_argument("--all-paths", action="store_true",
                   help="omit gobgp's --only-best (much higher memory)")
    p.set_defaults(fn=cmd_bringup)

    p = sub.add_parser("converge")
    p.add_argument("--timeout", type=float, default=None)
    p.set_defaults(fn=cmd_converge)

    p = sub.add_parser("peers")
    p.add_argument("--since", default="-10m",
                   help="journalctl window for the DUT log counters")
    p.set_defaults(fn=cmd_peers)

    p = sub.add_parser("probe")
    p.add_argument("--settle", type=float, default=15.0)
    p.add_argument("--keep-probes", action="store_true",
                   help="leave the policy probes announced during the malformed "
                        "phase (contaminates the log evidence; for debugging only)")
    p.add_argument("--no-isolate", action="store_true",
                   help="skip the per-case isolation pass even if the burst "
                        "reset the session")
    p.add_argument("--isolate-settle", type=float, default=3.0,
                   help="seconds to hold each isolated malformed case")
    p.add_argument("--no-restart", action="store_true",
                   help="do not restart ExaBGP before the isolation pass "
                        "(leaves stale announcements in its Adj-RIB-Out)")
    p.add_argument("--isolate-only", default=None,
                   help="comma-separated malformed case ids to isolate")
    p.set_defaults(fn=cmd_probe)

    p = sub.add_parser("run")
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--warmup", type=float, default=None)
    p.add_argument("--stop-on-violation", action="store_true")
    p.add_argument("--probe-settle", type=float, default=15.0,
                   help="seconds to wait after announcing the final policy probes")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("ramp")
    p.add_argument("--step-peers", type=int, default=None)
    p.add_argument("--step-prefixes", type=int, default=None)
    p.add_argument("--max-steps", type=int, default=None)
    p.set_defaults(fn=cmd_ramp)

    p = sub.add_parser("exercise")
    p.add_argument("--only", default=None,
                   help="comma-separated event kinds to exercise")
    p.add_argument("--gap", type=float, default=5.0,
                   help="seconds between events")
    p.add_argument("--recover", type=float, default=120.0,
                   help="seconds to allow for re-convergence after each event")
    p.set_defaults(fn=cmd_exercise)

    sub.add_parser("teardown").set_defaults(fn=cmd_teardown)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
