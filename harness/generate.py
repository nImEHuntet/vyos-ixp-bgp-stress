"""Generate every artefact a run needs, from a single profile.

    python -m harness.generate profiles/t2-ixp-realistic.yaml \
        --template "Template IXP VyOS Configuration.md" --out build

Produces `build/<profile>/`:

    topology.clab.yml        containerlab topology (bridge-backed shared peering LANs)
    prepare.sh               host-side addressing for the peer containers
    inventory.json           the expanded session list, for analysis
    dut/00-base.conf         the NE-1849 template, placeholders filled
    dut/10-neighbors.conf    generated neighbor stanzas
    dut/20-instrument.conf   optional measurement knobs
    dut/churn/*.conf         policy-churn apply/revert fragments
    dut/VERIFY-ON-IMAGE.md   commands whose availability is release-dependent
    gobgp/<container>/*.toml one gobgpd config per session
    mrt/<sid>.mrt            the table each gobgpd injects
    exabgp/<container>.conf  ExaBGP peers
    exabgp/run/nasty.py      the ExaBGP process helper (malformed-attribute suite)

Design notes
------------
*Shared peering LANs.* An IXP peering LAN is a broadcast domain, not a
point-to-point link. containerlab models that with a `bridge` node backed by a
pre-existing host Linux bridge, so every peer and the DUT land on one L2 segment
(`scripts/make-fabrics.sh` creates the bridges).

*Peer density.* GoBGP's documented weakness in every third-party benchmark is
many simultaneous *sessions*, not many paths. So sessions are packed
`per_container` into containers, each running one `gobgpd` per session bound to
its own address via `local-address-list`. That keeps each gobgpd's session count
at 1-2 while still reaching high peer counts, and it means a "peer flap" can be
a real process-level event rather than only an API call.

*Host-side addressing.* Peer addresses are applied with `nsenter` from the host
rather than `docker exec ip addr add`, because containerlab does not document
granting NET_ADMIN to `linux`-kind nodes and relying on it would be a guess.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import stat
import sys
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

import yaml

from . import dutconfig, model, routegen
from .model import Container, Inventory, Session

HOST_IFNAME_MAX = 15  # Linux IFNAMSIZ-1


# ---------------------------------------------------------------------------
# containerlab topology
# ---------------------------------------------------------------------------


def expand_octets(spec) -> List[int]:
    """Accept either a YAML list of ints or a compact range string.

        [1, 2, 3]        -> [1, 2, 3]
        "1-9,11-99"      -> [1..9, 11..99]

    Keeps profiles readable when the NLRI pool needs ~100 /8s to hold a
    million-prefix table.
    """
    if isinstance(spec, (list, tuple)):
        out = [int(x) for x in spec]
    elif isinstance(spec, str):
        out = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = part.split("-", 1)
                out.extend(range(int(lo), int(hi) + 1))
            else:
                out.append(int(part))
    else:
        raise ValueError("nlri.v4_first_octets must be a list or a range string")

    bad = [o for o in out if not (1 <= o <= 223)]
    if bad:
        raise ValueError(f"nlri.v4_first_octets contains non-unicast /8s: {bad[:8]}")
    # These /8s are matched by the template's ipv4-bogons list; NLRI drawn from
    # them would be dropped on import and the test would silently measure the
    # filter instead of the RIB.
    bogon8 = {0, 10, 127}
    clash = sorted(set(out) & bogon8)
    if clash:
        raise ValueError(
            f"nlri.v4_first_octets includes /8s the template's ipv4-bogons list "
            f"rejects: {clash}. Remove them or the DUT will drop this NLRI."
        )
    if len(set(out)) != len(out):
        raise ValueError("nlri.v4_first_octets contains duplicates")
    return out


def _host_ep(idx: int) -> str:
    """Short, unique host-side veth name for a bridge endpoint.

    Must stay under Linux's 15-char interface name limit, which container and
    fleet names blow through immediately.
    """
    name = f"clabp{idx:04d}"
    if len(name) > HOST_IFNAME_MAX:
        raise ValueError(f"endpoint name {name} exceeds {HOST_IFNAME_MAX} chars")
    return name


def build_topology(inv: Inventory, build_dir: str) -> Dict:
    prof = inv.profile
    dut = inv.dut
    nodes: Dict[str, Dict] = {}
    links: List[Dict] = []

    # bridge nodes, one per fabric
    for fid, fab in inv.fabrics.items():
        nodes[fab.bridge] = {"kind": "bridge"}

    # Every image in this lab is built locally and published nowhere, so there is
    # never anything to pull. containerlab defaults to `IfNotPresent`, which makes
    # a missing local image turn into a Docker Hub request and then an
    # authentication error that reads nothing like the real problem. `Never` makes
    # it fail as "image not available locally" instead.
    pull = prof.get("clab", {}).get("image_pull_policy", "Never")
    if pull not in ("Never", "IfNotPresent", "Always"):
        raise ValueError(
            f"clab.image_pull_policy must be Never, IfNotPresent or Always "
            f"(got {pull!r})")

    # DUT
    dut_node: Dict = {
        "kind": "vyosnetworks_vyos",
        "image": dut["image"],
        "image-pull-policy": pull,
    }
    if dut.get("memory"):
        dut_node["memory"] = dut["memory"]
    if dut.get("cpu"):
        dut_node["cpu"] = dut["cpu"]
    if dut.get("mgmt_ipv4"):
        dut_node["mgmt-ipv4"] = dut["mgmt_ipv4"]
    nodes[dut["name"]] = dut_node

    ep = 0
    # DUT -> each fabric bridge. containerlab enforces eth[1-9][0-9]* for this
    # kind and reserves eth0 for management.
    for fid, fab in inv.fabrics.items():
        links.append({
            "endpoints": [f"{dut['name']}:{fab.dut_iface}", f"{fab.bridge}:{_host_ep(ep)}"]
        })
        ep += 1

    # peer containers
    for cname, c in inv.containers.items():
        fab = inv.fabrics[c.fabric]
        node: Dict = {
            "kind": "linux",
            "image": c.image,
            "image-pull-policy": pull,
            "binds": [],
        }
        if c.engine == "gobgp":
            node["binds"] = [
                f"gobgp/{cname}:/etc/gobgp:ro",
                "mrt:/mrt:ro",
            ]
        else:
            node["binds"] = [
                f"exabgp/{cname}.conf:/etc/exabgp/exabgp.conf:ro",
                "exabgp/run:/etc/exabgp/run:ro",
                # This container's OWN boot file, at a fixed path the helper can
                # hard-code. It used to be copied to a fixed name inside the
                # container at start-up, which silently did nothing: the run
                # directory above is mounted :ro, so the copy failed, the helper
                # found no boot file, and the fleet came up Established with
                # zero prefixes announced. Binding it directly removes the copy,
                # and also means each container sees only its own boot file
                # rather than every fleet's.
                f"exabgp/run/boot-{cname}.txt:{EXABGP_BOOT_PATH}:ro",
            ]
        if c.memory:
            node["memory"] = c.memory
        if c.cpu:
            node["cpu"] = c.cpu
        nodes[cname] = node
        links.append({"endpoints": [f"{cname}:{c.iface}", f"{fab.bridge}:{_host_ep(ep)}"]})
        ep += 1

    topo = {
        "name": inv.name,
        "topology": {"nodes": nodes, "links": links},
    }
    mgmt = prof.get("clab_mgmt")
    if mgmt:
        topo["mgmt"] = mgmt
    return topo


# ---------------------------------------------------------------------------
# GoBGP configs
# ---------------------------------------------------------------------------


def gobgp_toml(inv: Inventory, s: Session) -> str:
    """One gobgpd config: the simulated peer, with its session(s) to the DUT.

    Written by hand rather than via a TOML library so the emitted keys stay
    exactly the documented spellings (`[neighbors.transport.config]`,
    `[[neighbors.afi-safis]]`, etc.) and are reviewable against
    gobgp/docs/sources/configuration.md.
    """
    fab = inv.fabrics[s.fabric]
    router_id = s.v4 or str(ipaddress.IPv4Address(0x0A000000 + s.nlri_slot))
    locals_ = [a for a in (s.v4, s.v6) if a]

    L: List[str] = [
        f"# {s.sid}  fleet={s.fleet} role={s.role} fabric={s.fabric}",
        "# GoBGP simulating one IXP peer. Listens only on its own addresses via",
        "# local-address-list, so many gobgpd processes coexist on port 179 in one",
        "# container without colliding.",
        "",
        "[global.config]",
        f"  as = {s.asn}",
        f'  router-id = "{router_id}"',
        "  local-address-list = [" + ", ".join(f'"{a}"' for a in locals_) + "]",
        "",
    ]

    is_rs = s.role == "route-server"
    ka = s.timers.get("keepalive")
    hold = s.timers.get("holdtime")

    for af, peer_addr, local_addr in (
        ("ipv4-unicast", fab.dut_v4, s.v4),
        ("ipv6-unicast", fab.dut_v6, s.v6),
    ):
        if not local_addr:
            continue
        L += [
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{peer_addr}"',
            f"    peer-as = {inv.dut_asn}",
            "  [neighbors.transport.config]",
            f'    local-address = "{local_addr}"',
        ]
        if s.passive:
            L.append("    passive-mode = true")
        if ka or hold:
            L.append("  [neighbors.timers.config]")
            if hold:
                L.append(f"    hold-time = {hold}")
            if ka:
                L.append(f"    keepalive-interval = {ka}")
        if is_rs:
            # NO route-server-client here, deliberately. It looks like the right
            # switch for an RFC 7947 route server and it silently breaks the whole
            # fleet. Verified against gobgp v4.8.0 source:
            #
            #   pkg/server/server.go:3526  a route-server-client peer is bound to
            #                              s.rsRib, not s.globalRib
            #   pkg/server/server.go:1464  propagateUpdateToNeighbors does
            #                                if source == nil &&
            #                                   targetPeer.isRouteServerClient()
            #                                        continue
            #   pkg/server/server.go:2432  addPathList (the AddPath/AddPathStream
            #                              gRPC path used by `gobgp mrt inject
            #                              global`) calls propagateUpdate(nil, ...)
            #
            # So every MRT-injected path has source == nil and is skipped for
            # route-server clients. s.rsRib is only ever written from paths
            # RECEIVED on another RS client's session (server.go:1338), and
            # AddPathStream rejects any TableType other than GLOBAL and VRF
            # (grpc_server.go:703). There is no `gobgp mrt inject` target for an
            # RS table. Net effect: the session comes up Established, pfxRcd
            # reads 0, and nothing in `show bgp summary` says why.
            #
            # The cost of leaving it off is that gobgpd prepends its own ASN on
            # egress to an eBGP peer (internal/pkg/table/path.go:273,
            # PrependAsn) instead of staying transparent. That is handled on the
            # MRT side instead: see GOBGP_PREPENDS_OWN_ASN in write_gobgp.
            L.append("# route-server-client deliberately NOT set - see comment in "
                     "harness/generate.py:gobgp_toml")
        L += [
            "  [[neighbors.afi-safis]]",
            "    [neighbors.afi-safis.config]",
            f'      afi-safi-name = "{af}"',
            "",
        ]

    if s.role == "transit":
        # Transit sends a default route too; the DUT's import policy should treat
        # it per the template (default4/default6 prefix-lists exist but the
        # shipped import route-maps do not reference them - worth watching).
        L.append("# role=transit: default route is injected via MRT alongside the table")
    return "\n".join(L) + "\n"


#: gobgpd prepends its own ASN when it advertises to an eBGP peer. The prepend
#: happens in `table.UpdatePathAttrs` (internal/pkg/table/path.go:273,
#: `path.PrependAsn(info.LocalAS, 1, confed)`) on the egress filter path, and it
#: is applied to API/MRT-injected paths just like any other. It is skipped ONLY
#: for route-server clients (path.go:236, `if info.RouteServerClient { return
#: original }`) - and we cannot use route-server-client at all, because that
#: variant never receives MRT-injected paths (see gobgp_toml).
#:
#: So the AS_PATH written into the MRT must NOT already contain the speaker's own
#: ASN, or the DUT sees it twice: MRT [64001, 3356, 12345] plus the egress
#: prepend becomes [64001, 64001, 3356, 12345]. Writing it transparent gives the
#: DUT exactly [64001, 3356, 12345], which is also what makes FRR's
#: enforce-first-as check pass (default ON from FRR 10.0).
GOBGP_PREPENDS_OWN_ASN = True


def gobgp_mrt_transparent(s) -> bool:
    """Should this gobgp session's MRT omit the speaker's own ASN?

    Yes, always, unless the profile explicitly overrides it - because gobgpd adds
    the ASN back on egress. An explicit `transparent_as_path: false` in the
    profile is honoured so the doubled-ASN case can itself be tested.
    """
    if s.transparent_as_path is not None:
        return bool(s.transparent_as_path)
    return GOBGP_PREPENDS_OWN_ASN


def write_gobgp(inv: Inventory, build_dir: str, plan: routegen.PrefixPlan) -> Dict[str, Dict]:
    stats: Dict[str, Dict] = {}
    gdir = os.path.join(build_dir, "gobgp")
    mdir = os.path.join(build_dir, "mrt")
    os.makedirs(mdir, exist_ok=True)

    for cname, c in inv.containers.items():
        if c.engine != "gobgp":
            continue
        cdir = os.path.join(gdir, cname)
        os.makedirs(cdir, exist_ok=True)
        manifest = []
        for s in c.sessions:
            with open(os.path.join(cdir, f"{s.sid}.toml"), "w", encoding="utf-8") as fh:
                fh.write(gobgp_toml(inv, s))
            manifest.append({"sid": s.sid, "api_port": s.api_port,
                             "config": f"/etc/gobgp/{s.sid}.toml",
                             "mrt": f"/mrt/{s.sid}.mrt" if not s.mrt else s.mrt})
            # MRT table for this session
            if s.mrt:
                stats[s.sid] = {"mrt": s.mrt, "external": True}
                continue
            path = os.path.join(mdir, f"{s.sid}.mrt")
            st = routegen.build_session_mrt(
                path, s, plan, inv.dut_asn,
                med_base=100 if s.role in ("transit", "route-server") else 0,
                transparent=gobgp_mrt_transparent(s),
            )
            stats[s.sid] = st
        with open(os.path.join(cdir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
    return stats


# ---------------------------------------------------------------------------
# ExaBGP configs
# ---------------------------------------------------------------------------

#: Where each ExaBGP container finds its own boot announcements. Bound per
#: container by build_topology; read by EXABGP_HELPER. Must stay in sync.
EXABGP_BOOT_PATH = "/etc/exabgp/boot.txt"

EXABGP_HELPER = r'''#!/usr/bin/env python3
"""ExaBGP process helper: bulk announcer plus the malformed-attribute suite.

Two hard rules from ExaBGP's own shipped examples, both load-bearing:

  1. flush() after every write, or commands sit in the buffer.
  2. **Drain the ACK stream.** ExaBGP writes `done` / `error` / `shutdown` back
     on our stdin for every command. If we do not read them the pipe fills and
     the BGP session stalls - which would look exactly like a DUT fault.

Commands are read from a FIFO so the harness can drive this at runtime:
    echo 'announce route 1.0.0.0/24 next-hop 198.51.100.31' > /run/exabgp-cmd
"""
import os
import sys
import select
import threading

CMD_FIFO = os.environ.get("EXABGP_CMD_FIFO", "/run/exabgp-cmd")
LOG = open(os.environ.get("EXABGP_HELPER_LOG", "/run/exabgp-helper.log"), "a", buffering=1)


def log(msg):
    LOG.write(msg + "\n")


def drain_acks(stop):
    """Consume ExaBGP's replies forever. Never let this stop."""
    while not stop.is_set():
        r, _, _ = select.select([sys.stdin], [], [], 0.5)
        if not r:
            continue
        line = sys.stdin.readline()
        if not line:
            return
        line = line.strip()
        if line and not line.startswith("done"):
            log("ack: " + line)


def send(cmd):
    sys.stdout.write(cmd + "\n")
    sys.stdout.flush()


def main():
    stop = threading.Event()
    t = threading.Thread(target=drain_acks, args=(stop,), daemon=True)
    t.start()

    if not os.path.exists(CMD_FIFO):
        os.mkfifo(CMD_FIFO)
    log("helper up, reading %s" % CMD_FIFO)

    # Initial announcement set, written at generation time and bound in per
    # container. Announce nothing silently is the failure mode this logging
    # exists to prevent: a missing boot file used to leave the fleet Established
    # with an empty table and no error anywhere.
    boot = os.environ.get("EXABGP_BOOT", "/etc/exabgp/boot.txt")
    if not os.path.exists(boot):
        log("BOOT-MISSING: %s does not exist; announcing nothing. Check the "
            "container's binds." % boot)
    else:
        with open(boot) as fh:
            n = 0
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    send(line)
                    n += 1
        log("sent %d boot commands from %s" % (n, boot))
        if n == 0:
            log("BOOT-EMPTY: %s contained no commands" % boot)

    # Then serve the FIFO forever. Reopening on EOF lets the harness write
    # repeatedly rather than once.
    while True:
        with open(CMD_FIFO) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                send(line)
                log("sent: " + line[:120])


if __name__ == "__main__":
    main()
'''


def exabgp_conf(inv: Inventory, c: Container) -> str:
    """One ExaBGP process, N neighbor blocks, all driven by one helper."""
    fab = inv.fabrics[c.fabric]
    L: List[str] = [
        f"# {c.name}: ExaBGP peers on fabric {c.fabric}",
        "# ExaBGP handles the protocol-nastiness half of the workload: RFC 7606",
        "# error handling, unknown attributes, wrong attribute flags, over-long",
        "# AS_PATHs. GoBGP has no equivalent of `attribute [ 0x99 0x60 0x... ]`.",
        "",
        "process announcer {",
        "\trun /etc/exabgp/run/nasty.py;",
        "\tencoder json;",
        "}",
        "",
    ]
    for s in c.sessions:
        for local_addr, peer_addr in ((s.v4, fab.dut_v4), (s.v6, fab.dut_v6)):
            if not local_addr:
                continue
            L += [
                f"neighbor {peer_addr} {{",
                f"\tdescription \"{s.sid}\";",
                f"\trouter-id {s.v4 or '10.255.255.1'};",
                f"\tlocal-address {local_addr};",
                f"\tlocal-as {s.asn};",
                f"\tpeer-as {inv.dut_asn};",
            ]
            if s.timers.get("holdtime"):
                L.append(f"\thold-time {s.timers['holdtime']};")
            L += [
                "\tgroup-updates false;",
                # ExaBGP defaults adj-rib-out to true. At high prefix counts that
                # is pure overhead on the generator side; disable it unless the
                # profile asks to keep it (`show adj-rib out` needs it).
                "\tadj-rib-out {};".format(
                    "true" if s.prefixes_v4 + s.prefixes_v6 <= 2000 else "false"
                ),
                "",
                "\tfamily {",
                "\t\tipv4 unicast;" if ":" not in local_addr else "\t\tipv6 unicast;",
                "\t}",
                "",
                "\tcapability {",
                "\t\tgraceful-restart;",
                "\t\tasn4 enable;",
                # ExaBGP defaults route-refresh to *disable*. The DUT sets
                # `soft-reconfiguration inbound` on every peer-group, but policy
                # churn on the DUT can still trigger an outbound route-refresh;
                # enable it so the session behaves like a real peer.
                "\t\troute-refresh enable;",
                "\t}",
                "",
                "\tapi {",
                "\t\tprocesses [ announcer ];",
                "\t}",
                "}",
                "",
            ]
    return "\n".join(L) + "\n"


def exabgp_boot(inv: Inventory, c: Container, plan: routegen.PrefixPlan) -> str:
    """Initial announcements for an ExaBGP container, as batched attribute sets."""
    fab = inv.fabrics[c.fabric]
    lines: List[str] = ["# generated boot announcements"]
    for s in c.sessions:
        if s.v4 and s.prefixes_v4:
            pfx = plan.session_v4(s.nlri_slot, s.prefixes_v4)
            lines += list(routegen.exabgp_announce_batches(
                pfx, next_hop=s.v4, as_path=[s.asn, 3356, 15169], med=50,
                large_communities=[f"{s.asn}:0:100"],
                neighbor=str(fab.dut_v4), local_ip=s.v4, batch=200,
            ))
        if s.v6 and s.prefixes_v6:
            pfx = plan.session_v6(s.nlri_slot, s.prefixes_v6)
            lines += list(routegen.exabgp_announce_batches(
                pfx, next_hop=s.v6, as_path=[s.asn, 6939, 20000], med=50,
                large_communities=[f"{s.asn}:0:100"],
                neighbor=str(fab.dut_v6), local_ip=s.v6, batch=200,
            ))
    return "\n".join(lines) + "\n"


def write_exabgp(inv: Inventory, build_dir: str, plan: routegen.PrefixPlan) -> None:
    edir = os.path.join(build_dir, "exabgp")
    rdir = os.path.join(edir, "run")
    os.makedirs(rdir, exist_ok=True)
    any_exa = False
    for cname, c in inv.containers.items():
        if c.engine != "exabgp":
            continue
        any_exa = True
        with open(os.path.join(edir, f"{cname}.conf"), "w", encoding="utf-8") as fh:
            fh.write(exabgp_conf(inv, c))
        with open(os.path.join(rdir, f"boot-{cname}.txt"), "w", encoding="utf-8") as fh:
            fh.write(exabgp_boot(inv, c, plan))
    if any_exa:
        hp = os.path.join(rdir, "nasty.py")
        with open(hp, "w", encoding="utf-8") as fh:
            fh.write(EXABGP_HELPER)
        os.chmod(hp, os.stat(hp).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


# ---------------------------------------------------------------------------
# prepare.sh: host-side peer addressing
# ---------------------------------------------------------------------------

PREPARE_HEADER = r'''#!/usr/bin/env bash
# Generated by harness.generate - do not edit.
#
# Applies peering-LAN addressing inside each peer container from the HOST
# network namespace via nsenter. Done this way on purpose: containerlab does not
# document granting NET_ADMIN to `linux`-kind nodes, so `docker exec ip addr add`
# would be relying on undocumented behaviour. nsenter from a root shell on the
# host always works.
#
# Run after `containerlab deploy`, before starting the generators.
set -euo pipefail

CLAB_PREFIX="${CLAB_PREFIX:-clab-%(lab)s}"

need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
need nsenter
need docker

pid_of() {
  docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null || { echo "0"; }
}

nsx() {  # nsx <container> <cmd...>
  local c="$1"; shift
  local p; p="$(pid_of "$c")"
  if [ "$p" = "0" ] || [ -z "$p" ]; then
    echo "!! container $c not running - skipping" >&2
    return 0
  fi
  nsenter -t "$p" -n "$@"
}

echo "== addressing peer containers =="
'''


def write_prepare(inv: Inventory, build_dir: str) -> None:
    lines = [PREPARE_HEADER % {"lab": inv.name}]
    for cname, c in inv.containers.items():
        fab = inv.fabrics[c.fabric]
        full = f"${{CLAB_PREFIX}}-{cname}"
        base_if = c.iface
        lines.append(f'\necho "-- {cname} ({len(c.sessions)} sessions, fabric {c.fabric})"')
        lines.append(f'nsx "{full}" ip link set {base_if} up')
        if fab.vlan is not None:
            vif = f"{base_if}.{fab.vlan}"
            lines.append(
                f'nsx "{full}" ip link show {vif} >/dev/null 2>&1 || '
                f'nsx "{full}" ip link add link {base_if} name {vif} '
                f'type vlan id {fab.vlan}'
            )
            lines.append(f'nsx "{full}" ip link set {vif} up')
            lines.append(
                f'nsx "{full}" sysctl -qw '
                f'net.ipv6.conf.{vif.replace(".", "/")}.keep_addr_on_down=1 || true')
            target_if = vif
        else:
            target_if = base_if
        # IPv6 needs to be usable inside the peer netns
        lines.append(f'nsx "{full}" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 || true')
        # Linux flushes every *global* IPv6 address on an interface when the
        # link goes down, and does not restore them on link-up. IPv4 addresses
        # survive; IPv6 ones are simply gone from the kernel.
        #
        # The `peer_flap mode=link_down` event does `ip link set eth1 down`,
        # and eth1 carries every session in the container — so one link flap
        # permanently killed the IPv6 side of five sessions at once. T3 runs 1
        # and 2 both ended with exactly 75 IPv6 sessions in Active, from
        # exactly the 9 containers that had been link-flapped, and run 1 came
        # within one step of being reported to the FRR team as "VyOS loses 49%
        # of its IPv6 sessions under churn and never recovers". See
        # FINDINGS.md H-59.
        #
        # keep_addr_on_down=1 is also the behaviour being modelled: a real IXP
        # peer does not lose its configured address because a port bounced.
        # Set it per-interface as well as `all`, because `all` is only consulted
        # for interfaces created afterwards.
        lines.append(
            f'nsx "{full}" sysctl -qw net.ipv6.conf.all.keep_addr_on_down=1 || true')
        lines.append(
            f'nsx "{full}" sysctl -qw net.ipv6.conf.{base_if}.keep_addr_on_down=1 '
            f'|| true')
        for s in c.sessions:
            if s.v4:
                lines.append(
                    f'nsx "{full}" ip addr replace {s.v4}/{fab.v4_net.prefixlen} '
                    f'dev {target_if}'
                )
            if s.v6:
                lines.append(
                    f'nsx "{full}" ip -6 addr replace {s.v6}/{fab.v6_net.prefixlen} '
                    f'dev {target_if}'
                )
    lines.append('\necho "== done =="')
    path = os.path.join(build_dir, "prepare.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)


# ---------------------------------------------------------------------------
# fabric bridge script
# ---------------------------------------------------------------------------


def write_fabrics(inv: Inventory, build_dir: str) -> None:
    brs = sorted({f.bridge for f in inv.fabrics.values()})
    L = [
        "#!/usr/bin/env bash",
        "# Generated. Creates the host Linux bridges that back the shared peering LANs.",
        "# containerlab's `bridge` kind attaches to a bridge that must already exist.",
        "set -euo pipefail",
        "",
        "case \"${1:-up}\" in",
        "up)",
    ]
    for b in brs:
        L += [
            f'  ip link show {b} >/dev/null 2>&1 || ip link add name {b} type bridge',
            f'  ip link set {b} up',
            # A peering LAN is pure L2. Disable the host's IP stack on it so the
            # host does not answer ARP/ND or route for the exchange.
            f'  sysctl -qw net.ipv6.conf.{b}.disable_ipv6=1 || true',
            # Do not let the host bridge run STP or learn from the DUT.
            f'  ip link set {b} type bridge stp_state 0 || true',
            # Jumbo-capable so large UPDATE bursts are not fragmented at 1500.
            f'  ip link set {b} mtu {inv.profile.get("host", {}).get("mtu", 9000)} || true',
        ]
    L += ["  echo 'fabric bridges up: " + " ".join(brs) + "'", "  ;;", "down)"]
    for b in brs:
        L.append(f'  ip link del {b} 2>/dev/null || true')
    L += ["  echo 'fabric bridges removed'", "  ;;",
          "*) echo \"usage: $0 [up|down]\" >&2; exit 2;;", "esac"]
    path = os.path.join(build_dir, "fabrics.sh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    os.chmod(path, 0o755)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def generate(profile_path: str, template_path: str, out_root: str,
             force: bool = False, dut_image: Optional[str] = None) -> str:
    inv = model.load(profile_path)
    # Overriding the DUT image here rather than in the profile keeps one profile
    # usable across several VyOS releases: build-image.sh derives its tag from the
    # ISO filename, so the tag differs per release even though the tier does not.
    if dut_image:
        inv.profile["dut"]["image"] = dut_image
    build_dir = os.path.join(out_root, inv.name)
    if os.path.exists(build_dir):
        if not force:
            print(f"!! {build_dir} exists; regenerating in place "
                  f"(use --force to wipe first)", file=sys.stderr)
        else:
            shutil.rmtree(build_dir)
    os.makedirs(build_dir, exist_ok=True)

    nl = inv.profile["nlri"]
    plan = routegen.PrefixPlan(
        v4_first_octets=expand_octets(nl["v4_first_octets"]),
        v4_len=int(nl.get("v4_len", 24)),
        v6_base=nl.get("v6_base", "3fff::/20"),
        v6_len=int(nl.get("v6_len", 48)),
        seed=int(nl.get("seed", 1)),
        contested_fraction=float(nl.get("contested_fraction", 0.10)),
        contested_pool_v4=int(nl.get("contested_pool_v4", 20000)),
        contested_pool_v6=int(nl.get("contested_pool_v6", 5000)),
    )
    plan.check_capacity(inv.sessions)

    # topology. The image check runs before the file is written so a resolved
    # substitution lands in the topology rather than only in the log.
    topo = build_topology(inv, build_dir)
    image_msgs = _resolve_and_check_images(inv, topo)
    with open(os.path.join(build_dir, "topology.clab.yml"), "w", encoding="utf-8") as fh:
        yaml.safe_dump(topo, fh, sort_keys=False, default_flow_style=False, width=200)

    # DUT config
    ddir = os.path.join(build_dir, "dut")
    os.makedirs(os.path.join(ddir, "churn"), exist_ok=True)
    r = dutconfig.render(inv, template_path)
    _write(os.path.join(ddir, "00-base.conf"), r.base)
    _write(os.path.join(ddir, "10-neighbors.conf"), r.neighbors)
    _write(os.path.join(ddir, "20-instrument.conf"), r.instrumentation)
    for name, body in r.churn_fragments.items():
        _write(os.path.join(ddir, "churn", f"{name}.conf"), body)

    with open(os.path.join(ddir, "VERIFY-ON-IMAGE.md"), "w", encoding="utf-8") as fh:
        fh.write("# Commands to confirm against your actual VyOS image\n\n")
        fh.write(
            "VyOS 1.5 is not developed in public: the `vyos-1x` 1.5 branch is named\n"
            "`circinus-public-unmaintained` and its content predates 1.5.0 GA. The\n"
            "commands below were confirmed either in the docs *or* in the rolling\n"
            "branch XML, but not both, so verify each one commits on your image\n"
            "before trusting a run that depends on it.\n\n"
        )
        if not r.verify_on_image:
            fh.write("_Nothing release-dependent is enabled in this profile._\n")
        for cmd, why in r.verify_on_image:
            fh.write(f"- `{cmd}`\n  - {why}\n")
        fh.write("\n## Notes from rendering\n\n")
        for n in r.notes:
            fh.write(f"- {n}\n")

    # generators
    mrt_stats = write_gobgp(inv, build_dir, plan)
    write_exabgp(inv, build_dir, plan)
    write_prepare(inv, build_dir)
    write_fabrics(inv, build_dir)

    # inventory for the runner and for analysis
    invj = {
        "name": inv.name,
        "profile_path": os.path.abspath(profile_path),
        "dut": inv.dut,
        "dut_asn": inv.dut_asn,
        "fabrics": {
            fid: {
                "bridge": f.bridge, "vlan": f.vlan,
                "v4_net": str(f.v4_net), "v6_net": str(f.v6_net),
                "dut_v4": str(f.dut_v4), "dut_v6": str(f.dut_v6),
                "dut_iface": f.dut_iface,
            } for fid, f in inv.fabrics.items()
        },
        "sessions": [asdict(s) for s in inv.sessions],
        "containers": {
            k: {"engine": v.engine, "fabric": v.fabric, "iface": v.iface,
                "sessions": [s.sid for s in v.sessions]}
            for k, v in inv.containers.items()
        },
        "mrt_stats": mrt_stats,
        "totals": inv.totals(),
        "scenario": inv.profile.get("scenario", {}),
        "budgets": inv.profile.get("budgets", {}),
        "nlri": nl,
    }
    with open(os.path.join(build_dir, "inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(invj, fh, indent=2)

    t = inv.totals()
    print(f"generated {build_dir}")
    print(f"  DUT image  : {inv.dut['image']}")
    for m in image_msgs:
        print(m)
    print(f"  sessions   : {t['sessions']} across {t['containers']} containers")
    print(f"  paths v4/v6: {t['paths_v4']:,} / {t['paths_v6']:,} "
          f"(total {t['paths_total']:,})")
    print(f"  fabrics    : " + ", ".join(
        f"{fid}({f.bridge}, vlan={f.vlan})" for fid, f in inv.fabrics.items()))
    for w in enforce_first_as_warnings(inv):
        print(w)
    for w in sync_agent_warnings(os.path.dirname(os.path.abspath(out_root)) or "."):
        print(w)
    if r.notes:
        print("  notes:")
        for n in r.notes:
            print(f"    - {n[:150]}")
    return build_dir


def sync_agent_warnings(repo_root: str) -> List[str]:
    """Warn if a file-sync agent is live over this repo without excluding build/.

    containerlab bind-mounts directories out of build/<profile>/ into the running
    peer containers. A bind mount holds the inode it was created with, so a sync
    agent that replaces one of those directories mid-run detaches every container
    from it: the host directory is full, the container's view is empty, Docker
    reports nothing, and the consumer fails to open a file that visibly exists.
    Detected once in the field as `gobgp mrt inject` reporting
    "no such file or directory" for all four tables. See FINDINGS.md H-6.

    Only Syncthing is detected, because it leaves an unambiguous marker
    (`.stfolder`). Other agents (Dropbox, OneDrive, rsync cron jobs) have the
    same failure mode and cannot be detected this way.
    """
    marker = os.path.join(repo_root, ".stfolder")
    if not os.path.isdir(marker):
        return []
    ignore = os.path.join(repo_root, ".stignore")
    patterns: List[str] = []
    if os.path.exists(ignore):
        with open(ignore, "r", encoding="utf-8") as fh:
            patterns = [l.strip() for l in fh
                        if l.strip() and not l.strip().startswith("//")]
    if any(pat.strip("/!*") == "build" for pat in patterns):
        return []
    return [
        "  WARNING    : this repo is inside a Syncthing folder (.stfolder present)",
        "               and build/ is not in .stignore. containerlab bind-mounts",
        "               build/<profile>/mrt and build/<profile>/exabgp/run into the",
        "               running peer containers. If Syncthing replaces either",
        "               directory while the lab is up, every container detaches from",
        "               it: the host files are there, the container sees nothing, and",
        "               `gobgp mrt inject` fails with 'no such file or directory'.",
        f"               Fix: add `build` and `results` to {ignore}",
        "               (a ready-made .stignore ships in this repo).",
    ]


def enforce_first_as_warnings(inv) -> List[str]:
    """Flag AS_PATHs the DUT will see that do not begin with the peer's own ASN.

    FRR enables `bgp enforce-first-as` by default from 10.0
    (`FRR_CFG_DEFAULT_BOOL(BGP_ENFORCE_FIRST_AS)` with `match_version "< 9.1"`,
    bgpd/bgp_vty.c) and since 7.4 a violation is treat-as-withdraw rather than a
    NOTIFICATION (`bgp_attr_aspath_check` returns `BGP_ATTR_PARSE_WITHDRAW`).
    The combination is nasty to debug: the session stays Established, `pfxRcd`
    reads 0, and the only evidence is `incorrect first AS (must be N)` in the
    DUT log. FRR's own BGP docs say it outright: "If you have a peering to RS
    (Route-Server), most likely you MUST disable the first AS enforcement."

    gobgp fleets cannot hit this: gobgpd prepends its own ASN on egress to an
    eBGP peer (internal/pkg/table/path.go:273), so the MRT is written WITHOUT
    that ASN and the DUT ends up seeing it exactly once. See
    GOBGP_PREPENDS_OWN_ASN. The only exposure is a fleet explicitly configured
    transparent on an engine that does not re-prepend.
    """
    warn: List[str] = []
    dbl = [s for s in inv.sessions
           if s.engine == "gobgp" and s.transparent_as_path is False]
    if dbl:
        fleets = sorted({s.fleet for s in dbl})
        warn += [
            f"  note       : fleet(s) {', '.join(fleets)} set transparent_as_path=false;",
            "               gobgpd also prepends its own ASN on egress, so the DUT will",
            "               see that ASN twice in AS_PATH. A valid thing to test, but",
            "               not the default.",
        ]
    exposed = [s for s in inv.sessions if s.engine != "gobgp" and s.transparent]
    if exposed:
        p4 = sum(s.prefixes_v4 for s in exposed)
        p6 = sum(s.prefixes_v6 for s in exposed)
        fleets = sorted({s.fleet for s in exposed})
        warn += [
            f"  WARNING    : fleet(s) {', '.join(fleets)} announce a transparent AS_PATH",
            "               on an engine that does not re-prepend it. On FRR >= 10.0 with",
            "               enforce-first-as at its default these sessions sit",
            f"               Established with pfxRcd=0 and {p4:,} v4 / {p6:,} v6 prefixes",
            "               missing, with no error in `show bgp summary`.",
            "               Verify with: make peers PROFILE=<profile>",
        ]
    return warn


def _docker_argv() -> Optional[List[str]]:
    """The working docker invocation, or None if the daemon is unreachable."""
    import subprocess
    for argv in (["docker"], ["sudo", "-n", "docker"]):
        try:
            if subprocess.run(argv + ["info"], capture_output=True,
                              timeout=20).returncode == 0:
                return argv
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def local_images(argv: List[str], pattern: str = "") -> List[str]:
    """`repo:tag` for every local image, optionally filtered by substring."""
    import subprocess
    try:
        p = subprocess.run(argv + ["images", "--format", "{{.Repository}}:{{.Tag}}"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return []
    if p.returncode != 0:
        return []
    out = [l.strip() for l in p.stdout.splitlines() if l.strip()]
    out = [i for i in out if not i.endswith(":<none>")]
    if pattern:
        out = [i for i in out if pattern in i]
    return sorted(out)


def resolve_dut_image(declared: str, candidates: List[str],
                      declared_present: bool) -> Tuple[str, Optional[str]]:
    """Pick the DUT image, tolerating the tag the ISO filename produced.

    `build-image.sh` derives its tag from the ISO filename, so building
    `vyos-1.5.1-generic-amd64.iso` yields `vyos-stress:1.5.1` while the profiles
    declare `vyos-stress:latest`. Requiring the operator to remember
    `VYOS_IMAGE=` on every `generate` is a footgun: forget it once and the
    topology references a tag that does not exist, and containerlab reports that
    as a Docker Hub authentication failure.

    Rules, in order:
      * declared image is present locally -> use it, say nothing
      * exactly one candidate -> use it, and report the substitution loudly
      * several candidates -> refuse and list them; guessing would silently
        change which VyOS release is under test, and the release is one of the
        two variables that most affects the result
      * none -> keep the declared value so the missing-image message names what
        the profile actually asked for

    Returns (image, note).
    """
    if declared_present:
        return declared, None
    others = [c for c in candidates if c != declared]
    if len(others) == 1:
        return others[0], (
            f"DUT image {declared!r} is not present locally; using the only "
            f"VyOS image that is: {others[0]!r}. Pass VYOS_IMAGE=... to choose "
            f"explicitly, or set dut.image in the profile."
        )
    if len(others) > 1:
        raise ValueError(
            f"DUT image {declared!r} is not present locally, and there are "
            f"{len(others)} candidates to choose from: {', '.join(others)}.\n"
            f"       Refusing to guess — which VyOS release is under test is one "
            f"of the two variables that most affects the result.\n"
            f"       Pick one:  make generate PROFILE=<tier> VYOS_IMAGE=<tag>"
        )
    return declared, None


def _resolve_and_check_images(inv: Inventory, topo: Dict,
                              image_pattern: str = "vyos-stress") -> List[str]:
    """Resolve the DUT image against what is actually built, then report.

    Done at generation time rather than deploy time so a tag mismatch is caught
    while it is still cheap to fix.
    """
    msgs: List[str] = []
    argv = _docker_argv()
    if argv is None:
        return ["  images     : docker unreachable — local image check skipped"]

    present = set(local_images(argv))
    candidates = [i for i in local_images(argv, image_pattern)
                  if "/" not in i.split(":")[0]]      # exclude vyos-stress/gobgp etc.

    dut_name = inv.dut["name"]
    declared = topo["topology"]["nodes"][dut_name]["image"]
    chosen, note = resolve_dut_image(declared, candidates, declared in present)
    if chosen != declared:
        topo["topology"]["nodes"][dut_name]["image"] = chosen
        inv.profile["dut"]["image"] = chosen
    if note:
        msgs.append(f"  image note : {note}")

    images = []
    for node in (topo.get("topology", {}).get("nodes", {}) or {}).values():
        img = (node or {}).get("image")
        if img and img not in images:
            images.append(img)
    missing = [i for i in images if i not in present]
    if not missing:
        msgs.append(f"  images     : all {len(images)} present locally")
        return msgs
    msgs.append(f"  images     : {len(missing)} of {len(images)} MISSING locally: "
                f"{', '.join(missing)}")
    msgs.append("               containerlab cannot fetch these (nothing is")
    msgs.append("               published) and topologies pin")
    msgs.append("               image-pull-policy: Never, so it will say so")
    msgs.append("               plainly rather than asking Docker Hub.")
    msgs.append("               `make images` builds the peer images;")
    msgs.append("               `make vyos-image ISO=...` builds the DUT.")
    return msgs


def _write(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a VyOS IXP stress-test lab")
    ap.add_argument("profile")
    ap.add_argument("--template", required=True,
                    help="path to 'Template IXP VyOS Configuration.md'")
    ap.add_argument("--out", default="build")
    ap.add_argument("--force", action="store_true", help="wipe the build dir first")
    ap.add_argument("--dut-image", default=os.environ.get("VYOS_IMAGE") or None,
                    help="override dut.image, e.g. vyos-stress:1.5.0 "
                         "(also read from $VYOS_IMAGE). Lets one profile target "
                         "several VyOS releases without editing it.")
    a = ap.parse_args(argv)
    try:
        generate(a.profile, a.template, a.out, a.force, a.dut_image)
    except (model.ProfileError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
