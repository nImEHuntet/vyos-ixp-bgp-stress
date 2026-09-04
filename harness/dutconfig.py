"""Render the DUT's VyOS configuration from the NE-1849 template.

The template (`Template IXP VyOS Configuration.md`) is the source of truth. This
module extracts its authoritative "Complete Configuration Dump" block,
substitutes the `<PLACEHOLDER_*>` tokens from the profile, applies a small set of
lab-safety edits, and appends generated neighbor + instrumentation stanzas.

Nothing is invented: every emitted command either comes verbatim from the
template or from a VyOS CLI form confirmed against docs.vyos.io / the vyos-1x
interface definitions. Commands whose availability is release-dependent are
gated behind explicit profile flags and listed in
`build/<profile>/dut/VERIFY-ON-IMAGE.md`.

Lab-safety edits, and why each is necessary
-------------------------------------------
1. **Management VRF is skipped by default.** The template moves `eth0` into
   `vrf management` and moves SSH into that VRF. Under containerlab `eth0` *is*
   the management interface that containerlab itself addresses and that this
   harness drives over SSH. Section 9 of the template already warns "YOU MAY
   LOSE SSH ACCESS". Enable with `dut.mgmt_vrf: true` only if you have console
   access.
2. **An explicit input-filter accept for eth0 is added.** The template sets
   `firewall ipv4 input filter default-action drop` and only accepts management
   traffic via `inbound-interface name 'management'` — the VRF. With the VRF
   skipped, that rule never matches and the first `commit` would lock the
   harness out of the DUT.
3. **RPKI is skipped unless a cache is configured.** The template points at
   `<PLACEHOLDER_RPKI_SERVER>`; committing an unreachable cache is harmless to
   BGP but adds noise, so it is opt-in via `rpki.enabled`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import Inventory, Session

DUMP_HEADING = "## Complete Configuration Dump"


# ---------------------------------------------------------------------------
# template extraction
# ---------------------------------------------------------------------------


def extract_dump(template_path: str) -> List[str]:
    """Pull the set-commands out of the template's Complete Configuration Dump."""
    with open(template_path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    start = None
    for i, ln in enumerate(lines):
        if ln.startswith(DUMP_HEADING):
            start = i
            break
    if start is None:
        raise ValueError(
            f"{template_path}: could not find a '{DUMP_HEADING}' heading. "
            "Point --template at the NE-1849 template markdown."
        )

    # first fenced block after the heading
    fence = None
    for i in range(start, len(lines)):
        if lines[i].strip().startswith("```"):
            fence = i
            break
    if fence is None:
        raise ValueError(f"{template_path}: no fenced code block after '{DUMP_HEADING}'")

    body: List[str] = []
    for ln in lines[fence + 1:]:
        if ln.strip().startswith("```"):
            break
        body.append(ln)
    if not body:
        raise ValueError(f"{template_path}: Complete Configuration Dump block is empty")
    return body


def placeholders_in(lines: Iterable[str]) -> List[str]:
    found = set()
    for ln in lines:
        found.update(re.findall(r"<PLACEHOLDER_[A-Za-z0-9_]+>", ln))
    return sorted(found)


# ---------------------------------------------------------------------------
# placeholder mapping
# ---------------------------------------------------------------------------


def build_substitutions(inv: Inventory) -> Dict[str, str]:
    prof = inv.profile
    own = prof["own"]
    fabs = list(inv.fabrics.values())
    if len(fabs) < 2:
        raise ValueError(
            "the NE-1849 template is a dual-IXP config and references IXP1 and "
            "IXP2 placeholders; declare at least two fabrics in the profile"
        )
    f1, f2 = fabs[0], fabs[1]
    rpki = prof.get("rpki", {}) or {}
    mgmt = prof.get("mgmt", {}) or {}

    subs = {
        "<PLACEHOLDER_ASN>": str(inv.dut_asn),
        "<PLACEHOLDER_ROUTER_ID>": str(inv.dut["router_id"]),

        # eth0 addressing is applied by containerlab post-deploy; these are only
        # used if dut.mgmt_vrf is enabled.
        "<PLACEHOLDER_MGMT_IPv4>": mgmt.get("v4", "172.20.20.99/24"),
        "<PLACEHOLDER_MGMT_IPv6>": mgmt.get("v6", "3fff:172:20:20::99/64"),
        "<PLACEHOLDER_MGMT_GW4>": mgmt.get("gw4", "172.20.20.1"),
        "<PLACEHOLDER_MGMT_GW6>": mgmt.get("gw6", "3fff:172:20:20::1"),
        "<PLACEHOLDER_SSH_PUBKEY>": mgmt.get("ssh_pubkey", "AAAAC3NzaC1lZDI1NTE5AAAAILAB"),
        "<PLACEHOLDER_SSH_TYPE>": mgmt.get("ssh_type", "ssh-ed25519"),

        "<PLACEHOLDER_RPKI_SERVER>": rpki.get("server", "127.0.0.1"),
        "<PLACEHOLDER_RPKI_PORT>": str(rpki.get("port", 323)),

        "<PLACEHOLDER_IXP1_IF>": f1.dut_iface,
        "<PLACEHOLDER_IXP1_IPv4>": f1.dut_v4_cidr,
        "<PLACEHOLDER_IXP1_IPv6>": f1.dut_v6_cidr,
        "<PLACEHOLDER_IXP2_IF>": f2.dut_iface,
        "<PLACEHOLDER_IXP2_VLAN>": str(f2.vlan if f2.vlan is not None else 200),
        "<PLACEHOLDER_IXP2_IPv4>": f2.dut_v4_cidr,
        "<PLACEHOLDER_IXP2_IPv6>": f2.dut_v6_cidr,

        "<PLACEHOLDER_OWN_SUPER4>": own["supernet4"],
        "<PLACEHOLDER_OWN_SUPER6>": own["supernet6"],
        "<PLACEHOLDER_OWN_LOCAL4>": own["local4"],
        "<PLACEHOLDER_OWN_LOCAL6>": own["local6"],

        "<PLACEHOLDER_IXP1_PEERING_NET4>": str(f1.v4_net),
        "<PLACEHOLDER_IXP2_PEERING_NET4>": str(f2.v4_net),
        "<PLACEHOLDER_IXP1_PEERING_NET6>": str(f1.v6_net),
        "<PLACEHOLDER_IXP2_PEERING_NET6>": str(f2.v6_net),

        "<PLACEHOLDER_LC_IXP1>": f"{inv.dut_asn}:1:{prof.get('lc',{}).get('ixp1',1001)}",
        "<PLACEHOLDER_LC_IXP2>": f"{inv.dut_asn}:1:{prof.get('lc',{}).get('ixp2',1002)}",
    }
    return subs


# ---------------------------------------------------------------------------
# lab-safety filtering
# ---------------------------------------------------------------------------

# Lines dropped when the management VRF is not in use. Dropping these keeps the
# containerlab control channel intact.
MGMT_VRF_PATTERNS = [
    re.compile(r"^set vrf name management\b"),
    re.compile(r"^set service ssh vrf 'management'"),
    re.compile(r"^set service ntp vrf 'management'"),
    re.compile(r"^set interfaces ethernet eth0 vrf 'management'"),
    re.compile(r"^set interfaces ethernet eth0 address\b"),
    re.compile(r"inbound-interface name 'management'"),
]

RPKI_PATTERN = re.compile(r"^set protocols rpki\b")

# containerlab applies eth0 addressing itself; re-declaring it fights clab.
ETH0_ADDR_PATTERN = re.compile(r"^set interfaces ethernet eth0 address\b")


@dataclass
class RenderResult:
    base: List[str]
    neighbors: List[str]
    instrumentation: List[str]
    churn_fragments: Dict[str, List[str]]
    notes: List[str]
    verify_on_image: List[Tuple[str, str]]


def render_base(inv: Inventory, template_path: str) -> Tuple[List[str], List[str]]:
    prof = inv.profile
    raw = extract_dump(template_path)
    subs = build_substitutions(inv)
    notes: List[str] = []

    missing = placeholders_in(raw)
    unresolved = [p for p in missing if p not in subs]
    if unresolved:
        raise ValueError(
            "template contains placeholders this renderer does not know how to "
            f"fill: {unresolved}. Add them to build_substitutions()."
        )

    mgmt_vrf = bool(inv.dut.get("mgmt_vrf", False))
    rpki_on = bool((prof.get("rpki", {}) or {}).get("enabled", False))

    out: List[str] = []
    dropped_mgmt = dropped_rpki = 0
    for ln in raw:
        s = ln.strip()
        if not s or s.startswith("#"):
            out.append(ln)
            continue
        for token, val in subs.items():
            if token in s:
                s = s.replace(token, val)

        if not mgmt_vrf and any(p.search(s) for p in MGMT_VRF_PATTERNS):
            out.append(f"# [lab-safety: mgmt_vrf disabled] {s}")
            dropped_mgmt += 1
            continue
        if mgmt_vrf and ETH0_ADDR_PATTERN.match(s):
            out.append(f"# [lab-safety: containerlab owns eth0 addressing] {s}")
            continue
        if not rpki_on and RPKI_PATTERN.match(s):
            out.append(f"# [lab-safety: rpki.enabled=false] {s}")
            dropped_rpki += 1
            continue
        out.append(s)

    if dropped_mgmt:
        notes.append(
            f"{dropped_mgmt} management-VRF line(s) commented out. Under containerlab, "
            "eth0 is the management interface this harness drives over SSH; moving it "
            "into a VRF and relocating sshd risks losing the control channel "
            "(the template's own Section 9 carries this warning). "
            "Set dut.mgmt_vrf: true to keep them."
        )
    if dropped_rpki:
        notes.append(
            f"{dropped_rpki} RPKI line(s) commented out because rpki.enabled is false. "
            "Note the template's 'rpki' route-map contains only 'rule 1000 action permit', "
            "i.e. it is a no-op placeholder that does not actually reject Invalids — "
            "enabling a cache alone will not change route acceptance."
        )
    return out, notes


# ---------------------------------------------------------------------------
# generated: firewall/lab access
# ---------------------------------------------------------------------------


def render_access(inv: Inventory) -> List[str]:
    """Keep the harness able to reach the DUT after the template's drop policy."""
    if inv.dut.get("mgmt_vrf", False):
        return ["# mgmt_vrf enabled: template rule 10 covers management access"]
    return [
        "# --- lab access: the template sets input filter default-action drop and only",
        "# --- accepts management traffic on the 'management' VRF. With the VRF skipped,",
        "# --- accept on eth0 explicitly or the first commit locks us out.",
        "set firewall ipv4 input filter rule 11 action 'accept'",
        "set firewall ipv4 input filter rule 11 description 'Lab: mgmt via eth0'",
        "set firewall ipv4 input filter rule 11 inbound-interface name 'eth0'",
        "set firewall ipv6 input filter rule 11 action 'accept'",
        "set firewall ipv6 input filter rule 11 description 'Lab: mgmt via eth0'",
        "set firewall ipv6 input filter rule 11 inbound-interface name 'eth0'",
    ]


def render_interfaces(inv: Inventory) -> List[str]:
    """VLAN sub-interfaces and peering-LAN addressing for tagged fabrics.

    The template hardcodes one untagged and one tagged fabric. Profiles may
    declare more, so emit addressing for every fabric from the inventory.
    """
    out = ["# --- peering LAN addressing derived from the profile's fabrics ---"]
    for fid, fab in inv.fabrics.items():
        out.append(f"# fabric {fid}: bridge={fab.bridge} vlan={fab.vlan}")
        if fab.vlan is None:
            out += [
                f"set interfaces ethernet {fab.dut_iface} address '{fab.dut_v4_cidr}'",
                f"set interfaces ethernet {fab.dut_iface} address '{fab.dut_v6_cidr}'",
                f"set interfaces ethernet {fab.dut_iface} description 'Peering: {fid}'",
            ]
        else:
            out += [
                f"set interfaces ethernet {fab.dut_iface} description '{fid} trunk'",
                f"set interfaces ethernet {fab.dut_iface} vif {fab.vlan} "
                f"address '{fab.dut_v4_cidr}'",
                f"set interfaces ethernet {fab.dut_iface} vif {fab.vlan} "
                f"address '{fab.dut_v6_cidr}'",
                f"set interfaces ethernet {fab.dut_iface} vif {fab.vlan} "
                f"description 'Peering: {fid}'",
            ]
    return out


def render_firewall_groups(inv: Inventory) -> List[str]:
    """Ensure every peering LAN is in bgp_speakers4/6 so BGP is actually allowed in."""
    out = ["# --- ensure all fabrics are permitted by the input filter's BGP rules ---"]
    for fid, fab in inv.fabrics.items():
        out.append(f"set firewall group network-group bgp_speakers4 network '{fab.v4_net}'")
        out.append(f"set firewall group ipv6-network-group bgp_speakers6 network '{fab.v6_net}'")
    return out


# ---------------------------------------------------------------------------
# generated: BGP neighbors
# ---------------------------------------------------------------------------


def render_neighbors(inv: Inventory) -> List[str]:
    out: List[str] = [
        "# --- generated BGP neighbors ---",
        "# One stanza per address family per session. VyOS emits",
        "# 'no bgp default ipv4-unicast' unconditionally (vyos.dev/T3463), so every",
        "# neighbor needs an address-family - inherited here from the peer-group.",
    ]
    for s in inv.sessions:
        desc = f"{s.fleet} {s.role} AS{s.asn}"
        if s.v4:
            if not s.dut_pg4:
                raise ValueError(f"session {s.sid} has a v4 address but no dut_peer_group4")
            n = s.v4
            out += [
                f"set protocols bgp neighbor {n} description '{desc}'",
                f"set protocols bgp neighbor {n} peer-group '{s.dut_pg4}'",
                f"set protocols bgp neighbor {n} remote-as '{s.asn}'",
            ]
            if s.max_prefix4:
                out.append(
                    f"set protocols bgp neighbor {n} address-family ipv4-unicast "
                    f"maximum-prefix '{s.max_prefix4}'"
                )
            out += _neighbor_common(n, s)
        if s.v6:
            if not s.dut_pg6:
                raise ValueError(f"session {s.sid} has a v6 address but no dut_peer_group6")
            n = s.v6
            out += [
                f"set protocols bgp neighbor {n} description '{desc}'",
                f"set protocols bgp neighbor {n} peer-group '{s.dut_pg6}'",
                f"set protocols bgp neighbor {n} remote-as '{s.asn}'",
            ]
            if s.max_prefix6:
                out.append(
                    f"set protocols bgp neighbor {n} address-family ipv6-unicast "
                    f"maximum-prefix '{s.max_prefix6}'"
                )
            out += _neighbor_common(n, s)
    return out


def _neighbor_common(n: str, s: Session) -> List[str]:
    out: List[str] = []
    # Timers are NOT available on VyOS peer-groups (verified against the
    # vyos-1x XML: peer-group has no 'timers' child) - they must be per-neighbor.
    ka = s.timers.get("keepalive")
    hold = s.timers.get("holdtime")
    if ka:
        out.append(f"set protocols bgp neighbor {n} timers keepalive '{ka}'")
    if hold:
        out.append(f"set protocols bgp neighbor {n} timers holdtime '{hold}'")
    if s.timers.get("connect"):
        out.append(f"set protocols bgp neighbor {n} timers connect '{s.timers['connect']}'")
    if s.timers.get("advertisement_interval") is not None:
        # advertisement-interval (MRAI) is neighbor-level only, range 0-600.
        out.append(
            f"set protocols bgp neighbor {n} advertisement-interval "
            f"'{s.timers['advertisement_interval']}'"
        )
    if s.passive:
        out.append(f"set protocols bgp neighbor {n} passive")
    return out


# ---------------------------------------------------------------------------
# generated: instrumentation
# ---------------------------------------------------------------------------


def render_instrumentation(inv: Inventory) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Optional knobs that make the DUT measurable. Each is profile-gated."""
    instr = inv.profile.get("instrumentation", {}) or {}
    out: List[str] = ["# --- generated instrumentation ---"]
    verify: List[Tuple[str, str]] = []

    fds = instr.get("frr_descriptors")
    if fds:
        out.append(f"set system frr descriptors '{fds}'")
        out.append("# docs.vyos.io/configuration/system/frr: 'If the operator plans to run")
        out.append("# bgp with several thousands of peers then this is where we would modify")
        out.append("# FRR to allow this to happen.' Maps to FRR's --limit-fds.")
        out.append("# NOTE: requires a routing-daemon restart or reboot to take effect.")

    prof_sel = instr.get("frr_profile")
    if prof_sel:
        if prof_sel not in ("traditional", "datacenter"):
            raise ValueError("instrumentation.frr_profile must be traditional or datacenter")
        out.append(f"set system frr profile '{prof_sel}'")
        out.append("# 'If unset, the traditional profile is applied.'")

    ud = instr.get("update_delay") or {}
    if ud.get("max_delay"):
        out.append(f"set protocols bgp parameters update-delay max-delay '{ud['max_delay']}'")
        if ud.get("establish_wait"):
            out.append(
                f"set protocols bgp parameters update-delay establish-wait "
                f"'{ud['establish_wait']}'"
            )
        out.append("# update-delay gives bgpd an explicit, self-declared convergence event:")
        out.append("# read-only mode ends when every peer has sent explicit or implicit EOR")
        out.append("# (the first keepalive after Established counts as implicit), or max-delay")
        out.append("# fires. This is the only first-class 'converged' signal FRR exposes.")
        verify.append((
            "set protocols bgp parameters update-delay max-delay <s>",
            "Documented on docs.vyos.io/en/1.5 BGP page but absent from the public "
            "circinus-public-unmaintained vyos-1x snapshot. Confirm it commits on your image.",
        ))

    if instr.get("suppress_fib_pending"):
        out.append("set protocols bgp parameters suppress-fib-pending")
        out.append("# Withholds advertisement until zebra confirms FIB install. Correctness")
        out.append("# win, latency cost: FRR's default adds a 1000 ms batching window.")
        verify.append((
            "set protocols bgp parameters suppress-fib-pending",
            "Exists in the vyos-1x XML as a valueless flag but is NOT on the docs.vyos.io "
            "BGP page. Confirm it commits.",
        ))

    if instr.get("fast_convergence"):
        out.append("set protocols bgp parameters fast-convergence")
        verify.append((
            "set protocols bgp parameters fast-convergence",
            "Present in the vyos-1x XML, undocumented. Confirm it commits.",
        ))

    iq = instr.get("input_queue_limit")
    oq = instr.get("output_queue_limit")
    if iq:
        out.append(f"set protocols bgp parameters input-queue-limit '{iq}'")
    if oq:
        out.append(f"set protocols bgp parameters output-queue-limit '{oq}'")

    gr = instr.get("graceful_restart") or {}
    if gr.get("enabled"):
        out.append("set protocols bgp parameters graceful-restart")
        if gr.get("stalepath_time"):
            out.append(
                f"set protocols bgp parameters graceful-restart stalepath-time "
                f"'{gr['stalepath_time']}'"
            )
        out.append("# VyOS does not expose FRR's restart-time, select-defer-time,")
        out.append("# rib-stale-time, preserve-fw-state or long-lived GR. Only")
        out.append("# 'graceful-restart' and 'stalepath-time' are available, so FRR's")
        out.append("# defaults apply: select-defer-time 120s, rib-stale-time 500s.")

    prom = instr.get("prometheus") or {}
    if prom.get("enabled"):
        addr = prom.get("listen_address", "0.0.0.0")
        out.append(f"set service monitoring prometheus frr-exporter listen-address '{addr}'")
        out.append(f"set service monitoring prometheus frr-exporter port '{prom.get('port', 9342)}'")
        out.append(
            f"set service monitoring prometheus node-exporter listen-address '{addr}'"
        )
        out.append(
            f"set service monitoring prometheus node-exporter port "
            f"'{prom.get('node_port', 9100)}'"
        )
        for c in prom.get("frr_collectors", []):
            out.append(f"set service monitoring prometheus frr-exporter collector {c}")
        if prom.get("frr_collectors"):
            verify.append((
                "set service monitoring prometheus frr-exporter collector <name>",
                "The collector subtree is present on the vyos-1x rolling branch but is NOT "
                "in the 1.5 docs (which list only listen-address/port/vrf). Drop this block "
                "if it fails to commit on a 1.5 image.",
            ))

    bmp = instr.get("bmp") or {}
    if bmp.get("enabled"):
        out.append("set system frr bmp")
        out.append("# BMP is a loadable FRR module: bgpd must start with -M bmp. VyOS gates")
        out.append("# that behind 'set system frr bmp' and it needs 'run restart bgp'.")
        tgt = bmp.get("target", "collector")
        out.append(f"set protocols bgp bmp target {tgt} address '{bmp['address']}'")
        out.append(f"set protocols bgp bmp target {tgt} port '{bmp.get('port', 11019)}'")
        for af in bmp.get("monitor", ["ipv4-unicast", "ipv6-unicast"]):
            for policy in bmp.get("policies", ["pre-policy", "post-policy"]):
                out.append(f"set protocols bgp bmp target {tgt} monitor {af} {policy}")
        out.append("# Caveat from FRR's bmp.rst: with add-path enabled on a monitored")
        out.append("# session, route-monitoring behaviour is 'somewhat unpredictable' -")
        out.append("# the add-path ID is never included and an unpredictable path is picked.")

    for line in instr.get("extra_set_commands", []) or []:
        out.append(line)

    if len(out) == 1:
        out.append("# (no instrumentation enabled in this profile)")
    return out, verify


# ---------------------------------------------------------------------------
# generated: policy churn fragments
# ---------------------------------------------------------------------------


def peergroup_limits(inv: Inventory) -> Dict[str, Dict[str, int]]:
    """The maximum-prefix each DUT peer-group actually needs, from the fleets.

    Template defect 9: `ixp1-peer4`, `ixp1-peer6`, `ixp2-peer4` and `ixp2-peer6`
    all carry `maximum-prefix 200`. That is a plausible production choice for a
    bilateral session, but in this lab it is the *binding constraint on the
    experiment*: every profile pins its bilateral fleets to 180 v4 / 90 v6
    prefixes purely to stay under it, including t4-breakit, where 350 bilateral
    sessions contribute 63,000 v4 paths against the route servers' 590,000. The
    sessions that the chaos engine actually flaps are therefore the smallest ones
    in the lab, so flap-recovery and update-generation cost are measured on
    almost empty sessions.

    VyOS also exposes `maximum-prefix` as a bare limit — no `warning-only`, no
    `restart`, no `threshold` — so tripping it is an unrecoverable teardown
    (see FINDINGS.md defect 9 and H-31). A limit that can silently truncate the
    table under test is worse than no limit at all.

    So compute the limit from what the fleets in each peer-group announce, with
    headroom for the `walk` churn mode (which announces fresh NLRI before
    withdrawing old, so the table transiently exceeds the steady-state count).
    The per-neighbour `max_prefix4/6` from the profile still overrides this where
    a fleet sets it explicitly.
    """
    want: Dict[str, Dict[str, int]] = {}
    for sess in inv.sessions:
        for pg, af, count in ((sess.dut_pg4, "ipv4", sess.prefixes_v4),
                              (sess.dut_pg6, "ipv6", sess.prefixes_v6)):
            if not pg or not count:
                continue
            cur = want.setdefault(pg, {})
            cur[af] = max(cur.get(af, 0), int(count))
    out: Dict[str, Dict[str, int]] = {}
    for pg, afs in want.items():
        for af, count in afs.items():
            # 4x headroom, floor 1000: `walk` can double a session's footprint
            # mid-event, and paths_per_prefix multiplies paths but not prefixes.
            out.setdefault(pg, {})[af] = max(1000, count * 4)
    return out


PG_MAXPFX_RE = re.compile(
    r"^set protocols bgp peer-group (\S+) address-family (ipv4|ipv6)-unicast "
    r"maximum-prefix '(\d+)'\s*$")


def peergroup_limits_in(lines: Sequence[str]) -> Dict[str, Dict[str, int]]:
    """maximum-prefix already set per peer-group in a rendered config."""
    cur: Dict[str, Dict[str, int]] = {}
    for ln in lines:
        m = PG_MAXPFX_RE.match(ln.strip())
        if m:
            cur.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    return cur


def render_peergroup_limits(inv: Inventory, base: Sequence[str]
                            ) -> Tuple[List[str], List[str]]:
    """Raise peer-group maximum-prefix where the template's value would throttle.

    Only ever raises. The first version of this emitted the computed limit
    unconditionally, which *lowered* `ixp1-rs4` from the template's 400000 to
    4000 on t0-smoke — harmless in that the per-neighbour override wins, but a
    generated config that silently reduces a limit it was written to protect is
    exactly the kind of thing that later reads as a DUT result.
    """
    want = peergroup_limits(inv)
    have = peergroup_limits_in(base)
    raised: List[Tuple[str, str, int, int]] = []
    for pg in sorted(want):
        for af in ("ipv4", "ipv6"):
            n = want[pg].get(af)
            if not n:
                continue
            cur = (have.get(pg) or {}).get(af)
            if cur is None or n > cur:
                raised.append((pg, af, cur if cur is not None else 0, n))
    if not raised:
        return [], []
    out = [
        "# --- generated: peer-group maximum-prefix overrides ---",
        "# Template defect 9: the four bilateral peer-groups ship with",
        "# `maximum-prefix 200`, which is below what any useful stress profile",
        "# announces and is why every tier pinned its bilateral fleets to 180/90.",
        "# Raised to 4x the largest announcement in each peer-group so the limit",
        "# is never what ends a test. Values already high enough are left alone.",
        "# maxprefix_trip still exercises the teardown deliberately, against a",
        "# limit computed from the live table.",
    ]
    for pg, af, cur, n in raised:
        out.append(f"set protocols bgp peer-group {pg} address-family "
                   f"{af}-unicast maximum-prefix '{n}'")
    notes = [
        "peer-group maximum-prefix raised so the template's limit is not the "
        "binding constraint on the experiment (template defect 9): "
        + ", ".join(f"{pg} {af} {cur or 'unset'}->{n}"
                    for pg, af, cur, n in raised)
    ]
    return out, notes


def render_churn_fragments(inv: Inventory) -> Dict[str, List[str]]:
    """Config deltas the chaos engine applies and reverts at runtime.

    Each fragment is a pair of files: `apply` and `revert`. These are the
    "policy/filter changes" half of the workload — on a real IXP router these
    happen during business hours, on a router already carrying a full table, and
    each one forces a policy re-evaluation across every affected session.
    """
    asn = inv.dut_asn
    own4 = inv.profile["own"]["supernet4"]
    frags: Dict[str, List[str]] = {}

    # 1. Prefix-list growth: add then remove 64 entries. Exercises the
    #    prefix-list -> route-map -> RIB re-evaluation path.
    add, rem = [], []
    for i in range(64):
        net = f"{100 + (i // 8)}.{(i % 8) * 32}.0.0/12"
        add.append(
            f"set policy prefix-list ipv4-bogons rule {900 + i} action 'permit'"
        )
        add.append(f"set policy prefix-list ipv4-bogons rule {900 + i} le '32'")
        add.append(f"set policy prefix-list ipv4-bogons rule {900 + i} prefix '{net}'")
        rem.append(f"delete policy prefix-list ipv4-bogons rule {900 + i}")
    frags["prefixlist-grow.apply"] = add
    frags["prefixlist-grow.revert"] = rem

    # 2. Local-pref flip on IXP-1 imports: changes bestpath for every prefix
    #    learned there. This is the single most disruptive routine policy change
    #    an IXP-connected router sees.
    frags["localpref-flip.apply"] = [
        "set policy route-map ebgp4-import-ixp1 rule 20 set local-preference '325'",
        "set policy route-map ebgp6-import-ixp1 rule 110 set local-preference '325'",
    ]
    frags["localpref-flip.revert"] = [
        "set policy route-map ebgp4-import-ixp1 rule 20 set local-preference '275'",
        "set policy route-map ebgp6-import-ixp1 rule 110 set local-preference '275'",
    ]

    # 3. Export policy tightening: deny a chunk of own space outbound, then
    #    restore. Forces outbound re-advertisement to every peer.
    frags["export-tighten.apply"] = [
        f"set policy prefix-list own-supernet4 rule 20 action 'deny'",
        f"set policy prefix-list own-supernet4 rule 20 prefix '{own4}'",
    ]
    frags["export-tighten.revert"] = [
        "delete policy prefix-list own-supernet4 rule 20",
    ]

    # 4. AS-path filter add/remove: a new regex on the import path.
    frags["aspath-filter.apply"] = [
        "set policy as-path-list lab-churn description 'chaos: transient as-path filter'",
        "set policy as-path-list lab-churn rule 10 action 'permit'",
        "set policy as-path-list lab-churn rule 10 regex '_3356_'",
        "set policy route-map ebgp4-import rule 15 action 'deny'",
        "set policy route-map ebgp4-import rule 15 description 'chaos: transient'",
        "set policy route-map ebgp4-import rule 15 match as-path 'lab-churn'",
    ]
    frags["aspath-filter.revert"] = [
        "delete policy route-map ebgp4-import rule 15",
        "delete policy as-path-list lab-churn",
    ]

    # 5. Large-community retag: changes an attribute on every imported route
    #    without changing the prefix count - isolates attribute churn from RIB
    #    churn, which is exactly the case where pfxRcd stays flat while
    #    tableVersion moves.
    frags["community-retag.apply"] = [
        f"set policy route-map ebgp4-import-ixp1 rule 10 set large-community replace "
        f"'{asn}:1:9001'",
    ]
    frags["community-retag.revert"] = [
        f"set policy route-map ebgp4-import-ixp1 rule 10 set large-community replace "
        f"'{asn}:1:{inv.profile.get('lc',{}).get('ixp1',1001)}'",
    ]

    # 6. Peer-group import route-map swap: the heaviest churn, since it changes
    #    the policy applied to every member at once.
    frags["pg-routemap-swap.apply"] = [
        "set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast "
        "route-map import 'allow-all'",
    ]
    frags["pg-routemap-swap.revert"] = [
        "set protocols bgp peer-group ixp1-peer4 address-family ipv4-unicast "
        "route-map import 'ebgp4-import'",
    ]

    # 7. maximum-prefix squeeze on a peer-group: deliberately trips the limit so
    #    teardown and recovery are observable.
    #
    #    Both numbers used to be hardcoded — squeeze to 50, restore to 200 — and
    #    both were wrong once the peer-group limits stopped being the template's
    #    200. The squeeze has to be below what the members actually announce or
    #    nothing trips, and the revert has to restore the *generated* limit or it
    #    silently re-imposes the throttle this build removed. Derive both.
    limits = peergroup_limits(inv)
    squeeze_pg = "ixp1-peer4"
    announced = max([sess.prefixes_v4 for sess in inv.sessions
                     if sess.dut_pg4 == squeeze_pg and sess.prefixes_v4] or [0])
    restore = (limits.get(squeeze_pg, {}) or {}).get("ipv4")
    if announced and restore:
        # Half the offered table: unambiguously below it, and still large enough
        # that the trip is about the limit rather than about a rounding edge.
        squeeze_to = max(1, announced // 2)
        frags["maxprefix-squeeze.apply"] = [
            f"# squeeze {squeeze_pg} to {squeeze_to}, below the {announced} "
            f"prefix(es) its members announce",
            f"set protocols bgp peer-group {squeeze_pg} address-family "
            f"ipv4-unicast maximum-prefix '{squeeze_to}'",
        ]
        frags["maxprefix-squeeze.revert"] = [
            f"set protocols bgp peer-group {squeeze_pg} address-family "
            f"ipv4-unicast maximum-prefix '{restore}'",
        ]

    return frags


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------


def render(inv: Inventory, template_path: str) -> RenderResult:
    base, notes = render_base(inv, template_path)
    pg_lines, pg_notes = render_peergroup_limits(inv, base)
    notes = notes + pg_notes
    base = base + [""] + render_interfaces(inv) + [""] + render_firewall_groups(inv) \
        + [""] + render_access(inv) + [""] + pg_lines
    instr, verify = render_instrumentation(inv)
    return RenderResult(
        base=base,
        neighbors=render_neighbors(inv),
        instrumentation=instr,
        churn_fragments=render_churn_fragments(inv),
        notes=notes,
        verify_on_image=verify,
    )
