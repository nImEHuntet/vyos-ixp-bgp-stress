"""Profile loading and inventory expansion.

A Profile (YAML) is expanded into a concrete Inventory: every BGP session gets
an explicit local address, ASN, container, gRPC/API port and DUT peer-group
binding. Everything downstream (topology generation, DUT config, chaos target
selection, telemetry labelling) reads the Inventory, never the raw YAML.

Deterministic by construction: given the same profile the same inventory is
produced, so a run is reproducible and results are comparable across runs.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

import yaml

# ASN ranges rejected by the asn-bogons as-path-list in the NE-1849 template.
# (rule -> inclusive range). Used to fail fast rather than debug a silent filter.
BOGON_ASN_RANGES = [
    (0, 0),
    (23456, 23456),
    (64496, 64511),
    (64512, 65535),
    (65536, 65551),
    (65552, 65999),
    (66000, 69999),
    (70000, 130999),
    (131000, 131071),
    (4200000000, 4294967294),
]

# containerlab enforces eth[1-9][0-9]* for the vyosnetworks_vyos kind; eth0 is
# reserved for management.
VYOS_IFACE_MIN = 1
VYOS_IFACE_MAX = 99


class ProfileError(ValueError):
    pass


def asn_is_bogon(asn: int) -> bool:
    return any(lo <= asn <= hi for lo, hi in BOGON_ASN_RANGES)


def next_safe_asn(asn: int) -> int:
    """Advance past any bogon range so peer ASN allocation never lands in one."""
    while asn_is_bogon(asn):
        for lo, hi in BOGON_ASN_RANGES:
            if lo <= asn <= hi:
                asn = hi + 1
                break
    return asn


@dataclass
class Fabric:
    fid: str
    bridge: str
    vlan: Optional[int]
    v4_net: ipaddress.IPv4Network
    v6_net: ipaddress.IPv6Network
    dut_host: int
    dut_iface: str
    peer_host_base: int

    @property
    def dut_v4(self) -> ipaddress.IPv4Address:
        return self.v4_net.network_address + self.dut_host

    @property
    def dut_v6(self) -> ipaddress.IPv6Address:
        return self.v6_net.network_address + self.dut_host

    @property
    def dut_v4_cidr(self) -> str:
        return f"{self.dut_v4}/{self.v4_net.prefixlen}"

    @property
    def dut_v6_cidr(self) -> str:
        return f"{self.dut_v6}/{self.v6_net.prefixlen}"

    @property
    def dut_iface_effective(self) -> str:
        """Interface the DUT actually addresses (VLAN sub-interface if tagged)."""
        return self.dut_iface if self.vlan is None else f"{self.dut_iface}.{self.vlan}"


@dataclass
class Session:
    """One BGP session between a simulated peer and the DUT."""

    sid: str                  # unique, e.g. "ixp1-bilat-007"
    fleet: str
    fabric: str
    engine: str               # gobgp | exabgp
    role: str
    asn: int
    v4: Optional[str]         # local address of the simulated peer
    v6: Optional[str]
    container: str            # container that hosts this speaker
    api_port: int             # gobgp gRPC port (gobgp only); 0 for exabgp
    dut_pg4: Optional[str]
    dut_pg6: Optional[str]
    max_prefix4: Optional[int]
    max_prefix6: Optional[int]
    prefixes_v4: int
    prefixes_v6: int
    paths_per_prefix: int
    passive: bool
    timers: Dict[str, int]
    flappable: bool
    mrt: Optional[str]
    nlri_slot: int            # index into the deterministic NLRI space
    # None => derive from role (route-server => transparent). An RFC 7947 route
    # server does not prepend its own ASN, which collides head-on with FRR's
    # enforce-first-as: default ON since FRR 10.0, and a violation is
    # treat-as-withdraw, so the session stays Established while every route is
    # silently dropped. Set this explicitly per fleet to control which side of
    # that you are testing.
    transparent_as_path: Optional[bool] = None

    @property
    def transparent(self) -> bool:
        """Does this speaker omit its own ASN from AS_PATH?"""
        if self.transparent_as_path is None:
            return self.role == "route-server"
        return bool(self.transparent_as_path)

    @property
    def afi_v4(self) -> bool:
        return self.v4 is not None

    @property
    def afi_v6(self) -> bool:
        return self.v6 is not None


@dataclass
class Container:
    name: str
    engine: str
    fabric: str
    image: str
    memory: Optional[str]
    cpu: Optional[float]
    sessions: List[Session] = field(default_factory=list)
    iface: str = "eth1"       # data interface inside the peer container


@dataclass
class Inventory:
    profile: Dict[str, Any]
    fabrics: Dict[str, Fabric]
    sessions: List[Session]
    containers: Dict[str, Container]

    # ---- convenience accessors -------------------------------------------

    @property
    def name(self) -> str:
        return self.profile["name"]

    @property
    def dut(self) -> Dict[str, Any]:
        return self.profile["dut"]

    @property
    def dut_asn(self) -> int:
        return int(self.dut["asn"])

    def sessions_of(self, **kw) -> List[Session]:
        out = []
        for s in self.sessions:
            if all(getattr(s, k) == v for k, v in kw.items()):
                out.append(s)
        return out

    @property
    def flappable(self) -> List[Session]:
        return [s for s in self.sessions if s.flappable]

    def session(self, sid: str) -> Session:
        for s in self.sessions:
            if s.sid == sid:
                return s
        raise KeyError(sid)

    def totals(self) -> Dict[str, int]:
        v4 = sum(s.prefixes_v4 * max(1, s.paths_per_prefix) for s in self.sessions)
        v6 = sum(s.prefixes_v6 * max(1, s.paths_per_prefix) for s in self.sessions)
        return {
            "sessions": len(self.sessions),
            "containers": len(self.containers),
            "paths_v4": v4,
            "paths_v6": v6,
            "paths_total": v4 + v6,
        }


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def load_profile(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        prof = yaml.safe_load(fh)
    if not isinstance(prof, dict):
        raise ProfileError(f"{path}: profile must be a YAML mapping")
    for key in ("name", "dut", "fabrics", "own", "nlri", "fleets", "scenario"):
        if key not in prof:
            raise ProfileError(f"{path}: missing required top-level key '{key}'")
    return prof


def _validate_dut(prof: Dict[str, Any]) -> None:
    asn = int(prof["dut"]["asn"])
    if asn_is_bogon(asn):
        raise ProfileError(
            f"dut.asn {asn} is matched by the template's asn-bogons as-path-list; "
            "the DUT would filter its own AS_PATH on export. "
            "Use 1-64495 (not 0/23456) or 131072-4199999999. See profiles/_schema.md."
        )


def _validate_iface(name: str, where: str) -> None:
    if not name.startswith("eth"):
        raise ProfileError(f"{where}: interface '{name}' must be ethN")
    try:
        n = int(name[3:])
    except ValueError as exc:
        raise ProfileError(f"{where}: interface '{name}' must be ethN") from exc
    if not (VYOS_IFACE_MIN <= n <= VYOS_IFACE_MAX):
        raise ProfileError(
            f"{where}: interface '{name}' out of range. containerlab's "
            "vyosnetworks_vyos kind allows eth1-eth99 only (eth0 is management)."
        )


def build_inventory(prof: Dict[str, Any]) -> Inventory:
    _validate_dut(prof)

    fabrics: Dict[str, Fabric] = {}
    used_ifaces: Dict[str, str] = {}
    for fid, f in prof["fabrics"].items():
        _validate_iface(f["dut_iface"], f"fabrics.{fid}.dut_iface")
        if f["dut_iface"] in used_ifaces:
            raise ProfileError(
                f"fabrics.{fid}.dut_iface '{f['dut_iface']}' already used by "
                f"fabric '{used_ifaces[f['dut_iface']]}'"
            )
        used_ifaces[f["dut_iface"]] = fid
        fabrics[fid] = Fabric(
            fid=fid,
            bridge=f["bridge"],
            vlan=f.get("vlan"),
            v4_net=ipaddress.IPv4Network(f["v4_net"]),
            v6_net=ipaddress.IPv6Network(f["v6_net"]),
            dut_host=int(f["dut_host"]),
            dut_iface=f["dut_iface"],
            peer_host_base=int(f["peer_host_base"]),
        )

    declared_bridges = set(prof.get("host", {}).get("bridges", []))
    for fid, fab in fabrics.items():
        if declared_bridges and fab.bridge not in declared_bridges:
            raise ProfileError(
                f"fabrics.{fid}.bridge '{fab.bridge}' not listed in host.bridges"
            )

    sessions: List[Session] = []
    containers: Dict[str, Container] = {}
    # per-fabric host counters so two fleets on the same LAN never collide
    host_cursor = {fid: fab.peer_host_base for fid, fab in fabrics.items()}
    nlri_cursor = 0
    # ASN -> owning fleet, so overlapping asn_base ranges are caught at generation
    # time. Silently renumbering would leave the DUT config disagreeing with what
    # the operator wrote in the profile.
    asn_owner: Dict[int, str] = {}

    for fleet in prof["fleets"]:
        fid = fleet["fabric"]
        if fid not in fabrics:
            raise ProfileError(f"fleet '{fleet['id']}' references unknown fabric '{fid}'")
        fab = fabrics[fid]
        engine = fleet["engine"]
        if engine not in ("gobgp", "exabgp"):
            raise ProfileError(f"fleet '{fleet['id']}': engine must be gobgp or exabgp")

        n = int(fleet["peers"])
        per_c = max(1, int(fleet.get("per_container", 1)))
        asn = next_safe_asn(int(fleet["asn_base"]))
        afi = fleet.get("afi", ["ipv4", "ipv6"])
        image = fleet.get(
            "image",
            "vyos-stress/gobgp:latest" if engine == "gobgp" else "vyos-stress/exabgp:latest",
        )

        for i in range(n):
            c_index = i // per_c
            cname = f"{fleet['id']}-c{c_index:03d}"
            if cname not in containers:
                containers[cname] = Container(
                    name=cname,
                    engine=engine,
                    fabric=fid,
                    image=image,
                    memory=fleet.get("memory"),
                    cpu=fleet.get("cpu"),
                )
            host = host_cursor[fid]
            host_cursor[fid] += 1
            if host >= fab.v4_net.num_addresses - 1:
                raise ProfileError(
                    f"fabric '{fid}' v4_net {fab.v4_net} exhausted at peer {i} of "
                    f"fleet '{fleet['id']}' — widen the peering LAN"
                )

            v4 = str(fab.v4_net.network_address + host) if "ipv4" in afi else None
            v6 = str(fab.v6_net.network_address + host) if "ipv6" in afi else None

            if asn in asn_owner:
                other = asn_owner[asn]
                span = n + sum(
                    1 for a in range(int(fleet["asn_base"]), asn) if asn_is_bogon(a))
                raise ProfileError(
                    f"AS{asn} is claimed by both fleet '{other}' and fleet "
                    f"'{fleet['id']}'. Fleet '{fleet['id']}' has asn_base "
                    f"{fleet['asn_base']} and {n} peers, so it needs roughly "
                    f"{fleet['asn_base']}..{int(fleet['asn_base']) + span} — which "
                    f"overlaps. Move one fleet's asn_base. Safe ranges under the "
                    f"template's asn-bogons list are 1-64495 (excluding 0 and "
                    f"23456) and 131072-4199999999."
                )
            asn_owner[asn] = fleet["id"]
            if asn == prof["dut"]["asn"]:
                raise ProfileError(
                    f"fleet '{fleet['id']}' allocates AS{asn}, which is also the "
                    f"DUT's own ASN. The DUT would drop these routes as an AS loop."
                )

            sess = Session(
                sid=f"{fleet['id']}-{i:04d}",
                fleet=fleet["id"],
                fabric=fid,
                engine=engine,
                role=fleet.get("role", "bilateral"),
                asn=asn,
                v4=v4,
                v6=v6,
                container=cname,
                # one gRPC port per gobgpd process inside the container
                api_port=(50051 + (i % per_c)) if engine == "gobgp" else 0,
                dut_pg4=fleet.get("dut_peer_group4"),
                dut_pg6=fleet.get("dut_peer_group6"),
                max_prefix4=fleet.get("max_prefix4"),
                max_prefix6=fleet.get("max_prefix6"),
                prefixes_v4=int(fleet.get("prefixes_v4", 0)),
                prefixes_v6=int(fleet.get("prefixes_v6", 0)),
                paths_per_prefix=int(fleet.get("paths_per_prefix", 1)),
                passive=bool(fleet.get("passive", False)),
                timers=dict(fleet.get("timers", {}) or {}),
                flappable=bool(fleet.get("flappable", True)),
                mrt=fleet.get("mrt"),
                nlri_slot=nlri_cursor,
                transparent_as_path=fleet.get("transparent_as_path"),
            )
            nlri_cursor += 1
            sessions.append(sess)
            containers[cname].sessions.append(sess)
            asn = next_safe_asn(asn + 1)

    if not sessions:
        raise ProfileError("profile declares no sessions")

    return Inventory(profile=prof, fabrics=fabrics, sessions=sessions, containers=containers)


def load(path: str) -> Inventory:
    return build_inventory(load_profile(path))


def iter_profiles(directory: str) -> Iterator[str]:
    for fn in sorted(os.listdir(directory)):
        if fn.endswith((".yaml", ".yml")) and not fn.startswith("_"):
            yield os.path.join(directory, fn)
