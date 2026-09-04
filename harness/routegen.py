"""Deterministic route generation.

Two jobs:

1. **Prefix planning** — hand every session a reproducible, mostly-disjoint slice
   of NLRI space, plus a deliberately *contested* slice that several peers
   advertise simultaneously. The contested slice is what makes bestpath actually
   work: without it a stress test only measures RIB insertion, not path
   selection.

2. **Wire formats** — emit those prefixes in the two formats the generators can
   ingest at speed:
   * MRT TABLE_DUMP_V2 (RFC 6396) for `gobgp mrt inject global`, which is the
     only documented bulk path into gobgpd (it drives AddPathStream internally).
     A shell loop over `gobgp global rib add` opens a fresh gRPC connection per
     prefix and is orders of magnitude slower.
   * ExaBGP `announce attributes ... nlri ...` batches, which pack one attribute
     set plus many NLRI into a single UPDATE.

MRT encoding notes (RFC 6396 §4.3):
  * TABLE_DUMP_V2 always carries 4-byte ASNs in AS_PATH, regardless of the
    peer's negotiated capability.
  * IPv4 next-hop rides in the NEXT_HOP attribute (type 3).
  * IPv6 next-hop rides in MP_REACH_NLRI (type 14), but in the reduced form
    RFC 6396 §4.3.4 defines: the body is *only* the Next Hop Address Length and
    the Next Hop Address. AFI, SAFI, the Reserved octet and the NLRI are all
    omitted, because the MRT record header already carries them. Emitting the
    full RFC 4760 body instead makes a conformant reader treat the AFI's high
    byte as the next-hop length and see a zero-length next hop.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# prefix planning
# ---------------------------------------------------------------------------


@dataclass
class PrefixPlan:
    """Deterministic prefix allocator.

    v4 space is carved as /`v4_len` out of each /8 in `v4_first_octets`.
    v6 space is carved as /`v6_len` out of `v6_base` (RFC 9637 3fff::/20).

    `contested_fraction` of each session's advertisement is drawn from a shared
    pool so that N peers advertise identical NLRI with different attributes.
    """

    v4_first_octets: Sequence[int]
    v4_len: int = 24
    v6_base: str = "3fff::/20"
    v6_len: int = 48
    seed: int = 1
    contested_fraction: float = 0.10
    contested_pool_v4: int = 20000
    contested_pool_v6: int = 5000

    _v6_net: ipaddress.IPv6Network = field(init=False)

    def __post_init__(self) -> None:
        if not (8 <= self.v4_len <= 24):
            raise ValueError(
                f"v4_len {self.v4_len} outside 8..24; the template's "
                "'ipv4-acceptable' prefix-list would drop it"
            )
        if not (12 <= self.v6_len <= 48):
            raise ValueError(
                f"v6_len {self.v6_len} outside 12..48; the template's "
                "'ipv6-acceptable' prefix-list would drop it"
            )
        self._v6_net = ipaddress.IPv6Network(self.v6_base)
        if self.v6_len < self._v6_net.prefixlen:
            raise ValueError(f"v6_len {self.v6_len} shorter than v6_base prefixlen")

    # -- capacity ----------------------------------------------------------

    @property
    def per_octet_v4(self) -> int:
        return 1 << (self.v4_len - 8)

    @property
    def capacity_v4(self) -> int:
        return len(self.v4_first_octets) * self.per_octet_v4

    @property
    def capacity_v6(self) -> int:
        return 1 << (self.v6_len - self._v6_net.prefixlen)

    # -- indexed access ----------------------------------------------------

    def v4_at(self, index: int) -> str:
        """Map a flat index onto a /`v4_len` prefix. Wraps at capacity."""
        index %= self.capacity_v4
        octet = self.v4_first_octets[index // self.per_octet_v4]
        within = index % self.per_octet_v4
        addr = (octet << 24) | (within << (32 - self.v4_len))
        return f"{ipaddress.IPv4Address(addr)}/{self.v4_len}"

    def v6_at(self, index: int) -> str:
        index %= self.capacity_v6
        step = 1 << (128 - self.v6_len)
        addr = int(self._v6_net.network_address) + index * step
        return f"{ipaddress.IPv6Address(addr)}/{self.v6_len}"

    # -- per-session allocation -------------------------------------------

    def _split(self, count: int) -> Tuple[int, int]:
        contested = int(count * self.contested_fraction)
        return count - contested, contested

    @staticmethod
    def _contested_indices(slot: int, cont: int, pool: int) -> Iterator[int]:
        """Indices into the shared contested pool, guaranteed to overlap.

        Drawing these at random per session does *not* work: with a pool much
        larger than the per-session count, two sessions almost never pick the same
        prefix, and the whole point of the contested pool is that several peers
        advertise identical NLRI so bestpath has to choose between them.

        Instead each session takes a contiguous window whose start rotates by a
        quarter of its own width, so adjacent slots overlap by ~75% and distant
        slots still overlap once the rotation wraps the pool.
        """
        if cont <= 0 or pool <= 0:
            return
        width = min(cont, pool)
        rotate = max(1, width // 4)
        base = (slot * rotate) % pool
        for i in range(width):
            yield (base + i) % pool

    def session_v4(self, slot: int, count: int, offset: int = 0) -> Iterator[str]:
        """Prefixes for one session.

        `offset` shifts the exclusive window, which is how the `walk` churn mode
        advertises fresh NLRI while withdrawing older NLRI.
        """
        if count <= 0:
            return
        excl, cont = self._split(count)
        # the exclusive window starts above the contested pool so the two never mix
        base = self.contested_pool_v4 + slot * max(excl, 1) + offset
        for i in range(excl):
            yield self.v4_at(base + i)
        for idx in self._contested_indices(slot, cont, self.contested_pool_v4):
            yield self.v4_at(idx)

    def session_v6(self, slot: int, count: int, offset: int = 0) -> Iterator[str]:
        if count <= 0:
            return
        excl, cont = self._split(count)
        base = self.contested_pool_v6 + slot * max(excl, 1) + offset
        for i in range(excl):
            yield self.v6_at(base + i)
        for idx in self._contested_indices(slot, cont, self.contested_pool_v6):
            yield self.v6_at(idx)

    def check_capacity(self, sessions) -> None:
        # The contested pool must be at least as large as the largest per-session
        # contested count, or a session's contested window is truncated to the pool
        # size and it silently advertises fewer prefixes than the profile asked for.
        for attr, pfx_attr, label in (("contested_pool_v4", "prefixes_v4", "v4"),
                                      ("contested_pool_v6", "prefixes_v6", "v6")):
            pool = getattr(self, attr)
            worst = 0
            worst_sid = ""
            for s in sessions:
                cont = int(getattr(s, pfx_attr) * self.contested_fraction)
                if cont > worst:
                    worst, worst_sid = cont, s.sid
            if worst > pool:
                raise ValueError(
                    f"nlri.{attr} is {pool}, but session '{worst_sid}' needs {worst} "
                    f"contested {label} prefixes "
                    f"(contested_fraction={self.contested_fraction}). The pool would be "
                    f"truncated and that session would advertise fewer prefixes than "
                    f"the profile declares. Raise nlri.{attr} to at least {worst}, or "
                    f"lower nlri.contested_fraction."
                )

        need4 = self.contested_pool_v4 + sum(
            max(1, s.prefixes_v4 - int(s.prefixes_v4 * self.contested_fraction))
            for s in sessions
        )
        if need4 > self.capacity_v4:
            raise ValueError(
                f"v4 NLRI space too small: need ~{need4} /{self.v4_len}s, "
                f"have {self.capacity_v4}. Add more entries to nlri.v4_first_octets "
                f"or lengthen nlri.v4_len."
            )
        need6 = self.contested_pool_v6 + sum(
            max(1, s.prefixes_v6 - int(s.prefixes_v6 * self.contested_fraction))
            for s in sessions
        )
        if need6 > self.capacity_v6:
            raise ValueError(
                f"v6 NLRI space too small: need ~{need6} /{self.v6_len}s, "
                f"have {self.capacity_v6}."
            )


# ---------------------------------------------------------------------------
# BGP path attribute encoding
# ---------------------------------------------------------------------------

ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_MULTI_EXIT_DISC = 4
ATTR_COMMUNITIES = 8
ATTR_MP_REACH_NLRI = 14
ATTR_LARGE_COMMUNITY = 32

FLAG_OPTIONAL = 0x80
FLAG_TRANSITIVE = 0x40
FLAG_PARTIAL = 0x20
FLAG_EXT_LEN = 0x10

AS_SEQUENCE = 2
AS_SET = 1


def _attr(code: int, flags: int, value: bytes) -> bytes:
    if len(value) > 255:
        flags |= FLAG_EXT_LEN
        return struct.pack("!BBH", flags, code, len(value)) + value
    return struct.pack("!BBB", flags, code, len(value)) + value


def enc_origin(origin: int = 0) -> bytes:
    return _attr(ATTR_ORIGIN, FLAG_TRANSITIVE, struct.pack("!B", origin))


def enc_as_path(asns: Sequence[int], as_set: Sequence[int] = ()) -> bytes:
    body = b""
    if asns:
        body += struct.pack("!BB", AS_SEQUENCE, len(asns))
        body += b"".join(struct.pack("!I", a) for a in asns)
    if as_set:
        body += struct.pack("!BB", AS_SET, len(as_set))
        body += b"".join(struct.pack("!I", a) for a in as_set)
    return _attr(ATTR_AS_PATH, FLAG_TRANSITIVE, body)


def enc_next_hop_v4(addr: str) -> bytes:
    return _attr(ATTR_NEXT_HOP, FLAG_TRANSITIVE, ipaddress.IPv4Address(addr).packed)


def enc_med(med: int) -> bytes:
    return _attr(ATTR_MULTI_EXIT_DISC, FLAG_OPTIONAL, struct.pack("!I", med))


def enc_communities(comms: Sequence[Tuple[int, int]]) -> bytes:
    body = b"".join(struct.pack("!HH", a, b) for a, b in comms)
    return _attr(ATTR_COMMUNITIES, FLAG_OPTIONAL | FLAG_TRANSITIVE, body)


def enc_large_communities(comms: Sequence[Tuple[int, int, int]]) -> bytes:
    body = b"".join(struct.pack("!III", a, b, c) for a, b, c in comms)
    return _attr(ATTR_LARGE_COMMUNITY, FLAG_OPTIONAL | FLAG_TRANSITIVE, body)


def enc_mp_reach_v6_nexthop(nexthop: str, link_local: Optional[str] = None) -> bytes:
    """MP_REACH_NLRI for TABLE_DUMP_V2 — the RFC 6396 section 4.3.4 exception.

    This is NOT the RFC 4760 wire format, and the difference is not cosmetic.
    RFC 6396 section 4.3.4:

        "Since the AFI, SAFI, and NLRI information is already encoded in the MRT
         record, only the Next Hop Address Length and Next Hop Address fields are
         included. The Reserved field is omitted."

    So the attribute body is exactly:

        Next Hop Address Length (1 octet) | Next Hop Address (n octets)

    Getting this wrong is silent and expensive. Emitting the full RFC 4760 body
    (AFI, SAFI, length, address, reserved) makes a conformant reader interpret the
    AFI's high byte, 0x00, as the next-hop length — so it sees a zero-length next
    hop. GoBGP then rejects the whole injection with
    "invalid nexthop: invalid IP" (netip.Addr's zero value stringifies as
    "invalid IP"), and because that aborts the gRPC stream, not one prefix loads.

    mrtparse does not catch this: it parses the full RFC 4760 shape, so it read the
    non-conformant form happily and the cross-check agreed with the bug. Only
    tests/mrtcheck.py now enforces the RFC 6396 layout.

    A 32-byte next hop (global + link-local) is permitted by RFC 2545 and is
    accepted here, though it is unusual in a table dump.
    """
    nh = ipaddress.IPv6Address(nexthop).packed
    if link_local:
        nh += ipaddress.IPv6Address(link_local).packed
    body = struct.pack("!B", len(nh)) + nh
    return _attr(ATTR_MP_REACH_NLRI, FLAG_OPTIONAL, body)


@dataclass
class PathAttrs:
    """Attribute set applied to a batch of prefixes."""

    as_path: Sequence[int]
    next_hop: str
    med: Optional[int] = None
    origin: int = 0
    communities: Sequence[Tuple[int, int]] = ()
    large_communities: Sequence[Tuple[int, int, int]] = ()
    as_set: Sequence[int] = ()

    def encode(self, v6: bool) -> bytes:
        out = enc_origin(self.origin) + enc_as_path(self.as_path, self.as_set)
        out += enc_mp_reach_v6_nexthop(self.next_hop) if v6 else enc_next_hop_v4(self.next_hop)
        if self.med is not None:
            out += enc_med(self.med)
        if self.communities:
            out += enc_communities(self.communities)
        if self.large_communities:
            out += enc_large_communities(self.large_communities)
        return out


# ---------------------------------------------------------------------------
# MRT TABLE_DUMP_V2 writer
# ---------------------------------------------------------------------------

MRT_TYPE_TABLE_DUMP_V2 = 13
SUB_PEER_INDEX_TABLE = 1
SUB_RIB_IPV4_UNICAST = 2
SUB_RIB_IPV6_UNICAST = 4

PEER_TYPE_AS4 = 0x02   # bit 1: 32-bit ASN
PEER_TYPE_IPV6 = 0x01  # bit 0: IPv6 peer address


def _mrt_msg(subtype: int, body: bytes, timestamp: int) -> bytes:
    return struct.pack("!IHHI", timestamp, MRT_TYPE_TABLE_DUMP_V2, subtype, len(body)) + body


def _pack_prefix(prefix: str) -> Tuple[int, bytes]:
    """Prefix length plus the minimum whole octets needed to hold it."""
    net = ipaddress.ip_network(prefix, strict=False)
    nbytes = (net.prefixlen + 7) // 8
    return net.prefixlen, net.network_address.packed[:nbytes]


@dataclass
class MrtPeer:
    ip: str
    asn: int
    bgp_id: str = "0.0.0.0"

    def encode(self) -> bytes:
        is_v6 = ":" in self.ip
        ptype = PEER_TYPE_AS4 | (PEER_TYPE_IPV6 if is_v6 else 0)
        out = struct.pack("!B", ptype)
        out += ipaddress.IPv4Address(self.bgp_id).packed
        out += ipaddress.ip_address(self.ip).packed
        out += struct.pack("!I", self.asn)
        return out


class MrtWriter:
    """Streaming MRT TABLE_DUMP_V2 writer.

    Usage:
        w = MrtWriter(path, peers=[MrtPeer("198.51.100.11", 64001)])
        w.open()
        w.add_v4("1.0.0.0/24", [(0, attrs)])
        w.close()

    Written incrementally so a 1M-prefix table never materialises in memory.
    """

    def __init__(self, path: str, peers: Sequence[MrtPeer], timestamp: int = 1700000000,
                 view_name: str = ""):
        self.path = path
        self.peers = list(peers)
        self.timestamp = timestamp
        self.view_name = view_name
        self._fh = None
        self._seq = 0

    def __enter__(self) -> "MrtWriter":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        self._fh = open(self.path, "wb")
        body = ipaddress.IPv4Address("0.0.0.0").packed
        name = self.view_name.encode()
        body += struct.pack("!H", len(name)) + name
        body += struct.pack("!H", len(self.peers))
        for p in self.peers:
            body += p.encode()
        self._fh.write(_mrt_msg(SUB_PEER_INDEX_TABLE, body, self.timestamp))

    def _add(self, subtype: int, prefix: str, entries: Sequence[Tuple[int, PathAttrs]],
             v6: bool) -> None:
        plen, praw = _pack_prefix(prefix)
        body = struct.pack("!I", self._seq)
        self._seq += 1
        body += struct.pack("!B", plen) + praw
        body += struct.pack("!H", len(entries))
        for peer_index, attrs in entries:
            enc = attrs.encode(v6=v6)
            body += struct.pack("!HIH", peer_index, self.timestamp, len(enc)) + enc
        self._fh.write(_mrt_msg(subtype, body, self.timestamp))

    def add_v4(self, prefix: str, entries: Sequence[Tuple[int, PathAttrs]]) -> None:
        self._add(SUB_RIB_IPV4_UNICAST, prefix, entries, v6=False)

    def add_v6(self, prefix: str, entries: Sequence[Tuple[int, PathAttrs]]) -> None:
        self._add(SUB_RIB_IPV6_UNICAST, prefix, entries, v6=True)

    @property
    def count(self) -> int:
        return self._seq

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


# ---------------------------------------------------------------------------
# high-level: build an MRT table for one session
# ---------------------------------------------------------------------------


def build_session_mrt(path: str, session, plan: PrefixPlan, dut_asn: int,
                      offset: int = 0, med_base: int = 0,
                      tag_community: Optional[Tuple[int, int]] = None,
                      transparent: bool = False) -> Dict[str, int]:
    """Write the MRT table one simulated peer will inject into its own gobgpd.

    AS_PATH is `[peer_asn, upstream, origin]` so paths look plausible and
    AS_PATH length actually varies between peers (which matters: bestpath
    tie-breaks on it, and the template's export policy matches on as-path).

    `transparent=True` omits the speaker's own ASN, which is how an RFC 7947
    IXP route server behaves: it does not prepend itself to AS_PATH. Use it for
    role=route-server fleets so the DUT sees the same AS_PATHs it would at a
    real exchange.
    """
    peers: List[MrtPeer] = []
    idx_v4 = idx_v6 = None
    if session.v4:
        idx_v4 = len(peers)
        peers.append(MrtPeer(session.v4, session.asn))
    if session.v6:
        idx_v6 = len(peers)
        peers.append(MrtPeer(session.v6, session.asn))

    rng = random.Random(plan.seed * 104729 + session.nlri_slot)
    written_v4 = written_v6 = 0

    with MrtWriter(path, peers) as w:
        if idx_v4 is not None and session.prefixes_v4:
            for i, pfx in enumerate(plan.session_v4(session.nlri_slot,
                                                    session.prefixes_v4, offset)):
                entries = []
                for p in range(max(1, session.paths_per_prefix)):
                    attrs = PathAttrs(
                        as_path=_as_path(session.asn, rng, dut_asn, transparent),
                        next_hop=session.v4,
                        med=med_base + (rng.randrange(0, 200) if med_base else 0) + p,
                        communities=list(tag_community and [tag_community] or []),
                        large_communities=[(session.asn, 0, 100 + p)],
                    )
                    entries.append((idx_v4, attrs))
                w.add_v4(pfx, entries)
                written_v4 += 1
        if idx_v6 is not None and session.prefixes_v6:
            for pfx in plan.session_v6(session.nlri_slot, session.prefixes_v6, offset):
                entries = []
                for p in range(max(1, session.paths_per_prefix)):
                    attrs = PathAttrs(
                        as_path=_as_path(session.asn, rng, dut_asn, transparent),
                        next_hop=session.v6,
                        med=med_base + (rng.randrange(0, 200) if med_base else 0) + p,
                        communities=list(tag_community and [tag_community] or []),
                        large_communities=[(session.asn, 0, 100 + p)],
                    )
                    entries.append((idx_v6, attrs))
                w.add_v6(pfx, entries)
                written_v6 += 1

    return {"prefixes_v4": written_v4, "prefixes_v6": written_v6,
            "rib_entries": written_v4 + written_v6}



def _as_path(peer_asn: int, rng: random.Random, dut_asn: int,
             transparent: bool) -> List[int]:
    """Plausible AS_PATH. Route servers (RFC 7947) do not prepend themselves."""
    tail = [next_safe_upstream(rng, dut_asn), next_safe_origin(rng, dut_asn)]
    return tail if transparent else [peer_asn] + tail


# AS_PATH members must also dodge the template's asn-bogons list, otherwise the
# DUT drops the route and the test measures the filter, not the RIB.
_SAFE_TRANSIT = [1299, 3356, 6939, 2914, 174, 3257, 6461, 6830, 1273, 12956]
_SAFE_ORIGIN_LO, _SAFE_ORIGIN_HI = 4000, 64000


def next_safe_upstream(rng: random.Random, dut_asn: int) -> int:
    while True:
        a = rng.choice(_SAFE_TRANSIT)
        if a != dut_asn:
            return a


def next_safe_origin(rng: random.Random, dut_asn: int) -> int:
    while True:
        a = rng.randrange(_SAFE_ORIGIN_LO, _SAFE_ORIGIN_HI)
        if a != dut_asn and a != 23456:
            return a


# ---------------------------------------------------------------------------
# ExaBGP batch command generation
# ---------------------------------------------------------------------------


def exabgp_announce_batches(prefixes: Iterable[str], next_hop: str,
                            as_path: Sequence[int], med: Optional[int] = None,
                            communities: Sequence[str] = (),
                            large_communities: Sequence[str] = (),
                            batch: int = 500,
                            neighbor: Optional[str] = None,
                            local_ip: Optional[str] = None,
                            withdraw: bool = False) -> Iterator[str]:
    """Yield `announce attributes ... nlri ...` lines, `batch` prefixes each.

    One attribute set, many NLRI, one UPDATE — the documented bulk form. Falls
    back to `withdraw route` per prefix when withdrawing, because
    `withdraw attributes` requires the original attribute set to match.
    """
    # `neighbor <dut>` on its own selects EVERY session in this ExaBGP process
    # that peers with that address. With two nasty sessions per container — which
    # is what the T2/T3/T4 profiles configure — each one then receives the
    # other's announcements too, and the DUT accepts 283 prefixes from a peer
    # the profile says announces 150. Add `local-ip` so the selector names one
    # session: ExaBGP builds each neighbour's identity as
    #   "neighbor <peer-address> local-ip <local> local-as <n> peer-as <n> ..."
    # (bgp/neighbor.py) and `extract_neighbors` accepts local-ip as a filter key
    # (reactor/api/command/limit.py). See FINDINGS.md H-47.
    scope = ""
    if neighbor:
        scope = f"neighbor {neighbor} "
        if local_ip:
            scope = f"neighbor {neighbor} local-ip {local_ip} "
    if withdraw:
        buf: List[str] = []
        for p in prefixes:
            buf.append(p)
            if len(buf) >= batch:
                for q in buf:
                    yield f"{scope}withdraw route {q}"
                buf = []
        for q in buf:
            yield f"{scope}withdraw route {q}"
        return

    attrs = [f"next-hop {next_hop}"]
    if as_path:
        attrs.append("as-path [ " + " ".join(str(a) for a in as_path) + " ]")
    if med is not None:
        attrs.append(f"med {med}")
    if communities:
        attrs.append("community [ " + " ".join(communities) + " ]")
    if large_communities:
        attrs.append("large-community [ " + " ".join(large_communities) + " ]")
    head = f"{scope}announce attributes " + " ".join(attrs) + " nlri"

    buf = []
    for p in prefixes:
        buf.append(p)
        if len(buf) >= batch:
            yield head + " " + " ".join(buf)
            buf = []
    if buf:
        yield head + " " + " ".join(buf)
