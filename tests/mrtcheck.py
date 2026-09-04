"""Dependency-free structural validation of MRT TABLE_DUMP_V2 files.

Why this exists
---------------
The selftest originally leaned on `mrtparse` to prove the generated MRT tables
were well-formed. That made the pass/fail path depend on an optional third-party
library whose API differs across versions: 1.x exposes the payload on
`entry.mrt` (attribute style), 2.x on `entry.data` (dict style). A 1.x install
therefore produced `AttributeError: 'Reader' object has no attribute 'data'` on
perfectly valid files — a tooling failure reported as an artefact failure, which
is the worst kind of test.

So structural validation is done here, with nothing but `struct`, and mrtparse is
kept as an *additional* cross-check that adapts to whichever API is installed.

What this checks is self-consistency, which is precisely the class of bug that
would break `gobgp mrt inject`:

  * every record header is well-formed and the record lengths tile the file
    exactly, with no truncation and no trailing bytes
  * the first record is a PEER_INDEX_TABLE and its peer entries consume exactly
    the declared body length
  * every RIB record carries `ceil(plen/8)` prefix bytes, a non-zero entry count,
    and entries that consume exactly the body
  * every attribute TLV walk consumes exactly the declared attribute length,
    honouring the extended-length flag
  * every RIB entry's peer index actually exists in the peer index table

It deliberately does not re-derive attribute *semantics* — that is what the
mrtparse cross-check and, ultimately, the live `gobgp mrt inject` are for.

Reference: RFC 6396 (MRT), sections 4.3.1 (PEER_INDEX_TABLE), 4.3.2/4.3.4
(RIB_IPV4_UNICAST / RIB_IPV6_UNICAST).
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

MRT_TABLE_DUMP_V2 = 13
SUB_PEER_INDEX_TABLE = 1
SUB_RIB_IPV4_UNICAST = 2
SUB_RIB_IPV6_UNICAST = 4

PEER_TYPE_IPV6 = 0x01
PEER_TYPE_AS4 = 0x02

FLAG_EXT_LEN = 0x10

ATTR_NAMES = {
    1: "ORIGIN", 2: "AS_PATH", 3: "NEXT_HOP", 4: "MULTI_EXIT_DISC",
    5: "LOCAL_PREF", 6: "ATOMIC_AGGREGATE", 7: "AGGREGATOR",
    8: "COMMUNITY", 9: "ORIGINATOR_ID", 10: "CLUSTER_LIST",
    14: "MP_REACH_NLRI", 15: "MP_UNREACH_NLRI", 16: "EXTENDED_COMMUNITY",
    17: "AS4_PATH", 18: "AS4_AGGREGATOR", 32: "LARGE_COMMUNITY",
}


class MrtStructureError(ValueError):
    """Raised with a byte offset so a malformed file can be located."""


@dataclass
class MrtSummary:
    path: str
    records: int = 0
    peers: List[Tuple[str, int]] = field(default_factory=list)
    prefixes_v4: int = 0
    prefixes_v6: int = 0
    rib_entries: int = 0
    attr_codes: Set[int] = field(default_factory=set)
    max_entries_per_prefix: int = 0
    bytes_total: int = 0
    first_prefix_v4: Optional[str] = None
    first_prefix_v6: Optional[str] = None

    @property
    def attr_names(self) -> List[str]:
        return sorted(ATTR_NAMES.get(c, f"UNKNOWN({c})") for c in self.attr_codes)

    def __str__(self) -> str:
        return (f"{self.records} records, {len(self.peers)} peer(s), "
                f"{self.prefixes_v4} v4 + {self.prefixes_v6} v6 prefixes, "
                f"{self.rib_entries} RIB entries")


def _u8(b: bytes, o: int) -> int:
    return b[o]


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("!H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("!I", b, o)[0]


def _walk_attributes(body: bytes, base_off: int, v6: bool = False) -> Set[int]:
    """Walk a BGP path-attribute block, requiring it to consume exactly.

    A TLV walk that overruns or under-runs is the single most likely encoding
    bug, and it is exactly what makes a peer reject an UPDATE.
    """
    codes: Set[int] = set()
    p = 0
    n = len(body)
    while p < n:
        if p + 2 > n:
            raise MrtStructureError(
                f"offset {base_off + p}: attribute header truncated "
                f"({n - p} byte(s) left, need at least 2)")
        flags = body[p]
        code = body[p + 1]
        p += 2
        if flags & FLAG_EXT_LEN:
            if p + 2 > n:
                raise MrtStructureError(
                    f"offset {base_off + p}: extended attribute length truncated")
            alen = _u16(body, p)
            p += 2
        else:
            if p + 1 > n:
                raise MrtStructureError(
                    f"offset {base_off + p}: attribute length truncated")
            alen = body[p]
            p += 1
        if p + alen > n:
            raise MrtStructureError(
                f"offset {base_off + p}: attribute {ATTR_NAMES.get(code, code)} "
                f"declares {alen} byte(s) but only {n - p} remain")
        # cheap semantic sanity on the fixed-width well-known attributes
        if code == 1 and alen != 1:
            raise MrtStructureError(f"ORIGIN length {alen}, must be 1")
        if code == 3 and alen != 4:
            raise MrtStructureError(f"NEXT_HOP length {alen}, must be 4")
        if code == 4 and alen != 4:
            raise MrtStructureError(f"MULTI_EXIT_DISC length {alen}, must be 4")
        if code == 32 and alen % 12:
            raise MrtStructureError(
                f"LARGE_COMMUNITY length {alen} is not a multiple of 12 (RFC 8092)")
        if code == 8 and alen % 4:
            raise MrtStructureError(
                f"COMMUNITY length {alen} is not a multiple of 4 (RFC 1997)")
        if code == 14:
            # RFC 6396 section 4.3.4: inside TABLE_DUMP_V2 the MP_REACH_NLRI body
            # is ONLY the Next Hop Address Length and the Next Hop Address. AFI,
            # SAFI, the Reserved octet and the NLRI are omitted, because the MRT
            # record header already carries them.
            #
            # This check exists because the writer originally emitted the full
            # RFC 4760 body. mrtparse accepted it, so the cross-check agreed with
            # the bug, and only GoBGP rejected it — reading the AFI's high byte
            # (0x00) as the next-hop length and reporting
            # "invalid nexthop: invalid IP".
            if alen < 1:
                raise MrtStructureError("MP_REACH_NLRI body is empty")
            nhlen = body[p]
            if nhlen not in (4, 16, 32):
                raise MrtStructureError(
                    f"MP_REACH_NLRI next-hop length {nhlen} is not 4, 16 or 32. "
                    f"If this is 0, the body is probably encoded in the full "
                    f"RFC 4760 form (AFI/SAFI/len/addr/reserved) instead of the "
                    f"reduced RFC 6396 section 4.3.4 form (len/addr), and the "
                    f"AFI's high byte is being read as the length.")
            if alen != 1 + nhlen:
                raise MrtStructureError(
                    f"MP_REACH_NLRI declares {alen} body byte(s) but the RFC 6396 "
                    f"form requires exactly 1 + {nhlen} = {1 + nhlen}. Anything "
                    f"extra means AFI/SAFI/Reserved/NLRI were not omitted.")
            if v6 and nhlen == 4:
                raise MrtStructureError(
                    "MP_REACH_NLRI on an IPv6 record carries a 4-byte next hop")
        if code == 2:
            # AS_PATH: segments of type(1) count(1) then count*4 bytes (MRT
            # TABLE_DUMP_V2 always uses 4-byte ASNs, RFC 6396 section 4.3.4)
            q = p
            end = p + alen
            while q < end:
                if q + 2 > end:
                    raise MrtStructureError(
                        f"offset {base_off + q}: AS_PATH segment header truncated")
                seg_type, seg_count = body[q], body[q + 1]
                if seg_type not in (1, 2, 3, 4):
                    raise MrtStructureError(
                        f"offset {base_off + q}: AS_PATH segment type {seg_type} "
                        f"is not AS_SET/AS_SEQUENCE/CONFED_SEQUENCE/CONFED_SET")
                q += 2 + seg_count * 4
            if q != end:
                raise MrtStructureError(
                    f"AS_PATH segments consume {q - p} bytes, declared {alen}")
        codes.add(code)
        p += alen
    return codes


def check_file(path: str, expect_v4: Optional[int] = None,
               expect_v6: Optional[int] = None) -> MrtSummary:
    """Validate one MRT file. Raises MrtStructureError on any inconsistency."""
    with open(path, "rb") as fh:
        buf = fh.read()

    s = MrtSummary(path=path, bytes_total=len(buf))
    if not buf:
        raise MrtStructureError("file is empty")

    peer_afi: List[bool] = []          # True = IPv6 peer address
    peer_count = 0
    off = 0
    first = True

    while off < len(buf):
        if off + 12 > len(buf):
            raise MrtStructureError(
                f"offset {off}: truncated MRT header "
                f"({len(buf) - off} byte(s) left, need 12)")
        _ts, rtype, subtype, length = struct.unpack_from("!IHHI", buf, off)
        body_off = off + 12
        if body_off + length > len(buf):
            raise MrtStructureError(
                f"offset {off}: record declares {length} body byte(s) but only "
                f"{len(buf) - body_off} remain — file is truncated")
        body = buf[body_off:body_off + length]

        if rtype != MRT_TABLE_DUMP_V2:
            raise MrtStructureError(
                f"offset {off}: MRT type {rtype}, expected "
                f"{MRT_TABLE_DUMP_V2} (TABLE_DUMP_V2)")

        if first:
            if subtype != SUB_PEER_INDEX_TABLE:
                raise MrtStructureError(
                    f"first record subtype is {subtype}, expected "
                    f"{SUB_PEER_INDEX_TABLE} (PEER_INDEX_TABLE). gobgp needs the "
                    f"peer table before any RIB record.")
            first = False

        if subtype == SUB_PEER_INDEX_TABLE:
            p = 4                                   # collector BGP id
            if len(body) < 6:
                raise MrtStructureError("PEER_INDEX_TABLE body too short")
            vlen = _u16(body, p); p += 2 + vlen
            if p + 2 > len(body):
                raise MrtStructureError("PEER_INDEX_TABLE peer count truncated")
            peer_count = _u16(body, p); p += 2
            for i in range(peer_count):
                if p + 1 > len(body):
                    raise MrtStructureError(f"peer {i}: type octet truncated")
                ptype = body[p]; p += 1
                p += 4                              # peer BGP id
                is6 = bool(ptype & PEER_TYPE_IPV6)
                alen = 16 if is6 else 4
                aslen = 4 if (ptype & PEER_TYPE_AS4) else 2
                if p + alen + aslen > len(body):
                    raise MrtStructureError(f"peer {i}: address/ASN truncated")
                raw = body[p:p + alen]; p += alen
                ip = str(ipaddress.IPv6Address(raw) if is6
                         else ipaddress.IPv4Address(raw))
                asn = _u32(body, p) if aslen == 4 else _u16(body, p)
                p += aslen
                peer_afi.append(is6)
                s.peers.append((ip, asn))
            if p != len(body):
                raise MrtStructureError(
                    f"PEER_INDEX_TABLE: peer entries consume {p} of {len(body)} "
                    f"declared body bytes")

        elif subtype in (SUB_RIB_IPV4_UNICAST, SUB_RIB_IPV6_UNICAST):
            v6 = subtype == SUB_RIB_IPV6_UNICAST
            maxlen = 128 if v6 else 32
            if len(body) < 7:
                raise MrtStructureError("RIB record body too short")
            p = 4                                   # sequence number
            plen = body[p]; p += 1
            if plen > maxlen:
                raise MrtStructureError(
                    f"prefix length {plen} exceeds {maxlen} for this AFI")
            nbytes = (plen + 7) // 8
            if p + nbytes > len(body):
                raise MrtStructureError("prefix bytes truncated")
            praw = body[p:p + nbytes]; p += nbytes
            padded = praw + b"\x00" * ((16 if v6 else 4) - nbytes)
            pfx = f"{ipaddress.IPv6Address(padded) if v6 else ipaddress.IPv4Address(padded)}/{plen}"
            if v6:
                s.prefixes_v6 += 1
                if s.first_prefix_v6 is None:
                    s.first_prefix_v6 = pfx
            else:
                s.prefixes_v4 += 1
                if s.first_prefix_v4 is None:
                    s.first_prefix_v4 = pfx

            if p + 2 > len(body):
                raise MrtStructureError(f"{pfx}: entry count truncated")
            ecount = _u16(body, p); p += 2
            if ecount == 0:
                raise MrtStructureError(f"{pfx}: entry count is 0")
            s.max_entries_per_prefix = max(s.max_entries_per_prefix, ecount)
            for i in range(ecount):
                if p + 8 > len(body):
                    raise MrtStructureError(f"{pfx} entry {i}: header truncated")
                pidx = _u16(body, p); p += 2
                p += 4                              # originated time
                alen = _u16(body, p); p += 2
                if pidx >= peer_count:
                    raise MrtStructureError(
                        f"{pfx} entry {i}: peer index {pidx} is not in the peer "
                        f"index table (which has {peer_count} entries)")
                if v6 != peer_afi[pidx]:
                    raise MrtStructureError(
                        f"{pfx} entry {i}: peer index {pidx} is an "
                        f"{'IPv6' if peer_afi[pidx] else 'IPv4'} peer but the "
                        f"record is {'IPv6' if v6 else 'IPv4'} unicast")
                if p + alen > len(body):
                    raise MrtStructureError(
                        f"{pfx} entry {i}: attributes declare {alen} byte(s), "
                        f"{len(body) - p} remain")
                codes = _walk_attributes(body[p:p + alen], body_off + p, v6=v6)
                s.attr_codes |= codes
                # RFC 6396 section 4.3.4: the IPv6 next-hop rides in
                # MP_REACH_NLRI; a v6 RIB entry without it has no next-hop.
                if v6 and 14 not in codes:
                    raise MrtStructureError(
                        f"{pfx} entry {i}: IPv6 RIB entry has no MP_REACH_NLRI, "
                        f"so it carries no next-hop")
                if not v6 and 3 not in codes:
                    raise MrtStructureError(
                        f"{pfx} entry {i}: IPv4 RIB entry has no NEXT_HOP attribute")
                p += alen
                s.rib_entries += 1
            if p != len(body):
                raise MrtStructureError(
                    f"{pfx}: entries consume {p} of {len(body)} declared body bytes")
        else:
            raise MrtStructureError(
                f"offset {off}: unexpected TABLE_DUMP_V2 subtype {subtype}")

        s.records += 1
        off = body_off + length

    if off != len(buf):
        raise MrtStructureError(
            f"{len(buf) - off} trailing byte(s) after the last record")
    if not s.peers:
        raise MrtStructureError("no peers in the peer index table")

    if expect_v4 is not None and s.prefixes_v4 != expect_v4:
        raise MrtStructureError(
            f"{s.prefixes_v4} IPv4 prefixes, profile declares {expect_v4}")
    if expect_v6 is not None and s.prefixes_v6 != expect_v6:
        raise MrtStructureError(
            f"{s.prefixes_v6} IPv6 prefixes, profile declares {expect_v6}")
    return s


if __name__ == "__main__":
    import sys
    rc = 0
    for arg in sys.argv[1:]:
        try:
            print(f"ok   {arg}: {check_file(arg)}")
        except MrtStructureError as exc:
            print(f"FAIL {arg}: {exc}")
            rc = 1
    raise SystemExit(rc)
