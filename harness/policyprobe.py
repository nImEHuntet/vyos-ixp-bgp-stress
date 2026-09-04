"""Policy probes and the RFC 7606 malformed-attribute suite.

A stress test that only measures convergence time answers "how fast" but not
"was it still correct". These probes answer the second question, continuously and
under load: each one is a single prefix with a known property, injected via
ExaBGP, whose accept/reject verdict on the DUT is then asserted against the
template's stated intent.

That distinction matters here because reading the template turned up policy that
does not do what its own descriptions claim. See `PROBES` below: several are
expected to FAIL against the shipped template, and the harness reports them as
template defects rather than as DUT faults.

The malformed-attribute suite is separate and uses ExaBGP's generic attribute
primitive:

    attribute [ 0x<code> 0x<flags> 0x<payload> ]

ExaBGP's parser does no semantic validation of that form at all — it checks only
that the three tokens are hex and the payload has even length — so arbitrary
type codes, deliberately wrong flag bits, and malformed payloads all reach the
wire. GoBGP has no equivalent. The point is RFC 7606 "treat-as-withdraw" and
"attribute discard" behaviour: a conformant speaker must not reset the session
for most of these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# policy probes
# ---------------------------------------------------------------------------


@dataclass
class Probe:
    """One prefix with a known property and an expected verdict."""

    pid: str
    afi: str                      # ipv4 | ipv6
    prefix: str
    expect: str                   # "accept" | "reject"
    rationale: str
    # ExaBGP attribute clause fragments appended to `announce route`
    attrs: str = ""
    # Set when the shipped template is expected NOT to enforce its own intent.
    template_defect: Optional[str] = None
    tags: Sequence[str] = ()


def build_probes(dut_asn: int, own_supernet4: str, own_supernet6: str,
                 peer_v4: str, peer_v6: str, peer_asn: int = 0) -> List[Probe]:
    """Probe set derived directly from the template's policy pipeline.

    Import order per the template's own comment:
      bogon ASN -> bogon prefix -> prefix size -> RPKI -> reject own prefixes
      -> scrub blackhole -> tag with IXP community -> set local-pref
    """
    P: List[Probe] = []

    # --- bogon prefixes: ebgp4-import rule 20 is a real deny, so these must go
    P.append(Probe(
        "bogon-rfc1918", "ipv4", "10.13.37.0/24", "reject",
        "ipv4-bogons rule 20 (10.0.0.0/8 le 32) and ebgp4-import rule 20 action deny",
        tags=("bogon",),
    ))
    P.append(Probe(
        "bogon-testnet", "ipv4", "192.0.2.128/25", "reject",
        "ipv4-bogons rule 70 (192.0.2.0/24 le 32)",
        tags=("bogon",),
    ))
    P.append(Probe(
        "bogon-v6-ula", "ipv6", "fc00:dead::/48", "reject",
        "ipv6-bogons rule 80 (fc00::/7 le 128) and ebgp6-import rule 20 action deny",
        tags=("bogon",),
    ))
    P.append(Probe(
        "bogon-v6-doc-old", "ipv6", "2001:db8:ffff::/48", "reject",
        "ipv6-bogons rule 50 (2001:db8::/32 le 128)",
        tags=("bogon",),
    ))

    # --- RFC 9637: the new IPv6 documentation space is NOT in the template's
    #     ipv6-bogons list (which carries 3ffe::/16, the retired 6bone block).
    P.append(Probe(
        "bogon-v6-doc-rfc9637", "ipv6", "3fff:dead:beef::/48", "reject",
        "RFC 9637 reserved 3fff::/20 as IPv6 documentation space in 2024; a bogon "
        "list should reject it",
        template_defect=(
            "ipv6-bogons has no entry for 3fff::/20 (RFC 9637). It carries 3ffe::/16, "
            "the retired 6bone prefix, which is a different block. Add: "
            "set policy prefix-list6 ipv6-bogons rule 115 action 'permit' / "
            "le '128' / prefix '3fff::/20'"
        ),
        tags=("bogon", "rfc9637"),
    ))

    # --- prefix length acceptability. These are the interesting ones: the
    #     template's rules 25/50 are written as `permit` with `continue`/
    #     `on-match next`, which in FRR route-map semantics does NOT reject a
    #     non-matching prefix — a rule that does not match simply falls through
    #     to the next rule. So the size filter is a no-op.
    P.append(Probe(
        "toolong-v4-25", "ipv4", "44.44.44.0/25", "reject",
        "ipv4-acceptable permits only ge 8 le 24; ebgp4-import rule 25 is described "
        "as 'Only allow /8 to /24'",
        template_defect=(
            "ebgp4-import rule 25 is `action permit` + `match ipv4-acceptable` + "
            "`continue 30`. In FRR a rule whose match clause fails falls through to "
            "the next rule, so a /25 is never denied — it reaches rule 30 and is "
            "ultimately permitted by rule 1000. The size check does not filter. "
            "Fix: add a deny rule for the complement, e.g. "
            "`set policy prefix-list ipv4-toolong rule 10 action permit ge 25 le 32 "
            "prefix 0.0.0.0/0` then `set policy route-map ebgp4-import rule 22 "
            "action deny match ip address prefix-list ipv4-toolong`."
        ),
        tags=("prefixlen",),
    ))
    P.append(Probe(
        "toolong-v4-32", "ipv4", "44.44.45.1/32", "reject",
        "ipv4-acceptable permits only ge 8 le 24",
        template_defect="Same root cause as toolong-v4-25.",
        tags=("prefixlen",),
    ))
    P.append(Probe(
        "toolong-v6-64", "ipv6", "3fff:200:1::/64", "reject",
        "ipv6-acceptable permits only ge 12 le 48; ebgp6-import rule 25 is described "
        "as 'Only allow /12 to /48'",
        template_defect=(
            "ebgp6-import rule 25 has the same permit+continue construction as its "
            "IPv4 counterpart, so a /64 is not denied. Same fix pattern."
        ),
        tags=("prefixlen",),
    ))
    P.append(Probe(
        "acceptable-v4-24", "ipv4", "44.44.46.0/24", "accept",
        "a /24 in non-bogon space with a clean AS_PATH must be accepted",
        tags=("baseline",),
    ))
    P.append(Probe(
        "acceptable-v6-48", "ipv6", "3fff:300:2::/48", "accept",
        "a /48 from RFC 9637 space with a clean AS_PATH must be accepted",
        template_defect=(
            "Depends on ipv6-bogons NOT covering 3fff::/20. If you apply the "
            "RFC 9637 fix suggested by bogon-v6-doc-rfc9637, this probe flips to "
            "reject and the harness's synthetic v6 NLRI pool must move too."
        ),
        tags=("baseline",),
    ))

    # --- own space: own-more-specific4 is ge 25, so a /25 inside our supernet
    #     is denied by rule 40 (a genuine deny). Note the interaction: the same
    #     /25 is also caught by the (broken) size check, so this probe only
    #     proves rule 40 works if the prefix is inside own space.
    net4 = own_supernet4.split("/")[0].rsplit(".", 2)[0]
    P.append(Probe(
        "own-more-specific-v4", "ipv4", f"{net4}.200.128/25", "reject",
        "own-more-specific4 (ge 25 le 32 inside our supernet) and ebgp4-import "
        "rule 40 action deny — a real deny rule",
        tags=("own",),
    ))
    P.append(Probe(
        "own-supernet-exact-v4", "ipv4", own_supernet4, "reject",
        "hearing our own supernet back from a peer",
        template_defect=(
            "own-more-specific4 is `ge 25 le 32`, so it does not match the supernet "
            "itself. ebgp4-import has no rule matching own-supernet4 on import, so "
            "an exact-match hijack of our own aggregate is ACCEPTED. Fix: add a deny "
            "for prefix-list own-supernet4 to the import path."
        ),
        tags=("own", "hijack"),
    ))

    # --- bogon ASNs. asn-bogons is called by ebgp4-import rule 10 which is
    #     `action permit` + `call asn-bogons` + `continue 20`. The called
    #     route-map denies, and in FRR a `call` that denies terminates
    #     processing with a deny — so this one does work.
    P.append(Probe(
        "bogon-asn-private", "ipv4", "45.45.45.0/24", "reject",
        "asn-bogons rule 40 matches 64512-65535; called from ebgp4-import rule 10",
        attrs=_as_path(peer_asn, 65001, 3356, 15169),
        tags=("asn",),
    ))
    P.append(Probe(
        "bogon-asn-zero", "ipv4", "45.45.46.0/24", "reject",
        "asn-bogons rule 10 matches AS 0 (RFC 7607)",
        attrs=_as_path(peer_asn, 0, 3356),
        tags=("asn",),
    ))
    P.append(Probe(
        "bogon-asn-trans", "ipv4", "45.45.47.0/24", "reject",
        "asn-bogons rule 20 matches AS_TRANS 23456 (RFC 4893)",
        attrs=_as_path(peer_asn, 23456, 3356),
        tags=("asn",),
    ))
    P.append(Probe(
        "bogon-asn-doc", "ipv4", "45.45.48.0/24", "reject",
        "asn-bogons rule 30 matches documentation ASNs 64496-64511",
        attrs=_as_path(peer_asn, 64500, 3356),
        tags=("asn",),
    ))

    # --- blackhole community scrubbing. scrub-blackhole deletes 65535:666 on
    #     import; the export policy then denies anything still carrying it.
    P.append(Probe(
        "blackhole-scrub", "ipv4", "46.46.46.0/24", "accept",
        "65535:666 must be scrubbed on import (scrub-blackhole) but the prefix "
        "itself accepted",
        attrs="community [ 65535:666 ]",
        tags=("community", "blackhole"),
    ))

    # --- next-hop based IXP tagging is IPv4-only in this template.
    P.append(Probe(
        "ixp-tag-v6", "ipv6", "3fff:300:3::/48", "accept",
        "IPv6 routes from IXP-2 should carry the IXP-2 large-community, mirroring "
        "the IPv4 path",
        template_defect=(
            "There is no `ebgp6-import-ixp2` route-map. Peer-groups ixp2-peer6 and "
            "ixp2-rs6 both use the generic `ebgp6-import`, which has no next-hop-based "
            "IXP detection and no community/local-pref tagging. IPv4 gets per-IXP "
            "tagging via ebgp4-import rules 100/120; IPv6 from IXP-2 gets none, so "
            "those routes keep the default local-pref of 100 while IXP-1 IPv6 gets "
            "275. Verify with: show bgp ipv6 unicast <prefix> — check for the "
            "large-community and localpref."
        ),
        tags=("tagging", "v6-asymmetry"),
    ))

    return P


def _as_path(peer_asn: int, *rest: int) -> str:
    """`as-path [ ... ]` beginning with the speaker's own ASN.

    Every AS_PATH the probe and malformed suites emit must start with the
    announcing speaker's ASN unless the AS_PATH itself is the thing under test.
    FRR enables `bgp enforce-first-as` by default from 10.0
    (FRR_CFG_DEFAULT_BOOL(BGP_ENFORCE_FIRST_AS), bgpd/bgp_vty.c) and treats a
    violation as withdraw rather than a reset (bgp_attr_aspath_check returns
    BGP_ATTR_PARSE_WITHDRAW, bgpd/bgp_attr.c). On such an image a probe with a
    third-party first AS is dropped before any policy runs, so the probe would
    report "reject" and look like it had validated a filter it never reached.

    peer_asn=0 reproduces the old behaviour and is only for unit tests.
    """
    asns = [a for a in ((peer_asn,) + rest) if a or a == 0]
    if not peer_asn:
        asns = list(rest)
    return "as-path [ " + " ".join(str(a) for a in asns) + " ]"


def neighbor_selector(dut_addr: str, local_addr: Optional[str] = None) -> str:
    """An ExaBGP API neighbour selector that names exactly one session.

    `neighbor <dut-address>` alone matches EVERY session in the ExaBGP process
    that peers with that address. The T2/T3/T4 profiles put two nasty sessions
    in one container, both peering with the same DUT fabric address, so every
    command reached both: at T2 each nasty peer announced 150 v4 prefixes per
    the profile and the DUT accepted 283 from it, and the malformed suite was
    delivered twice — the run-2 log shows the same case logged against
    198.51.96.95 and 198.51.96.96.

    ExaBGP builds each neighbour's identity as
        "neighbor <peer-address> local-ip <local> local-as <n> peer-as <n> ..."
    (bgp/neighbor.py) and `extract_neighbors` accepts `local-ip` as a filter key
    (reactor/api/command/limit.py), so adding it disambiguates.
    See FINDINGS.md H-47.
    """
    if local_addr:
        return f"neighbor {dut_addr} local-ip {local_addr}"
    return f"neighbor {dut_addr}"


def probe_announce_commands(probes: Sequence[Probe], peer_v4: str, peer_v6: str,
                            dut_v4: str, dut_v6: str,
                            default_as_path: Optional[str] = None,
                            peer_asn: int = 0) -> List[str]:
    """ExaBGP API lines that announce every probe prefix."""
    if default_as_path is None:
        default_as_path = _as_path(peer_asn, 3356, 15169)
    out: List[str] = ["# policy probes"]
    for p in probes:
        nh = peer_v4 if p.afi == "ipv4" else peer_v6
        nb = dut_v4 if p.afi == "ipv4" else dut_v6
        attrs = p.attrs if p.attrs else default_as_path
        if "as-path" not in attrs:
            attrs = f"{attrs} {default_as_path}"
        out.append(f"{neighbor_selector(nb, nh)} announce route {p.prefix} "
                   f"next-hop {nh} {attrs}")
    return out


def probe_withdraw_commands(probes: Sequence[Probe], dut_v4: str, dut_v6: str,
                            peer_v4: Optional[str] = None,
                            peer_v6: Optional[str] = None) -> List[str]:
    out: List[str] = []
    for p in probes:
        nb = dut_v4 if p.afi == "ipv4" else dut_v6
        lo = peer_v4 if p.afi == "ipv4" else peer_v6
        out.append(f"{neighbor_selector(nb, lo)} withdraw route {p.prefix}")
    return out


# ---------------------------------------------------------------------------
# RFC 7606 malformed-attribute suite
# ---------------------------------------------------------------------------


@dataclass
class Malformed:
    mid: str
    afi: str
    prefix: str
    attrs: str
    expect_session: str      # "up" | "reset-tolerated"
    expect_route: str        # "absent" | "present" | "either"
    rationale: str
    tags: Sequence[str] = ()
    # Minimum ExaBGP major version whose *config parser* accepts this string.
    # The container always runs 5.x, so this only affects host-side offline
    # validation: on a 4.x host the selftest skips these rather than failing.
    requires_exabgp: Optional[str] = None
    # True when `exabgp validate -r` rejects the statement even though ExaBGP
    # actually transmits it correctly at runtime. `-r` re-serialises and re-parses
    # each route, and a hand-encoded AS_PATH does not survive that round trip —
    # but `exabgp server` sends the intended bytes. Confirmed by capturing the
    # UPDATE off the wire; see the note below on which validation mode gates what.
    exabgp_r_rejects: bool = False
    #: A verified defect in the receiving implementation, quoted with its source
    #: location and version bounds. Set this so a confirmed implementation bug is
    #: reported as such rather than as an unexplained harness failure - the same
    #: role `Probe.template_defect` plays for the template.
    known_defect: Optional[str] = None
    #: A log substring the receiver should emit when this case is exercised. The
    #: isolation pass greps for it and records whether it appeared, so the
    #: decisive line ends up in the artefact instead of whatever else happened to
    #: be in the window.
    expect_log: Optional[str] = None


# ---------------------------------------------------------------------------
# ExaBGP clause-precedence rule — verified on the wire, and a real trap
# ---------------------------------------------------------------------------
#
# When a route statement carries both a typed clause (`as-path [...]`) and a
# generic attribute for the same attribute code (`attribute [ 0x02 ... ]`), the
# clause that appears FIRST wins and the second is silently ignored.
#
# Confirmed by capturing the UPDATE off the wire from ExaBGP 5.0.9:
#
#   as-path [ 3356 ] attribute [ 0x02 0x40 0x03... ]   -> AS_SEQUENCE [3356]
#   attribute [ 0x02 0x40 0x03... ] as-path [ 3356 ]   -> CONFED_SEQUENCE
#
# This matters because the failure is silent: the first form validates, sends a
# perfectly ordinary route, and the test then asserts something that was never
# tested. Any case below that hand-encodes AS_PATH therefore puts `attribute`
# FIRST, and tests/selftest.py asserts that ordering as a regression guard.
#
# ---------------------------------------------------------------------------
# Which ExaBGP validation mode gates what — also established empirically
# ---------------------------------------------------------------------------
#
#   exabgp validate -n   structural config validity. Rejects unknown keywords and
#                        invalid prefixes. Accepts everything this suite ships,
#                        and matches whether `exabgp server` will start.
#   exabgp validate -r   additionally re-serialises and re-parses each route, so
#                        it catches attribute-level breakage (a MED of the wrong
#                        length, an out-of-range ORIGIN, an empty AS_PATH).
#
# `-r` is stricter than the runtime, though: it rejects a hand-encoded AS_PATH
# that `exabgp server` demonstrably transmits correctly. So `-n` is the gate for
# every case, and `-r` is an additional gate for every case except those marked
# `exabgp_r_rejects=True`, which carry wire proof instead.


#: Tags excluded from the malformed suite by default.
#:
#: `martian` covers the two cases that provoke E-4 — FRR <= 10.6.x sends
#: NOTIFICATION 3/8 and resets the session on a martian IPv4 NEXT_HOP, which
#: RFC 7606 section 3(e) makes a MUST NOT. That defect is confirmed, is fixed
#: upstream in frr-10.7.0, and cannot be fixed in VyOS 1.5.1 / FRR 10.5.2 from
#: here. Continuing to fire it during a stress run costs a real session reset
#: per burst and contaminates every other measurement taken in that window —
#: prefix drift, convergence, flap recovery — with an outage the harness caused
#: on purpose for a result already known. Excluded by default; still runnable by
#: name (`--only nexthop-zero`) to reproduce the defect deliberately.
EXCLUDED_TAGS: Tuple[str, ...] = ("martian",)


def build_malformed(peer_v4: str, peer_v6: str, dut_asn: int = 64000,
                    peer_asn: int = 0,
                    exclude_tags: Sequence[str] = EXCLUDED_TAGS
                    ) -> List[Malformed]:
    """Attribute-level negative tests.

    RFC 7606 replaced "reset the session on any attribute error" with graded
    handling: attribute discard, treat-as-withdraw, AFI/SAFI disable, and session
    reset only as a last resort. Every case below should therefore leave the
    session UP. **A session reset is the finding.**

    Every string here was validated against ExaBGP 5.0.9 with
    `exabgp validate -r`. See NOT_ACHIEVABLE_WITH_EXABGP for cases that a
    byte-level injector would be needed for — ExaBGP re-decodes known attribute
    codes, so it cannot emit a known attribute with an invalid length or value.
    """
    M: List[Malformed] = []
    # The two AS_PATHs used by every case that is not itself an AS_PATH test.
    # They must start with this speaker's own ASN; see _as_path().
    _ap = _as_path(peer_asn, 3356, 15169)
    _ap6 = _as_path(peer_asn, 6939, 20000)

    # --- unrecognised attribute type codes -------------------------------
    #
    # The attribute FLAGS are the whole test here, and the first version of these
    # two cases got them wrong. Both used 0x60 / 0x70, which are
    # Transitive|Partial and Transitive|Partial|ExtendedLength - the OPTIONAL bit
    # (0x80) is clear in both. An attribute with the Optional bit clear claims to
    # be a *well-known* attribute, so those two cases were testing the
    # unrecognised-well-known path, not the unrecognised-optional path they were
    # named for, and their "route must be present" expectation was wrong.
    #
    # The earlier comment claimed ExaBGP's selfcheck requires Transitive|Partial
    # and that "0x80-only is not available". That is not true of ExaBGP 5.0.9.
    # Verified by packing each attribute through ExaBGP's own encoder and reading
    # the wire bytes - the flag byte is transmitted verbatim:
    #
    #   0x80 -> 80990400000064     Optional
    #   0xa0 -> a0990400000064     Optional|Partial
    #   0xc0 -> c0990400000064     Optional|Transitive
    #   0xe0 -> e0990400000064     Optional|Transitive|Partial
    #
    # `exabgp validate -r` rejects 0x80 and 0xc0 because its round trip
    # re-serialises an unrecognised optional-transitive attribute with PARTIAL
    # set, as RFC 4271 section 5 requires of a receiver passing it on. The server
    # still transmits the flags as written, so those two carry
    # exabgp_r_rejects=True (the same treatment as the hand-encoded AS_PATH
    # cases).
    M.append(Malformed(
        "unknown-attr-optional", "ipv4", "47.47.1.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x99 0x80 0x00000064 ]",
        "up", "present",
        "Unallocated attribute type 153 with ONLY the Optional bit set, i.e. "
        "optional non-transitive. RFC 4271 section 5: an unrecognised "
        "non-transitive optional attribute must be quietly ignored and not passed "
        "along. The route itself must be accepted untouched.",
        tags=("rfc7606", "unknown-attr", "optional"),
        exabgp_r_rejects=True,
    ))
    M.append(Malformed(
        "unknown-attr-optional-transitive", "ipv4", "47.47.2.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x99 0xc0 0x00000064 ]",
        "up", "present",
        "Type 153 with Optional|Transitive and PARTIAL clear - what an origin "
        "router emits. RFC 4271 section 5: the receiver must accept the route, "
        "retain the attribute, SET the Partial bit and re-advertise it. Check the "
        "re-advertised copy on a downstream peer to confirm Partial was set.",
        tags=("rfc7606", "unknown-attr", "optional", "transitive"),
        exabgp_r_rejects=True,
    ))
    M.append(Malformed(
        "unknown-attr-optional-transitive-partial", "ipv4", "47.47.20.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x99 0xe0 0x00000064 ]",
        "up", "present",
        "Type 153 with Optional|Transitive|Partial - what a router that has "
        "already passed the attribute through emits. Same requirement as above, "
        "and this spelling survives `exabgp validate -r`, so it is the variant to "
        "trust if the other two are ever skipped for tooling reasons.",
        tags=("rfc7606", "unknown-attr", "optional", "transitive"),
    ))
    # The two original spellings, kept for what they actually test: an attribute
    # with the Optional bit CLEAR, i.e. an unrecognised well-known attribute.
    M.append(Malformed(
        "unknown-wellknown-attr-transitive", "ipv4", "47.47.21.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x99 0x60 0x00000064 ]",
        "reset-tolerated", "either",
        "Type 153 with Transitive|Partial and the Optional bit CLEAR, so it "
        "claims to be a well-known attribute the receiver does not recognise. "
        "RFC 4271 section 6.3 mandates a NOTIFICATION with subcode Unrecognized "
        "Well-known Attribute. Observed on FRR 10.5.2: no NOTIFICATION and no "
        "reset - it logs \"(153) attribute received, while it is not known how to "
        "handle it, treating as withdraw\" and treats the UPDATE as a withdrawal "
        "(bgp_attr_unknown -> bgp_attr_malformed with "
        "BGP_NOTIFY_UPDATE_UNREC_ATTR, which RFC 7606 graded handling turns into "
        "treat-as-withdraw). That is more lenient than RFC 4271 requires and is "
        "the safer behaviour, but it is a deviation worth recording.",
        tags=("rfc4271", "unknown-attr", "wellknown"),
    ))
    M.append(Malformed(
        "unknown-wellknown-attr-extlen", "ipv4", "47.47.22.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x99 0x70 0x00000064 ]",
        "reset-tolerated", "either",
        "As above plus the Extended Length bit, so the length field is two "
        "octets (verified on the wire: 7099 0004 00000064). Confirms the "
        "unrecognised-well-known path is reached identically for both length "
        "encodings.",
        tags=("rfc4271", "unknown-attr", "wellknown", "length"),
    ))
    M.append(Malformed(
        "unknown-wellknown-attr", "ipv4", "47.47.3.0/24",
        f"next-hop {peer_v4} {_ap} attribute [ 0x9b 0x00 0xdeadbeef ]",
        "reset-tolerated", "either",
        "Attribute type 155 with all flag bits clear, i.e. it claims to be a "
        "well-known attribute the receiver does not recognise. RFC 4271 section 6.3 "
        "mandates a NOTIFICATION (Unrecognized Well-known Attribute), so a reset "
        "here is conformant. Observed on FRR 10.5.2: no NOTIFICATION, no reset, "
        "treat-as-withdraw - same path as the two 0x60/0x70 cases above.",
        tags=("rfc7606", "unknown-attr", "wellknown"),
    ))

    # --- AS_PATH ---------------------------------------------------------
    # AS_PATH type 2, segment type 3 = AS_CONFED_SEQUENCE, count 2, ASNs 3356 and
    # 15169. `attribute` comes first so it wins over the `as-path` clause (see the
    # precedence note above); the clause is still required because ExaBGP rejects
    # a route with a generic AS_PATH attribute and no as-path clause.
    # Verified on the wire: emits segment type 3 (CONFED_SEQUENCE) asns=[3356, 15169].
    M.append(Malformed(
        "aspath-confed-to-ebgp", "ipv4", "47.47.4.0/24",
        f"attribute [ 0x02 0x40 0x030200000d1c00003b41 ] {_ap} "
        f"next-hop {peer_v4}",
        "up", "absent",
        "AS_CONFED_SEQUENCE segment sent to an external peer, which RFC 5065 "
        "forbids. RFC 7606 section 5.4 requires treat-as-withdraw, not a reset.",
        tags=("rfc7606", "confed", "aspath"),
        requires_exabgp="5",
        exabgp_r_rejects=True,
    ))
    # AS_PATH declaring a 2-ASN segment but supplying only one: a segment-length
    # error. Verified on the wire as raw 020200000d1c, i.e. count=2 with 4 bytes
    # of ASN data. This became possible only once the precedence rule above was
    # understood, and it covers a case previously listed as unreachable.
    M.append(Malformed(
        "aspath-truncated-segment", "ipv4", "47.47.19.0/24",
        f"attribute [ 0x02 0x40 0x020200000d1c ] as-path [ 3356 ] "
        f"next-hop {peer_v4}",
        "up", "absent",
        "AS_PATH whose segment header claims 2 ASNs but carries 4 bytes of ASN "
        "data. RFC 7606 section 5.3 classifies a malformed AS_PATH as "
        "treat-as-withdraw; the session must survive.",
        tags=("rfc7606", "aspath", "length"),
        requires_exabgp="5",
        exabgp_r_rejects=True,
    ))
    long_path = " ".join(str(a) for a in
                         ([peer_asn] if peer_asn else [])
                         + [4000 + i for i in range(249)])
    M.append(Malformed(
        "aspath-very-long", "ipv4", "47.47.5.0/24",
        f"next-hop {peer_v4} as-path [ {long_path} ]",
        "up", "present",
        "250-hop AS_PATH. Forces extended-length attribute encoding and exercises "
        "bestpath's AS_PATH-length comparison at the top of its practical range.",
        tags=("aspath", "length"),
    ))
    # Verified on the wire: `as-path ( ... )` emits a genuine segment type 1
    # (AS_SET). ExaBGP 4.x rejects this syntax outright, and no 4.x-compatible
    # spelling emits a real AS_SET, so it is marked 5.x-only for offline
    # validation. The lab is unaffected: the peer container runs 5.0.9.
    M.append(Malformed(
        "aspath-as-set", "ipv4", "47.47.6.0/24",
        f"next-hop {peer_v4} as-path ( 3356 15169 )",
        "up", "present",
        "AS_SET segment (RFC 6472 deprecates originating these). Note the template's "
        "asn-bogons regexes use `_` delimiters, which in FRR also match at AS_SET "
        "braces - so a bogon ASN hidden inside an AS_SET is still caught.",
        tags=("aspath", "as-set"),
        requires_exabgp="5",
    ))
    M.append(Malformed(
        "aspath-loop-own-asn", "ipv4", "47.47.7.0/24",
        f"next-hop {peer_v4} as-path [ {peer_asn} 3356 {dut_asn} 15169 ]",
        "up", "absent",
        "AS_PATH containing the DUT's own ASN. Standard loop detection must drop "
        "this on import (no allowas-in is configured in the template).",
        tags=("aspath", "loop"),
    ))
    M.append(Malformed(
        "aspath-4byte", "ipv4", "47.47.8.0/24",
        f"next-hop {peer_v4} as-path [ {peer_asn} 131072 4199999999 ]",
        "up", "present",
        "32-bit ASNs that sit outside every asn-bogons range. Confirms AS4 handling "
        "and that the bogon regexes do not over-match legitimate 4-byte ASNs.",
        tags=("aspath", "as4"),
    ))

    # --- NEXT_HOP --------------------------------------------------------
    _MARTIAN_NH_DEFECT = (
        "CONFIRMED defect in FRR <= 10.6.x (VyOS 1.5.1 ships FRR 10.5.2). "
        "bgp_attr_nexthop_valid() in bgpd/bgp_attr.c calls ipv4_martian() and, on "
        "a match, sends NOTIFICATION 3/8 (UPDATE Error / Invalid NEXT_HOP) via "
        "bgp_notify_send_with_data() and returns BGP_ATTR_PARSE_ERROR. Both call "
        "sites turn that into `return BGP_Stop` in bgp_update_receive() "
        "(bgp_packet.c), i.e. a session reset. RFC 7606 section 3(e) makes this a "
        "MUST NOT: \"'Treat-as-withdraw' MUST be used for the cases that specify a "
        "session reset and involve any of the attributes ORIGIN, AS_PATH, "
        "NEXT_HOP, MULTI_EXIT_DISC, or LOCAL_PREF.\" RFC 4271 section 6.3 agrees "
        "for the semantic case: log it, ignore the route, do not send a "
        "NOTIFICATION and do not close the connection. FRR's own comment at the "
        "call site says the semantic case \"is implemented elsewhere\" "
        "(bgp_update_martian_nexthop(), a silent per-prefix filter), but the "
        "stricter check fires first so the compliant path is unreachable for the "
        "legacy NEXT_HOP attribute. Fixed upstream: frr-10.7.0 and the current "
        "stable/10.5, stable/10.6 and stable/10.7 branch heads return "
        "BGP_ATTR_PARSE_WITHDRAW and the BGP_Stop call site is gone. Verified "
        "absent from every released 10.4.x, 10.5.x and 10.6.x tag. Workaround on "
        "an affected release: `bgp allow-martian-nexthop` (bgp_vty.c), which "
        "bypasses both validation layers. `allow-reserved-ranges` does NOT help "
        "for 224.0.0.0/4 - it only makes 0.0.0.0/8 and 127.0.0.0/8 valid."
    )
    M.append(Malformed(
        "nexthop-zero", "ipv4", "47.47.9.0/24",
        f"next-hop 0.0.0.0 {_ap}",
        "up", "absent",
        "NEXT_HOP 0.0.0.0. RFC 7606 section 7.3 with section 3(e): a NEXT_HOP "
        "error is a treat-as-withdraw case and MUST NOT reset the session. "
        "0.0.0.0 fails ipv4_unicast_valid() via IPV4_NET0 (lib/prefix.c).",
        tags=("rfc7606", "nexthop", "martian"),
        known_defect=_MARTIAN_NH_DEFECT,
        expect_log="Martian nexthop",
    ))
    M.append(Malformed(
        "nexthop-broadcast", "ipv4", "47.47.10.0/24",
        f"next-hop 255.255.255.255 {_ap}",
        "up", "present",
        "NEXT_HOP 255.255.255.255, the value ExaBGP's own conf-attributes.conf "
        "fixture injects deliberately. Expectation corrected from `absent` after "
        "reading the code: ipv4_unicast_valid() (lib/prefix.c) tests "
        "IPV4_CLASS_E FIRST and returns true, so FRR treats all of 240.0.0.0/4 as "
        "usable unicast per draft-schoen-intarea-unicast-240 and this next-hop is "
        "NOT martian. It is accepted, and no session reset occurs - which is what "
        "the lab observed. Worth noting separately: FRR does not special-case "
        "255.255.255.255 (limited broadcast, RFC 919) within that /4, so the "
        "limited-broadcast address is accepted as a BGP next-hop.",
        tags=("nexthop", "class-e"),
    ))
    M.append(Malformed(
        "nexthop-multicast", "ipv4", "47.47.11.0/24",
        f"next-hop 224.0.0.1 {_ap}",
        "up", "absent",
        "NEXT_HOP inside 224.0.0.0/4, which fails ipv4_unicast_valid() via "
        "IPV4_CLASS_D (lib/prefix.c). Same RFC 7606 requirement as nexthop-zero. "
        "Also exercises the template's ipv4-bogons rule 130, though that list is "
        "matched against NLRI, not next-hops.",
        tags=("rfc7606", "nexthop", "martian"),
        known_defect=_MARTIAN_NH_DEFECT,
        expect_log="Martian nexthop",
    ))
    M.append(Malformed(
        "nexthop-offlan", "ipv4", "47.47.12.0/24",
        f"next-hop 192.0.2.254 {_ap}",
        "up", "either",
        "Third-party next-hop outside both peering LANs. ebgp4-import rules 100 and "
        "120 match `ip nexthop prefix-list ixp1-peers|ixp2-peers`, both /32-exact, so "
        "neither fires: the route lands with NO IXP large-community and the global "
        "default local-pref of 100 instead of 275/300. Route servers legitimately "
        "produce third-party next-hops, so this is a real operational gap, not just "
        "a synthetic case.",
        tags=("nexthop", "tagging", "gap"),
    ))

    # --- iBGP-only attributes arriving over eBGP -------------------------
    M.append(Malformed(
        "originator-id-over-ebgp", "ipv4", "47.47.13.0/24",
        f"next-hop {peer_v4} {_ap} originator-id 10.0.0.1",
        "up", "either",
        "ORIGINATOR_ID (type 9) received on an external session. RFC 7606 "
        "section 7.10: must be discarded, session must survive.",
        tags=("rfc7606", "ibgp-attr"),
    ))
    M.append(Malformed(
        "cluster-list-over-ebgp", "ipv4", "47.47.14.0/24",
        f"next-hop {peer_v4} {_ap} cluster-list 10.0.0.1",
        "up", "either",
        "CLUSTER_LIST (type 10) received on an external session. RFC 7606 "
        "section 7.11: must be discarded, session must survive.",
        tags=("rfc7606", "ibgp-attr"),
    ))

    # --- attribute bloat -------------------------------------------------
    comms = " ".join(f"{64000 + (i % 400)}:{i}" for i in range(200))
    M.append(Malformed(
        "community-bloat", "ipv4", "47.47.15.0/24",
        f"next-hop {peer_v4} {_ap} community [ {comms} ]",
        "up", "present",
        "200 standard communities (800 bytes) forcing extended-length encoding. "
        "Communities are interned in FRR, so this probes the intern table rather "
        "than per-path memory.",
        tags=("bloat", "community"),
    ))
    lcomms = " ".join(f"64000:{i}:{i}" for i in range(100))
    M.append(Malformed(
        "large-community-bloat", "ipv4", "47.47.16.0/24",
        f"next-hop {peer_v4} {_ap} large-community [ {lcomms} ]",
        "up", "present",
        "100 large communities (1200 bytes). Note FRR had large-community memory "
        "leaks in 8.4-9.1 (issues 14828, 15459); worth watching RSS across repeated "
        "announce/withdraw cycles of this prefix.",
        tags=("bloat", "large-community"),
    ))
    M.append(Malformed(
        "extended-community-on-unicast", "ipv4", "47.47.17.0/24",
        f"next-hop {peer_v4} {_ap} extended-community [ target:64000:1000 ]",
        "up", "either",
        "Route-target extended community on plain IPv4 unicast. Legal but unusual "
        "outside VPN address families; the template's policy never matches on it.",
        tags=("extcomm",),
    ))
    M.append(Malformed(
        "atomic-aggregate", "ipv4", "47.47.18.0/24",
        f"next-hop {peer_v4} {_ap} atomic-aggregate",
        "up", "present",
        "ATOMIC_AGGREGATE without an AGGREGATOR attribute. Legal; confirms the DUT "
        "does not require the pair.",
        tags=("aggregate",),
    ))

    # --- blackhole community (RFC 7999) ---------------------------------
    M.append(Malformed(
        "blackhole-community-v6", "ipv6", "3fff:400:1::/48",
        f"next-hop {peer_v6} {_ap6} community [ 65535:666 ]",
        "up", "present",
        "RFC 7999 BLACKHOLE on IPv6. scrub-blackhole should strip it on import; the "
        "export route-maps then deny anything still carrying it. Confirms the scrub "
        "happens on the v6 path too, where per-IXP tagging is missing.",
        tags=("community", "blackhole"),
    ))

    if exclude_tags:
        drop = set(exclude_tags)
        M = [m for m in M if not (drop & set(m.tags))]
    return M


# Cases that need a byte-level injector. ExaBGP 5.0.9 re-decodes any *known*
# attribute code given via `attribute [ ... ]`, so a known attribute carrying an
# invalid length or an out-of-range value is rejected at config-parse time
# (verified: `exabgp validate -r` fails on each of these). To cover them you need
# raw packet injection - e.g. a scapy-based speaker or a patched ExaBGP.
NOT_ACHIEVABLE_WITH_EXABGP = [
    ("ORIGIN with an out-of-range value (e.g. 7)",
     "attribute [ 0x01 0x40 0x07 ] is rejected by ExaBGP's own decoder. "
     "RFC 7606 section 7.2 expects treat-as-withdraw."),
    ("MULTI_EXIT_DISC with a length other than 4",
     "attribute [ 0x04 0x40 0x0064 ] crashes ExaBGP's parser. "
     "RFC 7606 section 7.5 expects attribute discard."),
    ("LARGE_COMMUNITY with a length not a multiple of 12",
     "attribute [ 0x20 0xc0 0x0000000100000002 ] crashes ExaBGP's parser. "
     "RFC 8092 / RFC 7606 expect attribute discard."),
    ("LOCAL_PREF received over eBGP",
     "attribute [ 0x05 0x40 0x000003e8 ] is rejected; ExaBGP owns local-preference "
     "encoding. RFC 7606 section 7.4 expects it to be ignored on an external session."),
    ("Zero-length AS_PATH from an external peer",
     "`as-path [ ]` is rejected by the ExaBGP parser. Note that AS_PATH *segment* "
     "malformation IS reachable via `attribute [ 0x02 ... ]` — see the "
     "aspath-truncated-segment case — because ExaBGP does not deep-validate "
     "AS_PATH segment contents at config-parse time, unlike the fixed-width "
     "attributes below."),
    ("Duplicate instances of the same attribute in one UPDATE",
     "Not expressible in ExaBGP's configuration or text API. "
     "RFC 7606 section 3(g) expects treat-as-withdraw."),
    ("Attribute-flags error on a known attribute (e.g. Optional set on ORIGIN)",
     "ExaBGP validates flags against the known attribute definition. "
     "RFC 7606 section 7 expects graded handling per attribute."),
]


def malformed_announce_commands(cases: Sequence[Malformed], dut_v4: str,
                                dut_v6: str,
                                peer_v4: Optional[str] = None,
                                peer_v6: Optional[str] = None) -> List[str]:
    out = ["# RFC 7606 malformed-attribute suite"]
    for m in cases:
        nb = dut_v4 if m.afi == "ipv4" else dut_v6
        lo = peer_v4 if m.afi == "ipv4" else peer_v6
        out.append(f"{neighbor_selector(nb, lo)} announce route {m.prefix} "
                   f"{m.attrs}")
    return out


def malformed_withdraw_commands(cases: Sequence[Malformed], dut_v4: str,
                                dut_v6: str,
                                peer_v4: Optional[str] = None,
                                peer_v6: Optional[str] = None) -> List[str]:
    return [
        f"{neighbor_selector(dut_v4 if m.afi == 'ipv4' else dut_v6, peer_v4 if m.afi == 'ipv4' else peer_v6)}"
        f" withdraw route {m.prefix}"
        for m in cases
    ]
