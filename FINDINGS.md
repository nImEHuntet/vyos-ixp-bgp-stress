# Findings from reading `Template IXP VyOS Configuration.md`

These came out of building the harness against the template, not out of running
it. Each is a static-analysis finding with the exact evidence, so you can confirm
it yourself without deploying anything. Several are asserted as probes in
`harness/policyprobe.py`, so a run will confirm or refute them on a live box —
the "verify with" line for each says how.

Severity is about operational consequence at an IXP, not about tidiness.

| # | Finding | Severity |
|---|---|---|
| 1 | Prefix-length filters do not filter | **high** |
| 2 | Bogon-ASN filter rejects private ASNs — including any you use in a lab | **high** (design constraint) |
| 3 | Own-supernet exact match is accepted on import | **high** |
| 4 | IPv6 gets no per-IXP tagging on IXP-2 | medium |
| 5 | `igp4` / `igp6` peer-groups are referenced but never defined | medium |
| 6 | The `rpki` route-map is a no-op | medium |
| 7 | `ipv6-bogons` predates RFC 9637 (`3fff::/20`) | medium |
| 8 | `ipv4-bogons` rule 30 is `10.64.0.0/10`, probably meant to be `100.64.0.0/10` | low |
| 9 | `maximum-prefix` on bilateral peer-groups is 200 | low (verify intent) |
| 10 | `continue` targets that do not exist | low |
| 11 | Management VRF plus `default-action drop` is a lockout risk | low (documented in the template) |

---

## 1. The prefix-length filters do not filter anything

**high.** The template's own comment says the import pipeline does a "prefix size
check", and `ipv4-acceptable` / `ipv6-acceptable` correctly express "only /8 to
/24" and "only /12 to /48". But the route-map rules that use them cannot reject
anything.

```
set policy route-map ebgp4-import rule 25 action 'permit'
set policy route-map ebgp4-import rule 25 continue '30'
set policy route-map ebgp4-import rule 25 description 'Only allow /8 to /24'
set policy route-map ebgp4-import rule 25 match ip address prefix-list 'ipv4-acceptable'
```

In FRR route-map semantics, a rule whose match clause **fails** does not deny the
route — it falls through to the next rule. So a `/25`:

* does not match rule 25, so rule 25 is skipped entirely;
* reaches rule 30 (`permit`, `call rpki`, `continue 40`), which has no match
  clause and therefore matches everything;
* continues down the chain and is permitted by rule 1000.

The `permit`-plus-`continue` construction only *adds* a path for prefixes that
**do** match. It never subtracts.

Affected: `ebgp4-import` rule 25, `ebgp6-import` rule 25, `ebgp6-import-ixp1`
rule 25, and `ebgp4-in-ixp1-rs` rule 50 (same shape with `on-match next`).

**Consequence.** The router accepts `/25`–`/32` from every IXP peer and route
server. At an exchange that is the de-aggregation exposure the filter was written
to prevent, and it inflates the RIB with prefixes no one else will accept.

**Fix.** Deny the complement explicitly:

```
set policy prefix-list ipv4-toolong description 'IPv4 prefixes longer than /24'
set policy prefix-list ipv4-toolong rule 10 action 'permit'
set policy prefix-list ipv4-toolong rule 10 ge '25'
set policy prefix-list ipv4-toolong rule 10 le '32'
set policy prefix-list ipv4-toolong rule 10 prefix '0.0.0.0/0'

set policy prefix-list ipv4-tooshort description 'IPv4 prefixes shorter than /8'
set policy prefix-list ipv4-tooshort rule 10 action 'permit'
set policy prefix-list ipv4-tooshort rule 10 le '7'
set policy prefix-list ipv4-tooshort rule 10 prefix '0.0.0.0/0'

set policy route-map ebgp4-import rule 22 action 'deny'
set policy route-map ebgp4-import rule 22 description 'Reject prefixes longer than /24'
set policy route-map ebgp4-import rule 22 match ip address prefix-list 'ipv4-toolong'

set policy route-map ebgp4-import rule 23 action 'deny'
set policy route-map ebgp4-import rule 23 description 'Reject prefixes shorter than /8'
set policy route-map ebgp4-import rule 23 match ip address prefix-list 'ipv4-tooshort'
```

and the IPv6 equivalents with `ge 49 le 128` and `le 11` against `::/0`, wired
into `ebgp6-import`, `ebgp6-import-ixp1` and both `*-rs` maps. Then delete
rules 25/50, which are now dead weight.

**Verify with:** probes `toolong-v4-25`, `toolong-v4-32`, `toolong-v6-64`
(`make probe`). Against the shipped template they report
`template-defect-confirmed`.

---

## 2. The bogon-ASN filter rejects private ASNs, in both directions

**high — a design constraint rather than a bug, but it bites immediately.**
`policy as-path-list asn-bogons` is applied on import (via `ebgp4-import` rule 10
and the `*-rs` maps) **and** on export (`ebgp4-export-ixp1` rule 20 and friends).
Its rules cover, cumulatively:

| Rule | Range |
|---|---|
| 10 | 0 |
| 20 | 23456 |
| 30 | 64496–64511, 65536–65551 |
| 40 | 64512–65535 |
| 50 | 65552–69999 |
| 60 | 70000–130999 |
| 70 | 131000–131071 |
| 80–110 | 4200000000–4294967294 |

The template's own placeholder table suggests `<PLACEHOLDER_ASN>` may be a "public
or lab ASN (e.g. 65001)". **65001 is matched by rule 40.** Configure it and the
router filters its own AS_PATH on export, so it advertises nothing, and it filters
every peer that also uses private space.

**Consequence for testing specifically:** any lab built on RFC 6996 private ASNs
looks catastrophically broken for reasons that have nothing to do with scale. This
is why `harness/model.py` refuses a bogon DUT ASN at generation time and every
shipped profile uses AS 64000 with peers from 64001 upward.

**Fix.** Either change the placeholder guidance to a safe range (1–64495 excluding
0 and 23456, or 131072–4199999999), or if private ASNs are genuinely wanted in a
lab, scope the bogon list so it is not applied to the lab's own AS. The former is
much safer.

---

## 3. Your own supernet is accepted back from peers

**high.** `own-more-specific4` is:

```
set policy prefix-list own-more-specific4 rule 10 ge '25'
set policy prefix-list own-more-specific4 rule 10 le '32'
set policy prefix-list own-more-specific4 rule 10 prefix '<PLACEHOLDER_OWN_SUPER4>'
```

`ge 25` means it matches more-specifics of the supernet but **not the supernet
itself**. `ebgp4-import` rule 40 denies matches of that list, and there is no
other rule on the import path matching `own-supernet4`. So an exact-match
advertisement of your own aggregate from an IXP peer is accepted.

Note also that `ge 25` leaves `/17`–`/24` more-specifics of a `/16` unmatched —
though for a `/16` supernet those are caught by nothing else either. The `ge`
value only makes sense if the supernet is a `/24`.

**Fix.** Add a deny for the supernet itself and widen the more-specific match:

```
set policy prefix-list own-more-specific4 rule 10 ge '17'    # supernet len + 1
set policy route-map ebgp4-import rule 41 action 'deny'
set policy route-map ebgp4-import rule 41 description 'Reject our own supernet'
set policy route-map ebgp4-import rule 41 match ip address prefix-list 'own-supernet4'
```

Same for `own-more-specific6` / `own-supernet6` and for both `*-rs` import maps
(the RS maps use `own-more-specific4` at rule 40 with the identical gap).

**Verify with:** probes `own-supernet-exact-v4` and `own-more-specific-v4`.

---

## 4. IPv6 routes from IXP-2 get no community tag and no local-preference

**medium.** IPv4 does per-IXP tagging by next-hop inside one generic map:

```
set policy route-map ebgp4-import rule 100 call 'ebgp4-import-ixp2' match ip nexthop prefix-list 'ixp2-peers'
set policy route-map ebgp4-import rule 120 call 'ebgp4-import-ixp1' match ip nexthop prefix-list 'ixp1-peers'
```

IPv6 has no equivalent. There is **no `ebgp6-import-ixp2` route-map at all**, and
both `ixp2-peer6` and `ixp2-rs6` use the generic `ebgp6-import`, which has no
next-hop detection, no `set large-community` and no `set local-preference`.

Result, per address family and exchange:

| Peer-group | Import map | IXP large-community | local-pref |
|---|---|---|---|
| `ixp1-peer4` | `ebgp4-import` → `ebgp4-import-ixp1` | yes | 275 |
| `ixp1-peer6` | `ebgp6-import-ixp1` | yes | 275 |
| `ixp1-rs4` | `ebgp4-in-ixp1-rs` | yes | 275 |
| `ixp1-rs6` | `ebgp6-in-ixp1-rs` | yes | 300 |
| `ixp2-peer4` | `ebgp4-import` → `ebgp4-import-ixp2` | yes | 300 |
| **`ixp2-peer6`** | `ebgp6-import` | **no** | **100 (global default)** |
| `ixp2-rs4` | `ebgp4-import` → `ebgp4-import-ixp2` | yes | 300 |
| **`ixp2-rs6`** | `ebgp6-import` | **no** | **100** |

So IPv6 via IXP-2 loses to IPv6 via IXP-1 on local-preference (100 vs 275) even
though the IPv4 policy deliberately prefers IXP-2 (300 vs 275). IPv4 and IPv6
traffic to the same destination take different exchanges, and no
large-community-based accounting or filtering will see IXP-2 IPv6 routes at all.

Note the IXP-1 inconsistency too: bilateral gets 275 in both families, but the RS
gets 275 on IPv4 and 300 on IPv6.

**Fix.** Add `ebgp6-import-ixp2` mirroring `ebgp6-import-ixp1` with the IXP-2 tag
and local-pref, and bind it on `ixp2-peer6` / `ixp2-rs6`. Better still, restructure
IPv6 to use next-hop detection the way IPv4 does, so the two families cannot drift
apart again. Then decide deliberately whether RS and bilateral should differ.

**Verify with:** probe `ixp-tag-v6`, and `nexthop-offlan` in the malformed suite.

---

## 5. `igp4` and `igp6` peer-groups are referenced but never defined

**medium.** The iBGP neighbour template says:

```
set protocols bgp neighbor <IBGP_PEER_IP4> peer-group 'igp4'
set protocols bgp neighbor <IBGP_PEER_IP6> peer-group 'igp6'
```

Neither peer-group exists anywhere in the config. `grep -o "peer-group [a-z0-9-]*"`
returns only the ten IXP and transit groups.

**Consequence.** Anyone following the template to add iBGP either fails to commit
or creates an empty peer-group. An empty peer-group is worse than a failure: VyOS
emits `no bgp default ipv4-unicast` unconditionally (vyos.dev/T3463), so the
session comes up carrying **no address family** and silently exchanges nothing.

**Fix.** Define them, including the address-family activation and iBGP specifics
(`route-reflector-client` if applicable, `next-hop-self`, `update-source`):

```
set protocols bgp peer-group igp4 remote-as '<PLACEHOLDER_ASN>'
set protocols bgp peer-group igp4 update-source 'lo'
set protocols bgp peer-group igp4 address-family ipv4-unicast nexthop-self
set protocols bgp peer-group igp4 address-family ipv4-unicast soft-reconfiguration inbound
set protocols bgp peer-group igp4 description 'iBGP mesh (IPv4)'
```

The harness's selftest asserts no session binds a peer-group the template does not
define, which is how this was caught.

---

## 6. The `rpki` route-map does not reject anything

**medium.** The pipeline comment promises "RPKI validation", and `ebgp4-import`
rule 30 does `call 'rpki'`. But the map is:

```
set policy route-map rpki description 'Do not accept RPKI Invalids'
set policy route-map rpki rule 1000 action 'permit'
```

One unconditional permit. It has no `match rpki invalid` clause, so it validates
nothing. The description states the opposite of what the map does.

**Fix.** Add the actual matches, and decide explicitly how NotFound is treated:

```
set policy route-map rpki rule 10 action 'deny'
set policy route-map rpki rule 10 description 'Reject RPKI Invalid'
set policy route-map rpki rule 10 match rpki 'invalid'

set policy route-map rpki rule 20 action 'permit'
set policy route-map rpki rule 20 description 'Prefer RPKI Valid'
set policy route-map rpki rule 20 match rpki 'valid'
set policy route-map rpki rule 20 set local-preference '350'

set policy route-map rpki rule 1000 action 'permit'
```

This also needs `protocols rpki cache` configured and reachable — with no cache
every prefix is NotFound, so an `invalid` deny is inert. Confirm `match rpki`
syntax on your image before relying on it.

---

## 7. `ipv6-bogons` has no entry for RFC 9637 `3fff::/20`

**medium.** The list covers `2001:db8::/32` (RFC 3849) and `3ffe::/16` (the retired
6bone), but not `3fff::/20`, which [RFC 9637](https://www.rfc-editor.org/rfc/rfc9637)
reserved in 2024 as additional IPv6 documentation space. It is inside `2000::/3`,
so it passes `ipv6-acceptable`, and nothing else rejects it.

**Fix.**

```
set policy prefix-list6 ipv6-bogons rule 115 action 'permit'
set policy prefix-list6 ipv6-bogons rule 115 le '128'
set policy prefix-list6 ipv6-bogons rule 115 prefix '3fff::/20'
```

**Interaction with this harness:** the shipped profiles deliberately use
`3fff::/20` for synthetic IPv6 NLRI precisely because the template does not filter
it. If you apply this fix, change `nlri.v6_base` and `own.supernet6` in the
profiles to something the bogon list permits, or every IPv6 test will measure the
filter instead of the RIB. Probe `acceptable-v6-48` will flip from pass to fail and
tell you.

---

## 8. `ipv4-bogons` rule 30 looks like a typo

**low.** Rule 30 is `10.64.0.0/10 le 32`. That is already fully covered by rule 20
(`10.0.0.0/8 le 32`), so rule 30 matches nothing that rule 20 does not. The
plausible intent is RFC 6598 shared address space, `100.64.0.0/10`, which is
genuinely missing from the list.

**Fix.** `set policy prefix-list ipv4-bogons rule 30 prefix '100.64.0.0/10'`.

**Interaction with this harness:** the profiles use `100.64.0.0/16` as the DUT's
own space, again because the template does not filter it. Applying this fix means
changing `own.supernet4` / `own.local4` in the profiles.

Also missing from the list relative to a current bogon set: `192.0.0.0/24`
(IETF protocol assignments) and `100.100.100.0/24`. `192.31.196.0/24`,
`192.52.193.0/24` and `192.175.48.0/24` are anycast ranges that are legitimately
globally routed and should *not* be added.

---

## 9. `maximum-prefix 200` on bilateral peer-groups

**low, but confirm it is intentional.** `ixp1-peer4`, `ixp1-peer6`, `ixp2-peer4`
and `ixp2-peer6` all set `maximum-prefix 200`, while the neighbour template
suggests overriding per-neighbour with 5000 (v4) / 2000 (v6). If a bilateral peer
is added without an override and sends more than 200 prefixes, the session is torn
down.

Worth knowing about VyOS specifically: `maximum-prefix` is a bare limit. The XML
defines it as a leaf taking only a number — there is **no** `warning-only`,
`restart` or `threshold` sub-option, unlike FRR's own CLI. So the only available
behaviour is teardown, and recovery is entirely manual. A conservative limit
therefore has a higher operational cost here than on platforms that can warn.

Also note `maximum-prefix-out` exists as a sibling if you want to bound what you
advertise.

**Verify with:** the `maxprefix_trip` scenario event, which squeezes the limit
below the offered table and confirms both teardown and recovery.

---

## 10. `continue` targets that do not exist

**low, cosmetic.** `ebgp4-import` rule 100 has `continue '110'`, but the map's
rules are 10, 20, 25, 30, 40, 60, 100, 120, 1000 — there is no 110.
`ebgp4-import-ixp1` and `-ixp2` rule 20 have `continue '30'` with no rule 30.

FRR's `on-match goto` moves to the next rule with an index greater than or equal
to the target, so behaviour is benign: 110 lands on 120, and 30 lands on 1000. But
it is fragile — inserting a rule at 110 later would silently change the pipeline.

**Fix.** Point `continue` at rules that exist.

---

## 11. Management VRF plus `default-action drop`

**low; the template already warns about it.** Section 9 moves `eth0` into
`vrf management` and relocates sshd, with the note "YOU MAY LOSE SSH ACCESS". The
firewall's only management accept is
`input filter rule 10 inbound-interface name 'management'`, with
`default-action drop`.

Two things worth adding to the template's warning:

* If the VRF move fails or is applied out of order, rule 10 never matches and the
  box is unreachable after the first `commit`. Console access is mandatory.
* Under containerlab, `eth0` is the management interface containerlab itself
  addresses, so the VRF move fights the orchestrator. The harness therefore
  defaults `dut.mgmt_vrf: false` and adds an explicit accept on `eth0`; see
  `harness/dutconfig.py`.

Also note the template sets `system conntrack` twice with identical values
(Section 8 lists the block, then repeats it), which is harmless but suggests a
copy-paste during assembly.

---

## Things the template gets right, worth not breaking

* Bogon-ASN regexes use `_` delimiters, so a bogon ASN hidden inside an `AS_SET`
  is still matched — many hand-written equivalents miss this.
* `soft-reconfiguration inbound` on every peer-group is what makes
  `clear bgp ... soft in` usable, which is the cheap way to re-apply policy without
  bouncing sessions. It costs a full Adj-RIB-In in memory, which is the right
  trade at an exchange but should be a conscious one.
* Export policy is default-deny (`rule 1000 action deny`) with explicit permits for
  own space. That is the correct shape and the single most important thing to get
  right at an IXP.
* `capability dynamic` on the IXP peer-groups avoids session resets when address
  families change.
* The `scrub-blackhole` / `blackhole-communities` pairing correctly strips
  `65535:666` on import and denies still-tagged routes on export.

---

# Findings about the environment, not the template

These are not template defects. They are properties of FRR and of the traffic
generators that change what a result *means*, so they belong next to the
template findings rather than buried in code comments.

## E-1. `enforce-first-as` is ON by default from FRR 10.0, and a violation is silent

VyOS 1.5.1 ships FRR 10.5.2. In FRR, `bgp enforce-first-as` became a default-on
setting in 10.0:

    /* bgpd/bgp_vty.c */
    FRR_CFG_DEFAULT_BOOL(BGP_ENFORCE_FIRST_AS,
        { .val_bool = false, .match_version = "< 9.1", },
        { .val_bool = true },
    );

Two consequences that matter for interpreting a run:

1. **A violation is treat-as-withdraw, not a session reset.** Since FRR 7.4,
   `bgp_attr_aspath_check` returns `BGP_ATTR_PARSE_WITHDRAW`
   (`bgpd/bgp_attr.c`), so the session stays `Established`, `PfxRcd` reads 0,
   and `show bgp summary` says nothing at all. The only evidence is the log
   line `incorrect first AS (must be N)`. The harness now counts that line
   (`Dut.LOG_PATTERNS["attr_first_as"]`) and `make peers` reports it.

2. **FRR prints this setting inverted.** At the default (on) it prints
   *nothing* per neighbour, and `no neighbor X enforce-first-as` means it has
   been explicitly disabled (`bgp_config_write_peer`, `bgpd/bgp_vty.c`). So an
   empty `show running-config | grep enforce` means enforcement is **active**,
   which reads exactly backwards from the intuition.

FRR's own BGP documentation states the operational consequence directly: *"If
you have a peering to RS (Route-Server), most likely you MUST disable the first
AS enforcement."* An RFC 7947 route server does not prepend its own ASN, so
every route it sends violates the check.

**Template implication:** the template's `ixp1-rs4` / `ixp1-rs6` /
`ixp2-rs4` / `ixp2-rs6` peer-groups are written for route servers but do not
disable `enforce-first-as`. On FRR >= 10.0 that combination silently discards
the entire route-server feed. VyOS exposes `enforce-first-as` as a valueless
opt-in node under `protocols bgp neighbor|peer-group`; whether VyOS 1.5.1's FRR
template emits the `no` form when the node is unset (added upstream in
vyos-1x PR #4469 / T7220, April 2025) could not be verified from public source,
because the 1.5 branch of `vyos-1x` is not public. Check it on the box:

    vtysh -c 'show running-config' | grep -i enforce
    # a `no neighbor ... enforce-first-as` line  -> enforcement is OFF
    # no output at all                           -> enforcement is ON

**Confirmed on VyOS 1.5.1** (`vtysh -c 'show running-config' | grep -i enforce`
via `make peers`): 20 `no neighbor ... enforce-first-as` lines — one for each of
the 10 peer-groups the template defines and each of the 10 configured
neighbours. So VyOS 1.5.1 *does* carry the T7220 change and emits the `no` form
for every peer when the CLI node is unset. Enforcement is therefore **off** by
default on VyOS 1.5.1, the opposite of bare FRR 10.5.

Two consequences:

* The template's route-server peer-groups are safe on VyOS 1.5.1 as shipped.
  They would not be safe on bare FRR 10.x, or on a VyOS release that predates
  T7220 (April 2025) — there the `no` line is absent and the FRR default wins.
* Because VyOS emits `no ... enforce-first-as` unconditionally, the VyOS CLI's
  `enforce-first-as` node is the *only* way to turn enforcement on, and there is
  no way to get FRR's own default behaviour. Anyone relying on first-AS
  enforcement at an IXP must set the node explicitly per peer.

Corroborating observation from the same lab: probe `acceptable-v4-24`, announced
with `as-path [ 3356 15169 ]` from a peer in AS 64400, was accepted, and
`attr_first_as` / `attr_withdraw` log counters both read 0.

## E-2. GoBGP's `route-server-client` and `mrt inject global` are mutually exclusive

Setting `route-server-client = true` on the DUT neighbour looks like the right
way to emulate an RFC 7947 route server, and it silently produces a session
that is `Established` and carries zero routes. Verified against gobgp v4.8.0:

* `pkg/server/server.go:3526` — a route-server-client peer is bound to
  `s.rsRib`, not `s.globalRib`.
* `pkg/server/server.go:2432` — `addPathList`, which is what the
  `AddPath`/`AddPathStream` gRPC API used by `gobgp mrt inject global` calls,
  invokes `propagateUpdate(nil, pathList)`; the source peer is `nil`.
* `pkg/server/server.go:1464` — `if source == nil && targetPeer.isRouteServerClient() { continue }`.

So every MRT-injected path is skipped for route-server clients. `s.rsRib` is
only ever written from paths *received* on another RS client's session
(`server.go:1338`), and `AddPathStream` rejects any `TableType` other than
`GLOBAL` and `VRF` (`grpc_server.go:703`) — there is no inject target for an RS
table. The harness therefore does **not** set `route-server-client`.

The cost of leaving it off is that gobgpd prepends its own ASN on egress to an
eBGP peer (`internal/pkg/table/path.go:273`, `path.PrependAsn`), which it skips
only for route-server clients (`path.go:236`). The harness compensates on the
MRT side: AS_PATHs written for gobgp fleets omit the speaker's own ASN
(`GOBGP_PREPENDS_OWN_ASN` in `harness/generate.py`), so the DUT sees it exactly
once. Set `transparent_as_path: false` on a fleet to test the doubled-ASN case
deliberately.

True RFC 7947 no-prepend transparency is not reachable through gobgpd's
MRT-inject path. Use an ExaBGP fleet for that — ExaBGP sends the AS_PATH it is
given, unmodified.

---

# Defects in this harness, found while running it

## H-1. `session_established_after` could never be anything but `None`

`ev_malformed_burst` asserted the RFC 7606 primary condition — the session must
survive an attribute error — by calling
`_peer_established(summary, dut_v4)`. FRR keys
`show bgp <afi> unicast summary json` by **neighbour** address, so looking up
the DUT's own fabric address never matched and the check silently returned
`None` for every run. Observed output: `RFC 7606 suite: session established
afterwards = None`.

Fixed: the lookup now uses `Session.v4` / `Session.v6`, checks both address
families, and additionally records `connectionsDropped` before and after, so a
reset that has already completed by the time the summary is read is still
visible.

## H-2. Probe and malformed AS_PATHs did not start with the announcing peer's ASN

Every probe defaulted to `as-path [ 3356 15169 ]` from a peer in AS 64400. On
an image with `enforce-first-as` at its FRR >= 10.0 default those routes are
dropped before any policy runs, so a probe would report `reject` and look like
it had validated a filter it never reached. All AS_PATHs now begin with the
announcing speaker's ASN, except in the cases where the AS_PATH itself is the
subject of the test (`aspath-as-set`, `aspath-truncated-segment`,
`aspath-confed-to-ebgp`).

## H-3. `converge` reported success while a third of the table was missing

`ConvergenceTracker` only asserts session counts and table stability. In one T0
run it reported `converged: True, established=5/5` while `pfxRcd` totalled 545
of 1,560 announced v4 prefixes — because of E-2 above. Session-level
convergence is the wrong assertion on its own. Added `make peers`, which prints
announced-vs-accepted per peer per address family, the shortfall, the
`enforce-first-as` state and the DUT's log counters, and exits non-zero on any
shortfall.


## H-4. The ExaBGP fleet announced nothing, and every check said it was fine

Symptom: `make peers` showed `ixp1-nasty-0000` `Established` on both address
families with `accepted=0` against 20 v4 / 10 v6 announced. `bringup` had
reported `processes started : 5`, `converge` reported `established=5/5`, and the
DUT log counters were all zero.

Cause: `build_topology` mounts the generated `exabgp/run` directory **read-only**
(`exabgp/run:/etc/exabgp/run:ro`), and `_start_generators` then ran

    cp /etc/exabgp/run/boot-<container>.txt /etc/exabgp/run/boot.txt 2>/dev/null || true

to put the per-container boot file at the fixed path the helper reads. The copy
always failed on the read-only mount, `|| true` discarded the failure, the
helper found no boot file and announced nothing. The runtime API path was
unaffected — its FIFO lives in `/run`, not in the mount — which is why the
policy-probe and RFC 7606 suites worked while the baseline table was empty. That
combination is what made the fault invisible: the session was up and responsive,
it just had no routes.

The boot-file *syntax* was correct throughout. Verified by feeding the generated
lines through ExaBGP 5.0.9's own text-API grammar
(`Configuration.partial('static', ...)` via `extract_neighbors`), which produced
exactly 20 and 10 changes.

Fixes:

* Each container's own boot file is now bound directly to
  `generate.EXABGP_BOOT_PATH` (`/etc/exabgp/boot.txt`). No copy, and a container
  can no longer see another fleet's boot file.
* The helper logs `sent N boot commands from <path>`, or `BOOT-MISSING` /
  `BOOT-EMPTY`, instead of silently skipping a missing file.
* `bringup` reads that log and treats "running but announced 0" as a failure,
  printing the helper log tail. Running is not the same as announcing.
* Four new selftest checks per ExaBGP container: the boot bind is present and
  points at the path the helper reads, the boot file is non-empty, every line
  parses through ExaBGP's text-API grammar, and the prefix count matches what
  the profile declares.

The general lesson, worth applying elsewhere in this harness: `|| true` on a
setup step converts a hard failure into a silent wrong answer. Every remaining
use of it should either be removed or paired with a check that the intended
effect happened.


## H-5. `exabgp_helper_log` took a Session; the new caller passed a container name

The verification added for H-4 called `PeerFleet.exabgp_helper_log(container)`,
but that method was declared `(self, s: Session)` and used `s.container`. Result:
`AttributeError: 'str' object has no attribute 'container'`, thrown from inside
`bringup` — after a full `destroy` / `deploy` / `prepare` / `config` cycle, so
roughly 90 seconds of DUT commits were spent before the crash.

`PeerFleet`'s API is deliberately split — `gobgpd_log` takes a `Session` because
there is one gobgpd per session, while `exabgp_log`, `exabgp_pids`,
`generator_pids`, `kill_generators` and `netem` take a container name because
there is one ExaBGP process per container — and nothing checked that the runner's
call sites agreed with it. `exabgp_helper_log` now accepts either.

The real gap was coverage, not the typo: the selftest validated only *generated
artefacts* and never imported the runtime drivers, so every mistake in
`peers.py` / `runner.py` call plumbing could only be found on live hardware.
Added three offline checks:

* `check_peerfleet_arg_shapes` — asserts `exabgp_helper_log` accepts both shapes.
  Verified to fail on the old code.
* `check_runner_smoke` — runs the real `_start_generators` for every profile's
  real inventory against a fake exec layer that asserts anything reaching
  `exec` / `exec_detached` is a `str`. A `Session` leaking into a
  container-name parameter now fails offline, per profile, in about a second.
* `check_boot_count_parser` — table-driven cases for the helper-log parser that
  decides whether ExaBGP announced anything.

## H-6. Bind mounts go stale, and the harness blamed generation for it

Symptom: `bringup` reported `MRT tables loaded : 0/4`, with

    failed to open file: open /mrt/ixp1-bilat-0000.mrt: no such file or directory

for all four sessions — while the host directory held all four files, freshly
generated, correct sizes. `make status` showed all four gobgpd processes running
and all five BGP sessions Established. The ExaBGP baseline worked in the same
run (`pfxRcd` 20 v4 / 10 v6 from `198.51.100.14` / `2001:db8:1::e`, confirming
the H-4 fix), which made the failure look like an MRT-generation bug rather than
a mount problem.

Cause: a bind mount holds the inode it was created with, not a path that is
re-resolved. `containerlab deploy` binds `build/<profile>/mrt` into every gobgp
container. If anything **replaces that directory** afterwards, the container
keeps pointing at the old, now-unlinked one: the host directory is full, the
container's view is empty, Docker reports nothing, and the only evidence is the
consumer failing to open a file that visibly exists. In this lab the repo lives
inside a Syncthing folder (`.stfolder` in the repo root, `.stversions` alongside
it), and `build/` was being synced — so generated artefacts under live bind
mounts were subject to conflict resolution and versioning.

This is not specific to Syncthing. Any agent that swaps a directory rather than
writing through it does the same: Dropbox, OneDrive, an rsync cron job, or a
`generate --force` that recreates the tree while the lab is up.

Fixes:

* `.stignore` now ships in the repo, excluding `build` and `results`. Every
  containerlab bind source lives under `build/<profile>/`, so none of it should
  ever be synced; `results/` is excluded separately because telemetry is written
  continuously during a run and syncing it only produces conflicts.
* `generate` warns when `.stfolder` is present and `build` is not ignored,
  naming the exact file to edit. Only Syncthing is detectable this way — other
  agents have the same failure mode and no marker.
* `bringup` verifies, per session, that the container can see its MRT file and
  that the size matches the host, **before** injecting. A mismatch is now a
  named diagnosis quoting both sides, with the three confirming commands and the
  fix, instead of gobgp's "no such file or directory".
* `status` prints the same container-vs-host comparison for every gobgp session,
  so a stale mount is visible without running `bringup`.
* Offline coverage: `check_stale_bind_detection` runs the real
  `_start_generators` with a fake container that reports the file missing and
  asserts nothing is injected and every session is reported failed;
  `check_sync_agent_warning` covers the warning's three states and asserts the
  repo actually ships the `.stignore`.

Operationally: `make destroy && make deploy` is required after anything
recreates `build/<profile>/`, because that is what rebuilds the mounts. Running
`make generate` on a deployed lab and then going straight to `bringup` is the
same trap from a different direction.

---

## E-3. RESOLVED (see E-4): the RFC 7606 suite resets the IPv4 session on VyOS 1.5.1 / FRR 10.5.2

First run in which the whole table was loaded (1,560 v4 / 680 v6 accepted,
shortfall 0) and in which the session assertion actually worked. It reports a
finding, not a harness fault:

| measurement | IPv4 | IPv6 |
|---|---|---|
| peer state before the burst | Established | Established |
| peer state after | **Clearing** | Established |
| `connectionsDropped` delta over ~20 s | **1,123** | 0 |

`attr_withdraw` (`rcvd UPDATE with errors in attr(s)!! Withdrawing route.`)
fired **6,791** times in the same window. `attr_first_as` was 0, so
enforce-first-as is not involved. 1,123 resets in roughly 20 s is about 56 per
second: ExaBGP reconnects immediately, re-announces the suite, and is reset
again. 6,791 / 1,123 ≈ 6 treat-as-withdraw events per connection, which is
consistent with the suite's six deliberately-withdrawable cases being replayed
on every reconnect.

**What this invalidates.** Every route check in a burst that resets is
unreliable — whether a prefix is present depends on where the reconnect landed,
not on how the DUT handled the attribute. The five "expected present,
present=False" results (`unknown-attr-nontransitive`,
`unknown-attr-transitive`, `community-bloat`, `large-community-bloat`,
`atomic-aggregate`) should not be read as findings about those attributes. Note
that `aspath-very-long`, `aspath-as-set` and `aspath-4byte` *were* present in
the same run, which is the signature of a reconnect race rather than of
per-attribute handling.

**What is not yet known.** Which case causes the reset, and by what mechanism.
`notification_sent` and `notification_recv` both read 0, which cannot be
literally true of a session that dropped 1,123 times — so either the log
patterns do not match FRR 10.5.2's wording for this path, or the teardown is
happening without a NOTIFICATION. The leading candidate is
`unknown-wellknown-attr` (attribute type 155 with every flag bit clear, i.e. it
claims to be a well-known attribute the receiver does not recognise): RFC 4271
mandates a NOTIFICATION with subcode Unrecognized Well-known Attribute, and
FRR's `bgp_attr_unknown` returns `BGP_ATTR_PARSE_ERROR` for an attribute
without the Optional bit. That case is already marked
`expect_session="reset-tolerated"`, so a reset there is conformant. **This is a
hypothesis, not a result.**

Instrumentation added so the next run answers it rather than needing another
round trip:

* The burst now records raw DUT log lines (`dut_log_sample`), deduplicated to
  `{count, line}` so a reset loop's thousands of identical lines collapse to the
  distinct set with multiplicities. Counters alone produced the contradictory
  `attr_withdraw=6791, notification_sent=0` reading above.
* New `malformed_isolate` event and an automatic isolation pass in `probe`:
  announce one case, sample `connectionsDropped` either side, withdraw, next.
  Runs only when the burst actually detected a reset, so the extra ~60 s is paid
  only when there is something to explain. It prints which cases reset the
  session and separates them into conformant (`expect_session=reset-tolerated`,
  i.e. RFC 4271 permits it) and **RFC 7606 violations** (`expect_session=up`,
  which must not reset).
* `probe` now prints the before/after peer state and the `connectionsDropped`
  delta, and states explicitly that the route checks are unreliable when a reset
  occurred, instead of listing five results that look like attribute findings.

## H-7. Probe local-preference assertions were never actually checked

Every accepted probe reported `"local_pref": null` while `large_community` came
through correctly. Cause: FRR emits LOCAL_PREF in JSON as **`locPrf`**
(`bgp_route.c`, `json_object_int_add(json_path, "locPrf", attr->local_pref)`),
and the harness read `localPref`. So the half of the IXP-tagging probes that
depends on local-preference — the template sets 275 on the IXP-1 import path and
300 on the IPv6 route-server path — was silently reading None and asserting
nothing. Fixed to read `locPrf` with `localPref` as a fallback, with a selftest
pinning the key.

This does not change any verdict above: the tagging probes assert presence and
the large-community, both of which were being read correctly. It does mean no
run so far has verified the local-preference values.

---

## E-4. CONFIRMED: FRR resets the BGP session on a martian IPv4 NEXT_HOP, which RFC 7606 forbids

This is the resolution of E-3, and it is the most significant result the harness
has produced. It is a defect in FRR, not in the template and not in the harness.

**Observed.** Per-case isolation on VyOS 1.5.1 / FRR 10.5.2. Each case announced
alone, `connectionsDropped` sampled either side, withdrawn before the next:

| case | next-hop | session after | drops in ~3 s |
|---|---|---|---|
| `nexthop-zero` | `0.0.0.0` | **Clearing** | **58** |
| `nexthop-multicast` | `224.0.0.1` | **Clearing** | **58** |
| `nexthop-broadcast` | `255.255.255.255` | Established | 0 (route accepted) |
| `nexthop-offlan` | `192.0.2.254` | Established | 0 (route accepted) |
| all 16 other cases | — | Established | 0 |

58 drops in 3 s is a reset loop: ExaBGP reconnects immediately, re-announces,
is reset again. Across the 20 s burst the counter moved 1,130.

**Mechanism, from source at tag `frr-10.5.2`.** `bgpd/bgp_attr.c`:

```c
enum bgp_attr_parse_ret bgp_attr_nexthop_valid(struct peer *peer,
                                               struct attr *attr)
{
        struct bgp *bgp = peer->bgp;

        if (ipv4_martian(&attr->nexthop) && !bgp->allow_martian) {
                uint8_t data[7]; /* type(2) + length(1) + nhop(4) */

                flog_err(EC_BGP_ATTR_MARTIAN_NH, "Martian nexthop %pI4",
                         &attr->nexthop);
                ...
                bgp_notify_send_with_data(peer->connection,
                                          BGP_NOTIFY_UPDATE_ERR,
                                          BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP,
                                          data, 7);
                return BGP_ATTR_PARSE_ERROR;
        }

        return BGP_ATTR_PARSE_PROCEED;
}
```

It sends NOTIFICATION 3/8 (UPDATE Error / Invalid NEXT_HOP) and returns
`BGP_ATTR_PARSE_ERROR`. Both call sites — in `bgp_attr_parse()` for the legacy
NEXT_HOP attribute, and in `bgp_update_receive()` for the deferred MP_REACH
path (`bgpd/bgp_packet.c`) — turn that into `return BGP_Stop`, i.e. tear the
session down.

**Why it is a violation.** RFC 7606 section 3, item (e):

> "'Treat-as-withdraw' MUST be used for the cases that specify a session reset
> and involve any of the attributes ORIGIN, AS_PATH, NEXT_HOP,
> MULTI_EXIT_DISC, or LOCAL_PREF."

RFC 4271 section 6.3 says the same for the semantic case:

> "If the NEXT_HOP attribute is semantically incorrect, the error SHOULD be
> logged, and the route SHOULD be ignored. In this case, a NOTIFICATION message
> SHOULD NOT be sent, and the connection SHOULD NOT be closed."

A 4-octet next-hop of `0.0.0.0` or `224.0.0.1` is syntactically valid and
semantically wrong, so both documents require the route to be dropped and the
session kept. FRR is aware of the distinction — its own comment at the call site
says the semantic case "is implemented elsewhere", referring to
`bgp_update_martian_nexthop()` in `bgpd/bgp_route.c`, which is a silent
per-prefix filter. But the stricter check fires first, so the compliant path is
unreachable for the legacy NEXT_HOP attribute.

**Affected and fixed versions**, established by reading `bgp_attr_nexthop_valid`
at each tag:

| ref | behaviour |
|---|---|
| `frr-10.4.2`, all `frr-10.5.x`, `frr-10.6.0`, `frr-10.6.1` | NOTIFY + `BGP_ATTR_PARSE_ERROR` → **session reset** |
| `frr-10.7.0`, `stable/10.5` HEAD, `stable/10.6` HEAD, `stable/10.7` HEAD, `master` | `BGP_ATTR_PARSE_WITHDRAW`, no NOTIFY, `BGP_Stop` call site removed |

So VyOS 1.5.1 (FRR 10.5.2) is affected, and the fix exists upstream but had not
landed in any released 10.5.x at the time of testing. The branch head also adds
a martian check inside MP_REACH_NLRI parsing, which is the fix for
CVE-2026-37458 (`bgpd: Validate MP_REACH_NLRI attribute against incorrect
next-hop`).

**Operational impact at an IXP.** Any peer that sends a route with a next-hop of
0.0.0.0 or anything in 224.0.0.0/4 — through misconfiguration, a buggy stack, or
deliberately — drops the BGP session with that VyOS router, repeatedly, for as
long as it keeps announcing. On a shared peering LAN this is a single-peer denial
of service against the session, and the affected router logs `Martian nexthop
<addr>` with no other indication of what happened.

**Mitigation on an affected release:** `bgp allow-martian-nexthop`
(`bgpd/bgp_vty.c`) bypasses both validation layers, at the cost of accepting
martian next-hops into the RIB. `allow-reserved-ranges` does **not** help for
224.0.0.0/4 — it only makes 0.0.0.0/8 and 127.0.0.0/8 valid. Note that VyOS may
not expose `allow-martian-nexthop` in its CLI; verify before relying on it.

**Related, non-defect observation.** `255.255.255.255` as a next-hop is
**accepted** and the route installed. `ipv4_unicast_valid()` in `lib/prefix.c`
tests `IPV4_CLASS_E` first and returns true, so FRR treats all of 240.0.0.0/4 as
usable unicast per draft-schoen-intarea-unicast-240. It does not special-case the
limited-broadcast address within that range. That is what the code says; whether
accepting 255.255.255.255 as a BGP next-hop is desirable is a separate question.
The harness's expectation for this case was `absent` and has been corrected to
`present` — the harness was wrong, not FRR.

**AS 0 handling is compliant**, for contrast. `bgp_attr_aspath_check()` at the
same tag returns `BGP_ATTR_PARSE_WITHDRAW` for AS 0 from an eBGP peer (RFC 7607
+ RFC 7606 section 7.2), logging `Malformed AS path, AS number is 0 in the path
from <peer>`. Treat-as-withdraw, session preserved. Correct.

---

## H-8. The log counters missed the line that explained the reset

`notification_sent` and `notification_recv` read 0 across a window containing
1,130 confirmed session resets, and the raw log sample showed only AS_PATH
lines. Two causes:

1. FRR's message for this path is `"Martian nexthop %pI4"` (`flog_err`,
   unconditional, `bgpd/bgp_attr.c`), and `LOG_PATTERNS` had no entry for it.
   Added as `martian_nexthop`.
2. The `notification_sent` / `notification_recv` patterns assume FRR words those
   lines "sending NOTIFICATION" / "received NOTIFICATION". **That is still
   unconfirmed for 10.5.2** — a run with 1,130 resets left both at 0. Added
   `notification_any`, matching just `NOTIFICATION`, as a version-independent
   counter. Until the wording is confirmed, read a zero in the two directional
   counters as "unknown", not as "no notifications".

The general lesson: a curated grep list is a liability when the thing you are
hunting is a message you did not anticipate. The raw `dut_log_sample` added in
the previous round is what actually solved this, and it should stay.

## H-9. The policy probes were left announced during the malformed phase

`cmd_probe` announced 18 policy probes and never withdrew them before running
the malformed suite. One of them, `bogon-asn-zero`, carries `as-path
[ 64400 0 3356 ]`. During the reset loop ExaBGP re-announced its whole table on
every reconnect, so FRR logged `Malformed AS path, AS number is 0 in the path
from 198.51.100.14` once per reconnect — and the isolation pass attributed those
lines to whichever malformed case was under test. The printed evidence for
`nexthop-zero` and `nexthop-multicast` was therefore about AS_PATH, pointing at
the wrong attribute entirely; the correct line, `Martian nexthop`, was not being
matched at all (H-8).

The *attribution* was still correct — drops began on announce and stopped on
withdraw, and only those two cases showed a non-zero delta — but the supporting
evidence was misleading, which is nearly as bad. Probes are now withdrawn before
the malformed phase (`--keep-probes` restores the old behaviour for debugging).

## H-10. The isolation pass collected clean data and graded none of it

`malformed_isolate` recorded `route_present` per case and never compared it to
`expect_route`, nor `state_after` to `expect_session`. The one pass with
uncontaminated per-case data produced no verdicts — the entire point of
isolating. It now grades both, and classifies each case as `pass`,
`reset-tolerated` (RFC 4271 permits a NOTIFICATION), `unexpected`,
`rfc7606-violation` (a reset that must not happen, not yet traced to source), or
`implementation-defect-confirmed` (a reset traced to quoted source, as with
E-4). Verdicts and the confirmed-defect text are printed and stored in
`probes.json`.

Grading it immediately exposed a wrong expectation: `nexthop-broadcast` had
`expect_route="absent"` and the route is legitimately accepted. Corrected, with
a selftest pinning it.

---

## E-5. FRR does not send a NOTIFICATION for an unrecognised well-known attribute

A deviation from RFC 4271 in the lenient direction, recorded for completeness
because it is the one place the harness expected a reset and did not get one.

Three cases carry attribute type 153 or 155 with the **Optional bit clear**,
which by RFC 4271 section 4.3 means the sender is claiming a well-known
attribute. RFC 4271 section 6.3 is explicit that an unrecognised well-known
attribute is one of the few remaining mandatory-NOTIFICATION cases:

> "If any of the well-known mandatory attributes are not recognized, then the
> Error Subcode MUST be set to Unrecognized Well-known Attribute."

Observed on VyOS 1.5.1 / FRR 10.5.2, all three cases: session stays
`Established`, `connectionsDropped` delta 0, route absent, and the log carries

```
[EC 33554433] (no message found)(153) attribute received, while it is not known how to handle it, treating as withdraw
[EC 33554488] 198.51.100.14: Attribute (no message found), parse error - treating as withdrawal
[EC 33554455] 198.51.100.14(Unknown) rcvd UPDATE with errors in attr(s)!! Withdrawing route.
```

So FRR routes the unrecognised-well-known case through `bgp_attr_unknown()` ->
`bgp_attr_malformed()` with `BGP_NOTIFY_UPDATE_UNREC_ATTR`, and RFC 7606's
graded handling turns that into treat-as-withdraw rather than a reset. That is
strictly safer than what RFC 4271 requires and consistent with RFC 7606's intent,
but it does mean **a peer cannot use an unrecognised well-known attribute to tear
down an FRR session** — worth knowing in both directions. The three cases are
marked `reset-tolerated` / `either`, so either behaviour passes.

Two observations that follow from the same run, neither yet traced to source:

* `notification_any` (matching just the string `NOTIFICATION`) read **0** across
  a window in which FRR's own code path for a martian next-hop calls
  `bgp_notify_send_with_data(... BGP_NOTIFY_UPDATE_ERR,
  BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP ...)` 1,161 times (`martian_nexthop` counted
  1,161). So FRR 10.5.2 appears **not to log the NOTIFICATION it sends** at
  default log level on this path. If that holds, an operator sees only
  `Martian nexthop <addr>` and has no record that a NOTIFICATION was emitted or
  that the session was torn down. Not confirmed against the logging code —
  flagged, not asserted.
* `getaddrinfo failed obtaining local hostname - using 'vyos' instead; error:
  System error [v8.2302.0]` appears a handful of times. Unrelated to BGP;
  recorded so it is not mistaken for a symptom.

## H-11. The unknown-attribute cases never set the Optional bit

The two cases named `unknown-attr-nontransitive` and `unknown-attr-transitive`
used attribute flag bytes **0x60** and **0x70**. Those are
`Transitive|Partial` and `Transitive|Partial|ExtendedLength` — the **Optional
bit (0x80) is clear in both**. An attribute with the Optional bit clear claims to
be *well-known*, so both cases were exercising the unrecognised-well-known path
(E-5) while asserting the unrecognised-*optional* requirement that the route be
preserved. Both therefore reported a failure that was mine, not the DUT's. They
are the two rows that survived every previous round as "unexpected".

The original code comment justified the flags with: *"ExaBGP's own shipped
fixture notes that its selfcheck requires the TRANSITIVE (0x40) and PARTIAL
(0x20) bits on a generic attribute, which is why 0x60 / 0x70 are used here and
0x80-only is not available."* That is **false** for ExaBGP 5.0.9. Verified by
packing each attribute through ExaBGP's own encoder and reading the emitted
bytes — the flag byte is transmitted verbatim:

```
0x80 -> 80990400000064     Optional
0xa0 -> a0990400000064     Optional|Partial
0xc0 -> c0990400000064     Optional|Transitive
0xe0 -> e0990400000064     Optional|Transitive|Partial
```

`exabgp validate -r` rejects 0x80 and 0xc0, which is presumably what the original
note was reacting to — but `-r` re-serialises each route and adds the PARTIAL bit
to an unrecognised optional-transitive attribute, exactly as RFC 4271 section 5
requires of a *receiver* passing it on. `exabgp server` transmits what was
written. Same class of `-r`-vs-runtime discrepancy already documented for the
hand-encoded AS_PATH cases.

The suite now has 23 cases instead of 20:

| case | flags | meaning | expectation |
|---|---|---|---|
| `unknown-attr-optional` | `0x80` | Optional, non-transitive | route kept, attribute silently dropped, session up |
| `unknown-attr-optional-transitive` | `0xc0` | Optional\|Transitive, as originated | route kept, Partial set on re-advertisement, session up |
| `unknown-attr-optional-transitive-partial` | `0xe0` | Optional\|Transitive\|Partial, as relayed | same; this spelling also survives `-r` |
| `unknown-wellknown-attr-transitive` | `0x60` | Optional bit clear | reset tolerated, route either |
| `unknown-wellknown-attr-extlen` | `0x70` | Optional clear + extended length | reset tolerated, route either |
| `unknown-wellknown-attr` | `0x00` | all bits clear | reset tolerated, route either |

Prefixes were also normalised: two of the new cases were initially given /25s,
which a *correctly fixed* template would deny on prefix length, making the case
test policy rather than the attribute. Every IPv4 malformed prefix is now a /24
and every IPv6 one a /48, with a selftest asserting it.

Six new selftests pin the flag semantics: the Optional bit's state per case, the
exact flag byte for the three optional variants, that no Optional-bit-clear case
demands the route be present, and that all three optional cases require the
route kept and the session up.

**The unrecognised-optional-attribute behaviour of FRR has therefore not yet been
measured.** That is the one substantive gap left in the RFC 7606 suite, and the
next `make probe` closes it.

---

## E-4 (continued). Result confirmed; the RFC 7606 suite is complete

Final t0-smoke pass: **21 of 23 isolated cases pass**, and the only two failures
are the confirmed FRR martian-next-hop defect. The three genuine
unrecognised-optional cases added in H-11 all pass — route present, session
`Established`, 0 drops — so **FRR 10.5.2 handles unrecognised optional
attributes correctly** for all three flag combinations (`0x80` Optional,
`0xc0` Optional|Transitive, `0xe0` Optional|Transitive|Partial). That was the
last unmeasured requirement in the suite.

Everything else is now accounted for: `community-bloat`, `large-community-bloat`,
`atomic-aggregate`, `nexthop-broadcast`, `originator-id-over-ebgp`,
`cluster-list-over-ebgp` and `extended-community-on-unicast` all pass in
isolation. The four "unexpected" rows that remain in the **burst** section are
the reset loop's collateral and are correctly labelled unreliable in the output;
read the isolated table instead.

### One measurement nuance worth carrying into any report

In this run `state_after` read `Established` for both offending cases while
`connections_dropped_delta` read 58. In the previous run the same cases read
`Clearing`. Both are correct: during a reset loop the peer state sampled at any
instant is a coin flip depending on where in the reconnect cycle the poll landed.
**`connectionsDropped` is the reliable signal, not the FSM state**, and the
classification keys on the counter — which is why the verdict was stable across
both runs while the state column was not. Anyone reading `show bgp summary` by
hand during a flap should not conclude from a single `Established` that the
session is healthy.

## H-12. ExaBGP withdrawals do not clear hand-encoded attribute routes

Observed, not yet traced to a cause. After `ev_malformed_burst` withdrew all 23
of its cases with `withdraw route <prefix>`, the isolation pass — running
afterwards, one case at a time — still saw these in the DUT log during the
`nexthop-zero` window:

```
x236  [EC 33554433] (no message found)(155) attribute received, while it is not known how to handle it, treating as withdraw
x236  [EC 33554436] Malformed AS path from 198.51.100.14, length is 6
x470  [EC 33554433] (no message found)(153) attribute received, while it is not known how to handle it, treating as withdraw
```

Attribute types 153 and 155 are the `0x99` and `0x9b` generic-attribute cases,
and a 6-byte AS_PATH segment is the `aspath-truncated-segment` case
(`attribute [ 0x02 0x40 0x020200000d1c ]`). All three had been announced and
withdrawn before the window opened, and each is re-announced on every reconnect
of the reset loop — so ExaBGP was still advertising them. The common factor is
that all three use a hand-encoded generic `attribute [ ... ]` clause, which is
consistent with `withdraw route <prefix>` failing to match a route whose
attribute set ExaBGP cannot reconstruct from the prefix alone. **That is a
hypothesis; it has not been verified against ExaBGP's source.**

Consequence while it was unfixed: the log excerpt printed under each confirmed
defect was residue from other cases, not the line that explains the reset. The
*classification* was never affected — it keys on `connectionsDropped` before and
after, plus the quoted FRR source — but the printed evidence was misleading for
three consecutive runs, which is its own kind of failure. Third time this project
has had a correct conclusion supported by the wrong evidence (see also H-8, H-9).

Fixes, both belt and braces:

* `malformed_isolate` now restarts ExaBGP before the pass by default, so its
  Adj-RIB-Out is provably empty. The process re-reads its boot file on start, so
  the baseline table returns on its own. `--no-restart` keeps the old behaviour.
* `Malformed` gained an `expect_log` field, and the isolation pass greps for it
  per case and records `expect_log_found` plus the matching lines separately from
  the broad window sample. `nexthop-zero` and `nexthop-multicast` declare FRR's
  verbatim `Martian nexthop` line, so the decisive evidence lands in the artefact
  instead of being left for a human to spot in a haystack. The broad sample is
  retained and now labelled `(window)` so it is not mistaken for per-case
  evidence.
* The ExaBGP launch command moved to `PeerFleet.EXABGP_SERVER_CMD`, with
  `start_exabgp()` and `restart_exabgp()` alongside it, so a restart cannot drift
  from a cold start. It was previously inline in `runner._start_generators` only.

---

# The first complete chaos run

600 s of chaos, 29 events, 310 samples, 2,240 paths. Verdict printed **FAIL**.
The verdict was wrong: two of the three violations were self-inflicted and the
final policy check asserted nothing. What the run genuinely produced is below,
followed by the four harness defects it exposed.

## Real results

**Convergence.** 1.0 s initial, 0.0 s post-chaos, both converged, against a 60 s
budget at 2,240 paths.

**Flap recovery** — 13 measured flaps, mean 12.7 s, p95 31.7 s, max 45.9 s.
This is the most useful number the run produced. `notification` mode re-settles
consistently faster (4.3–5.4 s) than `admin_down` (11–46 s), which is the
expected shape: a Cease NOTIFICATION tears down cleanly and the peer reconnects
immediately, whereas `admin_down` leaves the peer waiting on its own timers
before re-advertising.

**Policy-commit latency under load.** `community-retag` mean 4.27 s / max 8.21 s;
`localpref-flip` mean 8.41 s / max 8.47 s. Note the discrepancy between the
scheduler's event duration and the commit itself: event #9 took 23.5 s wall for a
commit measured at 0.33 s, and #21 took 31.8 s for an 8.47 s commit. The
difference is apply-plus-revert plus settle, not commit cost.

**Resource envelope.** bgpd RSS peaked at 24.9 MB and did not move for the entire
run (peak == final). zebra 21.5 MB, container 482.8 MB. bgpd CPU mean 0.6 %,
p95 2.5 %, max 21.0 %, with zero samples at or above 95 %. 16.25 IPv4 table
changes/s and 16.3 kernel installs/s sustained. T0 is a smoke profile and the DUT
was never close to a limit — which is the correct result for T0 and means nothing
about capacity.

**FRR martian-next-hop defect (E-4), now with the decisive log line.** The
isolation pass reports `expected log 'Martian nexthop': FOUND`, `x60
[EC 33554438] Martian nexthop 0.0.0.0` and `x60 ... Martian nexthop 224.0.0.1`.
21/23 isolated cases pass; the two failures are the defect. H-12's fix works.

## H-13. The peer-count predicate faulted the DUT for the harness's own flaps

`failed_peers_ipv4` and `failed_peers_ipv6` fired at t=56 with
`established=4/5`. Cross-referencing the timeseries against the event log, every
window in which `v4_established < 5` coincides with a deliberate `peer_flap`.
The scenario mix is 40 % `peer_flap` by weight and `max_failed_peers: 0` was
checked unconditionally, so **no run containing a peer flap could ever pass**.
The FAIL verdict was the harness reporting its own actions as a DUT fault.

Fixed: `PredicateSet` gained `impair_begin()` / `impair_end()`, and
`peer_flap`, `blackhole_peer` and their siblings wrap their outage in one, with a
60 s recovery grace window sized from the measured p95/max re-settle above.
Peer-count faults are suppressed for the duration. The assertion that replaces
it is the one that was always the interesting one: a flapped peer must come
*back*, which the flap-recovery measurement and the post-chaos convergence check
already cover. Three selftests pin the behaviour, including that faults resume
once the grace window expires.

## H-14. The "final policy check" announced nothing, so it asserted nothing

`ev_probe_check` built its probe list with empty peer addresses and went straight
to `lookup_prefix`. Used standalone by `cmd_probe` that was fine, because
`cmd_probe` announces first. As the `run` command's final policy check it queried
18 prefixes that nothing had announced. Every lookup came back empty, the grader
read empty as "reject", and so:

* the 14 probes that expect a reject **passed vacuously**, and
* the 4 that expect an accept (`acceptable-v4-24`, `acceptable-v6-48`,
  `blackhole-scrub`, `ixp-tag-v6`) were reported as **failures**.

The giveaway is `bogon-v6-doc-rfc9637` and all three `toolong-*` probes
"passing" in that check while being confirmed template defects in every other
run. Exactly inverted, and every verdict in that section was meaningless.

Fixed: `ev_probe_check` now announces from the real ExaBGP session with the
correct peer ASN, settles, checks, and withdraws. It also reports
`template_defects` and `unexplained` separately so a confirmed template defect
can never be counted as a run failure.

## H-15. A high-water mark was being read as a live measurement

`dplane_queue_saturated` warned that the queue "reached its limit (201/200)" at
t=20. But `queue_max` from `show zebra dplane` is the maximum depth **since zebra
started**, and the timeseries shows it at 201 in the very first sample (t=0.0)
and constant at 201 for all 310 samples. So the queue hit its limit during the
initial table load, before chaos began, and the warning then re-fired on every
sample at whatever timestamp the sampler happened to be at.

The underlying signal is real and worth keeping — 201 > 200 means the FIB install
path was the constraint at some point — but it happened during bringup, not
chaos. Now: the first value is latched as a baseline and reported once as
`dplane_queue_saturated_before_run` with that stated explicitly; a rise *during*
the run is reported separately as `dplane_queue_saturated`.

## H-16. `walk` churn leaves prefixes behind, and the report quotes the inflated number

`v6_pfx_rcd` ends the run at **804** against **680** announced, having stepped up
680 → 684 → 764 → 804 across `churn walk` events. IPv4 stayed at exactly 1,560
throughout. The report's headline "IPv6 paths received (peak) 804" is therefore
not a capacity figure — it is 124 prefixes the harness announced and failed to
withdraw. `walk` advertises a fresh window and withdraws the previous one
(`global rib add` for the new offset, `global rib del` for the old), so a
positive drift means some of those deletes are not matching. **Cause not yet
established** — the plausible candidate is `gobgp global rib del -a <afi>
<prefix>` failing to match a path originally injected from the MRT table rather
than added via the API, but that has not been verified.

Fixed so far, on the measurement side rather than the cause:

* `run` now runs an announced-vs-accepted comparison per address family before
  the final policy check and stores it in `run.json` as `accounting`.
* The report prints an **Announced vs accepted** table with the drift, and where
  drift is non-zero says outright that the peak figures are not a capacity
  result and should not be quoted before running `make peers`.
* The report now shows `IPv6 paths received (final)` alongside the peak; it
  previously showed final for IPv4 only, which is why a 680 → 804 climb was easy
  to miss.

## H-17. Log-signature counts include windows that predate the run

The report's "Failure signals" table lists `martian_nexthop: 332` and
`attr_withdraw: 447` for a chaos run whose event mix contains no malformed-burst
at all. Those lines were produced by the `make probe` that ran minutes earlier —
the DUT log timestamps confirm it (15:51:48 and 15:52:53, run started 15:54) —
and the sampler's first log windows reach back far enough to catch the tail.

The report now carries that caveat inline, pointing at `samples.jsonl`
timestamps. Not fixed properly: the right fix is to clamp the first window to the
run's start time, which has not been done.

---

# Second full chaos run — PASS, and two more measurement defects

Same profile, same seed. Verdict **PASS**, 0 fail, 1 warn, and the warn is now
correctly worded as `dplane_queue_saturated_before_run`. H-13, H-14 and H-15 are
all confirmed fixed:

* No `failed_peers_*` violations, despite 13 deliberate flaps.
* The final policy check reports **5 confirmed template defects, 0 unexplained**,
  with `local_pref: 275` and the IXP large-communities present on every accepted
  route — it is now asserting something. Note `64000:1:9001` appearing alongside
  `64000:1:1001` on the IPv4 rows, which is the blackhole-scrub / IXP-1 tagging
  pair the template intends.
* Flap recovery reproduced almost exactly: mean 12.9 s vs 12.7 s, p95 31.5 s vs
  31.7 s, max 45.7 s vs 45.9 s across two independent runs. The
  `notification`-vs-`admin_down` split holds. This measurement is stable and
  quotable.
* `policy_churn` commit latency: `community-retag` 0.31 s, `localpref-flip`
  8.46 s. The 27x difference between two apparently similar fragments is
  reproducible across both runs and worth investigating on its own.

## H-18. The DUT log window was never time-bounded, so no signature was live

The report showed `attr_withdraw: 447` and `martian_nexthop: 332` — **byte-identical
to the previous run's report**, for a run whose event mix contains no
malformed-attribute burst at all. Reading `samples.jsonl` directly: 62 of the 63
slow samples reported *exactly* `martian_nexthop: 332, attr_withdraw: 447`. Not
a drift, not a rate — the same constant, every window, for ten minutes.

Cause, in `Dut.log_since`:

```
journalctl --since '-10s' --no-pager -o cat 2>/dev/null | grep -Ei PAT ||
tail -n 4000 /var/log/messages 2>/dev/null | grep -Ei PAT || true
```

`grep` exits 1 when it matches nothing, and a quiet 10-second window matching
nothing is the *normal* case. So on almost every sample the first branch
"failed", the shell fell through to the second, and the second **has no time
bound at all** — it grepped the last 4000 lines of `/var/log/messages` and
returned the full historical set. The 332 martian lines were from a `make probe`
run the previous day.

This is the most consequential harness defect found so far, because the log
signatures are the *primary* failure detector at scale:
`SENDQ_STUCK_WARN`/`_PROPER` (FRR's own non-configurable 2×holdtime session
teardown), zebra netlink `recvmsg overrun`, `maxprefix`, holdtime expiry. At T4
the entire point is to catch the first one of those that fires. None of them
could have been seen.

Fixed: `log_since` now runs journalctl without a shell pipeline, uses its **exit
status** to distinguish "unusable" from "nothing matched", and matches the
patterns in Python. When it does have to fall back to the untimed read it sets
`log_window_unbounded`, which `log_counts` surfaces as `_window_unbounded` in the
sample.

The report side was wrong too, in the opposite direction. `log_totals` took the
**peak** of each counter, which reports one window's worth as if it were the
whole run; these counters are per-window, not cumulative, so the run total is a
sum. It now sums, and additionally:

* flags the whole table as untrustworthy if any sample recorded
  `_window_unbounded`, and
* flags a signature as **suspect** when it reports the identical non-zero value
  in every window it appears in — the shape of a stale read rather than of a
  signal recurring at a perfectly constant rate.

Both new behaviours are pinned by selftests that reproduce the 62×332 pattern and
confirm a genuinely varying series is summed without being flagged.

## H-19. The +124 IPv6 drift was inherited, and the accounting could not say so

H-16's accounting worked — it caught the drift and correctly refused to let the
peak figures be quoted. But the first sample of this run already reads
`v6_pfx_rcd = 804`: the drift was present **before chaos began**, carried over
from the previous run because the lab was never redeployed between them. This run
leaked nothing. Comparing only end-of-run accepted against profile-announced
cannot tell those two situations apart, and they call for opposite responses.

Fixed: `run` now takes an accounting baseline immediately after warmup
convergence and reports `drift_inherited` and `drift_this_run` separately, in
both the console output and the report table. When all the drift is inherited it
says so and tells you to redeploy rather than sending you hunting for a leak that
is not there.

**The underlying `walk`-churn leak (H-16) is still unexplained** and still needs
a clean-baseline run to characterise. The one hint from this run's timeseries:
at t=584–588 v6 briefly reads 718, then 684 — within 4 of the announced 680 —
before returning to 804. So the withdrawals do land, transiently. Whatever holds
the extra 120 re-appears afterwards.

---

# T1: 42 sessions, 90,830 paths — PASS, and the first real scale data

Clean baseline, 30 minutes of chaos, 68 events, 804 samples. `drift_inherited +0`
and `drift_this_run +0` on both address families, so H-19's attribution works and
**H-16's `walk` leak did not reproduce**. That narrows it usefully: every T1
`walk` event landed on a *bilateral* session (`prefixes: 108`), whereas the T0
run's drift followed `walk` events on the **route-server** session
(`prefixes: 560`). The leak is specific to walking a route-server fleet's NLRI
window, not to `walk` in general. Still unexplained, now much better bounded.

Results worth keeping:

* Convergence 1.0 s initial, 0.0 s post-chaos, against a 120 s budget.
* Flap recovery over 24 flaps: mean 10.5 s, p95 16.1 s, max 25.9 s — *better*
  than T0's 12.7/31.7/45.9 despite 40x the table. The `notification` mode is
  consistently ~4–5 s and `admin_down` ~11–16 s, the same split as T0.
* 80.85 IPv4 table changes/s and 62.2 kernel installs/s sustained for 30 min.
* bgpd RSS 174.3 MB, zebra 156.1 MB, container 836 MB at 90,830 paths.
* `soft_clear` on all peers: 0.04–0.10 s. Cheap to trigger, as expected.
* The final policy check and the mid-chaos `probe_check` both report 5 confirmed
  template defects and 0 unexplained, with `local_pref: 275` — the policy
  pipeline stayed correct *under load*, which is what that event exists to prove.

## H-20. FRR's own saturation warning was not in the pattern list

The DUT logged this four times during T1:

```
[EC 100663315] CPU starvation: {(event *)0x7f ... (bgp_generate_updgrp_packets)()
(&connection->t_generate_updgrp_packets) from ../bgpd/bgp_io.c:155}
getting executed 5181ms late, warning threshold ...
[EC 100663315] CPU starvation: {... update_subgroup_merge_check_thread_cb ...}
getting executed 4545ms late
```

bgpd's event loop ran scheduled work **4.5 to 5.2 seconds late**, on the update
generation and update-group merge paths. That is FRR telling us, in its own
words, that the single-threaded update path was saturated — the exact signal this
whole exercise exists to find. `LOG_PATTERNS` had no entry for it, so the report's
failure-signal table read `attr_withdraw: 2` and nothing else.

This is the most serious detection gap yet, worse than H-18: H-18 broke a
detector that existed, this one was never written. Added `cpu_starvation`
(matching `CPU starvation`), `event_slow`, and `read_packet_error` (matching
`bgp_read_packet error`, which also went uncounted despite appearing in the log).
Selftests assert all three against the verbatim T1 log lines.

Reading it alongside the CPU numbers: bgpd p95 73%, 21 samples at or above 95%,
and starvation events at 4.5–5.2 s. At 90,830 paths the main thread is already
the constraint under chaos. That is the T1 finding.

## H-21. Reported CPU% was physically impossible

The report gives `bgpd CPU max 527.0 %`. `bgpd_threads` is **4** in every one of
the 804 samples, and four threads cannot exceed 400%. Six samples read above
400% (519.98, 520.97, 447.48, 526.98, 526.47, 526.98).

Cause: `sample()` took `now = time.monotonic()` at the top and passed that as the
CPU divisor, but `proc_stats()` runs after the BGP summary scrapes. The tick
delta therefore spans (proc_read_n − proc_read_n−1) while the divisor was
(top_n − top_n−1). On a slow sample the heavy scrapes push the /proc read seconds
past the top of the sample, inflating the quotient. 527/400 ≈ 1.32, consistent
with roughly 0.6 s of extra lag on a 2 s interval.

Fixed: the clock is now taken next to the /proc read and used as the divisor.
Each sample also records `proc_read_lag_s`, so this class of skew is visible in
the data rather than inferred, and a value exceeding `threads * 100` increments
`cpu_pct_impossible` instead of being reported as a finding.

**The T1 CPU figures should be re-measured before being quoted.** The starvation
warnings are independent evidence of saturation and stand on their own; the
percentages do not.

## H-22. Bytes-per-path measured nothing, and T2 sizing depended on it

The report gives `bytes per path (estimate) 38 B`. bgpd RSS across the whole run
was 173.4 → 172.1 MB with a 174.3 peak: the table was loaded by `bringup` and the
run only churned it, so within-run RSS growth was noise and the figure divided
noise by noise.

The real numbers, from differencing two measured tiers
(T0: 2,240 paths / 24.9 MB, T1: 90,830 paths / 174.3 MB):

| basis | bgpd | zebra |
|---|---|---|
| marginal, T0→T1 | **1,768 B/path** | **1,593 B/path** |
| whole-table at T1 | 2,012 B/path | 1,802 B/path |

45x the reported 38 B, in the direction that makes the next tier look free.

Fixed: the report no longer presents within-run bytes-per-path as a sizing
number — it says outright when the figure is measuring nothing — and instead
gives whole-table RSS-per-path plus a linear extrapolation to the next tiers,
with the caveat that linear is wrong in both directions (attribute interning
makes shared paths cheaper; allocator fragmentation and per-peer Adj-RIB-In from
`soft-reconfiguration inbound` grow with peer count too) and that differencing
two measured tiers beats extrapolating from one.

**Applied to T2** (~2.02M paths): bgpd ≈ 3.35 GB, zebra ≈ 3.02 GB, ≈ 6.4 GB for
those two daemons. T2's budgets are `bgpd_rss_mb: 24576` and
`zebra_rss_mb: 8192`, so the budgets hold — but zebra at 3.0 GB against an 8 GB
budget is the tighter of the two, and the host needs roughly 8 GB free for the
DUT container alone before the 145 generator processes are counted.

## H-23. Commit latency averaged apply and revert together

`community-retag` was reported as `n=6, mean 5.7 s, p95 24.57 s, max 32.65 s` —
a bimodal distribution presented as a mean. Splitting by phase shows why: the
**apply** commits take ~32.6 s and the **reverts** ~0.3 s. A mean of 5.7 s
describes neither operation.

Fixed: the report now breaks commit latency out by fragment *and* phase, keeps
the combined table for continuity, and states the worst commit as a fraction of
the profile's `commit_s` budget — warning explicitly when it exceeds 70 %.

**This is the metric most likely to fail at T2.** T1's worst commit was 50.09 s
(`prefixlist-grow`) against a 60 s budget — 83 % of it — at 90,830 paths. Policy
commit forces a full re-evaluation of the table, so it scales with table size
while a fixed budget does not. T2 raises `commit_s` to 180 s for 22x the paths;
if commit time scales anywhere near linearly, that is not enough.

---

# Coverage gap: five event kinds and eight detectors have never run

Host memory question settled: the lab host has **62 GB total, 57 GB available,
plus 23 GB swap**. T2's extrapolated ~6.4 GB for bgpd + zebra is comfortable, and
T2's `bgpd_rss_mb: 24576` / `zebra_rss_mb: 8192` budgets hold. Memory is not a
constraint until well past T2.

But the harness is not as exercised as two PASS verdicts make it look. Counting
what actually executed across T0 and T1:

| event kind | executed | detector it exists to provoke |
|---|---|---|
| `churn` | 30 + T0 | — |
| `peer_flap` | 24 + T0 | `notification_*` (read 0, unexplained) |
| `policy_churn` | 9 + T0 | commit latency |
| `probe_check` | 2 | — |
| `soft_clear` | 3 | — |
| `malformed_burst` / `_isolate` | via `make probe` only | `martian_nexthop`, `attr_withdraw` |
| **`blackhole_peer`** | **never** | `sendq_stuck_warn`, `sendq_stuck_proper`, `holdtime_expire` |
| **`maxprefix_trip`** | **never** | `maxprefix` |
| **`gr_event`** | **never** | graceful-restart helper path |
| **`dut_bgpd_restart`** | **never** | PID-change crash detection |
| **`netem`** | **never** | in the T1 mix at weight 4; simply never drawn |

So **five of twelve event kinds have never executed**, and these detectors have
never been observed matching a real event:

`sendq_stuck_warn`, `sendq_stuck_proper`, `netlink_overrun`,
`zebra_recvmsg_overrun`, `maxprefix`, `holdtime_expire`, `bgpd_crash`,
`notification_sent` / `notification_recv` / `notification_any`.

That last group is not merely untested — it is **actively suspicious**. Two runs
performed dozens of `peer_flap mode=notification` events, in which gobgpd sends a
Cease NOTIFICATION with an RFC 8203 shutdown communication, and FRR provably sent
NOTIFICATION 3/8 itself on the martian-next-hop path (E-4). All three
notification counters read **0** throughout. Either FRR 10.5.2 does not log
notifications at default level, or the patterns are wrong. Unresolved.

`sendq_stuck_warn` matters most: it is FRR's own indicator that bgpd cannot drain
its send queue, and at two holdtimes FRR tears the session down itself — a
hardcoded, non-configurable limit absent from the FRR user documentation. It is
the single most likely first failure at T3/T4, and `blackhole_peer` is the only
event that provokes it deliberately. Neither has ever run.

**The empirical case for closing this before T2/T4:** every code path exercised
for the first time in this project has produced a defect. `bringup` (H-4, H-5),
the bind mounts (H-6), the isolation pass (H-10, H-12), the first chaos run
(H-13 to H-17), the first tier change (H-18, H-19), the first real scale
(H-20 to H-23). There is no reason to expect the first execution of five more
event kinds to be different, and finding out during a 2M-path T2 run costs an
hour per iteration instead of minutes.

## `make exercise`

Added a subcommand that runs **every** event kind once, cheapest first, and
reports what happened rather than leaving it to a weighted RNG:

* per event: wall time, status, whether the lab re-converged afterwards, and
  prefix drift against a baseline taken at the start;
* the log signatures that fired inside each event's own window, compared against
  the signatures that event is *declared* to provoke (`expect_logs`), so a
  pattern that silently never matches is reported as `logs-missing` rather than
  as a quiet zero;
* a closing list of **detectors still never observed firing**, so the gap is
  visible in the artefact instead of having to be reconstructed from run.json.

Exit status is non-zero if any event errors or the lab fails to recover. It is a
test of the harness against the DUT, not a capacity test — T0 is the right
profile for it, and it takes minutes.

Seventeen steps, covering all four `peer_flap` modes (`admin_down`,
`notification`, `process_kill`, `process_term`) and all four `churn` modes
(`flap_same`, `walk`, `attr_churn`, `withdraw_storm`) — several of which have
also never run. `withdraw_storm` in particular is the case an FRR maintainer
comment records as having taken "40+ seconds" of main-thread CPU, and it has
never been triggered here.

Fourteen selftests keep the plan from drifting behind the catalogue: every
scheduler event kind must appear in it, every declared signature must be a real
`LOG_PATTERNS` key, and the three never-fired detectors that matter most
(`sendq_stuck_warn`, `maxprefix`, `holdtime_expire`) must be declared as
expectations by some event.

## Honest status

Production-ready for what it has demonstrated: **T0 and T1 scale, six event
kinds, and the policy/RFC-7606 suites**, which between them produced five
confirmed template defects and one confirmed FRR defect (E-4), all reproducible
across runs.

Not yet demonstrated: the five unexercised event kinds, the eight unproven
detectors, T2 scale and above, the `walk` leak's root cause (H-16 — and note T2's
largest fleets *are* route servers, at 380k/300k/190k prefixes, which is exactly
where the leak was seen), and whether commit latency at 22x the table stays
inside T2's 180 s budget after measuring 50 s at 60 s budget on T1.

## H-24. `make exercise` crashed on its first step, and 489 offline checks missed it

```
TypeError: Ctx.log() got multiple values for argument 'kind'
```

`cmd_exercise` built a per-event row keyed `kind` and expanded it into
`ctx.log("exercise_step", **row)`. Python binds the positional `kind`, then finds
`kind` again in the keyword dict, and raises **at the call site** — so no
defensive code inside the function could have helped. Died on step 1 of 17.

Two fixes, because the typo and the design are separate problems:

* The row field is now `event`, not `kind`. `ctx.log` writes its own `kind`, so
  a row that carries one is a name collision by construction.
* `kind` is **positional-only** in both log sinks — `Ctx.log(self, kind, /, **kw)`
  and `Sampler.event(self, kind, /, **kw)`. Four call sites in `scenarios.py` and
  `runner.py` expand dicts into these functions, and the signature is the only
  place the collision can actually be prevented. A caller-supplied `kind` now
  lands in `kw` and is preserved as `event_kind` instead of raising.

### The coverage lesson, which is the more important half

The static check added one turn earlier — `check_exercise_plan_covers_catalogue`
— **passed** while the subcommand was completely broken. It verified that every
event kind appeared in `EXERCISE_PLAN` and that every declared signature was a
real `LOG_PATTERNS` key. Both true. Neither required the code to run.

This is the third instance of the same blind spot:

| defect | what was verified | what was not |
|---|---|---|
| H-5 | `peers.py` imported and parsed | that `runner` called it with the right type |
| H-14 | probe expectations were correct | that the check announced anything |
| H-24 | the plan covered the catalogue | that the plan could execute |

H-5's fix was `check_runner_smoke`, which invokes the real `_start_generators`
against a fake exec layer. The same treatment now applies here:
`check_exercise_runs_end_to_end` invokes the real `cmd_exercise` for every
profile, with a fake DUT and fleet, `_converge` and `_accounting` stubbed, and
`dry_run=True` so the events return immediately rather than sleeping through a
225-second blackhole. It asserts a clean exit, one row per plan step, no event
raising, and that every row is keyed `event`.

That still does not prove the events *do* anything — only a lab can — but it does
prove all 17 steps can be entered and left, which is what was actually broken.
The standing rule for this harness: **a static check on a code path that has
never executed is not coverage.** Every subcommand needs a smoke invocation
against fakes, and `status`, `config`, `converge`, `probe`, `run`, `ramp` and
`teardown` still do not have one.

---

# `make exercise` — 17/17 ran, and it found five things

All 17 events executed, none errored, all 17 recovered. The subcommand works. Two
detectors were confirmed genuinely working (`martian_nexthop` and
`attr_withdraw`, both on `malformed_burst`). Everything else it reported was a
defect.

## H-25. `process_kill` / `process_term` bring the session back empty

Prefix drift went to **-1000 v4 / -400 v6** at step 10 (`peer_flap
mode=process_kill`) and stayed there for all six remaining events. Every step
after it also reported `recovered: true`.

Both are correct, and together they are the bug. `unflap` restarts gobgpd, so the
session re-establishes and the session count is right — but **a fresh gobgpd has
an empty RIB**. The MRT table was never re-injected, so the peer came back
advertising nothing. `ConvergenceTracker` asserts session counts and table
stability, both of which were satisfied by a peer that is up and silent.

The affected session was `ixp1-rs-0000`: 1,000 v4 and 400 v6, i.e. **64 % of the
T0 IPv4 table**, silently absent for the rest of the run while every check said
PASS. Any run containing `process_kill`, `process_term` or `gr_event` loses that
peer's whole contribution from the moment it fires. T0 and T1 never hit it
because those three events had never executed.

Fixed: `unflap` now calls `reinject_after_restart`, which waits for the fresh
gobgpd's gRPC API to answer before loading the table — a gobgpd that has only
just been exec'd refuses the connection, and the injection would otherwise fail
silently into a discarded `RunResult`.

## H-26. Two notification detectors were matching non-BGP noise

`make exercise` reported `dut_bgpd_restart` as having fired `notification_sent`
and `notification_any`. Neither had anything to do with BGP:

| detector | pattern | what it actually matched |
|---|---|---|
| `notification_sent` | `sending NOTIFICATION` | `zebra[448]: NB_OP_CHANGE: oper_walk_done: ERROR: Error sending notification message for path: /frr-vrf:lib/vrf[name="default"]/state` |
| `notification_any` | `NOTIFICATION` | `frrinit.sh[456]: bgpd: memstats:  BGP Notification Message : 4 * (variably sized)` |

The first is zebra's YANG northbound plumbing. The second is bgpd's shutdown
memory accounting dump. **A false positive is worse than a gap** — it reports a
detector as proven when it has never seen the thing it is named for.

Fixed: anchored on bgpd plus the protocol wording — `bgpd.*(sending|Send)
NOTIFICATION`, `bgpd.*(received|rcvd|Receive) NOTIFICATION`, and
`bgpd.*NOTIFICATION \d` for the catch-all (FRR writes the subcode, as in
`NOTIFICATION 6/2 (Cease/Administrative Shutdown)`, which memstats does not).
Selftests assert both real lines match and both noise lines do not.

## H-27. FRR logs no session events at all at default level

This is the reason eight detectors have never fired, and it is not a pattern
problem.

Across the entire `make exercise` log — 17 events including four peer-flap modes,
a blackhole held for 2.5x holdtime, a max-prefix trip and a bgpd restart — the
count of `went from`, `Hold Timer`, `Maximum-prefix` and `bgp_read_packet` lines
is **zero**. bgpd's only output for the whole run was attribute-parse errors.
FRR gates session state changes, holdtime expiry and notification send/receive on
`debug bgp neighbor-events` (`bgp_fsm.c` and `bgp_packet.c` test
`BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS)`), and nothing had ever enabled it.

So `notification_sent`, `notification_recv`, `notification_any`, `peer_down`,
`holdtime_expire` and `read_packet_error` were **structurally unable to fire**,
regardless of how the patterns were written. Every "logs-missing" verdict against
them was a false negative.

Fixed: `Dut.BGP_DEBUGS` names the required debug, `enable_bgp_debugs()` applies it
over vtysh, and `bgp_debugs_active()` reads back whether it took. `bringup` arms
it and reports success or failure; `exercise` arms it, reads it back, and prints
a warning that its own results are false negatives if the debugs are not active.
These are FRR-level rather than VyOS config nodes, so a VyOS commit can drop
them — re-arming after `policy_churn` is the obvious next step and is not done
yet.

**Superseded in part by H-30.** The conclusion above — "it is not a pattern
problem" — was wrong for six of the eight detectors: their patterns matched
strings FRR never emits, so they would have stayed at zero even with the debug
armed. The missing debug was real but it was not the whole cause, and the first
attempt at arming it did not work either (`armed=True` came from vtysh's exit
status while the readback said `False`). H-30 has the corrected patterns, the
working arming path, and the measurement that separates a missing flag from a
log-severity floor.

## H-28. An unmounted external MRT was diagnosed as a stale bind mount

T3 `bringup` printed the correct line — *"external MRT declared in the profile
(...); mount it into ixp1-rs-c000 yourself"* — and then unconditionally printed
the stale-bind-mount paragraph underneath it, telling the operator to redeploy and
check their file-sync agent. Neither applies. The advice block ran whenever any
session failed, without checking whether the failures were external.

This is not a sync issue and redeploying will not help. Using a real collector
dump needs three things the harness does not do:

1. the file present on the host **and bound into each peer container** at the path
   the profile names — nothing generates or mounts it;
2. it **decompressed** — `gobgp mrt inject` reads raw MRT, not `.bz2`;
3. **per-address-family injection with `--nexthop <peer-addr>` plus `--no-ipv4` /
   `--no-ipv6`** — a collector dump's next-hops point at the collector's peers,
   not at this lab's peering LAN, so without the rewrite every path loads and is
   then unreachable.

Item 3 is the deferred T3 work flagged at the start of this project. Until it
exists, T3 cannot produce a meaningful result even with the file mounted. The
message now says all of this instead of misdirecting.

## H-29. The per-event log window bled between events

`maxprefix_trip` was reported as having fired `attr_withdraw` and
`martian_nexthop`. Those were `malformed_burst`'s lines, from the step before:
the window was `event_duration + 20 s`, and with a 41.8 s event that reaches back
past the previous step. Clamped to `duration + 3 s`.

Separately, `maxprefix_trip` did not fire `maxprefix`, and that is a real gap: on
t0-smoke the bilateral peer-groups have `maximum-prefix 200` while the fleets
announce 180, so the event has only 20 prefixes of headroom and does not appear
to cross it. Unverified — needs the event's own logic checked against the
profile's limits.

## Still open after this round

* **`sendq_stuck_warn` may be unreachable in this topology.** `blackhole_peer`
  ran for 75.2 s against a 30 s holdtime and fired nothing. The likely reason is
  structural: `pfx_snt_total` is **0** in every T0 sample, because the DUT
  correctly advertises almost nothing at an IXP (its own supernets, denied to
  most peers by the export policy). FRR's send-queue teardown needs a queue that
  cannot drain, and a queue with nothing in it never backs up. If that holds,
  provoking it needs the DUT to be advertising heavily — a topology change, not a
  pattern fix. **Hypothesis; needs the blackhole re-run with debugs armed to
  confirm the session even dropped.**
* `attr_first_as`, `cpu_starvation`, `event_slow`, `netlink_overrun`,
  `zebra_recvmsg_overrun`, `optmem`, `bgpd_crash`, `sendq_stuck_proper`,
  `maxprefix`, `holdtime_expire` — still never observed firing.
* The `walk` leak (H-16) did **not** reproduce here either: `churn/walk` showed
  drift 0. It has now failed to reproduce twice, both times on bilateral
  sessions. Still only ever seen on a route-server fleet.

## H-30. Six log detectors matched strings FRR never emits

H-27 concluded that the never-firing session detectors were blocked by a missing
debug flag. That was half of it at most. Reading the FRR 10.5.2 sources for every
pattern in `Dut.LOG_PATTERNS` — rather than trusting the wording each was written
from — found six that could not have matched anything, at any scale, with or
without debugs armed.

| detector | pattern before | what FRR actually logs | severity |
|---|---|---|---|
| `sendq_stuck_warn` | `SENDQ_STUCK_WARN` | `<peer> has not made any SendQ progress for 1 holdtime (90s), peer overloaded?` | `flog_warn` |
| `sendq_stuck_proper` | `SENDQ_STUCK_PROPER` | `<peer> has not made any SendQ progress for 2 holdtimes (180s), terminating session` | `flog_err` |
| `zebra_recvmsg_overrun` | `RECVMSG_OVERRUN` | `routing socket overrun: <err>` | `flog_err` |
| `maxprefix` | `Maximum-prefix` | `%MAXPFXEXCEED: No. of IPv4 Unicast prefix received from <peer> 181 exceed, limit 50` | `zlog_info` |
| `notification_sent` | `bgpd.*(sending\|Send) NOTIFICATION` | `%NOTIFICATION: sent to neighbor <peer> 6/2 (Cease/...) 0 bytes` | `zlog_info` |
| `notification_recv` | `bgpd.*(received\|rcvd\|Receive) NOTIFICATION` | `%NOTIFICATION: received from neighbor <peer> 6/2 (...) 0 bytes` | `zlog_info` |
| `notification_any` | `bgpd.*NOTIFICATION \d` | (as above; `%` is the anchor) | `zlog_info` |
| `event_slow` | `event .* took .*ms` | `CPU HOG: task <name> (<id>) ran for 4531ms (cpu time 4210ms)` / `STARVATION: task ...` | `flog_warn` |

Three distinct mistakes, each worth naming separately:

1. **Matching C enum names.** `EC_BGP_SENDQ_STUCK_WARN` is an *error-code
   constant*. `flog_err`/`flog_warn` print the numeric form — `[EC 33554461]` —
   never the symbol. `sendq_stuck_warn` and `sendq_stuck_proper` are the two most
   important detectors in the table, because FRR's 2x-holdtime send-queue
   teardown (`sendholdtime = holdtime * 2`, hardcoded) is the failure mode this
   whole project set out to find. Neither could ever have matched. The
   "`sendq_stuck_warn` may be unreachable in this topology" hypothesis in H-29's
   still-open list was therefore built on a detector that was not wired up at
   all; it needs re-testing before it can be believed either way.
2. **Guessing word order.** All three notification patterns put the verb before
   the tag (`sending NOTIFICATION`). `bgp_notify_print()` puts it after
   (`%NOTIFICATION: sent to neighbor`). The exercise report's own note —
   *"all three counters read 0 across two runs, which is still unexplained"* —
   is now explained.
3. **Matching a message that needs an unavailable config option.**
   `Maximum-prefix` appears only in the *restart-timer* messages, emitted when
   `maximum-prefix <n> restart <min>` is configured. VyOS exposes no `restart`
   sub-option, so those lines cannot occur on this DUT under any circumstances.

### The severity pattern, which is the useful part

Sorting the detectors by FRR log severity separates them exactly along the line
between "has fired" and "has never fired":

* **`flog_err` / `flog_warn`** — `attr_withdraw`, `martian_nexthop`,
  `cpu_starvation`. All three have been observed. `sendq_stuck_*`,
  `netlink_overrun`, `read_packet_error` and `event_slow` are also in this band
  and should be reachable now that their patterns are right.
* **`zlog_info`** — `%NOTIFICATION`, `%ADJCHANGE`, `%MAXPFX`. None ever observed.
* **`zlog_debug`** — the FSM `went from` line. Never observed.

That is consistent with a severity floor between warn and info somewhere below
bgpd (FRR's own `log syslog <level>`, the container's rsyslog, or journald),
which no code in this harness had ever set or read. It is *also* consistent with
the patterns simply being wrong. The two had never been told apart, so the fix
does both and then measures which one it was.

### What changed

* Patterns corrected against source, plus two new ones (`maxprefix_exceeded`,
  `peer_up`) and the zebra-connection pair from the same rerun's log
  (`zebra_conn_lost`, `nexthop_reg_fail` — bgpd lost its zclient socket after a
  restart and nothing counted it).
* `enable_bgp_debugs()` now: turns on `bgp log-neighbor-changes` (config, not a
  debug — it survives a bgpd restart and it is what unlocks `%ADJCHANGE` and
  `%NOTIFICATION` at info level, per `bgp_debug.c`, which checks
  `BGP_DEBUG(neighbor_events) || BGP_FLAG_LOG_NEIGHBOR_CHANGES`); sets
  `log syslog debugging` so FRR's own destination floor cannot drop the debug
  lines; tries the **enable-node** form of the debug before the config-node form;
  and reports `ok` from `show debugging bgp` rather than from vtysh's exit
  status. The previous version reported `armed=True` from the exit status while
  the very next readback said `False`.
* `rearm_bgp_debugs()` runs before **every** exercise event, and each row records
  `debugs_active`. Terminal debugs live in bgpd's memory, so step 17
  (`dut_bgpd_restart`) cleared them, and a VyOS commit runs frr-reload which can
  drop the config-node form — everything after step 12 was unarmed regardless.
* `verify_log_pipeline()` resets one session and reports `tier_reached`:
  `debug` (the FSM line arrived), `info` (only `%ADJCHANGE`/`%NOTIFICATION`), or
  `warn_or_err_only` (nothing did). This is the measurement that settles the
  severity-floor question, and `exercise` prints it before running the plan.
* A selftest now asserts every pattern against a line copied from the FRR source
  that emits it, and rejects any pattern containing a C-enum-shaped token. Six
  patterns were invented and six were wrong; the check that would have caught
  them cost twenty lines.

## H-31. `maxprefix_trip` had no evidence of its own

The event was a one-line delegation to `ev_policy_churn`, so the only thing
distinguishing "the limit tripped and the session was torn down" from "nothing
happened" was a log signature — and per H-30 that signature was the wrong string.
The row read `ok / recovered: true / drift 0` either way.

Two facts settle how it should behave, both from source:

* Lowering the limit **does** trip immediately. `peer_maximum_prefix_set`
  (`bgpd/bgpd.c`) calls `bgp_maximum_prefix_overflow(peer, afi, safi, 1)` — note
  `always=1` — for the peer and again for every peer-group member. No new UPDATE
  is needed, which was the competing hypothesis.
* Recovery is not guaranteed. The template's `maximum-prefix` is a bare limit
  because VyOS exposes no `warning-only`, `restart` or `threshold` sub-option, so
  teardown is the only behaviour and re-raising the limit may not be enough on
  its own.

The event now samples per-peer state directly — before, 2 s after the squeeze
commit, at the end of the hold, and again after the revert — and records
`tripped`, `still_down_after_revert` and `needed_explicit_clear`. If raising the
limit is not enough it issues the reset, but records that it was needed rather
than reporting a clean recovery.

## H-32. `exercise` never evaluated its own predicates

`cmd_exercise` constructed a `PredicateSet` and assigned `ctx.preds` so events
could suppress their deliberate impairments, and then never called `check()`.
Nothing in the command evaluated a single predicate — including the PID-change
daemon-restart detector, which is the only thing that catches a bgpd crash that
logs nothing, and which is the entire point of the `dut_bgpd_restart` step. That
step has been reported as passing in every run so far on the strength of a log
window that contained nothing.

Now evaluated per event, after the recovery check so a deliberate outage is
already over, with the violations recorded on the row and summarised at the end.

## Template defect triage: what is on the stress path and what is not

The eleven template defects above were found by reading the config, and they are
worth keeping as a review of NE-1849. But only some of them affect what this
harness *measures*, and carrying the rest as open items has been a distraction.
Triage, with what the generated lab now does about each:

| # | Defect | On the stress path? | Action |
|---|---|---|---|
| 9 | `maximum-prefix 200` on the four bilateral peer-groups | **Yes — it was the binding constraint on the whole experiment** | **Fixed in the generated config.** See below. |
| 11 | Management VRF + `default-action drop` | Yes — would lock the harness out of the DUT on first commit | Already neutralised: the VRF lines are commented out unless `dut.mgmt_vrf: true`, and an explicit eth0 accept is generated (`render_access`). |
| 2 | `asn-bogons` rejects private ASNs on import and export | Yes — the simulated fleets would be filtered out entirely | Already neutralised: `model.py` validates every fleet ASN against the bogon ranges at generation time and refuses to build a profile that would be filtered. Profiles use 1–64495. |
| 6 | `rpki` route-map is a no-op | No — no effect on load | Lines dropped when `rpki.enabled` is false, with a note that enabling a cache alone changes nothing. Documented, not fixed. |
| 1 | Prefix-length filters do not filter | No — the generated prefixes are inside the intended /8–/24 and /12–/48 anyway, so acceptance is unchanged either way | Documented. The policy probes encode the **actual** behaviour, not the intended behaviour, so they do not fail spuriously. |
| 3 | Own supernet accepted back from peers | No | Documented; one probe asserts the real behaviour. |
| 4 | IPv6 from IXP-2 gets no community and no local-pref | No — affects tagging, not volume | Documented; the v6 IXP-2 probes expect the untagged result. |
| 7 | `ipv6-bogons` missing RFC 9637 `3fff::/20` | No | Documented. Note the profiles use `3fff:100::/32` as the DUT's own v6 supernet, so this is load-bearing for the *lab's* addressing but not for the DUT's behaviour. |
| 8 | `ipv4-bogons` rule 30 is `10.64.0.0/10`, probably meant `100.64.0.0/10` | No | Documented. Worth noting the profiles use `100.64.0.0/16` for the DUT's own space, which the intended fix would have made a bogon. |
| 5 | `igp4` / `igp6` peer-groups referenced, never defined | No — inert here | The iBGP section is not part of the extracted config dump, so nothing in the lab references those peer-groups. Documented only. |
| 10 | `continue` targets that do not exist | No — FRR's `on-match goto` semantics make it benign | Documented only. |

### Defect 9, fixed: the limit was capping the experiment

`ixp1-peer4`, `ixp1-peer6`, `ixp2-peer4` and `ixp2-peer6` all ship with
`maximum-prefix 200`. Every profile in this repo had its bilateral fleets pinned
to **180 v4 / 90 v6 prefixes** to stay under it — including `t4-breakit`, where
350 bilateral sessions contributed 63,000 v4 paths against the route servers'
590,000.

That is not a cosmetic problem. The chaos engine flaps **bilateral** sessions
(`flappable: true`), so every flap-recovery, convergence and update-generation
number measured so far was taken on the smallest sessions in the lab. The T1
result "flap recovery mean 10.5 s, p95 16.1 s" is the cost of re-advertising 180
prefixes, not of anything a real IXP peer would do.

Two changes:

* `render_peergroup_limits()` computes, per peer-group, 4x the largest
  announcement of any fleet in it (floor 1000) and emits an override — **only
  where that raises the existing value**, so the route-server peer-groups'
  400000/200000 are left alone. The headroom covers the `walk` churn mode, which
  announces fresh NLRI before withdrawing the old and so transiently exceeds the
  steady-state count.
* Bilateral prefix counts raised in the profiles now that nothing caps them:
  T1 to 2,000 v4 / 500 v6; T2, T3 and T4 to 5,000 / 1,000. T0 is left at 180/90
  — it is a harness smoke test and its value is that it runs in minutes.

Effect on scale: T1 goes from 90,830 to 180,030 paths, T2 from ~1.88M to 2.80M,
T4 to 4.12M (≈14 GB at the measured 3.4 kB/path across bgpd and zebra, against
57 GB available on the lab host).

**This invalidates the existing T1 baseline.** The convergence, flap-recovery and
table-churn figures in "Real results" above were measured against 180-prefix
bilateral sessions and are not comparable to anything measured after this change.
They are kept as a record of the old configuration, not as the result.

`maxprefix-squeeze` also had both of its numbers hardcoded — squeeze to 50,
restore to 200. Both are now derived: the squeeze is half of what the peer-group's
members actually announce, and the revert restores the *generated* limit rather
than silently re-imposing the throttle this build removed.

## E-4, excluded from the suite

The martian-next-hop session reset (`nexthop-zero`, `nexthop-multicast`) is a
confirmed FRR defect, present in every released 10.4.x / 10.5.x / 10.6.x and
fixed in frr-10.7.0. It cannot be fixed on VyOS 1.5.1 / FRR 10.5.2 from inside
this project, and the only workaround, `bgp allow-martian-nexthop`, disables the
validation the test is about.

So there is nothing further to learn by firing it, and a real cost to doing so:
each malformed burst spends an actual IPv4 session reset inside the measurement
window, which contaminates prefix drift, convergence and flap-recovery for that
window with an outage the harness caused deliberately to re-derive a known
result.

Both cases are now excluded from the default suite via
`policyprobe.EXCLUDED_TAGS = ("martian",)`. They remain in the catalogue and are
still reachable by name — `ev_malformed_isolate(only=["nexthop-zero"])` passes
`exclude_tags=()` — so the defect can be reproduced on demand for a bug report or
re-tested against a fixed FRR. The `martian_nexthop` log pattern is kept as a
diagnostic: if it ever fires now, something injected a martian next-hop that was
not supposed to. `malformed_burst` no longer expects it.

The remaining RFC 7606 suite is 21 cases, including E-5 (unrecognised well-known
attributes are treat-as-withdraw rather than a NOTIFICATION), which is a real
finding and does not reset anything.

## H-33. Two impairments were silent no-ops, and one had never been questioned

`blackhole_peer` on 2026-08-21 ran for 75.3 s against a 30 s holdtime. The DUT's
log for that window contains **no FSM transition, no hold-timer expiry, no
NOTIFICATION and no ADJCHANGE** — while `debug bgp neighbor-events` was armed and
`log-neighbor-changes` was on, both proven working minutes earlier by the pipeline
probe (10 FSM lines, 2 ADJCHANGE, 1 NOTIFICATION from a single reset).

That combination is not physically possible if BGP was being dropped. A peer that
stops speaking for 2.5x holdtime must trip the DUT's hold timer at 1x. So the
impairment was never in place.

The cause is in the primitive:

```python
return self.exec(s.container, f"({cmd}) 2>/dev/null; true")
```

`; true` makes the exit status meaningless, `2>/dev/null` throws away the reason,
and both call sites ignored the returned `RunResult` entirely. A peer image
without `iptables` therefore produces: clean exit, zero rules, no outage, and a
green `blackhole_peer` row with `recovered: True`.

This also retires the "`sendq_stuck_warn` may be unreachable in this topology"
hypothesis from H-29's still-open list as untested — it was never tested, because
nothing was ever blackholed. The hypothesis itself still looks right for a
different reason, now recorded as a fact rather than a guess: `pfx_snt_total` is
**0** in every T0 sample, because the DUT correctly advertises almost nothing at
an IXP. FRR's send-queue teardown needs a queue that cannot drain, and a queue
with nothing in it never backs up. `ev_blackhole_peer` now records
`dut_pfx_snt_to_peer` and `sendq_path_reachable` so that zero is an explained
fact, and the exercise plan no longer demands `sendq_stuck_warn` from a topology
that cannot produce it. What it *does* demand is the hold-timer expiry, which is
unconditional.

`netem` is the same shape and has never produced an observable effect in any run.
"40 ms and 1% loss is too mild to matter at this scale" and "tc was never
applied" had not been told apart. Both primitives now read their state back
(`blackhole_rules()`, `netem_active()`), and both events abort with a distinct
record — `blackhole_ineffective`, `netem_ineffective` — rather than sleeping
through an unimpaired path and reporting success.

## H-34. One unknown vtysh command disarmed every event after the first commit

The 2026-08-21 log has an exact cutoff. FSM transition lines and `%ADJCHANGE`
lines run from 17:33:37 to 17:37:44 and then stop dead. 17:38:11 is
`watchfrr: Configuration Read in Took: 00:00:00` — the first `policy_churn`
commit. Nothing session-level is logged again for the remaining five events
(`malformed_burst`, `maxprefix_trip`, `blackhole_peer`, `gr_event`,
`dut_bgpd_restart`), even though `rearm_bgp_debugs()` ran before each one.

The whole chain traces to a single line in the run's own evidence dump:

```
show_debugging_bgp: {'rc': 1, 'out': '% Unknown command: show debugging bgp'}
```

1. `show debugging bgp` is what FRR's `bgp_debug.c` installs, and it is what the
   readback asked for. VyOS 1.5.1's vtysh does not have it.
2. So `bgp_debugs_active()` returned False — for a *parse* reason, not because
   the debug was off. The enable-node arming had already succeeded and FRR had
   said so: `out: 'BGP neighbor-events debugging is on'`.
3. On that false negative, arming fell through to the CONFIG_NODE form.
4. The config-node form appears in `show running-config`. The enable-node form
   does not — `TERM_DEBUG_ON` sets an in-process flag only.
5. VyOS's commit runs `frr-reload.py`, which diffs the running config against the
   frr.conf VyOS generates. It finds `debug bgp neighbor-events` there, does not
   find it in the generated file, and issues `no debug bgp neighbor-events`.
   `DEBUG_OFF` clears the term flag along with the config flag.
6. Every subsequent re-arm was undone by the next commit inside the same event.

So the fix is not "re-arm harder". It is:

* try more than one readback command and treat "unknown command" as *ask
  something else*, never as *the debug is off* (`DEBUG_SHOW_CMDS`);
* accept FRR's own `"...debugging is on"` echo as proof, since it is more
  authoritative than a readback the build may not implement;
* arm in the **enable node only**, whose flag frr-reload cannot see and therefore
  cannot remove. The config-node fallback remains for a build where the enable
  form fails, but the returned `via` now says out loud that it will not survive a
  commit.

This is the third time in this project that a detector reported a clean zero
because of a defect on the *harness* side of the boundary. The pattern is
consistent enough to be worth stating as a rule: **a readback that can fail for a
reason other than "the thing is off" must distinguish those cases, or it will
eventually be read as a DUT result.**

## H-35. The per-event log window closed before the lab came back

`peer_flap/admin_down` was marked missing `peer_up` with `recover=8.0s` against a
5.1 s event. The window was `event_duration + 3 s`, taken *before* `_converge`, so
the session came back three seconds after it closed. `dut_bgpd_restart` had the
same shape: 5.8 s event, 3 s recovery, `peer_up` missed.

A session-up line is part of the event that took the session down, so the window
now spans `event + recovery + 3 s`, read after `_converge`. Still clamped — it
cannot reach back into the previous step the way the old `secs + 20` did (H-29).

## H-36. `maxprefix_trip` cannot tell "did not trip" from "never got the chance"

The event fired no `%MAXPFXEXCEED`. The only DUT log line anywhere in its window
is:

```
17:39:22  bgpd: [EC 33554455] 198.51.100.11 [Error] bgp_read_packet error: Connection reset by peer
17:39:22  watchfrr: Configuration Read in Took: 00:00:00
```

Same second as the apply commit. That is consistent with VyOS's frr-reload
**bouncing the peer-group's sessions** on a `maximum-prefix` change rather than
adjusting a live limit — and there is no `%ADJCHANGE ... Up` for that peer before
the revert 33 s later, i.e. it had not finished reconnecting while the squeezed
limit was in force. A peer that is still in Connect cannot exceed a prefix limit.

This does **not** contradict the source reading in H-31 — `peer_maximum_prefix_set`
does call `bgp_maximum_prefix_overflow(..., always=1)` per peer and per
peer-group member. It means the harness never let FRR get to the state where that
matters, and could not say so.

The event now reads the peer-group limits back out of the running config after
the apply commit (`peergroup_limits_after_apply`) and waits for the bounced
sessions to re-establish before judging
(`all_peers_reestablished_after_s`). If the sessions do not come back inside the
hold, that is the recorded outcome instead of a bare "no trip".

Note this makes the *session bounce* itself a finding worth confirming
separately: if a `maximum-prefix` change on a VyOS peer-group resets every member
session, that is a materially different operational cost from an in-place limit
change, and it is not what an operator would expect from tightening a limit.
Stated as a hypothesis with one run's evidence behind it, not as a result.

## H-37. 292 offline checks passed while the harness could not start

`make exercise` died on its first line:

```
AttributeError: 'Dut' object has no attribute 'enable_neighbor_changes'
```

Three methods — `local_asn`, `neighbor_changes_state`, `enable_neighbor_changes`
— had been removed by a bad edit while `enable_bgp_debugs()` kept calling
`self.enable_neighbor_changes()`. The full offline suite passed, twice, across
five profiles.

The reason it passed is the interesting part. The check that was supposed to cover
exactly this did:

```python
r.check("enable_neighbor_changes" in src, "arming also turns on ...")
```

A **string match on the source text**. The call site *is* that string, so the
check passed precisely because the broken call was still written. It proved a call
is written, not that it can be made — the same category of mistake as H-30's
invented log patterns, where the assertion and the thing asserted were both
authored from the same wrong belief.

Fixed generally rather than by restoring three methods and moving on:
`check_self_references_resolve` parses each driver class (`Dut`, `PeerFleet`,
`Sampler`, `PredicateSet`, `Ctx`), collects every attribute it reads off `self`,
and resolves each against the class, its own `self.x = ...` assignments, and its
dataclass fields. Verified by deleting `enable_neighbor_changes` in-process and
confirming the check fails.

Standing rule this project keeps re-learning: **a check written as a substring
search over source code is worth roughly nothing.** Resolve the symbol, call the
function, or compare against an external ground truth.

## Zebra dplane queue limit: not a workaround, a constraint

`dplane_queue_saturated_before_run` fires at 201/200 during table load with only
2,240 paths. VyOS does not expose `zebra dplane limit` as a configuration option
(vyos.dev/T5454), so there is nothing to raise.

Recorded as an operating constraint of the platform under test rather than
something to tune around: whatever FIB-install ceiling this imposes is the
ceiling a real VyOS deployment has. If a T2/T3 plateau turns out to be the
dataplane queue rather than bgpd, that *is* the finding, and T5454 is the ticket
it belongs to.

## H-38. A back-dated metric was used as a wall-clock duration

The arming fix from H-34 worked, exactly as intended:

```
FRR debugs: ['debug bgp neighbor-events'] active=True via=enable_node
readback_cmd: show debugging
readback: bgp debugging status:\n  bgp neighbor-events debugging is on
log pipeline: tier=debug fsm=10 adjchange=2 notification=1
```

And detection got **worse**. `notification_recv`, `notification_any`,
`peer_down`, `attr_withdraw`, `zebra_conn_lost` and `nexthop_reg_fail` had all
fired in the previous run and all went to zero, while `peer_up` fired on every
peer_flap row. That asymmetry is the diagnosis: `peer_up` is the *last* line an
event produces, the others are the *first*.

The window introduced in H-35 was `event_seconds + rec_s + 3`, and `rec_s` is not
a duration. `telemetry.wait_for_convergence` back-dates it deliberately:

```python
elapsed = time.monotonic() - t0 - (tracker.stable_samples - 1) * sampler.interval
```

It answers "when did the table actually settle", not "how long was I in this
function". With `stable_samples=3` and a 2 s interval that is **4 seconds of real
time unaccounted for**, plus the poll loop's own sleep — so it can legitimately
return `0.0` for a call that took six seconds. The window therefore started
several seconds *after* the event did and clipped the beginning of it.

Confirmed against the DUT's own log for `peer_flap/admin_down`:

```
18:17:30  %ADJCHANGE: neighbor 198.51.100.11 ... Down BGP Notification received
18:17:42  %ADJCHANGE: neighbor 198.51.100.11 ... Up
```

Row: `seconds 5.1, recover_s 9.0` → window 17 s, read at ≈18:17:52, so the window
opened at ≈18:17:35. The Up is inside it; the Down and the NOTIFICATION are not.
The DUT logged everything correctly. `malformed_burst` lost its five
`errors in attr(s)` lines at 18:20:26 to the same edge by about one second.

Fixed by measuring the clock — `elapsed = time.monotonic() - t0` around the event
*and* its recovery, window `ceil(elapsed) + 3` — and the row now carries
`elapsed_s` next to `recover_s` so the gap between real and reported time is
visible rather than load-bearing.

The general lesson, third instance of the same shape: **a derived metric is not
an observation.** `queue_max` was a high-water mark read as a live depth (H-15),
CPU% divided by the wrong interval (H-21), and now a deliberately back-dated
convergence time used as wall time. Every one of them was a number that looked
like the thing it was not.

Two further changes from this run:

* Each row now carries `event_record`, the event's own return value. Until now
  the only place an event's self-collected evidence lived was `samples.jsonl`,
  which is tens of MB at T1+ — so `maxprefix_trip` and `blackhole_peer`, whose
  entire point is log-independent evidence, could not be diagnosed from
  `exercise.json` at all.
* An event returning a `*_ineffective` record is now marked `INEFFECTIVE` and
  makes the command exit non-zero, instead of reading as `ok`.
* `debugs_active_after` is read back at the end of each event. Whether a VyOS
  commit *inside* an event clears the enable-node debug has been an untestable
  hypothesis for two runs, because the committing events happened to produce no
  session transitions either way. before/after settles it.

## Open after this run — two things that need the next run's `event_record`

**`maxprefix_trip` did not trip, and the earlier explanation is now refuted.**
The 81.5 s window (18:20:57 apply → 18:22:02 revert) contains no `%MAXPFXEXCEED`,
no `%NOTIFICATION: sent ... 6/1`, no `%ADJCHANGE`, and — unlike the previous run —
no TCP reset either. So the sessions did not bounce this time and the limit still
did not trip, with the debug armed and log-neighbor-changes on.

One candidate explanation is dead: VyOS *does* render peer-group
`maximum-prefix`. `vyos-1x`'s `frr-bgp.j2` uses a single `bgp_neighbor(neighbor,
config, peer_group=false)` macro for both neighbours and peer-groups, and the
`maximum_prefix` branch inside it emits `neighbor <name> maximum-prefix <n>`
regardless of which it is called for.

What is still unknown is whether the squeeze commit took at all. The event now
records `peergroup_limits_after_apply` (read back out of the running config) and
`all_peers_reestablished_after_s`, and those land in `exercise.json` from the
next run.

**`blackhole_peer` ran its full 75.6 s, which means the impairment *was* in
place.** The new guard returns after a few seconds with `blackhole_ineffective`
when no DROP rules are found, so a full-length run implies `iptables` exists and
the rules were counted. Yet the DUT never expired a 30 s hold timer over 75 s of
silence, and logged nothing at all.

If `rules_installed > 0` in the next run's `event_record`, that is a real and
surprising result about where those rules sit relative to the session's path, and
it needs a packet-level check (is the session actually traversing INPUT/OUTPUT in
that netns?) rather than more log reading. Recorded as unresolved, not as a
finding.

## H-39. The debug flag was on, and the log floor had moved

This closes both of the "two problems" that had been open for three runs, and
the answer is that **the DUT was right both times**.

The event records added in H-38 land in `exercise.json`:

```json
"maxprefix_trip": {
  "applied": {"rc": 0, "commit_s": 8.47},
  "tripped": ["198.51.100.11", "198.51.100.12"],
  "tripped_count": 2,
  "still_down_after_revert": [], "needed_explicit_clear": false,
  "established_after": 5
}
"blackhole_peer": {
  "session": "ixp2-bilat-0000", "holdtime": 30, "hold_s": 75,
  "iptables_present": true, "rules_installed": 6, "rules_after_clear": 0,
  "state_before": {"ipv4": "Established"},
  "state_at_1x_holdtime": {"ipv4": "Connect"},
  "dropped_within_holdtime": true
}
```

`maximum-prefix` **does** trip: both members of `ixp1-peer4` left Established
when the limit went below what they announce, and both came back on the revert
with no operator action — `needed_explicit_clear: false`. The blackhole **does**
blackhole: 6 DROP rules installed, and the session was in `Connect` at one
holdtime, i.e. FRR expired the hold timer exactly as it should.

Neither logged a single line.

The reason is in `show logging`, not `show debugging`. FRR consults the debug
flag first and the *destination's severity floor* second. The flag was armed in
the enable node so frr-reload cannot touch it (H-34) — and `show debugging`
confirmed it before and after every event. But `log syslog debugging` is
**config**, so the first VyOS commit's frr-reload removed it. From the DUT's own
log:

```
18:45:05  debug + info + warn + error   (last session line before any commit)
18:45:31  watchfrr: Configuration Read in Took: 00:00:00   <- policy_churn
18:46:12  [EC 33554455] ... errors in attr(s)              <- error, still logged
18:46:42  Configuration Read ...                           <- maxprefix apply
18:47:47  Configuration Read ...                           <- maxprefix revert
          (blackhole runs here — nothing at all)
18:50:09  Stopping FRRouting
```

Warnings and errors all the way through; **no info and no debug after the first
commit.** `%MAXPFXEXCEED` is `zlog_info`. `%ADJCHANGE` is `zlog_info`. The FSM
`went from` line is `zlog_debug`. All three were generated and all three were
discarded below bgpd.

Fixed in `Dut.configure()` — the only thing in the harness that commits, and
therefore the only place the floor can be lost. It now calls
`reassert_logging()`, which restores both the floor and the debug flag and reads
the floor back. Each exercise row records `bgpd_log_level_after` and
`debug_reaches_log_after` next to `debugs_active_after`, so "flag on, floor up"
can never again look like "the DUT did not do it".

Three runs of "maxprefix does not trip" and "the blackhole does nothing" were
harness blindness. Worth stating plainly because the pattern is now four for
four: **every single one of the DUT's apparent misbehaviours in this project has
turned out to be a defect on the harness side of the boundary.** The confirmed
DUT-side findings — E-1, E-4, E-5, the five template defects — all came from
*positive* evidence, never from an absence.

## Scope: what this harness is for

Restated after review, because the event catalogue had drifted toward adversarial
cases that are not the point.

The question is whether a VyOS/FRR router carrying full tables from Tier-1 and
IXP peers **stays up and keeps forwarding** when the things that actually happen
happen: a link goes down, a link degrades, a remote router restarts or stops
forwarding, a full table churns, an operator commits a policy change at the wrong
moment. The failure modes that matter are BGP sessions dropping when they should
not, bgpd or zebra dying, and the main thread starving long enough to miss
keepalives. The output is evidence for the FRR and VyOS teams.

What this is *not*: a hostile-peer test. Real ISPs are not attackers. Malformed
attributes and a deliberate prefix-limit trip are worth running occasionally as
diagnostics — they confirm the RFC 7606 paths are intact and that the harness can
still see a session drop — but they should not compete for run time with the
failure modes under study.

The T2, T3 and T4 mixes are reweighted accordingly: **94% real-world failure
modes, 1% adversarial** (was 6%). `netem` (path degradation) goes 5 → 12 and
`peer_flap mode=link_down` 5 → 14, because a degraded or failed link is the most
common real event and produces a failure shape easily mistaken for CPU
saturation. `malformed_burst` and `maxprefix_trip` drop to weight 1 each. A
selftest now enforces the ratio so the catalogue cannot drift back.

### Which detectors matter for this question, and their status

The signals that answer "did the router stay up" are mostly **not** the
info-level ones that H-39 was about:

| signal | level | status |
|---|---|---|
| `cpu_starvation` — FRR's own scheduling-delay warning | `flog_warn` | observed at T1, 4.5–5.2 s late |
| `event_slow` — CPU HOG / STARVATION | `flog_warn` | pattern corrected from source, unobserved |
| `sendq_stuck_warn` / `_proper` | `flog_warn` / `flog_err` | pattern corrected; reachable only if the DUT is advertising |
| `netlink_overrun` | `flog_err` | pattern verified, unobserved |
| bgpd / zebra / staticd death | PID predicate | **proven** — fired on `dut_bgpd_restart` |
| session drops | `show bgp summary` per sample | **proven** — independent of logs |
| table drift, convergence, commit latency | sampled state | **proven** |
| dplane queue saturation | sampled counter | **proven** (fires at 201/200 during load) |

Warning- and error-level lines were never affected by the floor, and everything
about session state and table size is measured from `show bgp summary`, not from
logs. So the resilience question was answerable even during the three blind runs
— which is why T2 is a reasonable next step rather than a fourth debugging round.

## H-40 / R-1. T2: the control plane reported converged before the data plane started

This is both a harness defect and the first real T2 result, and it is the one
that matters most for the question this project exists to answer.

`make converge` immediately after loading 2,800,920 paths:

```
converged        : True
seconds          : 1.0   (budget 420.0)
ipv4             : established=149/149 pfxRcd=2,251,132 tableVersion=50 ribCount=2552093
ipv6             : established=149/149 pfxRcd=550,604   tableVersion=9  ribCount=760517
bgpd             : rss=3806.1 MB
```

Every session up, every prefix received, and `tableVersion` stable at 50 for
three consecutive samples — so the tracker's key was stable and it declared
convergence. What the same samples show at the same moment:

| | |
|---|---|
| bgpd CPU | **100.0 – 101.4%**, continuously, for as long as it was sampled |
| bgpd RSS | 4,411 → 4,786 MB in 36 s (**~9.5 MB/s**) |
| `tableVersion` | later climbed 746,811 → 1,275,781 in 36 s (**~15k/s**) |
| zebra `route_installs` | **136**, against a BGP RIB of 2,552,093 |
| zebra RSS / CPU | 13.8 MB / 0% at first, then 2,620 MB / 185% |
| dplane `queue_depth` | 201 against a limit of 200, `update_yields` 4,493 |

So the router had accepted the whole table, told everyone it was Established,
and installed **136 of 3.3 million** routes into the kernel. `tableVersion` had
not started moving because the work had not started — the counters were stable
in the way a queue is stable before anything is dequeued.

**Traffic follows the FIB.** A router in that state is black-holing 3.3 million
prefixes while `show bgp summary` looks perfect. For a test whose question is
"does VyOS cause an outage for users", this is exactly the failure to catch, and
the harness was about to use it as the *baseline* for every subsequent
measurement — flap recovery, commit latency, post-churn convergence would all
have been measured against an already-saturated router, and "converged in 1.0 s"
would have gone into the report as a result.

### Harness fix

`ConvergenceTracker` now requires the router to be **quiet**, not merely
**consistent**. In addition to the three original conditions (all sessions
Established, `tableVersion` stable, `pfxRcd` stable):

4. bgpd below `busy_cpu_pct` (default 60% of one core);
5. zebra's dataplane queue empty and its install count no longer moving;
6. the FIB within `fib_min_ratio` (default 95%) of the BGP RIB.

It also names its blocker instead of returning a bare `False`, and `converge`
prints `FIB installed : N of M (P%)`. `require_quiet=False` restores the old
behaviour so the two verdicts can be compared on the same data.

Verified by replaying the actual T2 samples through both:

```
probe-time samples, require_quiet=False -> converged at sample 18
probe-time samples, require_quiet=True  -> never, reason='bgpd at 110% CPU'
```

### New predicate: `fib_behind_rib`

The measurement that corresponds to user-visible impact. Fires when installs are
below `fib_min_ratio` of the RIB, `warn` while inside `fib_lag_grace_s` (300 s,
the initial-load window) and `fail` beyond it. Replaying the real T2 samples:

```
[warn] fib_behind_rib: 136 of 3,312,643 RIB entries installed in the FIB (0%),
       for 0s. Traffic follows the FIB: BGP is up and 3,312,507 prefixes are
       not reachable.
```

This is the number to put in front of the FRR and VyOS teams, and it is not
derivable from anything in `show bgp summary`.

## T2 bringup: what else the numbers say

Recorded before the chaos run, so the run has a documented starting point.

**Memory tracks the T1 model.** bgpd RSS 4,786 MB for 2,801,746 paths ≈
**1.71 kB/path**, against the 1,768 B/path measured at T1 — the extrapolation
held to within 3%. Container total 6.65 GB against 62 GB of host RAM, so T3/T4
are not memory-bound on this host.

**Commit latency scales with config size, not table size.** 00-base 691
commands / 55.5 s; 10-neighbors **1,488 commands / 123.9 s**; 20-instrument 7
commands / 26.9 s. Total 206 s for the initial configuration. The per-command
cost is roughly flat (~80 ms), so a 300-neighbour IXP router should expect
minutes for a full apply. Note this is on an *empty* table — `policy_churn`
measures the same operation against a loaded one.

**The DUT advertises far more at T2 than at T0.** `pfx_snt_total` went from 0 to
1,807,852 (v4) and 760,518 (v6) during the probe window; the v6 figure is
essentially the whole v6 RIB, and there are exactly 2 transit sessions
(760,518 ≈ 2 × 380,259). So the DUT is announcing its full table to its transit
peers. Two consequences:

1. **The send-queue teardown path is reachable at T2**, unlike T0 where
   `pfx_snt_total` was 0. `sendq_stuck_warn` / `_proper` are live detectors here,
   and `blackhole_peer` against a transit session is now a meaningful test.
2. **Whether announcing the full IXP table to transit is intended is a template
   question worth answering** before reading too much into it. Announcing
   everything learned at an IXP to an upstream is a classic route leak, and an
   upstream would filter it — but the template's transit export policy is what
   decides, and this has not been read closely yet. Flagged, not concluded.

**`maxprefix: 6` fired during bringup**, which is `%MAXPFX` — FRR's *threshold*
warning at 75% of a configured limit, not a teardown (`%MAXPFXEXCEED`). Some
peer-group is within 75% of its limit at T2 scale. Which one is not yet
identified; at T3 the same peer would cross it and the session would be torn
down with no automatic recovery, so it is worth naming before T3.

**`peer_up: 298`** = 149 sessions × 2 address families, each coming up exactly
once. No hidden flaps during load.

**The nasty peers show `accepted` > `announced`** (150 → 283, 80 → 151). Expected
and benign: `announced` is what the *profile* says the fleet originates, while
the ExaBGP boot file also announces the probe and RFC 7606 prefix sets. The
delta is those extra prefixes, not a leak.

## 12. `transit4` / `transit6` have no export route-map — confirmed full-table leak

**high, and measured rather than inferred.** Both transit peer-groups get an
import policy and nothing on the way out:

```
set protocols bgp peer-group transit4 address-family ipv4-unicast route-map import 'ebgp4-import'
set protocols bgp peer-group transit6 address-family ipv6-unicast route-map import 'ebgp6-import'
```

The template says so itself, immediately above the transit neighbour stanza:

> `# To add an export route-map to the transit4 peer-group, or override
> per-neighbor with the appropriate export policy.`

With no export route-map, FRR's default eBGP behaviour applies: announce
everything eligible. At T2 that is measurable in `show bgp summary`:

```
pfx_snt_total  ipv6  760,518      (v6 RIB is 760,517 — two transit sessions x the whole table)
pfx_snt_total  ipv4  1,807,852    (and still climbing when sampled)
```

So the DUT announced the entire exchange's table to both upstreams. Announcing
IXP-learned routes to a transit provider is a textbook route leak: it invites the
upstream to send you traffic for networks you do not serve, and the only thing
standing between it and a real incident is the upstream's own filtering.

Every other peer-group in the template *does* have an export map
(`ebgp4-export-ixp1` and friends), which is what makes this look like an
omission rather than a decision.

**Fix.** Give the transit peer-groups an export policy that permits only the
DUT's own aggregates:

```
set policy route-map ebgp4-export-transit rule 10 action 'permit'
set policy route-map ebgp4-export-transit rule 10 match ip address prefix-list 'own-supernet4'
set policy route-map ebgp4-export-transit rule 1000 action 'deny'
set protocols bgp peer-group transit4 address-family ipv4-unicast route-map export 'ebgp4-export-transit'
```
and the IPv6 equivalent against `own-supernet6`.

**Interaction with this harness.** Two things follow from the leak, both useful:

* It is what makes the send-queue teardown path reachable at T2. At T0 the DUT
  advertised nothing (`pfx_snt_total` 0), so FRR's 2x-holdtime teardown could
  never trigger — there was no queue to stall. With ~1.8M prefixes outbound
  there is, so `sendq_stuck_warn` / `_proper` are live detectors here and
  `blackhole_peer` against a transit session is a real test rather than a no-op.
* `make peers` now prints an `advertised` column and names any peer being sent
  more than 1,000 prefixes, so this is a standing check instead of something
  noticed once.

Note the leak also inflates the DUT's workload considerably — generating updates
for 1.8M outbound prefixes across two sessions is a large part of what bgpd was
doing at 100% CPU in H-40. Fixing defect 12 would materially change the T2
numbers, so it should be a deliberate decision: leave it in to stress
update-generation, or fix it to measure a correctly-configured router. Both are
defensible; running without knowing which is not.

## H-41. The FIB gate could be satisfied without ever reading the FIB

The T2 re-run reported:

```
converged        : True
seconds          : 4.0   (budget 420.0)
ipv4  established=149/149 pfxRcd=2,251,132 tableVersion=1,276,074 ribCount=2,552,093
ipv6  established=149/149 pfxRcd=550,604   tableVersion=380,261   ribCount=760,517
bgpd  rss=4787.3 MB cpu=0.33%     zebra rss=2811.9 MB cpu=0.33%
```

That is a genuinely quiet router this time: `tableVersion` has stopped moving,
both daemons are at 0.33% CPU, and zebra's RSS has gone from 13.8 MB to 2.8 GB —
it has clearly done a large amount of FIB work. Compare the first attempt, which
reported converged with `tableVersion` at 50 and zebra at 13.8 MB.

But the `FIB installed` line did not print, and that exposed a hole in the gate
added in H-40. `route_installs`, `queue_depth` and the rest of the zebra and
dplane block only ride on every `slow_every`-th sample (5th). With
`stable_samples=3`, a stable streak can easily contain **no** slow sample — so
`busy()` evaluated only bgpd CPU, found it idle, and confirmed. Treating an
absent FIB reading as a satisfied one reintroduces exactly the failure H-40 was
written to stop, just with a smaller window.

Two fixes:

* `ConvergenceTracker` now tracks whether the current streak actually *saw* a FIB
  reading (`_fib_seen`, cleared whenever the streak resets) and will not confirm
  without one. It reports `waiting for a FIB reading (arrives on slow samples)`
  while it holds, and `stabilising (n/3 samples)` otherwise, so the blocker is
  never a bare False.
* `Dut.route_summary(afi)` reads `show ip route summary` / `show ipv6 route
  summary` — zebra's own per-source RIB and FIB counts — and `converge` prints
  it for both address families. That is the authoritative figure and it does not
  depend on sampling at all. It is deliberately not sampled per tick: zebra walks
  the table to produce it, which is not something to do every two seconds against
  millions of routes. One shot at convergence time is the right cost.

So the T2 baseline is *probably* sound — quiet daemons, settled table version,
2.8 GB of zebra — but "probably" is what this project keeps getting wrong, and
the FIB number was not actually read. The next `converge` prints it.

## Template defect 12: kept deliberately

Decision recorded, with the reasoning, because it changes how the T2 numbers
should be read.

The full-table export to the transit peer-groups **stays**. In a real deployment
a core router does advertise a large table to *somewhere* — a downstream, or a
second core router acting as backup — and standing up another router purely to
receive it would exercise the same code path at the same cost. The leak is
therefore left in place as a stand-in for that legitimate egress load.

Consequences, all intended:

* bgpd generates updates for ~1.8M outbound IPv4 and ~760k outbound IPv6
  prefixes across two sessions. That is a substantial and *realistic* share of
  the DUT's work, and a large part of what put bgpd at 100% of one core during
  the initial load (H-40).
* FRR's send-queue teardown is reachable, unlike T0 where `pfx_snt_total` was 0.
  `sendq_stuck_warn` / `_proper` are live detectors at T2 and `blackhole_peer`
  against a transit session is a real test.
* `make peers` still prints the `advertised` column and still names peers being
  sent more than 1,000 prefixes. That is now confirmation the egress load is
  present, not a warning.

The defect remains in the template review for NE-1849 — a `transit` peer-group
with an import map and no export map is still a gap an operator should close on a
real box, and the template's own comment says so. What changed is that the *lab*
keeps it on purpose.

# T2 run 1 — results and what they mean

Run `20260824T030055`, 4,990 s, 48 events, 2.80M paths, 149 sessions.
Verdict `FAIL`. Two of the findings are real and reportable; one large part of
the failure was self-inflicted, and saying which is which is the whole job.

## R-2. watchfrr killed a working bgpd — the platform's own supervision is the failure

The headline. From the DUT's journal:

```
11:15:06  watchfrr[473]: [EC 268435457] bgpd state -> unresponsive :
                         no response yet to ping sent 90 seconds ago
11:15:06  watchfrr[473]: Forked background command [pid 71630]:
                         /usr/lib/frr/watchfrr.sh restart bgpd
11:15:11  bgpd[504]:     Terminating on signal
11:16:36  watchfrr[473]: restart bgpd child process 71630 still running after
                         90 seconds, sending signal 15
11:16:48  watchfrr[473]: bgpd state -> down : unexpected read error
11:17:38  bgpd[73345]:   Configuration Read in Took: 00:00:00
11:17:42  bgpd[73345]:   Begin read-only mode - update-delay timer 300 seconds
```

**bgpd did not crash.** There is no `Segmentation`, no `assert`, no `SIGSEGV`, no
`abort`, no OOM anywhere in the 17,917-line journal. It was killed by its own
watchdog for failing to answer a liveness ping.

The mechanism is structural. VyOS starts watchfrr with `--timeout=90`
(`frrinit.sh`: `/usr/lib/frr/watchfrr -d --timeout=90 mgmtd zebra bfdd bgpd …`).
bgpd is single-threaded for UPDATE parsing, bestpath, policy evaluation and
update generation — only socket I/O and keepalive generation are on separate
pthreads. At 2.80M paths under churn, bgpd was pinned at ~100% of one core
continuously from t=126 s onward, and the log carries 44 `CPU starvation` and 6
`CPU HOG` warnings from FRR's own event-loop detector. A main thread that busy
will eventually go 90 seconds without servicing a supervisor ping — and then the
platform kills a daemon that was working.

Cost of the kill:

| | |
|---|---|
| detection | 90 s of unresponsiveness before the verdict |
| restart | 11:15:11 → 11:17:38 = **147 s** |
| read-only mode after restart | `update-delay timer 300 seconds` |
| sessions re-established | **69 of 149** IPv4, ~128 of 149 IPv6 |
| never recovered | 80 IPv4 / 51 IPv6 sessions, over the following 65 minutes |

So a full control-plane outage of roughly **7.5 minutes**, followed by permanent
partial failure. On a real IXP router that is a customer-visible outage caused
not by a bug in BGP but by a supervisor timeout that is shorter than the work its
supervisee legitimately has to do.

This is the single most useful thing in the run for the FRR and VyOS teams, and
it is actionable in three different places: watchfrr's timeout could scale with
table size, its ping could be serviced off the main thread, or VyOS could expose
`--timeout` so an operator with a full table can raise it. Detector added:
`daemon_unresponsive` and `daemon_watchdog_restart` — `bgpd_crash` could never
have caught this, because nothing crashed.

## R-1. One `set` on a peer-group takes 343 s on a 2.8M-path table

| commit | commands | result |
|---|---|---|
| `localpref-flip` apply | 1 | 6.18 s |
| `localpref-flip` revert | 1 | 0.31 s |
| `pg-routemap-swap` apply | 1 | **343.09 s** |
| `pg-routemap-swap` revert | 1 | **timeout at 360 s** |
| `maxprefix-squeeze` apply | 1 | **timeout at 360 s** |

A peer-group `route-map import` swap forces FRR to re-evaluate policy for every
path in the table, on the same single thread that services BGP. Two of the three
peer-group commits under load did not return inside 360 s. The router could not
be reconfigured while carrying its table.

Note the contrast in the same run: `localpref-flip` — a route-map *rule* change —
was 6.18 s. The expensive operation is specifically swapping the map bound to a
peer-group, which invalidates every path that peer-group imported.

## R-3. Peers dropped from CPU starvation, invisibly

`cpu_starvation` 12, `holdtime_expire` 20, `notification_sent` 35 in the DUT
log's own windows. bgpd too busy to service keepalives → hold timers expire →
FRR sends a 4/0 NOTIFICATION and tears the session down. Nothing in
`show bgp summary` explains why; the operator sees sessions bouncing with no
cause.

## What was self-inflicted, and must not be reported as a DUT result

`maxprefix-squeeze`'s apply hit the 360 s `CommitTimeout`. The old code returned
on that exception **before reverting**, so `ixp1-peer4` stayed clamped at
`maximum-prefix 2500` against 5,000 announced. Consequences, all harness-caused:

* all **80** ixp1-bilat IPv4 sessions torn down at t≈391 s and held down for the
  remaining 72 minutes — this is the `failed_peers_ipv4: 80` violation, and the
  drift of exactly **-400,000** (= 80 × 5,000);
* `maxprefix: 98` / `maxprefix_exceeded: 15` in the log — the clamped peers
  retrying, exceeding, being torn down, retrying;
* 19 of 20 flap-recovery measurements returned `None`, because the lab never
  re-settled: **mean 8.0 s over 1 measured flap** is not a result;
* `pg-routemap-swap`'s revert also timed out, leaving that peer-group's import
  map on `allow-all` for the rest of the run.

The 80 permanently-dead peers also fed R-2: a flap treadmill of 80 sessions each
re-sending 5,000 prefixes and being torn down is a large part of why bgpd stayed
at 100% CPU long enough for watchfrr to kill it. **R-2 is real, but its timing was
accelerated by a harness fault.** Worth re-running clean before quoting the
7.5-minute outage as a T2 characteristic.

## H-42. A commit timeout left the DUT permanently modified

Fixed. `ev_policy_churn` reverts in a `finally`; `ev_maxprefix_trip` no longer
returns on the apply's `CommitTimeout` and always attempts its revert. When a
revert genuinely cannot complete, the event returns `config_left_modified: True`.

The commit timeout itself went from `commit_s * 2` to `max(600, commit_s * 4)`.
The timeout exists to stop the harness hanging forever, not to enforce the
budget: a latency over budget is a *finding*, a timeout is a lost measurement
plus a broken lab. Profile budgets updated to measured reality — T2
`commit_s: 420` (above the 343 s measured), T3 600, T4 900, and T2
`zebra_rss_mb: 12288` after a 5.92 GB peak.

## H-43. Failed telemetry reads were recorded as zeros

**45 of 2,392** address-family summary reads (1.9%) returned nothing, every one
of them while bgpd was at ~100% of one core — vtysh could not get an answer out
of a saturated main thread inside its 30 s timeout. `_summarise_bgp(None)`
emitted `peers: 0, established: 0, pfx_rcd_total: 0, table_version: null` as
though those were measurements.

Effects: the convergence tracker's key changed on every such sample, resetting
the streak — so *post-chaos re-convergence: 1260 s, converged=False* may be an
artefact of failed reads rather than a router that would not settle. Peak, final
and drift figures all derive from the same fields.

This is H-18 again in a new costume: **the telemetry became least reliable exactly
when the DUT was most loaded, which is when it matters.** Fixed: reads carry
`read_ok`, a failed read neither confirms nor denies convergence, and the
predicate set emits one `telemetry_read_failed` warning instead of letting
`peers: 0` read as a total outage.

## H-44. The run measured a lab it had already broken, for 67 more minutes

bgpd was killed at t≈983 s and 80 peers were down from t≈391 s. The run continued
to t=4,990 s. Everything after the first hard failure describes a different
router, and mixing the two makes both unquotable.

Fixed: an event returning `config_left_modified` aborts the chaos loop
unconditionally — not gated on `--stop-on-violation`, because it is a harness
fault rather than a result. Separately, the first `fail`-severity violation is
now recorded in `meta["first_hard_failure"]` with its timestamp even when the run
continues, so pre-failure measurements stay separable from post-failure ones.

## H-45. bgpd CPU reported as -1547%

On the sample after the restart, the tick delta was taken against the dead
process's counters. `_cpu_pct` now keys its baseline on `(ticks, clock, pid)` and
returns `None` across a PID change, and any negative percentage is counted as
impossible rather than reported.

## H-28 closed: T3 runs from generated NLRI

Decided rather than implemented. The authenticity a real RouteViews/RIS dump buys
— true AS_PATH length distribution, real prefix-length mix, real community
density — does not change the question this project asks, and everyone reading
the results knows the peers are simulated. The external-MRT path also needed a
manual fetch, decompress and per-AF next-hop rewrite before every run.

The `mrt:` keys are removed from `t3-fulltable.yaml` and the profile header
records the one caveat that matters: FRR interns attributes, AS_PATHs and
communities, so generated tables share more than a real dump does, which makes
**T3 memory-per-path a lower bound** on a real full table. Everything else T3
measures — convergence, CPU saturation, commit latency, hold-timer behaviour,
session recovery — is driven by path count, peer count and churn rate, all of
which are real here.

# T2 run 3 — the clean reproduction

Run `20260828T032337`, 3,600 s of chaos, 20 events, 2.80M paths, 149 sessions.
The H-42/43/44 fixes held: **no config was left modified, no commit timed out,
and IPv4 paths held at 2,251,132 final = peak.** Run 2's 80 dead peers and
-400,000 drift do not appear. What remains is the DUT.

## R-2 confirmed, without the self-inflicted help

```
11:37:21  watchfrr: [EC 268435457] bgpd state -> unresponsive :
                    no response yet to ping sent 90 seconds ago
11:37:21  watchfrr: Forked background command [pid 87652]: watchfrr.sh restart bgpd
11:37:24  bgpd[501]: Terminating on signal
11:38:51  watchfrr: bgpd state -> down : unexpected read error
```

Same failure, same mechanism, on a lab that was **not** carrying 80 zombie
sessions this time. It happened inside `maxprefix_trip`, i.e. while a
`maximum-prefix` change was committing. So the watchdog kill is a genuine T2
characteristic and can be reported as one.

New evidence from the restarted daemon:

```
STARVATION: task bgp_start_label_manager ran for 18449ms (cpu time 0ms)
CPU starvation: bgp_config_finish() getting executed 15310ms late,
                warning threshold 4000ms. System load: 1.37, 1.09, 0.68
```

`18,449 ms wall, 0 ms CPU` is the interesting pair: that task was *blocked*, not
computing. And a third thing worth a separate report — on restart, bgpd fails to
accept its inbound sessions:

```
[EC 33554461] 203.0.112.72: nexthop_set failed, local: 203.0.112.1:179
              remote: 203.0.112.72:39457 update_if: (None) resetting connection
[EC 100663299] bgp_connect_success: bgp_getsockname(): failed for peer 203.0.112.72, fd 30
```

repeated across many peers. `getsockname()` failing on an established socket
during startup is not an expected condition, and it is part of why recovery
after the kill is slow.

## R-1 quantified: 5 to 11 minutes per single-command config change

Every commit completed this time, so these are measurements rather than
timeouts:

| fragment / phase | commands | seconds |
|---|---|---|
| `localpref-flip` apply | 1 | **311.17** |
| `localpref-flip` revert | 1 | 0.32 |
| `pg-routemap-swap` apply | 1 | **463.18** |
| `pg-routemap-swap` revert | 1 | **640.75** |
| `maxprefix-squeeze` apply | 1 | **552.15** |
| `maxprefix-squeeze` revert | 1 | **283.84** |

At 2.80M paths a single `set` costs five to eleven minutes, and the run only fit
20 events into 3,600 s because three of them consumed 2,577 s between them. Note
`localpref-flip` apply was 6.18 s in run 2 and 311 s here — the same fragment,
the same table size. Worth a repeat measurement before quoting a figure for it;
the peer-group operations are the consistently expensive ones.

`maxprefix_trip` recovered cleanly: `tripped_count: 149`,
`still_down_after_revert: []`, `needed_explicit_clear: false`.

## H-47. Every ExaBGP command reached both sessions in the container

The answer to "is the +532 / +284 baseline drift expected?" — it is explained,
it was not intended, and it is now fixed.

`neighbor <dut-address> announce …` selects **every** session in the ExaBGP
process that peers with that address. The T2/T3/T4 profiles put two nasty
sessions in one container, both peering with the same DUT fabric address, so
each received the other's announcements as well as its own:

```
ixp1-nasty-0000  ipv4  announced 150  accepted 283   (+133)
ixp1-nasty-0000  ipv6  announced  80  accepted 151    (+71)
```

150 + 150 = 300, less 17 the import policy dropped = 283. Four nasty sessions ×
133 = **532**, and × 71 = **284** — exactly the "table already differs from the
profile" warning. Run 2's malformed sample shows the same double delivery from
the other side: identical cases logged against both `198.51.96.95` and
`198.51.96.96`.

Fixed by naming the session, not just the peer. ExaBGP builds each neighbour's
identity as `neighbor <peer-address> local-ip <local> local-as …`
(`bgp/neighbor.py`) and `extract_neighbors` accepts `local-ip` as a filter key
(`reactor/api/command/limit.py`), so `neighbor <dut> local-ip <session-local>`
resolves to one session. Verified against ExaBGP's own matcher rather than
against a guess at its syntax:

```
neighbor 198.51.96.1 announce …                       -> matched 2 of 2
neighbor 198.51.96.1 local-ip 198.51.96.95 announce … -> matched 1 of 2
```

Applied to the generated boot file, the probe announce/withdraw builders, the
malformed announce/withdraw builders and the per-case isolation path. **The
profiles must be regenerated** for the boot files to pick it up.

This also means every malformed-attribute result recorded so far was measured
against two peers receiving each case, not one. It did not change any verdict —
the suite's assertions are per-prefix and both peers behaved identically — but
`connections_dropped` deltas from those runs are per-container, not per-session.

## H-48. A deliberate restart reported itself as a failure

`dut_bgpd_restart` exists to restart bgpd, and then the PID-change predicate
faulted the run for it. Three cases now, three verdicts:

* the running event declared it (`preds.expect_daemon_restart`) — `info`;
* watchfrr's `daemon_unresponsive` line is in the same window — `fail`, and the
  message says *watchdog kill*, names `--timeout=90` and the single-threaded main
  loop, instead of the generic "restarted or crashed";
* anything else — `fail`, unchanged.

The expectation is consumed by the first PID change observed, so a second,
unintended restart later in the same run is not masked.

## H-49. A silent 21-minute wait looks exactly like a hang

Post-chaos re-convergence had a 1,260 s timeout and printed nothing, so the run
was interrupted at that point and the final accounting was lost. `_converge` now
takes a `progress_every` (20 s default) and prints elapsed, budget, per-AF
established counts and the tracker's current blocker; `run` announces the settle
timeout before entering it. The report no longer prints `**Nones**` for an
interrupted run — it says the figure was not measured and why.

## T3 becomes the single profile, and had to be made different from T2 first

T2 and T3 had converged on identical labs. Diffed:

| | T2 | T3 (before) |
|---|---|---|
| fleets | identical | identical |
| nlri / instrumentation | identical | identical |
| sessions / paths | 149 / 2,800,920 | 149 / 2,800,920 |
| container | 48 GB, 12 cpu | 96 GB, 16 cpu |
| duration / warmup | 3600 / 420 s | 5400 / 900 s |
| budgets | conv 420, commit 420 | conv 900, commit 600 |

Two changes caused it, both mine. T3's only real distinction was the live MRT
dump, dropped by decision (H-28). And when template defect 9 was fixed, T2's
bilateral fleets were raised from 180/90 to 5,000/1,000 — which happened to be
exactly T3's numbers. The two collapsed into the same lab from both ends, and
T3 became "T2 with a bigger container and a longer clock".

### What T3 is now

154 sessions, **4,020,600 IPv4 + 784,320 IPv6 = 4,804,920 paths**, 24 peer
containers. Three populations, because a real exchange has three:

| population | sessions | v4 each | v6 each | why |
|---|---|---|---|---|
| transit | 2 | 1,000,000 | 200,000 | a full table per upstream — the heaviest single sessions on the box |
| route servers | 2 + 1 | 250,000 / 150,000 | 60,000 / 40,000 | the exchange's aggregated member view, which is not a full table |
| bilateral — major | 15 + 10 | 50,000 | 8,000 | CDNs and large eyeball networks |
| bilateral — tail | 70 + 50 | 1,000 | 200 | most of the sessions, little table each |
| nasty (ExaBGP) | 2 + 2 | 150 | 80 | probes and the RFC 7606 suite |

A uniform bilateral population is the least realistic thing a synthetic IXP lab
can do. At a real exchange most sessions carry hundreds to a few thousand
prefixes and a handful carry six figures, and the shape matters independently of
the total: update-group formation, flap cost and per-peer Adj-RIB-In all scale
with the distribution, not just the sum.

Supporting changes:

* `contested_pool_v4` 120,000 → 200,000 and `_v6` 40,000 → 60,000. The pool must
  cover the largest per-session contested slice or that session is silently
  truncated; the transit fleets set the floor at 1,000,000 × 0.15 = 150,000.
* Budgets from the T2 measurements rather than guesses: 4.80M paths at
  1,805 B/path (bgpd) and 1,597 B/path (zebra) projects to 8.7 GB and 7.7 GB, so
  `bgpd_rss_mb: 20480`, `zebra_rss_mb: 16384`, `convergence_s: 1200`.
  DUT container 96 GB → 32 GB: the peer side needs roughly as much again on the
  same 62 GB host, so this is sized to leave room rather than to claim the box.
* **`policy_churn` weight 12 → 3.** At 2.8M paths a single peer-group `set`
  measured 311–641 s. At 4.8M it is not a load source, it is a stopwatch that
  eats the run — three commits consumed 2,577 s of T2 run 3's 3,600 s window.
  Six commit-latency measurements already exist; weight 3 still takes one or two
  per run without crowding out the flap, churn and degradation events this tier
  exists for.
* `duration_s` 5400 → 7200, `warmup_s` 900 → 1200. A full-table peer flapping
  takes minutes to re-advertise.

Generated and validated: 24 containers, 361 MB of MRT across 150 files, 401
offline checks pass.

`t0-smoke` stays as the pre-flight. Every defect in the last six rounds was found
there first, in minutes, before a multi-hour run was spent on it. `t1`, `t2` and
`t4` can go once T3 has a clean run behind it — keep T2's results, they are the
only two-tier memory datapoints available for differencing.

## Planned, not yet built: SNMP, RPKI, forwarding-plane traffic

Recorded now so the reasoning is not re-derived later. All three are deferred
until the current basics are stable.

### SNMP — a plausible *cause*, not just extra load

FRR exposes BGP4-MIB (RFC 4273) through an AgentX subagent. The peer table is
cheap, but `bgp4PathAttrTable` walks the entire BGP RIB, and it is served **on
bgpd's main thread** — the same thread that parses UPDATEs, runs bestpath and
generates updates, and the same one whose 90-second unresponsiveness already
gets bgpd killed by watchfrr (R-2).

A monitoring system polling every 60 s is completely ordinary. If a full-table
walk blocks that thread for longer than watchfrr's `--timeout=90`, SNMP polling
alone would reproduce the T2 outage on a router doing nothing else. That makes
this the highest-value of the three: it is not a stress multiplier, it is a
candidate root cause with a real-world trigger.

Work: enable AgentX on the DUT (VyOS `set service snmp` plus FRR's SNMP support
— **needs verifying that the VyOS build ships it**), add an `snmp_walk` event
that runs `snmpbulkwalk` against the peer table and against
`bgp4PathAttrTable`, record walk duration and bgpd CPU across it, and correlate
with `cpu_starvation` and `daemon_unresponsive`.

### RPKI — per-prefix validation on import, and full revalidation on refresh

FRR does RPKI through rtrlib against an RTR cache. Two distinct costs, both
realistic: validation runs per prefix on import, and **a cache refresh with a
changed VRP set revalidates the entire table** — a large, periodic, main-thread
event that happens on every real deployment.

Work: a StayRTR container serving a generated VRP set that covers the synthetic
prefix space, `set protocols rpki cache …` on the DUT, and an `rpki_refresh`
event that pushes a new VRP set mid-run and measures the revalidation. This also
lets the lab close template defect 6 — the template's `rpki` route-map is
`rule 1000 action permit` and rejects nothing — by making it actually drop
Invalids, so the import path does real work.

### Traffic — the only thing that measures the answer directly

Everything the harness currently records is control plane. The stated question
is whether users lose traffic, and `fib_behind_rib` is the closest proxy for it.
An iperf3 UDP stream at 200–500 Mb/s across the DUT, with per-second loss and
jitter, measures it directly: loss during a convergence event *is* the outage.

UDP rather than TCP deliberately — TCP backs off and hides exactly the loss
being measured.

The engineering that needs care: the destination has to be an address inside a
prefix a peer actually advertises, on the opposite fabric, and that peer's
container has to hold the address and reply. Otherwise the stream measures the
lab's own plumbing rather than the DUT's forwarding. Two dedicated containers
(one per fabric) with addresses drawn from their fleet's announced slice is the
straightforward form.

## H-50. The FIB gate was satisfied by a reading it never evaluated

Third instance of the same failure, and the tightest one yet. T3 pre-run:

```
converged        : True
seconds          : 34.0   (budget 1200.0)
ipv4 FIB         : unavailable (no bgp line in route summary)
ipv6 FIB         : unavailable (no bgp line in route summary)
ipv4  established=154/154 pfxRcd=4,020,600 tableVersion=50 ribCount=4891343
ipv6  established=154/154 pfxRcd=784,320   tableVersion=9  ribCount=959017
bgpd  rss=6330.8 MB cpu=0.0%     zebra rss=13.8 MB cpu=0.0%
```

`tableVersion` 50 against a 4.89M-entry RIB, zebra at **13.8 MB**, and zebra's
route summary containing no `bgp` line at all: the FIB was completely empty and
bestpath had barely run. Both prior gates passed:

* H-40's quiet check — bgpd at 0.0% CPU, dplane queue empty. Satisfied.
* H-41's "the streak must contain a FIB reading" — satisfied too, and wrongly.
  One early slow sample carried `route_installs` while the *summary* read had
  failed, so `rib_count` was 0. The ratio comparison is guarded by
  `if rib and installs < rib * ratio`, so with `rib == 0` it was skipped — but
  `_fib_seen = True` had already been set on the way in. The flag recorded
  "a FIB reading arrived", when what actually arrived was a number with nothing
  to compare it to.

Two fixes, because one is not enough for something that has now slipped through
three times:

1. `_fib_seen` is set only when the ratio is **actually evaluated** — install
   count present *and* RIB size known. An install count with no RIB size returns
   "no information" rather than "checked and fine".
2. `_converge` no longer trusts the sampled counters as the final word.
   When the tracker is satisfied it asks zebra directly via
   `show ip route summary` (`_fib_agrees`), and if zebra disagrees it prints the
   disagreement, resets the streak and keeps waiting with the remaining budget.
   An *unavailable* summary is treated as agreement — refusing to converge
   because a diagnostic command is missing would be worse than the problem — but
   an empty one, while bgpd claims a multi-million-entry RIB, is not.

The pattern across H-40, H-41 and H-50 is worth naming: **every one was a guard
that could be satisfied without the thing it guards being true.** A gate that has
a path to "pass" which does not involve measuring anything is not a gate.

## PfxSnt 0 to the transit peers is the same thing, not a config change

```
198.51.96.11  4  64450  1000006  16  1502569  0  0  00:07:09  1000000  0  transit
```

`PfxSnt 0`, `MsgSent 16` — the DUT had advertised nothing to either upstream
seven minutes in. Nothing in T3 disabled the re-advertisement: `transit4` and
`transit6` still have an import route-map and no export route-map (template
defect 12, kept deliberately), so FRR's default eBGP behaviour still applies.

The DUT had not advertised because it had not yet *processed*: `tableVersion`
50, an empty FIB, and bgpd idle at 0.0% CPU. It cannot advertise a bestpath it
has not selected. T2 behaved identically — `pfx_snt_total` read 0 through
bringup and converge, and only climbed to 1.8M minutes later — so this is the
same deferred-work shape observed earlier in the timeline, not a regression.

The unexplained part is *why* bgpd was idle rather than working through it, and
the leading candidate is `bgp update-delay` read-only mode: the profile sets
`update_delay: {max_delay: 300, establish_wait: 60}`, and in read-only mode bgpd
defers bestpath, FIB install and advertisement by design. `Begin read-only mode
- update-delay timer 300 seconds` is in the T2 restart log, so the mechanism is
live on this DUT. Against that, the snapshot is at 429 s, past `max_delay` 300.
Recorded as the leading hypothesis, not a conclusion.

**A dedicated route-receiving device is not needed.** The gobgpd transit peers
already accept everything — they run with no import policy — so the DUT's
advertisements have a real receiver that parses and stores them, which is where
the cost is. Adding a second router would only add another daemon to babysit.
The one thing a dedicated receiver would buy is verifying *what* was advertised,
and `pfxSnt` plus `gobgp global rib summary` on the transit container already
answers that.

## R-4. Cold start at 4.8M paths: 8m12s from first session to forwarding

The T3 pre-run question — why bgpd sat idle at 0.0% CPU with an empty FIB and
`PfxSnt 0` — is answered, and the answer is a measurement worth reporting rather
than a fault. FRR's own accounting, verbatim:

```
Read-only mode update-delay limit: 300 seconds
                   Establish wait: 60 seconds
  First neighbor established: 2026/08/28 12:55:41.944
          Best-paths resumed: 2026/08/28 13:00:41.944
        zebra update resumed: 2026/08/28 13:03:52.908
        peers update resumed: 2026/08/28 13:03:53.541
BGP table version 2445675
```

| phase | duration | what happens |
|---|---|---|
| read-only (update-delay) | **300.0 s** | bestpath, FIB install and advertisement all deferred |
| bestpath + FIB install | **191.0 s** | 2,445,625 IPv4 routes computed and pushed to the kernel |
| start advertising | 0.6 s | peers update resumed |
| **first session up → forwarding** | **491.6 s** | |

Final state: `ebgp 2445625 / FIB 2445625` — every BGP route installed, zero
pending. Host memory 24 GB → 42 GB for the whole lab (DUT plus 154 gobgpd
peers). bgpd back to 0% CPU.

**This is FRR behaving correctly.** `update-delay` exists precisely to stop a
router advertising and forwarding a half-computed table, and it did its job: it
held everything, computed 2.4M best paths, installed them, and began advertising
0.6 s later. The idle 0% CPU that looked like a hang was read-only mode, not a
stall.

Three things in it are still findings:

1. **The 300 s was the limit *expiring*, not the condition being satisfied.**
   Best-paths resumed at exactly 300.000 s after the first neighbour
   established. Read-only mode ends on all-peers-End-of-RIB *or* the limit —
   hitting it to the millisecond means 154 peers had not all sent EoR in 300 s.
   At this scale the configured `update-delay 300` is too short to do what it
   was set to do, and an operator would want it raised. The harness now flags
   this as `limit_expired`.

2. **191 s of single-threaded bestpath and FIB install** for 2.4M routes, and
   this is the phase nothing else can overlap.

3. **This is the recovery cost of every bgpd restart, which prices R-2
   exactly.** The watchdog kill costs detection (90 s) + restart (~147 s) +
   read-only (300 s) + bestpath and FIB (191 s at this scale) ≈ **728 s, over
   twelve minutes of no forwarding**, from a supervisor timeout firing on a
   daemon that was working. That number is the single most quotable thing this
   project has produced for the FRR and VyOS teams.

`Dut.update_delay_state()` now parses these four timestamps and derives
`readonly_s`, `bestpath_and_fib_s`, `to_advertise_s` and `limit_expired`;
`converge` prints and records them. It was noticed by eye this time; it will be
recorded from now on.

Note also `static 47` in the route summary — the template's blackhole-scrub and
supernet statics, as expected — and that 4,020,600 IPv4 *paths* received reduce
to 2,445,625 unique IPv4 *destinations* in the FIB, which is the contested-pool
overlap working as designed: bestpath has real work to do.

---

# T3 run 1 (2026-09-01, 06:23 → 10:03 local, 13,243 s)

154 sessions, 4,020,600 IPv4 + 784,320 IPv6 paths announced, 24 peer containers,
DUT 32 GB / 16 vCPU. The operator's report of the run: *"The initial convergence
is false, and so is the re-convergence. Not sure what was the problem with
convergence, because if I do `sh ip bgp` / `sh bgp`, everything looked good and
there was no convergence."*

They were right, and the reason is a harness defect I introduced in the fix for
H-50. What follows separates that from the four DUT findings the same run did
produce, which are real and are the reason the run was worth doing.

## H-51. `show ip route summary` has no `bgp` row, and the FIB gate demanded one

**The single most consequential defect in the project so far.** It made the
flagship profile's headline number wrong, and it was shipped in the fix for
H-50 — the fix for a gate that could pass without measuring anything became a
gate that could never pass at all.

FRR does not print one `bgp` row. `zebra_vty.c` splits BGP-learned routes by
peer type. From the DUT, verbatim, mid-run:

```
Route Source         Routes               FIB  (vrf default)
kernel               1                    1
connected            3                    3
local                3                    3
static               47                   47
ebgp                 2445625              2445625
ibgp                 0                    0
------
Totals               2445679              2445679
```

`Dut.route_summary()` read `out["sources"].get("bgp")`, got `None`, and set
`bgp_routes = None`. `runner._fib_agrees()` turned that into:

```
zebra has no ipv4 BGP routes at all, while bgpd reports a
4,891,343-entry RIB — the FIB is empty
```

That string was printed **160 times over the full 2,400 s warmup**, against a
FIB that was 2,445,625 of 2,445,625 installed — 100.0%. Every one of those 160
rejections called `tracker.reset()`, so the run burned its entire warmup budget
in a loop that could not terminate, then recorded `initial_converged: false`.

Replaying the recorded samples through the tracker proves the tracker itself was
never the problem: it confirmed convergence at **t = 15 s** and 316 more times
after that. Every confirmation was thrown away by the FIB gate.

The wording made it worse. "The FIB is empty" is a claim about the router.
"There is no row here I recognise" is a claim about the parser. I wrote the
first when only the second was true, and it cost the operator a run and sent
them looking at `sh ip bgp` for a fault that was in this code.

**Fixed.** `Dut.BGP_ROUTE_SOURCES = ("bgp", "ebgp", "ibgp")`; `route_summary()`
sums every row present and reports `bgp_source_rows` so a future rename is
visible rather than silent. `_fib_agrees()` now treats an unrecognised layout as
**unmeasured** — it does not block convergence, and it records why — while a
genuinely short FIB still blocks and says by how much.

**Verified** against the operator's verbatim output as a selftest fixture
(`check_route_summary_reads_real_frr_output`): `bgp_routes` 2,445,625,
`bgp_fib` 2,445,625, ratio 1.0, rows `["ebgp", "ibgp"]`. A single-`bgp`-row
build still parses. A summary with no BGP row at all yields `None`, and
`_fib_agrees` reports it as unmeasured rather than empty.

## H-52. A cumulative counter was divided by a table-node count and called a FIB ratio

Both operands of the sampled FIB check were the wrong quantity.

* `zebra.route_installs` is zebra's **cumulative** count of install operations
  since the daemon started. It rises without bound as routes churn. This run
  finished at **13,890,066** against a 5,783,732-entry RIB — the convergence
  record's `fib_lag` field reads **−8,106,334**, which is the whole error in one
  number.
* `bgp[afi].rib_count` is bgpd's *RIB entries* figure from `show bgp summary`,
  which counts BGP table nodes, not installable best paths: 4,891,343 for
  2,445,625 actual IPv4 routes, a factor of exactly 2.

So the ratio read ~50% throughout a warmup in which the FIB was 100% installed,
and the report published it as a warning with a sentence attached:

> `fib_behind_rib` (warn): 3,049,967 of 5,821,556 RIB entries installed in the
> FIB (52%) … BGP is up and 2,771,589 prefixes are not reachable.

Not one figure in that sentence is a measurement of anything. It cost one
streak reset per slow sample as well, though that was minor next to H-51.

**Fixed.** `ConvergenceTracker.busy()` no longer compares them; a *stable*
install count is treated for what it is — evidence that zebra is quiescent —
and nothing more. The `fib_behind_rib` predicate moved to
`PredicateSet.feed_fib()`, which takes a parsed `show ip route summary` and
nothing else, and which the runner calls at every convergence decision. An
unreadable or unrecognised summary produces `fib_state_unreadable` /
`fib_summary_unrecognised` at `warn` — a named measurement gap, never a silent
pass and never a fabricated percentage.

**Verified** by a selftest that reads the source of `busy()` and
`PredicateSet.check()` and fails if either divides or compares an install
counter against a table size, plus behavioural checks on `feed_fib`.

## H-53. The recorded `blocked_by` was never the real blocker

`_converge` set `tracker.reason = fib_why` and then re-entered
`wait_for_convergence`, whose very next `feed()` overwrites `reason`. So the
recorded reason was always whatever the final sample happened to say.

`run.json` for this run: `blocked_by: "stabilising (2/3 samples)"`. The console,
160 times: `zebra has no ipv4 BGP routes at all`. Anyone reading the artefacts
without the terminal scrollback would have chased the wrong thing — and that is
precisely the situation the artefacts exist for.

**Fixed.** The loop keeps its own sticky rejection reason, distinct from
`tracker.reason`; both are recorded (`blocked_by`, `last_sample_reason`).

## H-54. "converged in 4.0s (converged=False)" — a duration for something that did not happen

`wait_for_convergence` deliberately back-dates its return by
`(stable_samples-1) * interval`, which is correct for a convergence that
happened and meaningless for one that did not. The report printed
**"initial convergence: 4.0s (converged=False)"** for a 2,400 s wait.

**Fixed.** `_converge` returns and logs wall time when it fails (`waited_s`),
keeps the streak figure separately, and `analysis/analyze.py` prints
*"did not converge — waited 2400s, blocked by: …"* rather than a number that
invites being read as a result.

## H-55. Three bgpd restarts were reported as one

`PredicateSet.check_new` suppresses repeats keyed on `(code, severity)`, which
is right for a standing condition ("RSS over budget") and wrong for a
repeatable discrete event. bgpd restarted **three** times in this run —
503 → 178177 → 198291 → 240636 — and the report shows one.

**Fixed.** `Violation` gained a `dedup` field; the restart predicate sets it to
`old->new` and numbers each occurrence (`restart #2 of this run`).

## H-56. A 10 s log window on a 15 s cadence never read a third of the journal

`Sampler.log_window` was the fixed string `"-10s"`. At the shipped T3 settings
(`interval 3.0`, `slow_every 5`) log reads are 15 s apart. One second in three
was never read.

Consequence, in this run: `daemon_unresponsive` counted **0** in every one of
705 slow samples, while the journal holds three
`bgpd state -> unresponsive : no response yet to ping sent 90 seconds ago`
lines. So the one restart that *was* reported carried
`watchdog_kill: false` — for a kill the supervisor had named explicitly.

A second cause compounded it: watchfrr logs "unresponsive", then waits its full
90 s grace before SIGTERM, so the line and the PID change are 90–160 s apart and
can never be in the same sample however wide the window.

**Fixed.** The window is now computed from the time actually elapsed since the
previous read plus a 2 s margin — a small deliberate overlap, because
double-counting a line at a window edge inflates a count while a gap loses the
line that explains the run — and each sample records `log_window_s`. Watchdog
attribution uses a 300 s memory of the signature rather than the current sample.

**Correction (operator, 2026-09-01).** The 16 occurrences of
`.... removed similar messages to save space` in `t3_journal_frr.log` are **not**
journald rate-limiting. The operator trimmed the journal by hand from 19 MB to
555 KB before sending it, and inserted those markers. There is no evidence of
log loss on the DUT, and no `RateLimitBurst` change is needed.

What *is* true is narrower and still worth stating: **every count in the R-5 to
R-8 sections below was taken from the trimmed 555 KB copy, so each is a lower
bound on the original.** 74 CPU-starvation events, 68 `getsockname` failures and
420 `%ADJCHANGE ... Down` lines are floors, not totals. The three watchfrr
sequences are complete (each has its full unresponsive → SIGTERM → up chain), so
R-5's timings are exact. For the next run the full journal should be kept
alongside the trimmed one — I can read a 19 MB file, and counts taken from it
would be exact.

The separate H-56 defect above stands on its own evidence and is unaffected: the
sampler's own 10 s window on a 15 s cadence is why `daemon_unresponsive` counted
0 in all 705 slow samples.

## H-57. The one moment that needed per-peer state is the one that never records it

`_summarise_bgp` caps per-peer detail at `PER_PEER_SAMPLE_LIMIT` and the
not-established list at `NOT_ESTABLISHED_CAP`, to keep a 2 s poll cheap. At T3
scale (154 sessions) that means **every sample carried `per_peer: null`** and a
25-entry truncated address list.

So the run ended with 75 IPv6 sessions in `Active` and no record of which
sessions, when each went down, or how many times it had flapped — and from the
run's own data "the DUT would not re-establish them" and "the far ends were
gone" cannot be told apart. See R-8.

**Fixed.** `_summarise_bgp(..., full_detail=True)` and `runner._snapshot_peers()`
take a complete one-shot picture — every non-established session with its state,
plus `connectionsDropped` per peer — at end of run and on every failed
convergence, logged as `peer_snapshot`.

**Still missing, and needed to close R-8:** nothing captures the *peer side*.
The next run should collect each generator container's log and session list at
the same two moments.

---

# What T3 run 1 actually found about the DUT

Four findings, all from positive evidence in the journal or the samples. Where
the evidence does not settle a question, it says so.

## R-5. watchfrr killed a working bgpd three times in one run

R-2 was reproduced twice at T2. This run reproduced it **three more times**, at
4.8M paths, with the full watchfrr sequence in the journal each time:

| # | unresponsive | bgpd terminated | back up | outage | bgpd PID |
|---|---|---|---|---|---|
| 1 | 15:06:32 | 15:06:32 | 15:09:08 | **156 s** | 503 → 178177 |
| 2 | 15:29:49 | 15:29:49 | 15:33:11 | **202 s** | 178177 → 198291 |
| 3 | 16:36:20 | 16:36:25 | 16:40:15 | **235 s** | 198291 → 240636 |

No crash, no signal, no assertion anywhere in the journal. The trigger is
`watchfrr --timeout=90` (the VyOS default) not getting an answer from a
single-threaded main loop that is busy.

Two details worth carrying to the FRR/VyOS teams:

1. **The 90 s is not the whole story.** The log line says the ping it is waiting
   on was *"sent 90 seconds ago"*, so bgpd had already been unresponsive since
   15:05:02 / 15:28:19 / 16:34:50. Total main-thread stall per incident: **246 s,
   292 s, 325 s.**
2. **The recovery machinery is jammed by the same load.** In all three cases
   `watchfrr.sh restart bgpd` itself had to be killed —
   `restart bgpd child process … still running after 90 seconds, sending
   signal 15` — and in incident 1 a *second* restart had to be forked at
   15:09:07 before bgpd came up.

Then the table has to reload. Measured from the samples, from restart to a full
4,020,600-path IPv4 table: **~293 s** (restart 1), **~510 s** (restart 2), and
restart 3 never fully recovered (see R-8). Against R-4's measured 491.6 s cold
start to forwarding, each incident is on the order of **11–13 minutes** in which
the router is not carrying what it advertises it carries.

## R-6. bgpd main-thread events ran up to 87.7 seconds late, on an idle host

At least 74 `CPU starvation` lines (count taken from the trimmed journal, so a
floor). The worst ten seen, in milliseconds late:

```
80061  80238  80432  80931  81907  82306  82607  86776  87701  87725
```

Warning threshold is 4,000 ms. The starved callback is almost always
`bgp_generate_updgrp_packets` (`bgpd/bgp_io.c:155`), with
`bgp_holdtime_timer` (`bgpd/bgp_fsm.c:442`) next — which is precisely how R-3's
hold-timer expiries happen: the timer that proves the session is alive cannot
run because the thread that runs it is elsewhere.

The load averages printed on those same lines are **1.11, 0.99, 1.26** …
**2.47, 2.02, 1.70**, on a 16-vCPU host. This is not host contention. It is one
thread, and no amount of hardware moves it. Sampled bgpd CPU: p95 199.7%,
max 201.6%, 608 samples at or above 95%.

One line deserves separate attention, because it is not the same shape: at
17:04:35 an event ran **75,821 ms late** while sampled bgpd CPU over that whole
hour was **mean 0.4%, p95 1.0%**. Late but not spinning means blocked, not busy.
What it was blocked on is not in this data.

## R-7. After each restart, bgpd resets the first inbound connection from ~27 peers

At least 68 pairs of these (trimmed-journal floor), at 15:09:44 (14 peers),
15:33:48 (27) and 16:40:47 (27) —
that is, seconds after each bgpd came back up, and at no other time in the run:

```
[EC 100663299] bgp_connect_success: bgp_getsockname(): failed for peer 2001:db8:1::3f, fd 33
[EC 33554461] 2001:db8:1::3f: nexthop_set failed, local: [2001:db8:1::1]:179
              remote: [2001:db8:1::3f]:50773 update_if: (None)
              resetting connection - intf (Unknown)
```

57 distinct peers, 28 IPv6 and 29 IPv4. `intf (Unknown)` says bgpd could not
resolve the interface for the peer — its interface table is repopulated from
zebra on restart, and zebra at that moment is 14 GB resident and reinstalling
millions of routes. Every peer that reconnects before zebra has answered gets
its connection reset and has to wait out its own retry timer.

This is a restart-recovery amplifier: the platform's own supervisor causes the
restart (R-5), and the restart then rejects a fifth of the fleet's first
reconnection attempt.

## R-8. IPv6 sessions decayed from 154 to 79 and never recovered — attribution unresolved

The clearest single number from the run, and the one I cannot yet assign.

IPv4 established held between 149 and 154 for the whole run. IPv6 established
went 154 → 144 (t≈4,728, just after the second restart) → 129 (t≈5,609) → 117
(t≈8,400) → 99 → 79 (t≈9,432), and stayed at **79/154 for the entire 3,600 s
settle**, which is why the post-chaos convergence correctly reports
`not all sessions established`. Final IPv6 drift: **−131,900 prefixes**.

All 25 recorded stuck sessions are in state `Active` — the DUT is trying to
connect and getting nothing back — in contiguous address blocks
(`2001:db8:1::f`–`::13`, `::19`–`::1d`, `::32`–`::40`).

What the evidence rules out:

* Not CPU starvation during the settle: sampled bgpd CPU over that hour was
  mean 0.4%, p95 1.0%.
* Not `maximum-prefix`: zero `%MAXPFX` lines in the journal.
* Not whole peer containers dying: the IPv4 sessions from the same containers
  stayed up.

What the evidence cannot settle: whether the far-end IPv6 speakers were alive.
Nothing in this run captures peer-side state — `per_peer` was `null` in every
sample (H-57) and no generator container logs were collected. `Active` with no
DUT-side log line is equally consistent with "the peer is not listening" and
"the DUT's connect attempts are failing".

**Not reportable as a DUT finding until the next run captures the peer side.**
H-57's `peer_snapshot` gives the DUT half; the generator half still needs
building.

---

## The recurring lesson, for the third time

Every apparent DUT misbehaviour in this project has turned out to be a
harness-side defect until proven otherwise, and each of the three FIB gates —
H-41, H-50, H-51 — failed in a different direction:

* **H-41**: a gate that could pass without reading the FIB.
* **H-50**: a gate satisfied by a reading it never evaluated.
* **H-51**: a gate that could not pass at all, because it demanded a row FRR
  does not print.

The common thread is that all three were written against what I expected the
output to look like rather than against a captured sample of it. The selftest
for H-51 uses the operator's verbatim terminal output as its fixture. That is
now the standard for every parser in this harness: **a pattern is not verified
until it has been run against a copy of the real thing.**

And a new one, from H-51's wording: a diagnostic must distinguish *"the router
is in state X"* from *"I cannot tell what state the router is in"*. Saying the
first when only the second is true sends the operator to look at the router.

---

# Recommendations to the FRR and VyOS teams

Ordered by effort-to-benefit, not by size. Each is tied to a measurement in this
document; where a claim rests on something not measured here, it says so.

**Split by project first, because two of these are commonly filed in the wrong
place.** `zebra dplane limit` is an *existing* FRR command
([FRR zebra docs](https://docs.frrouting.org/en/latest/zebra.html)) that VyOS
does not expose — a VyOS ask, which is exactly what
[T5454](https://vyos.dev/T5454) is (Backlog / Feature Requests, VyOS Rolling,
since October 2024). watchfrr's timeouts are FRR options that VyOS sets and does
not expose — also a VyOS ask. Only V-1, F-1 to F-4 are changes to FRR itself.

## V-1. Expose watchfrr's `--timeout` and `--restart-timeout` in VyOS config

**Highest leverage available today, and it needs no FRR change at all.**

Upstream defaults are `-t 10` and `-T 20`
([frr-watchfrr(8)](https://manpages.debian.org/testing/frr/frr-watchfrr.8.en.html)).
VyOS already raises both to 90 s — the journal proves the values in effect:
`no response yet to ping sent 90 seconds ago` and `child process … still
running after 90 seconds, sending signal 15`. Neither is reachable from VyOS
configuration.

90 s is not enough at full-table scale. Measured on this DUT (R-5): bgpd's main
thread was unavailable for **246 s, 292 s and 325 s** in three separate
incidents, each time while *working correctly*, and watchfrr killed it every
time. Cost per incident, counting R-4's measured 491.6 s cold start to
forwarding: roughly 11–13 minutes of a router not carrying what it advertises.

An operator running 4.8M paths who could set `-t 300` would have had **zero**
outages in this run. Everything else in this list is a real fix; this is the one
that makes the box survivable while the real fixes are written.

## V-2. Expose `zebra dplane limit` (T5454)

FRR's command already exists: *"Configure the limit on the number of pending
updates that are waiting to be processed by the dataplane pthread."*

Evidence it binds here: zebra's dataplane queue reached **202 against a limit of
200** during table load, on every run at T2 and T3 scale. `queue_max` is a
high-water mark since zebra started, so this is the initial install, not chaos.

Worth saying plainly to whoever picks up T5454: this project **did not** work
around the missing knob, deliberately, because a VyOS operator cannot. So the
numbers in this document are what VyOS delivers today, not what FRR is capable
of. That is the useful comparison, and it is also the argument for the ticket.

## F-0. An event queued to bgpd's main thread should wake that thread

**Added after T3 run 2, and it displaces F-1 as the highest-value FRR ask.**
See R-9 for the full evidence. In summary:

* reproduced in **four consecutive runs**: 7, 59 and 18 idle-bgpd instances in
  runs 2, 3 and 4 (run 1's log windows were too narrow to see them). Ready
  callbacks ran **73.7 s to 90.2 s late** while bgpd used 0.4–0.5% of one core;
* every one of those latencies is just under the configured 90 s holdtime, and
  none exceeds it — the delay is bounded by the next already-scheduled timer;
* all seven are in the quiet post-chaos phase, where nothing else is waking the
  event loop;
* `bgp_generate_updgrp_packets` is among the delayed events, so the send queue
  does not drain, and FRR's own watchdog logged
  `has not made any SendQ progress for 1 holdtime` **365 times** and
  `for 2 holdtimes (180s), terminating session` **11 times**.

Eleven BGP sessions were terminated by the DUT in run 2 and fourteen in run 4,
while the DUT was idle and the peers were healthy. That is a self-inflicted
outage with a complete causal chain from an undispatched event to a dropped
session. Runs 3 had zero, so it is a threshold effect — which makes the
one-holdtime warning the ceiling indicator, not the teardown.

**Every environmental alternative is excluded by measurement, not by argument.**
Across the idle-bgpd events: host memory stall 0.00 s, host IO stall 0.09 s,
DUT cgroup CPU throttling 0.00 s over 2,346 samples, DUT cgroup memory stall
0.00 s. In run 3 that was 2,530 s of accumulated lateness against 0.09 s of
host stall — a factor of roughly 28,000.

The hypothesis — that a cross-thread event enqueue is not writing the target
thread's wakeup pipe, so `poll()` sleeps until its original timeout — is ours
and is **not verified**. The measurements are. Handing them the measurements
and letting them find the mechanism is the right division of labour; event-loop
tracing or an `strace` of the main thread across one of these gaps would settle
it in minutes for someone who knows the scheduler.

## F-6. bgpd should stop running session-teardown timers once it is shutting down

From R-10, and independent of everything else on this list. On 2026-09-04 bgpd
logged `Terminating on signal` at 12:06:58 and then, as the same pid, terminated
**14 healthy BGP sessions** on the send-queue timer between 12:10:29 and
12:10:53 — three and a half minutes into a shutdown that took six minutes to
complete.

Two asks:

* **Bound the shutdown path at scale.** Six minutes to exit a 4.8M-path bgpd
  turns every restart into a much longer outage than the restart itself
  accounts for, and watchfrr's `-T` kill timeout fires repeatedly in the
  meantime (observed: `restart bgpd child process … still running after 90
  seconds` at 12:08:28 and 12:11:02).
* **Once `bgp_exit` has been entered, stop making decisions that cost the
  operator sessions.** A daemon on its way out has no business tearing down
  peers on a send-queue timer; those sessions would have re-established against
  the new process anyway, and instead they were dropped with a NOTIFICATION.

Cheap to fix, easy to verify, and it removes a multiplier on the outage cost of
every V-1/F-3 incident.

## F-1. Hold-timer expiry should not charge scheduler latency to the peer

Smallest FRR change on this list with the largest direct effect on "did the
router cause an outage".

`bgp_holdtime_timer` (`bgpd/bgp_fsm.c:442`) was measured running **4.1 s to
80 s late** (R-6). FRR already knows the lateness — it prints it in the
`CPU starvation` line. But a hold timer that fires 80 s late has, from the
peer's point of view, been counting silence the whole time, and at T2 this
produced **20 hold-timer expiries alongside 12 CPU-starvation events** (R-3):
sessions torn down not because the peer stopped talking, but because bgpd
could not get to the timer that proves it did.

The ask is for FRR to decide what the right behaviour is when the scheduler
owes a callback 80 seconds — discount the stolen time, re-arm, or something
else. **Not verified here:** whether `bgp_fsm.c` already compensates. The
observation is the pairing of starvation with expiries, not a reading of the
handler.

## F-2. A failed `bgp_getsockname()` after restart should defer the peer, not reset it

Small, self-contained, and reproducible on demand (R-7). Seconds after each
bgpd restart, and at no other point in a 3.7-hour run:

```
[EC 100663299] bgp_connect_success: bgp_getsockname(): failed for peer 2001:db8:1::3f, fd 33
[EC 33554461] 2001:db8:1::3f: nexthop_set failed, local: [2001:db8:1::1]:179
              remote: [2001:db8:1::3f]:50773 update_if: (None)
              resetting connection - intf (Unknown)
```

27 peers per restart, 57 distinct peers, 28 IPv6 and 29 IPv4. `intf (Unknown)`
means bgpd has not yet received interface state from zebra — which at that
moment is 14 GB resident and reinstalling millions of routes. Every peer that
reconnects inside that window is reset and must wait out its own retry timer.

Resetting a connection because *our* dependency is not ready yet is the wrong
response. Holding it in Connect/OpenSent until zebra answers, or retrying
`bgp_nexthop_set`, would remove a restart-recovery amplifier that currently
turns one bgpd restart into a second wave of session churn.

## F-3. watchfrr's liveness ping is answered on the thread most likely to be busy

The structural version of V-1. watchfrr connects to the VTY socket and sends an
echo, which bgpd services on its main loop — precisely the thread that is
saturated under a full-table load. So the health check fails exactly when the
daemon is working hardest, and never when it is genuinely wedged in a way the
main loop would survive.

Three kills in this run, zero crashes, zero signals, zero assertions anywhere in
the journal (R-5). Two directions worth their consideration: answer liveness
from a thread that is not the main loop (bgpd already has I/O and keepalive
pthreads), or have watchfrr check forward progress — `utime`/`stime` advancing —
before concluding the process is dead.

## F-4. The restart path itself does not survive a large table

Distinct from F-3, and visible in all three incidents:

```
restart bgpd child process 177089 still running after 90 seconds, sending signal 15
```

`watchfrr.sh restart bgpd` had to be SIGTERM'd every time, and in incident 1 a
second restart had to be forked at 15:09:07 before bgpd came back at 15:09:08.
The recovery machinery is jammed by the same load that triggered the recovery.

## F-5. bgpd's single main thread is the ceiling — filed with numbers, not opinion

The team's position is on record: pthreads exist in both zebra and bgpd,
*"There clearly is room for more pthreading to be done"*, and *"no-one is
working on it that I am aware of"* — Donald Sharp,
[FRR discussion #15033](https://github.com/FRRouting/frr/discussions/15033).
[PR #1145](https://github.com/FRRouting/frr/pull/1145) is the multithreaded-bgpd
work that produced the I/O and keepalive pthreads that exist today.

What that discussion is short of is measurements, so these are worth attaching:

| measurement | value | why it matters |
|---|---|---|
| bgpd CPU p95 / max | 199.7% / 201.6% | 4-thread process: the I/O pthreads *are* working. 200% is the ceiling, not idleness. |
| samples at ≥95% CPU | 608 of 3,522 | 17% of a 3.7-hour run pinned on one core |
| host load during starvation | 0.99 – 2.47 on 16 vCPU | not contention; 14 cores idle |
| bestpath + FIB install, cold | 191.0 s for 2,445,625 routes | R-4, single-threaded |
| worst callback lateness | 87,725 ms | threshold is 4,000 ms |
| single `set` on a peer-group at 2.8M paths | 311 – 641 s | R-1, all completing |

The honest framing for the ticket: this is not a request for a rewrite. It is
evidence that the *specific* stages that dominate — UPDATE parsing, bestpath,
and update generation, all on the main loop — are what a full-table VyOS box
spends its outage budget on, and that F-1 to F-4 are the parts that can be
fixed without touching that architecture.

## Not recommended, deliberately

* **The martian next-hop session reset.** Unfixable in VyOS 1.5.1 / FRR 10.5.2,
  so not tested and not reported. (Operator's call, and the right one.)
* **The five confirmed template defects** are configuration issues in the IXP
  template, not FRR defects. They belong in the template's own change log.
* **R-8 (IPv6 154 → 79) is WITHDRAWN.** Run 2's peer-side snapshot showed the
  generators alive and listening while their global IPv6 addresses were gone
  from the interface — because `ip link set eth1 down` makes Linux flush them
  and the harness never put them back (H-59). The correlation was exact: 9
  link-flapped containers, 9 containers missing addresses, 75 sessions in them,
  75 sessions dead. Not a DUT defect. Had run 1 been sent as it stood, this
  would have reached the FRR team as "VyOS loses 49% of its IPv6 sessions under
  churn", with 5 MB of telemetry apparently backing it.

---

## H-57 part 2. Peer-side socket state, so `Active` can be attributed

Built after run 1, to close the gap that made R-8 unreportable.

`Active` on the DUT means "I am dialling and getting nothing back". That is
equally consistent with the far end being dead and with the DUT's connects
failing, and run 1 held 75 IPv6 sessions in that state for a full hour with no
way to tell which. The discriminator is the *peer's* TCP state.

`PeerFleet.fleet_snapshot()` now takes it, per container and per session, at the
same two moments as the DUT snapshot (end of run, and every failed
convergence). Per session it returns one of:

| verdict | what it means | points at |
|---|---|---|
| `established` | the socket is up on the peer side too | — |
| `socket_syn_sent` | the peer is dialling and the DUT is not answering | DUT / path |
| `listening_no_connection` | the peer is up and waiting; nothing arrived | DUT / path |
| `no_socket_for_family` | the peer has no port-179 socket for that family at all | the generator — **lab-side, not a DUT result** |
| `no_socket_for_session` | sockets exist for the family, none for this pair | needs the logs |
| `unreadable` | the container could not be reached | nothing; it is a gap |

Each container snapshot also carries generator PIDs, the addresses actually
configured (`ip -o addr`), the live `netem` state, and the tails of
`exabgp.log` and the helper log. `containers_with_no_speaker` is called out
separately, because that single fact settles most of these questions on its own.

Two implementation notes worth keeping:

* **Read from `/proc/net/tcp{,6}`, not `ss` or `netstat`.** Neither is present
  in every generator image, and a missing binary would turn the answer back
  into a guess — which is the failure mode this whole section exists to remove.
* **The verdict strings name evidence, not blame.** `no_socket_for_family` is a
  statement about a socket table. Whether that is the generator's fault, the
  harness's, or a consequence of something the DUT did is a separate question,
  and the string does not pre-judge it. This is the same lesson as H-51's
  "the FIB is empty" versus "I do not recognise this row".

Verified by `check_peer_side_socket_state_is_captured`, whose fixture is
`/proc/net/tcp6` encoded exactly as the kernel writes it — each 32-bit word of
the address in host byte order — using `2001:db8:1::3f`, one of the sessions
that was actually stuck in run 1, dialling `2001:db8:1::1`, the DUT.

Containers are visited concurrently (8 workers); 24 containers x 5 commands
serially would take minutes at a point in the run where nothing else is
happening.

**What this still does not do:** it is a snapshot, not a history. If a session
dies at t=4,700 and the snapshot is taken at t=13,240, the snapshot says what
is true at the end, not when it changed. The DUT-side `conn_drop` counter in
the same record gives the flap count, which is the closest thing to a history
available without per-session polling that the sample budget cannot afford.

---

## H-58. A diagnostic call killed the command, one line after it succeeded

T3 run 2, `make converge`, 2026-09-01:

```
converged        : True
seconds          : 10.0   (budget 1200.0)
ipv4 FIB         : 2,445,625 of 2,445,625 BGP routes installed (100.0%)
Traceback (most recent call last):
  File ".../harness/runner.py", line 771, in cmd_converge
    ctx.log("fib_state", afi=afi, **{k: v for k, v in rs.items()
                                     if k != "sources"})
TypeError: harness.scenarios.Ctx.log() got multiple values for keyword argument 'afi'
```

The three lines above the traceback are the entire point of the previous round
of work: the H-51 fix works, convergence is confirmed in 10 s, and the FIB is
100.0% installed. Then a logging call aborted the command.

**Root cause.** `Dut.route_summary()` returns `{"ok":…, "afi":…, "sources":…}`.
The call passed `afi=afi` *and* expanded that same dict, so `afi` arrived twice.
Python raises this at the **call site**, before the function body runs, so
nothing inside `Ctx.log` could defend against it.

**Why it survived every previous run and 754 offline checks.** The guard
immediately above it was:

```python
if not rs.get("ok") or rs.get("bgp_routes") is None:
    ...
    continue
```

and H-51 meant `bgp_routes` was `None` on every real FRR build. The branch below
had therefore **never executed** — not in a run, not in a test. It was dead
code containing a call that could not work. Fixing H-51 made it reachable, and
it failed on first contact.

That is the more interesting half. A latent defect behind an always-false guard
is invisible to every form of testing that exercises real behaviour, and the
thing that exposes it is a *fix elsewhere*. Which means: **when a guard that
was always taken stops being always taken, everything behind it is new code**,
however old it looks in the file.

**Fixed, in three layers.**

1. **The signature.** `Ctx.log` and `Sampler.event` now take
   `payload: Optional[Dict]`, merged under any explicit keywords. A dict is
   passed as `payload=`, never expanded, so no key can collide. H-24 made
   `kind` positional-only, which fixed this for exactly one key; `payload`
   generalises it to all of them.
2. **The call sites.** Both places that mixed the two forms — `runner.py:771`
   and `scenarios.ev_policy_churn` (`fragment=name, **applied`, safe by luck
   rather than by construction) — now pass `payload=`.
3. **A static check.** `check_log_calls_cannot_collide_on_a_key` walks the AST
   of every `.py` under `harness/`, `analysis/` and `tests/` and fails if any
   `log`/`event` call mixes explicit keywords with a `**` expansion. 78 calls
   scanned. A pure `**` expansion with no sibling keywords stays legal — it
   cannot collide with anything.

Plus a regression test that logs the exact `route_summary` dict which crashed,
asserts an explicit keyword still wins over a payload key, and asserts H-24's
`kind` → `event_kind` preservation still holds.

**A small joke at my expense:** the first version of the accompanying check
searched `inspect.getsource(cmd_converge)` for the string `**rs` — and failed,
because it matched the *comment explaining the fix*. It now strips comments and
asserts structurally over the AST. Match the thing, not text that mentions it.

### What run 2's `converge` proves before it crashed

Worth recording separately, because it is a result:

| | run 1 | run 2 |
|---|---|---|
| convergence confirmed | **never** (2,400 s, 160 false rejections) | **10.0 s** |
| ipv4 FIB reported | `unavailable (no bgp line)` | **2,445,625 of 2,445,625 (100.0%)** |

H-51 and H-52 are closed by measurement, not by argument.

---

# T3 run 2 (2026-09-02, 11:30:28 → 14:32:09 local, 10,901 s)

Same profile, same seed, clean redeploy. Selftest green at 764 checks before the
run. The three fixes under test all held:

| | run 1 | run 2 |
|---|---|---|
| initial convergence | never, 2,400 s burned (H-51) | **True in 10.0 s** |
| ipv4 FIB reported | `unavailable (no bgp line)` | **2,445,625 / 2,445,625 (100.0%)** |
| ipv6 FIB reported | not reached | **479,500 / 479,500 (100.0%)** |
| cold start decomposed | by eye only | **485 s** (read-only 300.0 s — limit expired, bestpath+FIB 184.2 s) |
| bgpd restarts reported | 1 of 3 (H-55) | **3 of 3, numbered** |
| `fib_behind_rib` false warning | present, 52% (H-52) | **absent** |
| `sendq_stuck_warn` detected | never | **caught** |

H-51, H-52, H-54, H-55, H-56 and H-58 are closed by measurement.

## H-59. The harness destroyed 75 IPv6 sessions per run, and nearly blamed the DUT

**The most important finding in this document, and it is a harness defect.**

Runs 1 and 2 both ended with **exactly 75** of 154 IPv6 sessions in `Active`,
never recovering, with identical drift (−51,000 IPv4 / −131,900 IPv6). That
reproducibility was the tell: a router under pseudo-random churn does not
produce identical casualty counts twice. Something deterministic was doing it.

The peer snapshot built for R-8 answered it in a single reading:

```
verdict_counts: {"ipv4:established": 147, "ipv6:established": 77,
                 "ipv6:listening_no_connection": 73, "ipv4:listening_no_connection": 2,
                 "ipv6:socket_close_wait": 4, "ipv4:socket_close_wait": 5}
containers_with_no_speaker: []
```

Every generator alive. 73 IPv6 sessions listening, nothing connected. And the
container's own `ip -o addr`:

```
eth1 198.51.96.15/20 … 198.51.96.19/20      <- IPv4 present
eth1 fe80::a8c1:abff:feb8:2eaa/64           <- link-local ONLY
```

The `2001:db8:1::f`–`::13` addresses were **gone**, while gobgpd still held
LISTEN sockets bound to them — a listening socket outlives the address it was
bound to, which is why "the peer is listening" was true and useless.

**Cause.** Linux flushes every *global* IPv6 address on an interface when the
link goes down (`net.ipv6.conf.*.keep_addr_on_down` defaults to 0) and does not
restore them on link-up. IPv4 addresses survive. `peer_flap mode=link_down`
does `ip link set eth1 down`, and eth1 carries **every session in the
container** — so one flap of one session permanently killed the IPv6 half of
five.

**The correlation is exact.** Run 2: 10 `link_down` events hit 9 distinct
containers; exactly those 9 containers were missing their global IPv6
addresses; those 9 containers hold exactly 75 sessions. Set equality, no
residue in either direction.

Run 1 came one step from being reported to the FRR team as *"VyOS loses 49% of
its IPv6 sessions under churn and never recovers."* It would have been wrong,
confidently, with 5 MB of telemetry behind it.

**Fixed in three layers.**

1. `prepare.sh` sets `keep_addr_on_down=1` on `all` and on each interface by
   name (`all` is only consulted for interfaces created after it is set). This
   is also the behaviour being modelled — a real IXP peer does not lose its
   configured address because a port bounced.
2. `PeerFleet.unflap` calls `restore_addrs()`, which reads back what is present
   and re-adds only what is missing, against the inventory. Belt and braces:
   "the sysctl should handle it" is how this went unnoticed twice.
3. `ev_peer_flap` verifies the addresses came back and returns
   `peer_flap_ineffective` naming the count if not — the H-33 rule (an
   impairment that is not verified is not an impairment) applied to *recovery*
   rather than to application.

`PeerFleet` gained `expected_addrs`, supplied at all three construction sites
from the inventory; with it absent, `restore_addrs` does nothing and says so
instead of guessing.

**R-8 is therefore withdrawn.** It was never a DUT finding. The peer-side
snapshot cost one afternoon and prevented a false report to an upstream
project — which is the whole argument for building it.

## H-60. Two collection bugs, both from guessing a name

* `collect-run.sh` and `make monitor` guessed the DUT container as
  `clab-<profile>-dut`. It is named after the profile's node, which is `vyos` —
  `clab-t3-fulltable-vyos`. So run 2's bundle came back with **no DUT journal,
  no running config and no final `show` output**, and `host-metrics.csv` had
  empty `dut_*` columns. Both now read the name from `inventory.json`, with a
  docker-image fallback, and print it.
* `make report` picked `results/peers/` because it is the newest directory, and
  produced a report reading `samples: 0 over 0s` with empty tables. It now
  selects the newest directory matching `YYYYmmddTHHMMSS` and says which one it
  analysed. Only reason the run was still readable: `run.json` and
  `samples.jsonl` were intact in the real results directory.

Neither cost the run. Both are the same mistake as H-51 in miniature: a value
assumed rather than read from the thing that knows it.

---

# What run 2 found about the DUT

## R-5 confirmed a third time: three more watchfrr kills

| # | unresponsive | back up | outage | bgpd PID |
|---|---|---|---|---|
| 1 | 12:37:28 | 12:41:16 | **228 s** | 501 → 69060 |
| 2 | 13:27:23 | 13:33:25 | **362 s** | 69060 → 99836 |
| 3 | 13:59:44 | 14:03:42 | **238 s** | 99836 → 120015 |

Six kills across two runs, no crash in either. Add the 90 s the ping had
already been outstanding and the main-thread stalls were 318 s, 452 s and
328 s.

The restart path failed again, and worse: incident 2 needed **three** forks of
`watchfrr.sh restart bgpd`, two of them SIGTERM'd after 90 s
(`still running after 90 seconds, sending signal 15` at 13:28:53 and
13:31:23). Against the measured 485 s cold start, each incident is 11–14
minutes of a router not carrying its table.

## R-6 refined: the CPU-starvation events are two different phenomena

85 starvation lines. Correlating each against sampled bgpd CPU over the 90 s
window it was late across splits them cleanly:

**Population A — bgpd genuinely saturated.** 12:34:13, 12:35:46, 13:13:10:
mean CPU 180–200%, `frac>=50%` between 0.93 and 1.00 for the whole window.
This is the original R-6 story and it is unchanged.

**Population B — bgpd idle.** 13:44:18, 13:54:17, 13:57:32, 13:59:25, 13:59:40,
14:20:25, 14:25:03: mean CPU **0.4–0.5%**, max **1.7%**, `frac>=50% = 0.00`
across the full 90 s — for events that ran **73.7 s to 88.2 s late**. All seven
fall inside the post-chaos settle, where there is almost no traffic.

Whole run: mean 42.5%, p95 200.0%, max 202.8%, 24.5% of samples at ≥95%.

## R-9 (new). Ready events wait ~one holdtime on an idle bgpd, and it tears down sessions

The population-B events above are a distinct finding, and the host is
eliminated as a cause by measurement rather than by argument.

`host-metrics.csv`, 2,169 samples across the run window, 62.3 GiB host, 23 GiB
swap configured:

| | whole run | at the 12 worst starvation events (±30 s) |
|---|---|---|
| swap-in pages | 277,741 | **0** at 9 of 12 |
| major faults | 213,598 | **0** at 9 of 12; 2,855 and 996 at two others |
| PSI memory stalled | **6.0 s total** | 0.00–0.01 s |
| PSI IO stalled | **5.2 s total** | 0.00 s |
| `procs_blocked` > 0 | 6 of 2,169 samples | — |
| memory available | min 8.6 GiB | ≥ 9.6 GiB at every event |

Eleven seconds of host stall across three hours cannot produce an 88-second
delay, and at nine of the twelve worst events there was no swap activity, no
major fault and no stall at all. **The host did swap during the run, and it is
not the explanation.**

So the measured statement is: *a ready callback on bgpd's main thread ran up to
88 seconds late while that process used 0.4% of one core and the host was not
stalled.*

**The delay is bounded by the holdtime.** Configured holdtime is 90 s
(145 sessions at `holdtime 90 / keepalive 30`, 4 at `holdtime 90`), and every
population-B lateness lands in 73.7–88.2 s — just under it, never over.

**Leading hypothesis, offered as a hypothesis:** an event queued to bgpd's main
thread does not wake that thread's `poll()`, so it is not dispatched until the
next *already-scheduled* timer expires. On an otherwise idle session the next
timer is the hold timer, which bounds the delay at one holdtime. It would be
invisible under load, because traffic wakes the loop constantly — which is
exactly why all seven instances are in the quiet settle phase. What would
confirm it: FRR event-loop tracing, or `strace` on the main thread showing a
single long `poll()` spanning the gap. **Not verified here.**

**It is already causing session teardowns.** `bgp_generate_updgrp_packets` is
one of the delayed events. If it does not run, the send queue does not drain,
and FRR's own send-queue watchdog then reports:

* `has not made any SendQ progress for 1 holdtime` — **365 times**, clustered
  at 13:2x (137), 13:3x (121) and 14:0x (107): the settle window and the third
  restart, the same window as population B;
* `has not made any SendQ progress for 2 holdtimes (180s), terminating session`
  — **11 times**, on `2001:db8:2::38`, `::3b`, `::3d`, `::40`, `::41`, `::44`,
  `::45`, `::47`, `203.0.112.11`, `198.51.96.11`, `198.51.96.12`.

Those eleven sessions were torn down by the DUT while the DUT was idle. The
peers were fine. This is a self-inflicted outage with a clean causal chain from
an undispatched event to a terminated BGP session, and it is the strongest
single result either run has produced.

## Everything else

* Cold start, now measured rather than eyeballed: **485 s** from first session
  to advertising — 300.0 s in read-only mode with the **limit expiring** (not
  all peers sent End-of-RIB), then 184.2 s of bestpath and FIB install for
  2,445,625 IPv4 + 479,500 IPv6 routes.
* `dplane_queue_saturated` now fires separately for during-run (202/200) and
  before-run (201/200). Both hit the limit. V-2 stands.
* 253 `bgp_process_packet: BGP OPEN receipt failed` across 220 distinct peers —
  but **226 of them in a single minute (12:44)**, i.e. a burst, not a standing
  condition. Only 6 during the whole settle hour. Not the cause of the stuck
  sessions; that was H-59.
* 55 `bgp_getsockname(): failed` + `nexthop_set failed … intf (Unknown)`, again
  only at restarts. R-7 confirmed, same shape, lower count.
* Five confirmed template defects, 0 unexplained, unchanged.

---

# T3 run 3 (2026-09-03, 10:09 → 13:12 local, 10,854 s)

Clean redeploy, selftest green at 774 before the run, and the collection bundle
came back at 9.1 MB with everything in it — DUT journal (144 MB), running
config, final `show` output, host metrics with the container columns populated.

## H-59 confirmed fixed, and the drift now reconciles exactly

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| IPv6 sessions failed at end | 75 | 75 | **5** |
| IPv4 sessions failed at end | 3 | 2 | **5** |
| IPv6 drift | −131,900 | −131,900 | **−39,690** |
| IPv4 drift | −51,000 | −51,000 | −250,000 |
| flap recovery, mean / p95 | 598 / 1,356 s | — | **311 / 793 s** |
| flaps measured | 53 | — | **104** |
| SendQ 2-holdtime teardowns | — | 11 | **0** |

The IPv4 drift got *larger*, and that is the good news: it now reconciles.
The five dead sessions are `ixp2-bilat-major-0005` … `-0009`, all in one
container, and they announce 50,000 IPv4 and 8,000 IPv6 prefixes each:

* 5 × 50,000 = **250,000** — the reported IPv4 drift, exactly.
* 5 × 8,000 = 40,000 against a reported **39,690** — 310 short, a read-time
  residue.

For the first time the drift is fully accounted for by identified sessions
rather than being a number with no owner. Both address families now fail the
*same five* sessions, which is what a genuine session-level failure looks like;
the old 75-vs-3 asymmetry was the signature of the address bug.

Flap recovery halved and the sample size doubled — because sessions now actually
come back, so there is something to measure.

## H-61. The H-59 fix broke VLAN fabrics. Third time a fix has created the next defect

`restore_addrs()` defaulted to `iface="eth1"`. On a VLAN-backed fabric the
addresses live on `eth1.<vlan>` — ixp2 in this profile is VLAN 200, ixp1 is
untagged. So the H-59 repair put every ixp2 address on the **parent** interface
while the real ones sat on `eth1.200`:

```
eth1.200 203.0.112.17/20 … .21/20 + 2001:db8:2::11 … ::15/64
eth1     203.0.112.17/20 … .21/20 + 2001:db8:2::11 … ::15/64     <- should not exist
```

Two interfaces in one namespace then held the same address *and* the same
connected prefix, leaving the egress choice to the kernel. Consequence, in the
container that was link-flapped twice:

* DUT state: **`Connect`** on all five sessions;
* peer state: **`SYN_RECV`** on all five.

The DUT's tagged SYN arrived and the peer answered — and the SYN-ACK left by
whichever interface the kernel picked. When that was the untagged parent it
never reached the DUT, and the handshake never completed. Only 3 of the 24
containers were link-flapped on ixp2, all 3 got the duplicate, and only the
one flapped **twice** ended the run broken: non-deterministic breakage is
exactly what a duplicate address produces.

**The verification passed because it shared the bug.** `addrs_missing()` also
defaulted to `eth1`, so it looked for the addresses on the same wrong interface
the repair had just written them to, found them, and reported
`addresses_still_missing: {}` and `peer_flap_ineffective: false` for all ten
link flaps. *A check that makes the same assumption as the code it checks is
not a check.* That is the sharpest form of a lesson this project keeps
relearning, and it now has its own selftest.

**Fixed.**

* `expected_container_addrs()` returns `{"iface", "parent", "cidrs"}`, deriving
  `eth1.<vlan>` from the fabric rather than assuming anything.
* `restore_addrs()` writes to `iface` and additionally **deletes** any expected
  address found on `parent` — that is the repair for the damage as well as the
  prevention.
* `addrs_missing()` reads `iface`; new `addrs_misplaced()` reports addresses
  sitting on the parent.
* `ev_peer_flap` checks both and reports `peer_flap_ineffective` naming which,
  with the reason spelled out.
* Selftests cover the VLAN case, the untagged case, and assert the interface
  name is derived from the inventory rather than defaulted.

## H-62. The watchdog attribution window was a guess, and too short

Restart #2 was reported `watchdog_kill: false` with
`watchdog_seen_at_s: 5534.382` against `t: 5872.881` — a 338 s gap, just past
the 300 s window I picked. The journal names the kill explicitly.

Measured unresponsive-to-back-up across both runs: **177, 228, 238, 362, 365 s**.
The PID change is only *detected* once the new bgpd is up and the sampler reads
`/proc`, so the gap to attribute across is the whole sequence, not watchfrr's
first 90 s timeout. Window raised to 600 s, with the measurements in the
docstring so the next person does not have to re-derive them.

---

# What run 3 found about the DUT

## R-9 confirmed, and this time with 59 instances instead of 7

The log-window fix (H-56) is what made this visible: the report now carries
`cpu_starvation 99`, `holdtime_expire 109`, `sendq_stuck_warn 207`,
`peer_down 854`, `notification_sent 1333` — signals that read as zero in run 1.

Correlating all 88 journal starvation events against sampled bgpd CPU over the
window each was late across:

| | count | bgpd CPU over the 90 s window |
|---|---|---|
| bgpd genuinely saturated | 26 | mean ≥ 50%, up to 200% |
| **bgpd idle** | **59** | **mean 0.5%, max 1.7%** |
| no samples | 3 | — |

The worst: 88.5 s, 88.4 s, 88.4 s, 88.0 s, 87.6 s, 86.9 s, 85.6 s — and the
configured holdtime is **90 s**. Across three runs, not one idle-bgpd lateness
has exceeded one holdtime. The delay is bounded by the next already-scheduled
timer, which is what R-9's hypothesis predicts.

### The host is eliminated by measurement, not by argument

`host-metrics.csv`, 2,347 rows, and this time the DUT container's own cgroup
columns are populated:

| | whole run | summed across the 59 idle-bgpd events |
|---|---|---|
| swap-in | 1,440,121 pages | **41 pages** |
| major faults | 1,089,807 | **230** |
| PSI memory stalled (full) | 9.6 s | **0.00 s** |
| PSI IO stalled (full) | 17.5 s | **0.09 s** |
| DUT cgroup CPU throttled | **0.00 s** over 2,346 samples | — |
| DUT cgroup memory stalled | **0.00 s** over 2,346 samples | — |

**2,530 seconds of accumulated event lateness against 0.09 seconds of host
stall** in the same windows — a factor of roughly 28,000. The host swapped
heavily during the run and it is not the explanation. CFS throttling and
container-level memory reclaim are now excluded too, by direct measurement
rather than by reasoning about quotas.

This is the strongest result the project has produced. It is reproducible
across three runs, it has a bounded and predicted magnitude, every environmental
alternative has been measured and excluded, and in run 2 it terminated eleven
healthy BGP sessions.

**Run 3 had zero SendQ teardowns** (207 one-holdtime warnings, 0 at two). So
the teardown is a threshold effect, not a certainty — which makes the
one-holdtime warning the right ceiling indicator, exactly as the report says.

## R-5: two more watchfrr kills, and the restart path failed again

| # | unresponsive | back up | outage |
|---|---|---|---|
| 1 | 10:31:18 | 10:34:15 | **177 s** |
| 2 | 11:57:29 | 12:03:34 | **365 s** |

Eight kills across three runs, no crash in any of them. Incident 2 needed
**three** forks of `watchfrr.sh restart bgpd`, two SIGTERM'd after 90 s
(11:58:59 and 12:01:29). V-1 remains the highest-leverage change available.

## Resource envelope, third measurement

bgpd RSS peak 8,208 MB (1,791 B/path whole-table), zebra 10,684 MB
(2,331 B/path), container peak 21,417 MB. bgpd CPU mean 29.0%, p95 199.7%,
max 202.4%, 463 samples ≥ 95%. `dplane_queue_saturated` hit 202/200 during the
run and 201/200 before it — V-2 stands.

bgpd RSS/path is now measured three times within 0.5%: 1,800 / 1,791 / 1,791 B.
That is a usable sizing constant.

---

## Swap: why it is on, and set to 1

Asked before run 4: should swap be disabled? The operator's `htop` reading was
*"swap never exceeded 21 MB of 23 GB, memory never exceeded 54.2 of 62.3 GB"*,
which contradicted this document's claim that run 3 swapped 1,440,121 pages in.
Both are right, and the reconciliation is the interesting part.

**What actually happened.** Swap sat at **6.9 MiB** for the first 40 minutes of
run 3, spiked to **5,974 MiB at 10:08:22**, then drained to ~300 MiB by the end.
`htop` at 21 MB means nobody was watching during that three-minute window —
which is the argument for the sampled CSV over eyeballing, not a contradiction.

**Why it swapped is the finding.** Second-by-second across the spike:

| time | swap used | mem available | mem free | swap-in/s | swap-out/s |
|---|---|---|---|---|---|
| 10:06:11 | 6.9 MiB | 9.2 GiB | 6.7 GiB | 0 | 0 |
| 10:07:06 | 1,521 MiB | 8.1 GiB | 5.5 GiB | 296 | **59,977** |
| 10:07:52 | 4,996 MiB | 7.4 GiB | 4.9 GiB | 7,346 | 7,745 |
| 10:08:12 | 5,842 MiB | 7.5 GiB | 4.9 GiB | **13,156** | 9,213 |

The host was **not** short of memory: 7.5 GiB available, 4.9 GiB free, only
3.3 GiB of page cache to reclaim first. And it was swapping **in and out
simultaneously**, thousands of pages per second each way — evicting pages that
were still in use. That is thrashing, not reclaim.

Cause: `vm.swappiness = 60`, the distribution default, captured in
`host-state.txt`. It is tuned for general-purpose servers and is wrong for one
~8 GB anonymous-memory process alongside 24 containers.

**Recommendation: keep swap, set `vm.swappiness = 1`.** Now applied by
`scripts/host-tune.sh`.

* Disabling swap removes the confound but also removes the safety net. At the
  peak, ~6 GiB of anonymous pages were resident-or-swapped; with 7.5 GiB
  available they would *probably* have fit in RAM, but "probably" is a poor
  trade on a three-hour run. If they did not fit, the OOM killer takes bgpd —
  or a peer container, which would surface as a DUT failure and cost another
  round of exactly the misattribution this project keeps having to undo.
* `swappiness=1` stops routine eviction while leaving swap as an emergency
  reserve. `0` is not meaningfully safer and forfeits that reserve.
* A production router does not swap, so 1 is also the more faithful
  configuration — it just gets there by making swapping rare rather than
  impossible.

**This does not affect R-9.** Across the 59 idle-bgpd starvation events the
host showed **41 swap-in pages total and 0.00 s of memory stall**, and no
starvation event falls inside the 10:06–10:10 spike window at all. The spike
and the finding are disjoint in time. Setting swappiness to 1 makes that
argument unnecessary rather than changing its conclusion — which is worth
having, because "we had to reason the environment away" is weaker than "the
environment was not doing anything".

---

# T3 run 4 (2026-09-04, 10:24 → 12:34 local, 7,415 s) — the clean run

`vm.swappiness=1`, clean redeploy, selftest green at 782 before the run.

**Every harness defect found in runs 1–3 is closed, and the run is measuring the
DUT rather than measuring itself.**

| | run 1 | run 2 | run 3 | **run 4** |
|---|---|---|---|---|
| initial convergence | never (2,400 s) | 10.0 s | 10.0 s | **10.0 s** |
| post-chaos convergence | never (3,600 s) | never (3,600 s) | never (3,600 s) | **106.0 s** |
| IPv4 drift | −51,000 | −51,000 | −250,000 | **+0** |
| IPv6 drift | −131,900 | −131,900 | −39,690 | **+310** |
| sessions established at end | 151 / 151 | 152 / 79 | 149 / 149 | **154 / 154** |
| duplicate addresses (H-61) | — | — | 9 containers | **none** |
| run wall time | 13,243 s | 10,901 s | 10,854 s | **7,415 s** |

The run got shorter because the settle phase actually settled — 106 s instead of
timing out at an hour. Convergence in 106 s after two hours of chaos, from a
table that reconciles to the prefix, is the first result in this project that
describes only the router.

`+310` IPv6 is the same residue seen in run 3, and it is a read-time artefact
rather than a leak: `_accounting` samples the two address families in separate
vtysh calls, so churn between them shows up as a small signed difference.

**`make: *** [Makefile:118: run] Error 3` is by design, not a failure.**
`cmd_run` ends with `return 0 if not fails else 3`: exit 3 means "the run
completed and the verdict is FAIL". A crash would be exit 1 and a traceback.
Exit 0 would mean zero failing predicates, which at this scale would itself be
worth investigating.

## R-10 (new). bgpd kept tearing down BGP sessions for four minutes after SIGTERM

The most specific new finding in run 4, and it comes from a detail only the full
journal shows.

Incident 2 of 3:

```
12:06:58  watchfrr: bgpd state -> unresponsive : no response yet to ping sent 90 seconds ago
12:06:58  bgpd[69020]: Terminating on signal
12:08:28  watchfrr: restart bgpd child process 113547 still running after 90 seconds, sending signal 15
12:10:29  bgpd[69020]: 2001:db8:2::2d(ixp2-bilat-tail-c002) has not made any SendQ
          progress for 2 holdtimes (180s), terminating session
   ... 13 more, all bgpd[69020], through 12:10:53 ...
12:11:02  watchfrr: restart bgpd child process 114609 still running after 90 seconds, sending signal 15
12:13:04  watchfrr: bgpd state -> up : connect succeeded
```

All **14** send-queue teardowns were logged by **pid 69020** — the daemon that
had already logged `Terminating on signal` at 12:06:58. So:

* bgpd acknowledged SIGTERM and then took **six minutes** to actually exit;
* during that shutdown it kept running the BGP FSM, and **terminated 14 healthy
  sessions** on a send-queue timer at 12:10:29–12:10:53, 3.5 minutes after being
  told to die;
* the peers it tore down (`ixp2-bilat-tail-c002/3/4`, `transit-c000/c001`,
  `ixp2-rs-c000`) were fine — this is R-9's mechanism firing inside a shutdown
  that cannot complete.

Shutdown at 4.8M paths is not a fast path in FRR, and while it is in progress
the daemon is still making decisions that cost the operator sessions. Two
separate asks fall out of it: make the shutdown path bounded at scale, and stop
running session-teardown timers once `bgp_exit` has been entered.

## R-5, fourth confirmation: three more kills, and the longest yet

| # | unresponsive | back up | outage |
|---|---|---|---|
| 1 | 10:47:10 | 10:50:52 | 222 s |
| 2 | 12:06:58 | 12:13:04 | 366 s |
| 3 | 12:24:11 | 12:33:43 | **572 s** |

**Eleven watchfrr kills across four runs, zero crashes.** 572 s is a
nine-and-a-half-minute control-plane outage caused entirely by the platform's
own supervisor deciding a working daemon was dead. Incidents 2 and 3 again
needed extra forks of `watchfrr.sh restart bgpd`, SIGTERM'd after 90 s.

H-62's 600 s attribution window did its job: restart #3 was correctly reported
as `bgpd PID changed 116862 -> 132236 after watchfrr logged it unresponsive`,
which the 300 s window would have missed.

## R-9, fourth confirmation

78 starvation events with usable CPU correlation: 27 with bgpd saturated, **18
with bgpd idle** accumulating **758 s** of lateness, 33 unmeasurable (the
sampler's vtysh reads fail during restarts, which is itself consistent). Worst
lateness **90,188 ms** against a 90 s holdtime — the first instance to exceed
one holdtime, and only by 188 ms, which is what "waits for the next scheduled
timer, then dispatches" predicts.

`sendq_stuck_warn` 334, `sendq_stuck_proper` **14**, `holdtime_expire` 73. Run 3
had 0 teardowns; run 4 had 14. Across four runs: 0, 11, 0, 14 — a threshold
effect, not a certainty, which is exactly why the one-holdtime warning is the
right ceiling indicator.

## R-1, first completed measurement

`localpref-flip / apply` **completed** rather than timing out, at **662.97 s** —
110% of the 600 s `commit_s` budget. Every prior run recorded it as a timeout,
so this is the first bounded figure for a single-command policy change on a
4.8M-path table.

## swappiness=1 was the right call, measured

| | run 3 (swappiness default) | run 4 (swappiness=1) |
|---|---|---|
| swap used, peak | 5,974 MiB | **1,250 MiB** |
| swap-in over the run | 1,440,121 pages | **356,664 pages** |
| PSI memory stalled | 9.6 s | **3.95 s** |
| PSI IO stalled | 17.5 s | **3.71 s** |
| mem_available, median | 10.6 GiB | **16.2 GiB** |
| DUT cgroup CPU throttled | 0.00 s | **0.00 s** |
| DUT cgroup memory stalled | 0.00 s | **0.00 s** |

Two things this settles. The tuning helped, measurably. And it was never the
constraint: the DUT container's own cgroup recorded zero memory stall and zero
CPU throttling in both runs. No hardware change was needed to get a clean
result, and none is needed to keep getting them at T3.

bgpd RSS/path, four measurements: **1,800 / 1,791 / 1,791 / 1,793 B**. Spread
under 0.5%. That is a sizing constant.

---

# Closed as out of scope: SNMP, RPKI and forwarding-plane traffic

Recorded because the reasoning is worth keeping, and it is the operator's
(2026-09-04), not mine:

> *"if all they are going to do is add workload to the thread (which the bgp
> update and everything else is already doing) then adding it makes no sense.
> Plus for SNMP, my experience says the better way to do the SNMP would be BMP.
> And for IPERF, this would only make sense if the CPU i.e. IRQ is completely so
> busy with traffic that it does not have time for FRR, but as mentioned above,
> this is not the goal, the goal is to fix the frr. ... As most major enterprise
> often use minimum 32 CORE, I don't see the point as Debian knows how to work
> its way around."*

Assessment, item by item:

**SNMP — agreed, drop it, and BMP is the better instrument.** FRR's AgentX
integration services MIB walks on each daemon's main thread, so walking
BGP4-MIB against a 4.8M-path table would block bgpd exactly the way R-6 and R-9
already document. The finding would be "an SNMP walk is a denial of service
against your own control plane at full table" — a real operational warning, but
a third instance of a mechanism already established twice, and arguably a
"don't do that" rather than a defect. BMP (RFC 7854) is the right answer for
this data: it streams from bgpd rather than being polled, and FRR implements it.

**RPKI — agreed, with one thing given up.** RTR-driven revalidation forces a
full table walk on the main thread, so the mechanism is again R-9's. The one
genuinely distinct property is that an `rpki_refresh` is a *bulk* main-thread
operation triggered externally rather than by operator action — but R-1 already
measures a bulk revalidation at 662.97 s via policy commit, so the marginal
information is small. Template defect 6 (the `rpki` route-map containing only
`rule 1000 action permit`) stays documented and untested.

**Traffic — agreed, and this is the strongest of the three arguments.** VyOS
forwards in the kernel, not in FRR. IRQs spread across cores via RSS, FRR's main
thread is ordinary userspace, and on a 32-core box the control plane is not
competing with the data plane for the cycles that matter. Measuring iperf3
throughput would characterise the kernel's forwarding path, which is not the
question.

What is given up, stated plainly so nobody has to rediscover it: **nobody has
measured whether traffic is actually lost while the router reconverges.** The
dataplane queue hit its 200-entry limit in all four runs, and R-4 puts
bestpath+FIB install at 184–191 s for 2.4M routes — so there is a window where
the FIB is demonstrably behind the RIB. Whether packets drop in it is a
user-visible question this project does not answer. Answering it needs a
loss-accounting generator and per-flow measurement, not iperf3, and it would not
change any of the recommendations below.

**The project's findings do not depend on any of the three.** R-5, R-6, R-9 and
R-10 all stand on the DUT's own journal and its own CPU accounting, reproduced
across four runs.
