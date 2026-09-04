# Profile schema

A profile is the single source of truth for one test tier. Everything else —
containerlab topology, GoBGP configs, ExaBGP configs, the DUT's BGP neighbor
stanzas, and the scenario schedule — is generated from it by
`harness/generate.py`.

```yaml
name: <str>                 # tier id, used for lab name and result dir
description: <str>

dut:
  name: <str>               # containerlab node name (also the hostname)
  asn: <int>                # MUST NOT be a bogon ASN — see note below
  router_id: <ipv4>
  image: <str>              # docker image built by images/vyos/build-image.sh
  memory: <str|null>        # containerlab `memory:` e.g. "16Gb"
  cpu: <float|null>         # containerlab `cpu:`
  ssh_user: admin
  ssh_pass: admin

host:
  bridges: [<str>, ...]     # Linux bridges the fabrics attach to

fabrics:                    # shared L2 peering domains
  <fabric-id>:
    bridge: <str>           # must be listed in host.bridges
    vlan: <int|null>        # null = untagged
    v4_net: <cidr>          # peering LAN v4
    v6_net: <cidr>          # peering LAN v6
    dut_host: <int>         # host part for the DUT on this LAN
    dut_iface: <str>        # ethN on the DUT (eth0 is reserved for mgmt)
    peer_host_base: <int>   # first host part handed to simulated peers

own:                        # the DUT's own address space
  supernet4: <cidr>
  local4: <cidr>
  supernet6: <cidr>
  local6: <cidr>

nlri:                       # synthetic NLRI generation
  v4_first_octets: [<int>, ...]   # /8s to carve prefixes from
  v4_len: <int>                   # prefix length to generate (8..24)
  v6_base: <cidr>                 # RFC 9637 3fff::/20 recommended
  v6_len: <int>                   # 12..48
  seed: <int>                     # deterministic generation

fleets:                     # groups of simulated peers
  - id: <str>
    fabric: <fabric-id>
    engine: gobgp | exabgp
    role: route-server | bilateral | transit | ibgp | nasty
    peers: <int>            # number of BGP sessions
    per_container: <int>    # sessions packed into one container
    asn_base: <int>         # first ASN; incremented per peer
    afi: [ipv4, ipv6]
    prefixes_v4: <int>      # per peer
    prefixes_v6: <int>
    paths_per_prefix: <int> # >1 requires addpath on both ends
    mrt: <path|null>        # if set, inject this MRT instead of synthetic
    dut_peer_group4: <str>  # VyOS peer-group to bind on the DUT
    dut_peer_group6: <str>
    max_prefix4: <int|null> # per-neighbor override on the DUT
    max_prefix6: <int|null>
    passive: <bool>
    timers: {keepalive: <int>, holdtime: <int>}
    flappable: <bool>       # eligible for chaos peer selection
    memory: <str|null>
    cpu: <float|null>

scenario:
  duration_s: <int>
  seed: <int>
  warmup_s: <int>           # converge before chaos starts
  sample_interval_s: <float>
  events:                   # weighted event mix, see harness/scenarios.py
    - {kind: <str>, weight: <int>, ...kwargs}
  ramp:                     # only used by `runner.py ramp`
    step_peers: <int>
    step_prefixes: <int>
    max_steps: <int>

budgets:                    # break-it predicates
  convergence_s: <int>
  bgpd_rss_mb: <int>
  zebra_rss_mb: <int>
  commit_s: <int>
  max_failed_peers: <int>
```

## Bogon-ASN warning (important, template-specific)

`Template IXP VyOS Configuration.md` applies `policy as-path-list asn-bogons`
on **both** import and export. Its rules match, among others:

| Rule | Range matched |
|---|---|
| 10 | AS 0 |
| 20 | AS 23456 |
| 30 | 64496–64511, 65536–65551 |
| 40 | 64512–65535 |
| 50 | 65552–65999, 66000–69999 |
| 60 | 70000–130999 |
| 70 | 131000–131071 |
| 80–110 | 4200000000–4294967294 |

Consequently **RFC 6996 private ASNs (64512–65534) cannot be used for the DUT
or for any simulated peer** with this config: the DUT would filter its own
AS_PATH on export and every peer's AS_PATH on import, and the lab would look
"broken" for reasons unrelated to scale.

Safe ranges under this template: `1–64495` (excluding 0 and 23456) and
`131072–4199999999`. All shipped profiles use `64000` for the DUT and allocate
peers from `64001` upward, spilling into `131072+` past 495 peers.

## Address space choices

| Purpose | Value | Why |
|---|---|---|
| Peering LAN v4 | `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 documentation. Appear in the template's `ipv4-bogons`, which is fine — that list is matched against `ip address` (NLRI), never against next-hops. |
| Peering LAN v6 | `2001:db8:1::/64`, `2001:db8:2::/64` | RFC 3849. Same reasoning. |
| Own space v4 | `100.64.0.0/16` | RFC 6598. **Not** in the template's `ipv4-bogons` (see FINDINGS.md #1). |
| Own space v6 | `3fff:100::/32` | RFC 9637 documentation space. Inside `2000::/3` so it passes `ipv6-acceptable`; **not** in the template's `ipv6-bogons` (see FINDINGS.md #2). |
| Synthetic NLRI v4 | `/24`s carved from non-bogon `/8`s | Passes `ipv4-acceptable` (ge 8, le 24). |
| Synthetic NLRI v6 | `/48`s from `3fff::/20` | Passes `ipv6-acceptable` (ge 12, le 48). |
