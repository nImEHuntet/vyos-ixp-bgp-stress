# VyOS IXP BGP stress test — runbook

A step-by-step guide to standing up a lab that behaves like a real internet
exchange router, driving it until it breaks, and knowing what broke.

The DUT runs the configuration from `Template IXP VyOS Configuration.md`
(NE-1849) with placeholders filled in. Peers are simulated with GoBGP (volume)
and ExaBGP (protocol edge cases). Everything is generated from one profile file so
runs are reproducible and comparable.

**Read `FINDINGS.md` first.** Eleven issues in the template were found while
building this, three of them high severity, and two of them change how you must
choose lab address space. If you skip it you will spend time debugging the
template rather than the router.

---

## Contents

1. [What this actually tests](#1-what-this-actually-tests)
2. [Prerequisites](#2-prerequisites)
3. [Host preparation](#3-host-preparation)
4. [Build the images](#4-build-the-images)
5. [Generate a lab](#5-generate-a-lab)
6. [Deploy](#6-deploy)
7. [Configure the DUT](#7-configure-the-dut)
8. [Bring up the peers](#8-bring-up-the-peers)
9. [First convergence](#9-first-convergence)
10. [Policy correctness under load](#10-policy-correctness-under-load)
11. [Run the chaos schedule](#11-run-the-chaos-schedule)
12. [Find the limit](#12-find-the-limit)
13. [Reading the results](#13-reading-the-results)
14. [The scenario catalogue](#14-the-scenario-catalogue)
15. [Known failure modes and what they mean](#15-known-failure-modes-and-what-they-mean)
16. [Tuning knobs worth sweeping](#16-tuning-knobs-worth-sweeping)
17. [Troubleshooting](#17-troubleshooting)
18. [What this harness cannot tell you](#18-what-this-harness-cannot-tell-you)

---

## 1. What this actually tests

The goal is not "how many prefixes fit". It is to find, for a given VyOS build and
host, the point at which the router stops behaving correctly, and to identify
*which* subsystem gave way. There are four candidates and they fail differently:

| Subsystem | Symptom | What raises the ceiling |
|---|---|---|
| bgpd main thread | CPU pinned at ~100%, send queue stalls, `SENDQ_STUCK_*` | Nothing on this box. UPDATE parse, bestpath and update generation are all on one thread. |
| bgpd memory | RSS climbs, eventually OOM | RAM; fewer `soft-reconfiguration inbound` peers; fewer paths |
| zebra / kernel FIB | dataplane queue at limit, route install errors | `zebra dplane limit`, netlink buffers, IPv6 FIB sysctls |
| the config plane | `commit` takes minutes or never returns | Simpler policy, fewer prefix-list entries |

The fourth is the one people forget. A router that is still forwarding but cannot
be reconfigured has failed operationally. The harness times every commit for
exactly this reason.

Two properties make this different from a plain route-injection benchmark:

* **Contested NLRI.** A configurable fraction of every peer's advertisement is
  shared with other peers, so bestpath has real work to do. Without this you
  measure RIB insertion, not path selection.
* **Correctness assertions.** Policy probes run *during* the load, so you learn
  whether filtering still works at scale, not just whether sessions stayed up.

### Architecture

```
                    ┌──────────────────────────────┐
                    │   VyOS DUT (NE-1849 config)  │
                    │   AS 64000                   │
                    │   eth1 ──── eth2.200 ────    │
                    └────┬──────────────┬──────────┘
                         │              │
          ┌──────────────┴───┐   ┌──────┴─────────────┐
          │ br-ixp1 (L2)     │   │ br-ixp2 (L2, VLAN) │
          └──┬────┬────┬─────┘   └──┬────┬────────────┘
             │    │    │            │    │
      ┌──────┴─┐┌─┴───┐┌┴────────┐┌─┴──┐┌┴─────────┐
      │ RS x2  ││bilat││ ExaBGP  ││ RS ││ bilateral│
      │ GoBGP  ││GoBGP││ nasty   ││    ││ GoBGP    │
      │ 380k×2 ││ 80  ││ probes  ││190k││ 60       │
      └────────┘└─────┘└─────────┘└────┘└──────────┘
```

Peering LANs are real L2 broadcast domains (host Linux bridges), not
point-to-point links, because that is what an exchange is and it changes ARP/ND,
next-hop resolution and third-party next-hop behaviour.

Sessions are packed several per container, each with its own `gobgpd` bound to its
own address. GoBGP's documented weakness in every third-party benchmark is many
simultaneous *sessions* per process, not many paths — so one process per session
keeps the generator out of the way, and lets a "peer flap" be a real process event.

### Tiers

| Profile | Sessions | Paths | Host | Purpose |
|---|---|---|---|---|
| `t0-smoke` | 5 | ~2.2k | 8 GB, 2 core | Prove the pipeline works |
| `t1-bilateral-churn` | 42 | ~250k | 16 GB, 4 core | Session-count and policy-fanout cost |
| `t2-ixp-realistic` | 149 | ~2.0M | 64 GB, 12 core | The flagship. Does NE-1849 survive an exchange |
| `t3-fulltable` | 149 | real MRT | 128 GB, 16 core | Defensible numbers from a real table |
| `t4-breakit` | 359 | ramped | 64 GB+, 16 core | Find the wall |

Always run `t0` first on a new image. It takes five minutes and catches
image/bridge/config problems that would otherwise waste an hour at `t2`.

---

## 2. Prerequisites

**Host:** Linux with a kernel you can `modprobe` into (containerlab bind-mounts
`/lib/modules` into VyOS nodes so it can load `nft_nat`). Debian 12 / Ubuntu 24.04
are the well-trodden paths.

**Software:**

| Tool | Why | Notes |
|---|---|---|
| Docker | runs every node | needs IPv6 enabled on its networks |
| containerlab ≥ 0.69 | the `vyosnetworks_vyos` kind was added in 0.69 | 0.75+ for link IPs |
| `nsenter`, `iproute2` | peer addressing from the host | usually present |
| Python ≥ 3.9 + PyYAML | the harness | `pip install -r requirements.txt` |
| `squashfs-tools-ng`, `libarchive-tools` | building the VyOS image | `bsdtar`, `sqfs2tar` |
| `mrtparse` (optional) | independent MRT cross-check | `pip install 'mrtparse>=2.1'`; 1.x also supported, 2.0.x is not |
| `exabgp` (optional, on the host) | validates generated ExaBGP configs offline | `pip install 'exabgp>=5'`; 4.2+ works with reduced coverage |

**Docker IPv6.** The containerlab VyOS kind documents needing an IPv6-enabled
Docker network, and most distributions do not enable it:

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:d0ck::/64",
  "experimental": true,
  "ip6tables": true
}
EOF
sudo systemctl restart docker
```

**A VyOS ISO.** Any ISO you already have works — LTS included. You do not need to
download anything.

Two constraints on *which* one to pick:

* containerlab carries an explicit warning that its VyOS node "has only been
  tested with v1.5 Q1 Stream or higher". **1.5.0 Circinus LTS clears that floor.**
  1.4.x Sagitta and older are below it; they may work, but you are off the
  documented path, and `build-image.sh` will tell you so.
* Prefer LTS over rolling for anything you intend to publish. Rolling moves FRR
  underneath you between builds, and since FRR's BGP update path is
  single-threaded, the FRR version is one of the two variables that most affects
  the result (the other being the host's single-core performance). A pinned LTS
  gives you a number you can reproduce and attribute.

There is no usable published VyOS container image and no container flavor in
vyos-build — its flavor system emits qemu-img formats (`raw`, `qcow2`, `vdi`,
`vhdx`) and `iso` only, and `docker.io/vyos/vyos` was last pushed in 2021 at
1.3-epa2. So the image is built from the ISO's squashfs, which is the path both
docs.vyos.io and the containerlab kind page document. That is one command; see
§4.

Note for the record: VyOS 1.5 is not developed in public. The `vyos-1x` 1.5 branch
is named `circinus-public-unmaintained` and its contents predate 1.5.0 GA, so a
handful of CLI commands can only be confirmed against docs or against the rolling
branch, not both. The generator writes those to
`build/<profile>/dut/VERIFY-ON-IMAGE.md`. Check that file before a run that
depends on them.

---

## 3. Host preparation

```bash
git clone <this repo> && cd vyos-ixp-stress
pip install -r requirements.txt
cp /path/to/"Template IXP VyOS Configuration.md" .

make preflight
```

`preflight` checks tools, Docker IPv6, kernel version, sysctls, ulimits and
capacity, and tells you specifically what is wrong. Then:

```bash
sudo make host-tune NODES=60          # NODES = the node count of your largest tier
sudo systemctl restart docker         # picks up the new LimitNOFILE
```

Three things in `host-tune.sh` are worth understanding rather than trusting:

**inotify.** containerlab documents no inotify guidance for the VyOS kind. The
formula used (`nodes × 1250`) is borrowed from the Arista cEOS page, which is the
only kind with an explicit one. VyOS nodes run full systemd plus FRR plus journald,
so they are inotify-hungry in the same way — but this is a borrowed heuristic, not
vendor-sanctioned. If nodes fail to start with `Too many open files`, raise it.

**`net.core.rmem_max` probably does nothing for zebra.** zebra defaults its netlink
receive buffer to 4 MiB on Linux and sets it with `SO_RCVBUFFORCE`, which bypasses
`net.core.rmem_max` when it holds `CAP_NET_ADMIN`. Raising the sysctl is cargo cult
unless zebra has lost that capability. Check the value that was actually applied:

```bash
docker exec clab-t2-ixp-realistic-vyos vtysh -c 'show zebra' | grep -i 'socket buffer'
```

**`net.ipv4.route.max_size` is deliberately not set.** It has been a no-op since
kernel 3.6 — the IPv4 route cache is gone — and it is absent from FRR's own
recommended sysctl set. The IPv4 FIB is bounded by memory, so IPv4 exhaustion shows
up as memory pressure, never as "table full". `net.ipv6.route.max_size` **is** a
real enforced ceiling on kernels below 6.3 and is deprecated from 6.3 onward, so
whether it matters depends on `uname -r`. `preflight` tells you which case you are
in.

---

## 4. Build the images

### The DUT image, from an ISO you already have

```bash
make vyos-image ISO=/path/to/vyos-1.5.0-generic-amd64.iso
```

The tag is derived from the ISO filename, so `docker images` stays legible when
several releases are on the box:

| ISO | Tag |
|---|---|
| `vyos-1.5.0-generic-amd64.iso` | `vyos-stress:1.5.0` |
| `vyos-2026.03-generic-amd64.iso` | `vyos-stress:2026.03` |
| `vyos-2026.08.05-0033-rolling-generic-amd64.iso` | `vyos-stress:2026.08.05-0033-rolling` |

Override with `VYOS_TAG=` if you want something else.

The script reports what it built, and this is the part worth reading:

```
== image contents
   VyOS   : 1.5.0   flavor=generic  built=2026-03-31
   FRR    : 10.5-0~vyos...
   modules: /lib/modules/6.6.x (the host kernel must match closely)

   containerlab's tested floor (v1.5 Q1 Stream or higher): satisfied.
```

**Record the FRR version.** VyOS publishes no per-release FRR version table, so
the image is the only authority. The script reads it out of the image's dpkg
database at build time rather than making you deploy first, and it warns on two
known-bad ranges: FRR 8.4/8.5 (Extended Message Support inflated BGP memory
significantly; the 9.0 notes state the footprint returned to normal) and FRR
8.4–9.1 (large-community memory leaks, FRR issues 14828 and 15459).

Then point a profile at it:

```yaml
dut:
  image: vyos-stress:1.5.0
```

### The peer images

```bash
make images
```

GoBGP is built from the upstream release tarball because GoBGP publishes no
container image at all: its `.goreleaser.yml` has no `dockers:` section, the
release workflow pushes nothing, `ghcr.io/osrg/gobgp` 404s, and
`docker.io/osrg/gobgp` was last pushed in 2019. ExaBGP does publish one
(`ghcr.io/exa-networks/exabgp`) and it pre-creates the CLI named pipes, so that is
used as a base.

Sanity check all three:

```bash
docker run --rm vyos-stress/gobgp:latest gobgpd --version
docker run --rm --entrypoint exabgp vyos-stress/exabgp:latest version
docker run --rm --entrypoint sh vyos-stress:1.5.0 -c 'dpkg-query -W -f="\${Version}\n" frr'
```

---

## 5. Generate a lab

```bash
make generate PROFILE=t0-smoke VYOS_IMAGE=vyos-stress:1.5.0
```

`VYOS_IMAGE` overrides `dut.image`, so one profile works across several VyOS
releases without editing it. **You usually do not need it**: if the declared image
is not present locally and exactly one `vyos-stress:*` image is, `generate`
resolves to that one and says so. `build-image.sh` also tags `:latest` alongside
the version-derived tag, so a freshly built image matches the profile default
anyway.

Two cases where it will not guess:

* **several candidates** — it refuses and lists them. Which VyOS release is under
  test is one of the two variables that most affects the result, so silently
  picking one would be worse than stopping.
* **none built** — it keeps the declared tag, so the missing-image message names
  what the profile actually asked for.

The generator always echoes the image it resolved, so you cannot silently run the
wrong one:

```
generated build/t0-smoke
  DUT image  : vyos-stress:1.5.1
  image note : DUT image 'vyos-stress:latest' is not present locally; using the
               only VyOS image that is: 'vyos-stress:1.5.1'. Pass VYOS_IMAGE=...
               to choose explicitly, or set dut.image in the profile.
  images     : all 3 present locally
  sessions   : 5 across 4 containers
```

Equivalent forms: `--dut-image vyos-stress:1.5.0` on `harness.generate`, or the
`VYOS_IMAGE` environment variable.

This renders everything from `profiles/t0-smoke.yaml`:

```
build/t0-smoke/
├── topology.clab.yml       containerlab topology
├── fabrics.sh              creates the host bridges
├── prepare.sh              addresses the peer containers
├── inventory.json          the expanded session list
├── dut/
│   ├── 00-base.conf        NE-1849 with placeholders filled + lab-safety edits
│   ├── 10-neighbors.conf   generated neighbour stanzas
│   ├── 20-instrument.conf  optional measurement knobs
│   ├── churn/*.conf        policy-churn apply/revert pairs
│   └── VERIFY-ON-IMAGE.md  release-dependent commands to confirm
├── gobgp/<container>/*.toml
├── exabgp/*.conf + run/
└── mrt/<session>.mrt       the table each peer injects
```

Validate everything offline before deploying anything:

```bash
make selftest-fast            # t0-smoke only, ~20 s
make selftest                 # all five profiles, ~4 min
make selftest STRICT=1        # CI: a skipped check counts as a failure
```

It checks module imports, ASN and address collisions, containerlab kind
constraints (eth0 reserved, `eth[1-9][0-9]*`, 15-char host veth names), MRT
structure, ExaBGP config and route-statement validity, GoBGP TOML structure, and
DUT config consistency — including that a management path survives the template's
`default-action drop`.

`make selftest` takes about four minutes because it generates and validates the
MRT tables for every tier, and `t2`/`t4` are ~2M paths each. That is expected, not
a hang. Use `selftest-fast` in the edit-test loop.

### Skips are not failures

Two verification tools are optional, and both changed interface between major
versions in ways that are silent:

| Tool | Preferred | Also supported | Consequence if older |
|---|---|---|---|
| ExaBGP | 5.x (`exabgp validate -n\|-r`) | 4.2+ (`exabgp --test`) | 4.x has no route-reparse mode and rejects AS_SET / hand-encoded AS_PATH syntax, so 3 malformed-attribute cases are skipped |
| mrtparse | 2.1+ (`entry.data`) | 1.x (`entry.mrt`) | 2.0.x is unsupported and gets skipped |

The selftest detects what is installed, adapts, and prints a tooling banner first:

```
== verification tooling
  python    : 3.13.5
  exabgp    : 4.2.25 (flag CLI) at /usr/bin/exabgp
              note: 4.x works, but 5.x separates neighbour (-n) from
              route (-r) validation. `pip install 'exabgp>=5'` for both.
  mrtparse  : 1.8 (API 1.x, payload on entry.mrt)
  mrtcheck  : built in, no dependencies — always runs
```

When a tool is absent or its API is unrecognised, the affected check is
**skipped, not failed** — a missing verification library says nothing about
whether the generated lab is correct. Only artefact defects affect the exit
status, unless you pass `STRICT=1`.

MRT structural validation is dependency-free (`tests/mrtcheck.py`) and always
runs. It verifies exactly the self-consistency `gobgp mrt inject` relies on:
record lengths tiling the file with no truncation or trailing bytes, attribute
TLV walks consuming exactly their declared length, and peer indices resolving to
the peer index table. You can run it directly:

```bash
make mrtcheck PROFILE=t0-smoke
# ok  build/t0-smoke/mrt/ixp1-rs-0000.mrt: 1401 records, 2 peer(s),
#     1000 v4 + 400 v6 prefixes, 1400 RIB entries
```

To get the full optional coverage:

```bash
pip install 'exabgp>=5' 'mrtparse>=2.1'
```

### Two lab-safety edits the generator makes, and why

**The management VRF is skipped** (`dut.mgmt_vrf: false`). Under containerlab
`eth0` *is* the management interface containerlab addresses and the harness drives.
Moving it into `vrf management` and relocating sshd fights the orchestrator, and
the template's own Section 9 warns "YOU MAY LOSE SSH ACCESS". The skipped lines are
left in the file as comments.

**An explicit accept on `eth0` is added.** The template sets
`firewall ipv4 input filter default-action drop` and its only management accept
matches `inbound-interface name 'management'` — the VRF. With the VRF skipped that
rule never matches and the first `commit` would lock you out.

### Address space, and why these values

| Purpose | Value | Reason |
|---|---|---|
| IXP-1 / IXP-2 peering LANs | `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8:{1,2}::/64` | RFC 5737 / RFC 3849. These appear in the template's bogon lists, which is fine — those lists match NLRI, never next-hops. |
| Own space v4 | `100.64.0.0/16` | RFC 6598, and **not** in the template's `ipv4-bogons` (see FINDINGS #8). |
| Own space v6 | `3fff:100::/32` | RFC 9637 documentation space, and **not** in `ipv6-bogons` (FINDINGS #7). |
| Synthetic NLRI v4 | `/24`s from non-bogon `/8`s | passes `ipv4-acceptable` |
| Synthetic NLRI v6 | `/48`s from `3fff::/20` | passes `ipv6-acceptable` |
| DUT ASN | 64000 | outside every `asn-bogons` range |
| Peer ASNs | 64001+, spilling to 131072+ | same |

> **If you fix FINDINGS #7 or #8**, the lab's own space starts being filtered.
> Change `own.supernet4` / `own.supernet6` / `nlri.v6_base` in the profile at the
> same time, or every test will measure the filter rather than the router. Probes
> `acceptable-v6-48` and `bogon-v6-doc-rfc9637` will tell you which state you are in.

> **Never use RFC 6996 private ASNs** (64512–65534) anywhere in this lab. The
> template filters them on import *and* export, so the DUT would filter its own
> AS_PATH and advertise nothing. The generator refuses them.

---

## 6. Deploy

```bash
sudo make check-images PROFILE=t0-smoke   # are the three local images built?
sudo make fabrics      PROFILE=t0-smoke   # create br-ixp1 / br-ixp2
sudo make deploy       PROFILE=t0-smoke   # containerlab deploy
sudo make prepare      PROFILE=t0-smoke   # address the peer containers
```

`deploy` depends on `check-images`, so it will stop with an actionable message
rather than letting containerlab ask Docker Hub for an image that only exists on
your disk. Generated topologies pin `image-pull-policy: Never` for the same
reason.

`fabrics.sh` creates the host bridges that back the shared peering LANs —
containerlab's `bridge` kind attaches to a bridge that must already exist. It also
disables IPv6 on them and turns off STP, so the host does not participate in the
exchange, and sets MTU 9000.

`prepare.sh` applies peer addressing with `nsenter` from the host rather than
`docker exec ip addr add`, because containerlab does not document granting
`NET_ADMIN` to `linux`-kind nodes and depending on it would be a guess. It also
creates the VLAN sub-interface for tagged fabrics.

Confirm:

```bash
make status PROFILE=t0-smoke
```

You should see the VyOS and FRR versions, kernel, applied netlink buffer, and a
`procs=0/N` line per peer container. Record the FRR version — `show version` is
the only authoritative source, since VyOS publishes no per-release FRR table.

---

## 7. Configure the DUT

```bash
make config PROFILE=t0-smoke
```

Three commits, each timed:

```
-- 00-base.conf: 681 command(s) ... committed in 24.3s
-- 10-neighbors.conf: 50 command(s) ... committed in 6.1s
-- 20-instrument.conf: 7 command(s) ... committed in 2.4s
```

Configuration is applied over `docker exec` with `vbash` and VyOS's own
`script-template`, not SSH. That is deliberate: the DUT is about to be overloaded,
and an SSH control channel would be the first thing to become unreliable — exactly
when telemetry matters most.

If `20-instrument.conf` fails, read `dut/VERIFY-ON-IMAGE.md`. The likely culprits
are `update-delay` (on the 1.5 docs page but absent from the public 1.5 XML
snapshot), `suppress-fib-pending` (in the XML, undocumented), and the
`frr-exporter collector` subtree (rolling only). Remove the offending block from
the profile's `instrumentation:` section and regenerate.

Note that `set system frr descriptors <n>` needs a routing-daemon restart to take
effect. For a large tier, apply the config and then restart FRR once before
bringing peers up:

```bash
docker exec clab-t2-ixp-realistic-vyos systemctl restart frr
```

---

## 8. Bring up the peers

```bash
make bringup PROFILE=t0-smoke
```

Starts one `gobgpd` per session and one `exabgp` per ExaBGP container, then loads
each session's table with `gobgp mrt inject global`.

MRT injection is used rather than a loop over `gobgp global rib add` because
`mrt inject` streams over `AddPathStream` internally, while the CLI opens a fresh
gRPC connection per prefix. `--only-best` is on by default; on a real dump it is
close to mandatory (one GoBGP issue report measured ~16.8 GiB without it versus
~3 GiB with it for the same 820k-path table, because every collector peer's view
gets loaded). Override with `--all-paths` only if you specifically want that.

### A constraint worth knowing about multipath

VyOS exposes `addpath-tx-all` and `addpath-tx-per-as` but **no ADD-PATH receive**
option. So a single peer cannot deliver multiple paths for the same prefix to this
DUT. Per-prefix path diversity therefore comes from the **contested pool** —
different peers advertising the same NLRI — which is how it works at a real
exchange anyway. `paths_per_prefix` in a profile is left at 1 for this reason; the
MRT writer supports multi-path entries if you enable ADD-PATH receive yourself via
`instrumentation.extra_set_commands`.

---

## 9. First convergence

```bash
make converge PROFILE=t0-smoke
```

```
converged        : True
seconds          : 18.4   (budget 60)
ipv4             : established=5/5 pfxRcd=1,560 tableVersion=1874 ribCount=1489
bgpd             : rss=212.4 MB cpu=8.1% threads=3
```

### How "converged" is decided

There is no flag to read. FRR's own operational definition — the one
`bgp update-delay` uses — is that every configured non-shutdown peer has sent an
explicit or implicit End-of-RIB, where the first keepalive after Established
counts as implicit. Absent that, the harness requires three conditions to hold
together across three consecutive samples:

1. `failedPeers == 0` and the established count matches what was configured.
2. `tableVersion` unchanged.
3. Total `pfxRcd` unchanged.

`tableVersion` is the important one. FRR bumps it on every table change, so a
withdraw-plus-announce pair that leaves the prefix count identical still moves the
version. A prefix-count plateau on its own gives false positives during a
mid-convergence lull.

For a deterministic, bgpd-declared convergence event instead of an inferred
plateau, set `update-delay` in the profile — read-only mode ending *is* bgpd's own
definition of initial convergence:

```yaml
instrumentation:
  update_delay:
    max_delay: 300
    establish_wait: 60
```

`bgpd threads=3` is expected and is the central fact about FRR scaling: main, BGP
I/O, and keepalives. Everything that matters — UPDATE parse, bestpath, update
generation, the zebra handoff — is on main.

### Two commands never to poll

`show bgp <afi> unicast statistics` is a synchronous full-table walk on bgpd's main
thread, measured at over a second on a large table. Polling it competes with UPDATE
processing and can itself push the send queue toward teardown. It is available as a
deliberate one-shot only.

`show bgp ipv4 unicast json` dumps the entire table — gigabytes per sample at a
million prefixes. `tableVersion` from the summary gives the same settling signal
for free.

---

## 10. Policy correctness under load

```bash
make probe PROFILE=t0-smoke
```

18 policy probes plus a 19-case RFC 7606 malformed-attribute suite, injected from
ExaBGP and asserted against the template's stated intent.

```
probe                      expect  got     verdict
------------------------------------------------------------
bogon-rfc1918              reject  reject  pass
toolong-v4-25              reject  accept  template-defect-confirmed
own-supernet-exact-v4      reject  accept  template-defect-confirmed
ixp-tag-v6                 accept  accept  pass
...

RFC 7606 suite: session established afterwards = True

confirmed template defects : 5
unexplained probe failures : 0
```

Two categories, and the distinction matters:

* **`template-defect-confirmed`** — the probe failed *and* the reason was predicted
  from reading the config. These validate `FINDINGS.md` on your actual build.
* **unexplained failure** — the probe failed for a reason not accounted for. This is
  the interesting output; investigate before trusting anything else.

The RFC 7606 suite's primary assertion is that **the session survives**. RFC 7606
exists to replace "reset on any attribute error" with attribute discard and
treat-as-withdraw. The one case where a reset is arguably conformant is
`unknown-wellknown-attr` (an unrecognised attribute claiming well-known status),
where RFC 4271 mandates a NOTIFICATION — the suite records which behaviour FRR picks
rather than asserting one.

### What the suite cannot cover

ExaBGP re-decodes any *known* attribute code passed to `attribute [ ... ]`, so it
cannot emit a known attribute with an invalid length or an out-of-range value —
those are rejected at config-parse time (verified with `exabgp validate -r`). Seven
such cases are documented in `policyprobe.NOT_ACHIEVABLE_WITH_EXABGP` and appear in
the report, including invalid `ORIGIN`, malformed `MED` length, and duplicate
attributes. Covering them needs raw packet injection — a scapy-based speaker or a
patched ExaBGP. They are listed rather than silently skipped so the coverage gap is
visible.

---

## 11. Run the chaos schedule

```bash
make run PROFILE=t2-ixp-realistic
```

Warms up, converges, then runs the weighted event mix for `duration_s`, sampling
throughout, checking predicates after every event, and finally re-converging and
re-probing.

```
== warmup / initial convergence (up to 840s)
   converged=True in 412.7s
== chaos for 3600s
   [    12s] peer_flap            18.3s  #1
   [    47s] churn                 9.1s  #2
   [    93s] policy_churn         41.6s  #3
   [   140s] blackhole_peer      225.0s  #4
   !! [warn] sendq_stuck_warn: bgpd made no send-queue progress for one holdtime
   ...
== post-chaos re-convergence
   converged=True in 168.2s
== final policy check
```

The run is reproducible: same profile plus same `scenario.seed` replays the same
events at the same offsets. Change the seed to get a different mix at the same
statistical shape.

Useful flags:

```bash
python -m harness.runner --build build/t2-ixp-realistic run \
    --duration 7200 --stop-on-violation
python -m harness.runner --build build/t2-ixp-realistic --dry-run run   # log only
```

---

## 12. Find the limit

```bash
make ramp PROFILE=t4-breakit
```

Ramp mode scales in waves **without redeploying**: sessions start in batches, and
the per-session prefix count rises each step by injecting progressively more of
each MRT table. After every step the table must re-converge inside budget with no
failing predicate. The first step that fails is the answer.

```
== step 7: 105 session(s), prefix cap 280,000/session
   converged=True in 386.2s
   bgpd rss=18422.1 MB cpu=99.4% zebra rss=2140.8 MB
== step 8: 120 session(s), prefix cap 320,000/session
   !! LIMIT REACHED
      [fail] sendq_stuck_proper: bgpd terminated a session after 2x holdtime ...

======================================================================
verdict: predicate-failed after 8 step(s)
last step within budget: 105 sessions, 1,284,113 v4 paths received,
converged in 386.2s, bgpd RSS 18422 MB
```

`t4-breakit` sets `allow_sendq_warn: false` on purpose. A SENDQ *warning* is the
earliest honest signal that the main thread cannot keep up; stopping there gives a
defensible limit rather than one measured past the point of self-inflicted session
teardown.

Which predicate tripped is the more useful half of the result:

| Predicate | Bottleneck | Next move |
|---|---|---|
| `sendq_stuck_proper` / `_warn` | bgpd main thread | Nothing on this box — it is single-threaded. Reduce paths, lengthen holdtime, or split across routers. |
| `bgpd_rss_exceeded` | memory | More RAM; drop `soft-reconfiguration inbound` on high-volume peers; check for the 8.4–9.1 large-community leaks. |
| `dplane_queue_saturated` / `dplane_route_errors` | kernel FIB install | `zebra dplane limit`; check `net.ipv6.route.max_size` if kernel < 6.3. |
| `failed_peers_*` | holdtime expiry | Compare against the peers' timers; look for a main-thread stall just before. |
| `netlink_overrun` | zebra netlink socket | Check the *applied* buffer via `show zebra`, not the sysctl. |
| commit timeout | config plane | The router became unmanageable before BGP broke — arguably the more serious limit. |
| `bgpd_restarted` | crash or watchdog | Collect a core; check `journalctl` for asserts. |

Tighten `budgets:` to turn ramp mode into a regression gate for a specific build.

---

## 13. Reading the results

```bash
make report PROFILE=t2-ixp-realistic
```

Writes `report.md` and `timeseries.csv` into the newest results directory.

```
build/t2-ixp-realistic/results/20260810T143512/
├── samples.jsonl     raw telemetry + the event timeline, one JSON object per line
├── timeseries.csv    flattened, for plotting
├── run.json          metadata, events, violations
├── probes.json       policy + RFC 7606 results
└── report.md         the readable summary
```

### Interpretation rules the report applies

**Peak `pfxRcd` is not capacity.** It is what arrived. A run that received 1.2M
paths but missed the convergence budget did not demonstrate 1.2M-path capability.
The report separates "carried" from "carried within budget".

**`tableVersion` movement with flat `pfxRcd` is real work.** Attribute churn and
bestpath thrash do not change prefix counts. Reporting only prefix counts hides the
most expensive kind of churn.

**`show memory` is not RSS.** FRR's accounting is `count × sizeof(struct)` and
excludes allocator overhead. RSS from `/proc` is used for memory verdicts.
Bytes-per-path is computed from RSS deltas and explicitly labelled an estimate —
FRR interns attributes, AS_PATHs and communities, so the marginal cost of a path
depends on how much it shares with paths already held. This is also why synthetic
NLRI overstates memory per path relative to a real table, and why `t3-fulltable`
exists.

**Sustained bgpd CPU ≥ 95% is a ceiling, not a load level.** The report counts
those samples. More cores will not help.

Quick plot:

```bash
python3 - <<'EOF'
import csv, sys
rows=list(csv.DictReader(open('timeseries.csv')))
for r in rows[::20]:
    n=int((int(r['v4_pfx_rcd'] or 0))/25000)
    print(f"{float(r['t']):7.0f}s {r['v4_pfx_rcd']:>9} {'#'*n} rss={r['bgpd_rss_mb']}")
EOF
```

---

## 14. The scenario catalogue

Configured under `scenario.events` as a weighted mix. Every entry accepts the
keyword arguments of its handler in `harness/scenarios.py`.

### Session churn

| Event | What it exercises |
|---|---|
| `peer_flap mode=admin_down` | clean teardown and full re-advertisement |
| `peer_flap mode=notification` | Cease NOTIFICATION, Administrative Shutdown subcode, RFC 8203 shutdown communication |
| `peer_flap mode=softreset_in` | route refresh against the DUT's `soft-reconfiguration inbound` |
| `peer_flap mode=link_down` | interface-down path, ARP/ND flush, next-hop invalidation |
| `blackhole_peer` | **the send-queue teardown path.** Silently drops port 179 in the peer's netns, so the DUT keeps queueing UPDATEs to a peer that never reads. Expect `SENDQ_STUCK_WARN` at one holdtime and teardown at two. |
| `gr_event mode=process_kill` | SIGINT to gobgpd, which exits *without* NOTIFICATION → the DUT should enter GR helper mode |
| `gr_event mode=process_term` | SIGTERM, which *does* notify → GR must not engage. Running both and diffing is how you confirm GR works rather than assuming it. |

### RIB churn

| Event | What it exercises |
|---|---|
| `churn mode=flap_same` | withdraw then re-announce the same prefixes |
| `churn mode=walk` | announce fresh NLRI, withdraw older — stable table size, every prefix new. Worst case for the nexthop cache and update-group churn. |
| `churn mode=attr_churn` | same NLRI, different MED and large-community. Prefix count never moves, so this isolates bestpath and update-group cost from RIB size. |
| `churn mode=withdraw_storm` | mass withdrawal. An FRR maintainer comment records this path taking "40+ seconds" of main-thread CPU at scale. |

### Operator activity

| Event | What it exercises |
|---|---|
| `policy_churn` | applies and reverts a config fragment, timing both commits |
| `soft_clear` | `clear bgp ... soft in` — re-runs import policy against the stored Adj-RIB-In |
| `maxprefix_trip` | squeezes `maximum-prefix` below the offered table, then restores. Verifies teardown *and* recovery. VyOS offers no `warning-only`, so teardown is the only behaviour available. |
| `dut_bgpd_restart` | the DUT's own restart path, including `update-delay`. Also checks the config survived, given the documented "FRRouting Configuration Loss on Abnormal Service Restart" issue class. |

The seven shipped policy fragments (`dut/churn/`):

| Fragment | Effect |
|---|---|
| `prefixlist-grow` | adds then removes 64 prefix-list entries |
| `localpref-flip` | changes local-pref on all IXP-1 imports — bestpath moves for every prefix learned there |
| `export-tighten` | denies part of own space outbound, forcing re-advertisement to every peer |
| `aspath-filter` | adds a transient AS-path deny on the import path |
| `community-retag` | changes a large-community on every imported route without changing prefix count |
| `pg-routemap-swap` | swaps a peer-group's entire import route-map — the heaviest, since every member changes at once |
| `maxprefix-squeeze` | drives peers past their limit |

### Environment and correctness

| Event | What it exercises |
|---|---|
| `netem` | delay, jitter, loss on the peering LAN. Loss produces a *different* failure shape from CPU saturation — TCP retransmits stall the UPDATE stream — and the two are easy to confuse. |
| `probe_check` | asserts the policy pipeline is still correct, under load |
| `malformed_burst` | the RFC 7606 suite mid-chaos |

### Writing your own

```yaml
scenario:
  min_gap_s: 5
  max_gap_s: 45
  events:
    - {kind: peer_flap, weight: 20, mode: admin_down, count: 3, down_s: [5, 45]}
    - {kind: churn, weight: 15, mode: attr_churn, fraction: 0.4, count: 2}
    - {kind: policy_churn, weight: 10, hold_s: 30, fragments: [pg-routemap-swap]}
```

To isolate one mechanism, run a single-event scenario: one `blackhole_peer` at
weight 1 with everything else removed tells you the send-queue threshold cleanly.

---

## 15. Known failure modes and what they mean

### bgpd kills its own sessions — the one to expect first

FRR tears a session down when its send queue makes no progress for `2 × holdtime`:

```c
sendholdtime = holdtime * 2;
...
} else if (delta > sendholdtime) {
        flog_err(EC_BGP_SENDQ_STUCK_PROPER,
                 "%pBP has not made any SendQ progress for 2 holdtimes ...");
```

That threshold is **hardcoded and not configurable**, and it appears nowhere in the
FRR user documentation — only in the error reference. Combined with a main thread
that an in-tree comment admits could take "40+ seconds" during withdrawal storms,
this is the classic meltdown loop: churn saturates main → send queue stalls →
sessions dropped → more churn.

Practical consequences:

* Aggressive datacenter-style timers make this **worse**, not better. `timers 3 9`
  gives an 18-second budget; the shipped profiles use 30/90 for a reason.
* `sendq_stuck_warn` is your ceiling indicator. The last configuration without it
  is the defensible limit.

### zebra restarts itself on netlink overrun

`EC_ZEBRA_RECVMSG_OVERRUN`: "The kernel's buffer for a socket has been overrun,
rendering the socket invalid… Zebra will restart itself." Check the *applied*
buffer via `show zebra`, since zebra's 4 MiB default is set with `SO_RCVBUFFORCE`
and bypasses `net.core.rmem_max`. `net.ipv6.route.skip_notify_on_dev_down=1`
(set by `host-tune.sh`) reduces the notification storm on interface-down, which is
the usual trigger.

### FIB install lags the control plane

`show zebra dplane` exposes `Route update queue limit` (default 200), `queue max`,
`updates skipped` and `Dplane update yields`. If `queue max` sits at the limit,
routes are being selected faster than the kernel accepts them, and the RIB and FIB
disagree during that window. `bgp suppress-fib-pending` closes the correctness gap
at the cost of a zebra round-trip plus a default 1000 ms batching window on every
advertisement — worth measuring both ways.

### maximum-prefix teardown is unrecoverable without an operator

VyOS's `maximum-prefix` is a bare limit with no `warning-only`, `restart` or
`threshold` sub-option. Trip it and the session stays down until someone raises the
limit or resets it. With `ixp{1,2}-peer{4,6}` at 200 in the template, a peer that
grows past 200 prefixes drops out permanently. See FINDINGS #9.

### Graceful restart is thinner than FRR's

VyOS exposes only `graceful-restart` and `graceful-restart stalepath-time`. FRR's
`restart-time`, `select-defer-time`, `rib-stale-time`, `preserve-fw-state` and
long-lived GR are **not** surfaced, so FRR's defaults apply: `select-defer-time`
120 s, `rib-stale-time` 500 s, `stalepath-time` 360 s.

At high path counts `select-defer-time` is the risk. It is the RFC 4724 Route
Selection Deferral Timer: the restarting speaker defers bestpath until every peer
sends EOR or the timer fires — and when it fires, the **entire deferred bestpath
computation lands on the single main thread at once**, which is exactly the
condition that triggers `SENDQ_STUCK_*`. `rib-stale-time` 500 s also means stale
paths coexist with new ones for up to eight minutes, roughly doubling peak
`bgp_path_info` residency.

FRR is also restarter-only for long-lived GR — it cannot act as an LLGR *helper*.

### Memory

No official FRR figure exists for memory per path or per prefix. Note two things:
`soft-reconfiguration inbound` (set on every peer-group in the template) adds a
full Adj-RIB-In per peer, and FRR had large-community memory leaks in 8.4 through
9.1 (issues 14828, 15459) — worth watching RSS across repeated announce/withdraw
cycles if your image is in that range. Avoid FRR 8.4–8.5 for full-table work: the
extended-message support shipped in 8.4 increased memory significantly and was
fixed in 9.0.

---

## 16. Tuning knobs worth sweeping

Run the same tier repeatedly, changing one knob, and diff `report.md`. In rough
order of expected effect:

| Knob | Where | Hypothesis |
|---|---|---|
| holdtime 30/90 → 60/180 | fleet `timers` | Doubles the send-queue budget before teardown; should raise the ceiling measurably |
| `update_delay` | `instrumentation` | Batches initial convergence into one bestpath pass instead of many |
| `suppress_fib_pending` | `instrumentation` | Removes the RIB/FIB gap; costs 1000 ms per advertisement by default |
| `frr_profile: datacenter` | `instrumentation` | Faster convergence timers — may *lower* the ceiling by shortening the sendhold budget |
| `soft-reconfiguration inbound` off on RS peers | `dut/00-base.conf` | Should cut bgpd RSS substantially; costs the ability to `soft in` |
| `input_queue_limit` / `output_queue_limit` | `instrumentation` | Defaults are 10000; raising trades memory for burst tolerance |
| `zebra dplane limit` | vtysh | Only matters if the dataplane queue is saturating |
| `contested_fraction` | `nlri` | More contention = more bestpath work at the same path count. Isolates bestpath cost from RIB size. |
| `--only-best` off | `bringup --all-paths` | Much higher generator memory; changes what the DUT is offered |

One knob at a time, and re-run `make probe` after each — a change that improves
convergence while breaking filtering is not an improvement.

---

## 17. Troubleshooting

**`pull access denied for vyos-stress, repository does not exist or may require
'docker login'` on deploy.** This is not an authentication problem. All three
images are built locally and published nowhere, so a missing local image made
containerlab ask Docker Hub. Generated topologies now pin
`image-pull-policy: Never` (schema-confirmed in containerlab's `node-config`), so
you get a plain "not available locally" instead. Diagnose with:

```bash
sudo make check-images PROFILE=t0-smoke
```

It lists every image the topology needs, marks the missing ones, and prints the
build command plus the vyos-stress tags you actually have. The usual cause is a
tag mismatch: `build-image.sh` derives the tag from the ISO filename, so an ISO
named `vyos-1.5.1-generic-amd64.iso` produces `vyos-stress:1.5.1`, while the
profiles default to `vyos-stress:latest`.

`generate` now resolves that automatically, so the fix is simply to regenerate:

```bash
sudo make generate PROFILE=t0-smoke
```

`check-images` detects this specific case and distinguishes "not built" from
"built under a different tag", printing all three ways out — regenerate, name the
tag explicitly, or `docker tag` it. Newly built images are tagged `:latest` too,
so this cannot recur for images built from now on.

`make deploy` now depends on `check-images`, so it stops before containerlab runs.

**`permission denied while trying to connect to the Docker daemon socket`.** The
harness drives the lab through `docker exec`. It auto-detects whether plain
`docker` works and falls back to `sudo -n docker`, so `make status` will tell you
which form it is using. If neither works, either add yourself to the docker group
(`sudo usermod -aG docker $USER` then `newgrp docker`) or run the targets under
`sudo`. Running some steps as your user and others under `sudo` is fine — the
daemon state is shared — but be consistent about `generate`, or `build/` ends up
owned by root and later runs cannot rewrite it.

**Nodes fail to start, `Too many open files`.** inotify. Raise
`fs.inotify.max_user_instances`; `host-tune.sh` uses `nodes × 1250`.

**VyOS node never becomes healthy.** Check Docker IPv6 is enabled, and that
`/lib/modules` exists for the running kernel. `docker logs <container>` then
`docker exec <container> systemctl --failed`.

**Sessions stay in Active/Connect.** In order: is the peer address on the right
interface (`prepare.sh` output)? Is the peering LAN in `bgp_speakers4`/`6` (the
generator adds it, `make selftest` asserts it)? Did the firewall commit before the
neighbours? On a tagged fabric, does the peer have the VLAN sub-interface?

```bash
docker exec clab-<lab>-vyos vtysh -c 'show bgp ipv4 unicast summary'
docker exec clab-<lab>-<peer> gobgp -p 50051 neighbor
docker exec clab-<lab>-<peer> tcpdump -ni eth1 tcp port 179 -c 20
```

**Sessions establish but no prefixes arrive.** Almost always policy. Check
`show bgp ipv4 unicast neighbors <peer> received-routes` versus `routes`, and
remember from FINDINGS #2 that a private ASN anywhere in AS_PATH is filtered.
`make probe` will localise it.

**`make config` locks you out.** You enabled `mgmt_vrf`. Recover with
`docker exec -it <container> su - admin`, then
`configure; delete service ssh vrf; delete interfaces ethernet eth0 vrf; commit`.

**Commit times climb through a run.** Expected as the table grows, and itself a
result — that is `policy-change commit latency` in the report. If commits stop
returning, the config plane is the limit you found.

**`bringup` reports fewer processes started than expected, or 0 MRT tables
loaded.** Run `make status` — it now prints `procs=N/expected` per container and
flags any shortfall. `bringup` also prints the tail of the failing generator's own
log (`/var/log/gobgpd-<sid>.log`, `/var/log/exabgp.log`) and exits non-zero rather
than continuing, so the first useful evidence is on screen immediately.

If `gobgpd` starts and immediately dies, the log usually names the reason: a
peering address not yet configured on the container (re-run `make prepare`), a
gRPC port already bound (another gobgpd survived a previous run — `make teardown`),
or a TOML key the installed GoBGP does not recognise.

**`gobgp mrt inject` fails with `invalid nexthop: invalid IP`, 0 tables loaded.**
Fixed in the writer; if you see it, your `build/<profile>/mrt/*.mrt` predate the
fix — just `make generate` again. Root cause, for the record: inside
TABLE_DUMP_V2, RFC 6396 section 4.3.4 reduces the MP_REACH_NLRI body to *only*
the Next Hop Address Length and the Next Hop Address — AFI, SAFI, the Reserved
octet and the NLRI are all omitted, because the MRT record header already carries
them. The writer originally emitted the full RFC 4760 body, so GoBGP read the
AFI's high byte (`0x00`) as the next-hop length, got a zero-length next hop, and
`netip.Addr`'s zero value stringifies as exactly `invalid IP`. Because that aborts
the gRPC stream, not one prefix loads. `tests/mrtcheck.py` now enforces the
RFC 6396 layout, so this cannot recur silently.

Worth knowing: mrtparse accepts *both* encodings, so the independent cross-check
agreed with the bug. Only GoBGP — correctly — rejected it. A cross-check is only
as good as the strictest reader in the set.

**`exabgp` dies at startup with `configparser.MissingSectionHeaderError`.** Fixed
in the image; rebuild with `make images`. ExaBGP's `--env-file` is INI parsed by
Python's `configparser`, not a flat `key=value` file, so a bare line like
`exabgp.daemon.user=root` is fatal. The Dockerfile now writes proper sections
(taken from `exabgp env`, which dumps the authoritative defaults in that format)
and validates the file at **build** time with `exabgp --env-file ... env -d`, so a
format error fails the build rather than the run. Note that unknown *keys* are
silently ignored by ExaBGP, so that gate covers format only.

**Generators eat the host.** Each `gobgpd` is started with `--cpus 1` to keep the
harness out of the DUT's way. Cap containers with `memory:` / `cpu:` in the fleet
definition. If the host is the bottleneck rather than the DUT, the numbers are
meaningless — watch host idle CPU in `report.md`.

**MRT injection is slow.** Expected for large tables; it is a single gRPC stream.
Verify a file independently:

```bash
python3 -c "from mrtparse import Reader; print(sum(1 for _ in Reader('build/t2-ixp-realistic/mrt/ixp1-rs-0000.mrt')))"
```

**ExaBGP session stalls.** The helper must drain ExaBGP's ACK stream; if it does
not, the pipe fills and the session hangs in a way that looks exactly like a DUT
fault. Check `docker exec <c> tail /run/exabgp-helper.log`.

---

## 18. What this harness cannot tell you

Stated plainly so results are not over-claimed:

* **It does not test forwarding.** Everything here is control plane. A converged
  RIB and an installed FIB are not proof that packets flow at rate. Add a traffic
  generator for that.
* **Container networking is not silicon.** veth pairs and Linux bridges have
  different latency, loss and interrupt behaviour from real NICs on real fabric.
  Control-plane conclusions transfer reasonably; anything touching NIC drivers,
  offload or PPS does not.
* **Synthetic NLRI overstates memory per path.** Real tables share AS_PATHs and
  communities heavily and FRR interns all three. Use `t3-fulltable` with a real
  MRT dump for numbers you want to publish.
* **Seven RFC 7606 cases are untested** because ExaBGP cannot emit them. They are
  listed in the report rather than silently omitted.
* **Results are specific to one build and one host.** FRR is single-threaded on the
  update path, so the ceiling tracks single-core performance more than core count.
  Record `show version frr`, `uname -r`, and the host CPU with every result.
* **No VyOS system was available while this harness was written.** Every VyOS CLI
  command was checked against docs.vyos.io or the `vyos-1x` interface definitions,
  and release-dependent ones are listed in `dut/VERIFY-ON-IMAGE.md` — but the first
  `make config` on your image is the real test. Generated ExaBGP configs and MRT
  files *were* verified with `exabgp validate` and `mrtparse`.

---

## Quick reference

```bash
make preflight                              # can this host run it
sudo make host-tune NODES=60                # sysctls, ulimits
make vyos-image ISO=/path/to/vyos-1.5.0-....iso  # build the DUT image from your ISO
make images                                 # build peer images
make generate  PROFILE=t2-ixp-realistic VYOS_IMAGE=vyos-stress:1.5.0  # render the lab
make selftest                               # validate offline
sudo make fabrics PROFILE=t2-ixp-realistic  # host bridges
sudo make deploy  PROFILE=t2-ixp-realistic  # containerlab deploy
sudo make prepare PROFILE=t2-ixp-realistic  # address peers
make config    PROFILE=t2-ixp-realistic     # push NE-1849 config
make bringup   PROFILE=t2-ixp-realistic     # start generators, load tables
make converge  PROFILE=t2-ixp-realistic     # initial convergence
make probe     PROFILE=t2-ixp-realistic     # policy correctness
make run       PROFILE=t2-ixp-realistic     # chaos schedule
make ramp      PROFILE=t4-breakit           # find the limit
make report    PROFILE=t2-ixp-realistic     # readable summary
make teardown  PROFILE=t2-ixp-realistic     # stop generators
sudo make destroy PROFILE=t2-ixp-realistic  # remove the lab
```
