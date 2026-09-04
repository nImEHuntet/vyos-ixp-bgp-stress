# VyOS IXP BGP stress harness

A containerlab harness that peers a single VyOS router with **154 simulated BGP
sessions** carrying **4.8 million paths**, then subjects it to two hours of the
churn a real internet exchange produces — session flaps, prefix withdrawal
storms, attribute rewrites, route-server resets, link impairment, policy changes
under load — and records what the control plane does about it.

It exists to answer one operational question: *at full table, does a VyOS router
peered with Tier-1 transits and IXP route servers keep forwarding, or does it
cause an outage?*

The answer, over four runs, is in **[FINDINGS.md](FINDINGS.md)** and summarised
for upstream maintainers in **[REPORT.md](REPORT.md)**.

> This is a measurement instrument, not a benchmark. It is designed to be
> distrusted: roughly two thirds of the defects it found in four runs were in
> the harness itself, and each one is written up alongside how it was caught.
> Read [FINDINGS.md](FINDINGS.md) before quoting a number from it.

## What it measures

| | |
|---|---|
| **Convergence** | cold start decomposed into read-only hold, bestpath+FIB, and advertisement — from FRR's own `update-delay` timestamps |
| **FIB completeness** | zebra's `show ip route summary`, not an inferred counter. Traffic follows the FIB |
| **Flap recovery** | time from session down to full re-advertisement, per flap |
| **Policy commit latency** | a single `set` on a peer-group, apply and revert separated |
| **Resource envelope** | bgpd/zebra RSS and CPU, container memory, dataplane queue depth, bytes-per-path |
| **Failure signatures** | 24 patterns validated against FRR 10.5.2 source — send-queue stalls, CPU starvation, hold-timer expiry, watchdog kills, netlink overrun |
| **Peer-side truth** | every generator's TCP state read from `/proc`, so a stuck session can be attributed to the DUT or the lab rather than guessed at |

## Requirements

* Linux host, root, **≥ 62 GiB RAM** and ≥ 16 cores for the `t3-fulltable`
  profile (measured: 21 GiB for the DUT container, 33 GiB for the peer fleet)
* Docker and [containerlab](https://containerlab.dev/)
* Python 3.11+ (`pip install -r requirements.txt`)
* A VyOS ISO you are licensed to use, for `make vyos-image`

`make preflight` checks the host before you commit three hours to a run.

## Quick start

```bash
make preflight
make vyos-image ISO=/path/to/vyos-1.5.1-generic-amd64.iso
make images                                    # GoBGP + ExaBGP peer images
make generate  PROFILE=t0-smoke VYOS_IMAGE=vyos-stress:1.5.1
make selftest  > selftest.txt 2>&1             # 782 offline checks
sudo make fabrics deploy prepare PROFILE=t0-smoke
make config bringup converge PROFILE=t0-smoke
```

`t0-smoke` is a few thousand prefixes and comes up in under a minute. Use it to
prove the plumbing before starting `t3-fulltable`.

## A full T3 run

Three hours. Run it in `tmux` — an SSH drop mid-run loses the whole thing.

```bash
sudo make destroy   PROFILE=t3-fulltable
sudo make host-tune NODES=30                   # sysctls, fd limits, swappiness=1
sudo make generate  PROFILE=t3-fulltable
sudo make fabrics deploy prepare config bringup PROFILE=t3-fulltable

sudo make converge PROFILE=t3-fulltable
sudo make peers    PROFILE=t3-fulltable PEERS_DIR=build/t3-fulltable/results/peers-baseline
sudo make probe    PROFILE=t3-fulltable

tmux new -s t3
  sudo make monitor PROFILE=t3-fulltable       # host memory/stall recorder
  sudo make run     PROFILE=t3-fulltable       # ~2-3 h
  sudo make monitor-stop

sudo make peers   PROFILE=t3-fulltable         # the drift breakdown
sudo make report  PROFILE=t3-fulltable
sudo make collect PROFILE=t3-fulltable         # BEFORE destroy — reads live containers
```

`make run` exits **3** when the verdict is FAIL. That is not a crash: `0` means
no failing predicate, `3` means the run completed and something tripped, `1`
means the harness itself broke.

`make collect` bundles everything an analysis needs into one tarball — results,
the DUT's full journal, its running config, final `show` output, host metrics,
container inventory — and names anything missing so you find out before you send
it rather than after.

## Profiles

| profile | sessions | paths | purpose |
|---|---|---|---|
| `t0-smoke` | 6 | ~5 k | pre-flight; proves the plumbing in a minute |
| `t3-fulltable` | 154 | **4,804,920** | the flagship: 2 transits, 3 route servers, 25 bilateral majors, 120 tail peers, 4 misbehaving peers across two IXP fabrics (one untagged, one VLAN 200) |

`t1`, `t2` and `t4` are earlier tiers kept for differencing memory between
scales; `t3` is the one that produced every result in FINDINGS.md.

## Layout

```
harness/       the instrument
  dut.py         VyOS/FRR driver: vtysh, /proc, journal, config commits
  peers.py       GoBGP + ExaBGP fleets, impairments, peer-side socket forensics
  telemetry.py   sampler, convergence tracker, predicate set
  runner.py      the commands: config bringup converge exercise run ramp peers probe
  scenarios.py   the event catalogue — flaps, churn, policy, blackhole, netem, GR
  generate.py    renders topology, peer configs, MRT tables and the DUT config
  policyprobe.py RFC 7606 malformed-attribute and policy probes
analysis/      report generation from a results directory
tests/         782 offline checks; no lab required
scripts/       preflight, host tuning, collection, host monitoring
profiles/      the tiers
images/        peer container images and the VyOS image build
```

## The template

`Template IXP VyOS Configuration.md` is the production-shaped IXP configuration
the DUT is built from, with `<PLACEHOLDER_*>` tokens the harness substitutes per
profile. Its `/32` blackhole routes are RFC 5737 documentation addresses —
the original carried a live operational blocklist, replaced before publication.

The harness deliberately does **not** fix the template's defects. Twelve are
documented in FINDINGS.md and five are confirmed by probe on every run; they are
findings about the configuration, and silently correcting them would hide them.

## Reading a result honestly

Three rules the four runs earned the hard way, in order of how much they cost:

1. **A parser is not verified until it has been run against a captured sample of
   the real output.** `show ip route summary` prints `ebgp` and `ibgp`, never
   `bgp`. Assuming otherwise cost a whole run and produced a confident,
   completely wrong headline.
2. **A check that shares the code's assumption is not a check.** A verification
   that looked for addresses on the same wrong interface the repair had written
   them to passed ten times while the lab was broken.
3. **A guard with a path to "pass" that does not involve measuring anything is
   not a guard.** Three separate FIB gates failed this test in three different
   directions.

Every violation the harness reports distinguishes *"the router is in state X"*
from *"I cannot tell what state the router is in"*. The second is reported as a
measurement gap, never as a zero.

## License

MIT — see [LICENSE](LICENSE).
