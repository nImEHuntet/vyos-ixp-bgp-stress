# VyOS 1.5.1 / FRR 10.5.2 under a full IXP table: findings for maintainers

**Prepared by:** VyOS Networks · **Date:** 2026-09-04
**Device under test:** VyOS 1.5.1 (circinus), FRRouting 10.5.2 (vyos), Linux 6.12.101+deb13-amd64
**Scale:** 154 BGP sessions, 4,804,920 paths (4,020,600 IPv4 + 784,320 IPv6), two IXP fabrics
**Host:** 62.3 GiB RAM, 16 vCPU allocated to the DUT container
**Basis:** four complete runs, 2026-09-01 to 2026-09-04, ~2–3.7 hours each

---

## Why this exists, and how to read it

We wanted to know whether a VyOS router peered with Tier-1 transits and IXP
route servers keeps forwarding under realistic churn — or whether it causes an
outage. Not a hostile-peer test: these are the conditions a production edge
router meets every day.

**Every DUT finding below rests on the device's own journal and its own CPU
accounting, reproduced across independent runs.** Where a mechanism is our
hypothesis rather than a measurement, it says so. Where a plausible cause was
excluded, the measurement that excluded it is given.

We also found roughly twice as many defects in our own test harness as in the
device, and three findings were withdrawn after the harness turned out to be
responsible. Those are documented in the project's `FINDINGS.md`. This report
contains only what survived.

## The headline

**A working bgpd is killed by its own supervisor, repeatedly, and the platform
cannot be configured to prevent it.**

Eleven times across four runs, `watchfrr` declared a functioning bgpd
unresponsive and had it killed. No crash, no signal, no assertion in any of the
four journals. The daemon was busy on its single main thread and could not
answer a liveness ping. Outages ranged from **156 s to 572 s** before bgpd was
back up, and the table then needs a further **485 s** to reach forwarding.

The single most valuable change available today is not a code fix: it is
**exposing watchfrr's timeouts in VyOS configuration** (V-1). An operator who
could set `-t 300` on a full-table box would have had zero of these eleven
outages.

---

## Findings

### R-5 — watchfrr kills a working bgpd; 11 occurrences, 0 crashes

| run | # | unresponsive → back up | outage |
|---|---|---|---|
| 2 | 1 | 15:06:32 → 15:09:08 | 156 s |
| 2 | 2 | 15:29:49 → 15:33:11 | 202 s |
| 2 | 3 | 16:36:20 → 16:40:15 | 235 s |
| 3 | 1 | 10:31:18 → 10:34:15 | 177 s |
| 3 | 2 | 11:57:29 → 12:03:34 | 365 s |
| 4 | 1 | 10:47:10 → 10:50:52 | 222 s |
| 4 | 2 | 12:06:58 → 12:13:04 | 366 s |
| 4 | 3 | 12:24:11 → 12:33:43 | **572 s** |

*(runs 2–4 shown; run 1's three kills are in `FINDINGS.md` R-2.)*

```
watchfrr[474]: [T58XM-TP956][EC 268435457] bgpd state -> unresponsive :
               no response yet to ping sent 90 seconds ago
watchfrr[474]: [YFT0P-5Q5YX] Forked background command: /usr/lib/frr/watchfrr.sh restart bgpd
```

Three things worth separating:

1. **The 90 s is not the whole stall.** The log says the ping it is waiting on
   was sent 90 seconds earlier, so the main thread had already been
   unresponsive that much longer. Measured total main-thread stalls: 246 s,
   292 s, 318 s, 325 s, 328 s, 452 s.
2. **The restart path is jammed by the same load.** In every incident,
   `watchfrr.sh restart bgpd` had to be SIGTERM'd —
   `restart bgpd child process … still running after 90 seconds, sending
   signal 15` — and several needed two or three forks before bgpd came up.
3. **Recovery is not free.** R-4 measures 485 s from first session to
   forwarding. Each incident therefore costs 11–14 minutes of a router not
   carrying what it advertises.

Upstream defaults are `-t 10` / `-T 20` ([frr-watchfrr(8)](https://manpages.debian.org/testing/frr/frr-watchfrr.8.en.html)).
VyOS raises both to 90 s — the journal proves the values in effect — and exposes
neither.

### R-9 — ready callbacks wait ~one holdtime on an *idle* bgpd, and it terminates sessions

**The strongest result in the project.** Reproduced in every run where the log
windows were wide enough to see it.

Correlating each `CPU starvation` line against sampled bgpd CPU over the window
it was late across splits them into two populations:

| run | events | bgpd saturated | **bgpd idle** | accumulated lateness in the idle set |
|---|---|---|---|---|
| 2 | 85 | 3 | **7** | — |
| 3 | 88 | 26 | **59** | **2,530 s** |
| 4 | 78 | 27 | **18** | **758 s** |

In the idle set, bgpd used **0.4–0.5 % of one core, max 1.7 %**, for the full
90 s preceding a callback that ran **73.7 s to 90.2 s late**:

```
[EC 100663315] CPU starvation: {(event *)0x… ready (bgp_generate_updgrp_packets)()
  (&connection->t_generate_updgrp_packets) from ../bgpd/bgp_io.c:155}
  getting executed 88354ms late, warning threshold 4000ms. System load: 1.11, 0.99, 1.26
```

**The delay is bounded by the holdtime.** Configured holdtime is 90 s (145
sessions at `holdtime 90 / keepalive 30`, 4 at `holdtime 90`). Across all runs
the worst instance is 90,188 ms — 188 ms over one holdtime, and not one is
materially beyond it.

**It causes session teardowns.** `bgp_generate_updgrp_packets` is among the
delayed events. If it does not run, the send queue does not drain, and FRR's own
watchdog fires:

| run | `SendQ progress for 1 holdtime` | `for 2 holdtimes → terminating session` |
|---|---|---|
| 2 | 365 | **11** |
| 3 | 207 | 0 |
| 4 | 334 | **14** |

Twenty-five healthy BGP sessions terminated by the DUT across two runs, on a
threshold (`sendholdtime = holdtime * 2`, `bgp_packet.c`) that is not
configurable and not in the user documentation. Run 3's zero shows this is a
threshold effect, which makes the one-holdtime warning the ceiling indicator.

**Our hypothesis, offered as a hypothesis:** an event queued to bgpd's main
thread does not wake that thread's `poll()`, so it is dispatched only when the
next *already-scheduled* timer expires. On an otherwise quiet session that timer
is the hold timer, which bounds the delay at one holdtime — and it would be
masked under load, because traffic wakes the loop constantly. Consistent with
the idle instances clustering in quiet phases. **Not verified by us.** Event-loop
tracing, or an `strace` of the main thread across one gap, would settle it
quickly for someone who knows the scheduler.

**Every environmental alternative is excluded by measurement, not argument:**

| | run 3, whole run | run 3, summed across the 59 idle events |
|---|---|---|
| host swap-in | 1,440,121 pages | **41 pages** |
| host major faults | 1,089,807 | **230** |
| PSI memory stalled (full) | 9.6 s | **0.00 s** |
| PSI IO stalled (full) | 17.5 s | **0.09 s** |
| DUT cgroup CPU throttled | **0.00 s** over 2,346 samples | — |
| DUT cgroup memory stalled | **0.00 s** over 2,346 samples | — |

2,530 seconds of event lateness against 0.09 seconds of host stall in the same
windows — a factor of roughly 28,000. The host swapped during the run and is
not the explanation. Container CPU throttling and cgroup memory reclaim are
excluded by direct measurement of the DUT's own cgroup.

### R-10 — bgpd kept terminating sessions for four minutes after SIGTERM

Run 4, incident 2. Every timestamp below is the same pid:

```
12:06:58  bgpd[69020]: Terminating on signal
12:08:28  watchfrr: restart bgpd child process 113547 still running after 90 seconds, sending signal 15
12:10:29  bgpd[69020]: 2001:db8:2::2d(ixp2-bilat-tail-c002) has not made any SendQ
          progress for 2 holdtimes (180s), terminating session
   ... 13 more, all bgpd[69020], through 12:10:53 ...
12:11:02  watchfrr: restart bgpd child process 114609 still running after 90 seconds, sending signal 15
12:13:04  watchfrr: bgpd state -> up : connect succeeded
```

bgpd acknowledged SIGTERM, took **six minutes** to exit, and during that
shutdown **terminated 14 healthy sessions** on the send-queue timer — three and
a half minutes after being told to die. Those sessions would have
re-established against the new process; instead they were dropped with a
NOTIFICATION, adding churn to a recovery already in progress.

### R-6 — the single main thread is the ceiling

| measurement | value |
|---|---|
| bgpd CPU p95 / max | 199.7 % / 202.6 % (4-thread process) |
| samples at ≥ 95 % CPU | 608 of 1,407 (run 4: 49 %) |
| host load during starvation | 0.99 – 2.47 on 16 vCPU |
| bestpath + FIB install, cold | **184–191 s** for 2,445,625 IPv4 routes |
| worst callback lateness | 90,188 ms (threshold 4,000 ms) |

200 % on a four-thread process means the I/O pthreads *are* working: the ceiling
is the main loop, and 14 cores sit idle beside it. FRR maintainers have this on
record — *"There clearly is room for more pthreading to be done … no-one is
working on it that I am aware of"*
([discussion #15033](https://github.com/FRRouting/frr/discussions/15033)).
What that thread lacks is measurements; these are offered as such.

### R-1 — a single `set` on a peer-group takes 5–11 minutes

Measured on a 2.8M-path table: `localpref-flip` apply 311 s;
`pg-routemap-swap` apply 463 s, revert 641 s; `maxprefix-squeeze` apply 552 s,
revert 284 s. At 4.8M paths `localpref-flip` **completed at 663 s** — 110 % of
our 600 s budget, and the first bounded figure rather than a timeout.

A commit that does not return is an operational failure regardless of BGP state:
it means the router cannot be changed while under this load.

### R-4 — cold start: 485 s from first session to forwarding

From FRR's own `update-delay` timestamps:

| phase | duration |
|---|---|
| read-only mode | **300.0 s** — the configured limit *expiring*, not every peer sending End-of-RIB |
| bestpath + FIB install | **184.2 s** for 2,445,625 IPv4 + 479,500 IPv6 routes |
| to advertisement | 0.6 s |
| **total** | **485 s** |

This is the multiplier on every R-5 incident. Note that the limit expired rather
than being satisfied: `show bgp summary` reports that it expired but not *which*
peers failed to send EoR, which would be a useful addition.

### R-7 — after each restart, ~27 peers have their first reconnection reset

Seconds after each bgpd restart, and at no other point in any run:

```
[EC 100663299] bgp_connect_success: bgp_getsockname(): failed for peer 2001:db8:1::3f, fd 33
[EC 33554461] 2001:db8:1::3f: nexthop_set failed, local: [2001:db8:1::1]:179
              remote: [2001:db8:1::3f]:50773 update_if: (None)
              resetting connection - intf (Unknown)
```

57 distinct peers in run 1 (28 IPv6, 29 IPv4), 55 occurrences in run 2.
`intf (Unknown)` means bgpd has not yet received interface state from zebra —
which at that moment is 14 GB resident and reinstalling millions of routes.
Resetting a peer's connection because *our* dependency is not ready amplifies
every restart into a second wave of churn.

### Resource envelope — four consistent measurements

| | run 1 | run 2 | run 3 | run 4 |
|---|---|---|---|---|
| bgpd RSS peak | 8,249 MB | 8,208 MB | 8,208 MB | 8,216 MB |
| **bgpd RSS / path** | **1,800 B** | **1,791 B** | **1,791 B** | **1,793 B** |
| zebra RSS peak | 14,317 MB | — | 10,684 MB | 9,416 MB |
| DUT container peak | 24,594 MB | — | 20,935 MB | 20,536 MB |

bgpd bytes-per-path is reproducible within 0.5 % and is usable for sizing. The
figure is whole-table RSS over paths held, so it includes fixed base cost and
over-states the marginal path — the safe direction.

`zebra dplane` route-update queue reached its 200-entry limit in **all four
runs** (201–202/200), during table load and again during chaos.

---

## Requests, in the order we would prioritise them

Two of these belong to VyOS and are not FRR changes.

### V-1 (VyOS) — expose watchfrr's `--timeout` and `--restart-timeout`

Highest leverage available today; needs no FRR change. Eleven outages of
156–572 s were caused by a 90 s liveness timeout against measured main-thread
stalls of 246–452 s. An operator running 4.8M paths who could set `-t 300`
would have had none of them.

### V-2 (VyOS) — expose `zebra dplane limit` ([T5454](https://vyos.dev/T5454))

The FRR command already exists — *"Configure the limit on the number of pending
updates that are waiting to be processed by the dataplane pthread"*
([zebra docs](https://docs.frrouting.org/en/latest/zebra.html)). The queue hit
its default 200 in every run. T5454 has been in Backlog since October 2024.

We deliberately did **not** work around the missing knob, because a VyOS
operator cannot. Every number here is what VyOS delivers today, not what FRR is
capable of — which is both the caveat and the argument for the ticket.

### F-0 (FRR) — an event queued to bgpd's main thread should wake that thread

See R-9. Seven, fifty-nine and eighteen instances in three runs; delay bounded
by one holdtime; 25 healthy sessions terminated across two runs; every
environmental cause excluded by measurement. The mechanism is ours to
hypothesise and yours to confirm — we have the evidence, not the diagnosis.

### F-6 (FRR) — stop running teardown timers once `bgp_exit` is entered, and bound the shutdown path

See R-10. Two small changes: a bgpd on its way out should not terminate peers on
a send-queue timer, and six minutes to exit a 4.8M-path bgpd should be bounded.
Cheap, verifiable, and it removes a multiplier on every R-5 incident.

### F-2 (FRR) — a failed `bgp_getsockname()` should defer the peer, not reset it

See R-7. Small, self-contained, reproducible on demand. Holding the connection
until zebra answers, or retrying `bgp_nexthop_set`, removes a restart-recovery
amplifier.

### F-1 (FRR) — hold-timer expiry should not charge scheduler latency to the peer

`bgp_holdtime_timer` (`bgp_fsm.c:442`) was measured running 4.1–80 s late, and
FRR already knows the lateness — it prints it. 73–109 hold-timer expiries per
run accompany it. What the right behaviour is when the scheduler owes a callback
80 seconds is yours to decide; we have not read the handler and do not claim it
fails to compensate.

### F-3 (FRR) — watchfrr's liveness ping is answered on the thread most likely to be busy

The structural form of V-1. The health check queries the VTY socket, which bgpd
services on the main loop — precisely the thread that saturates. Two directions:
answer liveness from a thread that is not the main loop (bgpd already has I/O
and keepalive pthreads), or have watchfrr check forward progress (`utime`/`stime`
advancing) before concluding the process is dead.

### F-4 (FRR) — the restart path does not survive a large table

`watchfrr.sh restart bgpd` had to be SIGTERM'd in every one of the eleven
incidents, and several needed two or three forks. Distinct from F-3: the
recovery machinery is jammed by the same load that triggered the recovery.

### F-5 (FRR) — bgpd's single-threaded main loop

The long-horizon item, filed with numbers rather than opinion. See R-6. This is
not a request for a rewrite; F-0 to F-4 are the parts fixable without touching
the architecture.

---

## Also confirmed: five configuration defects in the IXP template

Not FRR defects — they belong to the template we tested and are listed for
completeness. Confirmed by probe on all four runs, 0 unexplained:

| probe | prefix | expected | observed |
|---|---|---|---|
| `bogon-v6-doc-rfc9637` | `3fff:dead:beef::/48` | reject | accept |
| `toolong-v4-25` | `44.44.44.0/25` | reject | accept |
| `toolong-v4-32` | `44.44.45.1/32` | reject | accept |
| `toolong-v6-64` | `3fff:200:1::/64` | reject | accept |
| `own-supernet-exact-v4` | `100.64.0.0/16` | reject | accept |

The prefix-length checks share one root cause worth flagging to anyone writing
VyOS route-maps: a rule of the form `action permit` + `match <acceptable>` +
`continue 30` does **not** deny the complement. In FRR a rule whose match clause
fails falls through to the next rule, so an over-long prefix is never denied —
it reaches the final `permit`. Denying the complement explicitly is required.

---

## Not tested, deliberately

Stated so nobody assumes coverage we do not have.

* **Martian next-hop handling.** Unfixable in VyOS 1.5.1 / FRR 10.5.2, so not
  exercised.
* **SNMP, RPKI, and forwarding-plane traffic.** All three add work to the same
  main thread and would restate R-6/R-9 with a new trigger. For BGP telemetry at
  this scale, BMP (RFC 7854) is the better instrument than polled SNMP —
  AgentX MIB walks are serviced on the daemon's main thread and at 4.8M paths a
  BGP4-MIB walk is a denial of service against your own control plane.
* **Packet loss during reconvergence.** The dataplane queue hit its limit in all
  four runs and bestpath+FIB takes 184–191 s, so there is a window where the FIB
  is provably behind the RIB. Whether traffic drops in it is a user-visible
  question this work does not answer; it needs loss accounting rather than
  throughput measurement.

---

## Reproducing this

The harness is at `vyos-ixp-bgp-stress`. `make selftest` runs 782 offline checks
with no lab required. A full T3 run is `make generate … deploy … run collect`;
`README.md` has the sequence and `RUNBOOK.md` the detail.

`make collect` produces a single tarball with the results, the DUT's complete
journal, its running config, final `show` output, host memory/stall metrics on
the same clock as the telemetry, and the container inventory — which is the
input every finding above was derived from.

**What we would want from you to go further on R-9:** an event-loop trace, or
guidance on instrumenting `poll()` wakeups in bgpd, across one of the idle-bgpd
gaps. We can reproduce the condition on demand and re-run with any
instrumentation you suggest.
