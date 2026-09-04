"""Turn a results directory into a readable report.

    python -m analysis.analyze build/<profile>/results/<timestamp>

Emits `report.md`, `timeseries.csv`, and `findings.md` next to the samples.

Interpretation rules that are easy to get wrong, and are applied here
--------------------------------------------------------------------
* **Peak `pfxRcd` is not capacity.** It is what arrived. A run that received
  1.2M paths but exceeded the convergence budget did not demonstrate 1.2M-path
  capability. The report separates "carried" from "carried within budget".
* **`tableVersion` movement with a flat `pfxRcd` is real work.** Attribute churn
  and bestpath thrash do not change the prefix count. Reporting only prefix
  counts hides it.
* **`show memory` is not RSS.** FRR's accounting is `count x sizeof(struct)` and
  excludes allocator overhead. RSS from `/proc` is the number used for memory
  verdicts here; bytes-per-path is computed from RSS deltas and labelled as an
  estimate.
* **A SENDQ warning is the leading indicator.** If `sendq_stuck_warn` appears at
  step N and teardown at step N+1, the honest limit is step N-1.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple


def read_jsonl(path: str) -> List[Dict]:
    out = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def read_json(path: str) -> Optional[Dict]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            return None


def _num(xs: Iterable) -> List[float]:
    return [float(x) for x in xs if isinstance(x, (int, float))]


def pct(xs: List[float], p: float) -> Optional[float]:
    if not xs:
        return None
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


# ---------------------------------------------------------------------------
# timeseries
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "t", "v4_established", "v4_failed", "v4_pfx_rcd", "v4_table_version",
    "v4_rib_count", "v6_established", "v6_failed", "v6_pfx_rcd",
    "v6_table_version", "bgpd_rss_mb", "bgpd_cpu_pct", "bgpd_threads",
    "zebra_rss_mb", "zebra_cpu_pct", "cgroup_mem_mb",
    "route_installs", "dplane_queue_max", "dplane_errors",
]


def flatten(rec: Dict) -> Optional[Dict[str, Any]]:
    if rec.get("kind") != "sample":
        return None
    b = rec.get("bgp") or {}
    v4, v6 = b.get("ipv4") or {}, b.get("ipv6") or {}
    p = rec.get("proc") or {}
    bg, ze = p.get("bgpd") or {}, p.get("zebra") or {}
    dp = rec.get("dplane") or {}
    zb = rec.get("zebra") or {}
    return {
        "t": rec.get("t"),
        "v4_established": v4.get("established"), "v4_failed": v4.get("failed"),
        "v4_pfx_rcd": v4.get("pfx_rcd_total"),
        "v4_table_version": v4.get("table_version"),
        "v4_rib_count": v4.get("rib_count"),
        "v6_established": v6.get("established"), "v6_failed": v6.get("failed"),
        "v6_pfx_rcd": v6.get("pfx_rcd_total"),
        "v6_table_version": v6.get("table_version"),
        "bgpd_rss_mb": bg.get("rss_mb"), "bgpd_cpu_pct": bg.get("cpu_pct"),
        "bgpd_threads": bg.get("threads"),
        "zebra_rss_mb": ze.get("rss_mb"), "zebra_cpu_pct": ze.get("cpu_pct"),
        "cgroup_mem_mb": rec.get("cgroup_mem_mb"),
        "route_installs": zb.get("route_installs"),
        "dplane_queue_max": dp.get("queue_max"),
        "dplane_errors": dp.get("route_update_errors"),
    }


def write_csv(rows: List[Dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in CSV_COLUMNS})


# ---------------------------------------------------------------------------
# derived metrics
# ---------------------------------------------------------------------------


def summarise(rows: List[Dict]) -> Dict[str, Any]:
    if not rows:
        return {}
    out: Dict[str, Any] = {"samples": len(rows), "duration_s": rows[-1].get("t")}

    for key in ("v4_pfx_rcd", "v6_pfx_rcd", "v4_rib_count"):
        vals = _num(r.get(key) for r in rows)
        if vals:
            out[f"{key}_peak"] = int(max(vals))
            out[f"{key}_final"] = int(vals[-1])

    for key in ("bgpd_rss_mb", "zebra_rss_mb", "cgroup_mem_mb"):
        vals = _num(r.get(key) for r in rows)
        if vals:
            out[f"{key}_peak"] = max(vals)
            out[f"{key}_final"] = vals[-1]
            out[f"{key}_min"] = min(vals)

    for key in ("bgpd_cpu_pct", "zebra_cpu_pct"):
        vals = _num(r.get(key) for r in rows)
        if vals:
            out[f"{key}_mean"] = round(statistics.fmean(vals), 1)
            out[f"{key}_p95"] = round(pct(vals, 0.95) or 0, 1)
            out[f"{key}_max"] = round(max(vals), 1)
            # bgpd's update path is single-threaded: sustained values near 100%
            # mean the main thread is the bottleneck, and no amount of extra
            # cores will help.
            out[f"{key}_saturated_samples"] = sum(1 for v in vals if v >= 95.0)

    tv = _num(r.get("v4_table_version") for r in rows)
    if len(tv) > 1:
        out["v4_table_version_delta"] = int(max(tv) - min(tv))
        span = (rows[-1].get("t") or 0) - (rows[0].get("t") or 0)
        if span > 0:
            out["v4_table_changes_per_s"] = round((max(tv) - min(tv)) / span, 2)

    ri = _num(r.get("route_installs") for r in rows)
    if len(ri) > 1:
        span = (rows[-1].get("t") or 0) - (rows[0].get("t") or 0)
        out["kernel_route_installs_total"] = int(max(ri) - min(ri))
        if span > 0:
            out["kernel_route_installs_per_s"] = round((max(ri) - min(ri)) / span, 1)

    # Bytes per path from RSS growth. Explicitly an estimate: RSS includes the
    # allocator's own overhead and never shrinks eagerly, and FRR interns
    # attributes, AS_PATHs and communities so the marginal cost of a path
    # depends on how much it shares with existing paths.
    rss = _num(r.get("bgpd_rss_mb") for r in rows)
    pfx = _num(r.get("v4_pfx_rcd") for r in rows)
    if rss and pfx and max(pfx) > 1000:
        d_rss = (max(rss) - min(rss)) * 1048576.0
        d_pfx = max(pfx) - min(pfx)
        if d_pfx > 1000:
            out["bytes_per_path_estimate"] = round(d_rss / d_pfx)
    return out


def flap_recovery(records: List[Dict], rows: List[Dict]) -> List[Dict]:
    """Time from each flap-up event until the table stops moving again."""
    downs = {}
    out = []
    for rec in records:
        k = rec.get("kind")
        if k == "peer_flap_down":
            for sid in rec.get("sessions", []):
                downs[sid] = rec.get("t")
        elif k == "peer_flap_up":
            t_up = rec.get("t")
            for sid in rec.get("sessions", []):
                t_down = downs.pop(sid, None)
                recov = _settle_after(rows, t_up)
                out.append({
                    "session": sid, "mode": rec.get("mode"),
                    "down_at": t_down, "up_at": t_up,
                    "resettle_s": recov,
                })
    return out


def _settle_after(rows: List[Dict], t_from: Optional[float],
                  stable_n: int = 3) -> Optional[float]:
    if t_from is None:
        return None
    seq = [r for r in rows if (r.get("t") or 0) >= t_from]
    streak, prev = 0, None
    for r in seq:
        key = (r.get("v4_table_version"), r.get("v4_pfx_rcd"),
               r.get("v6_table_version"), r.get("v6_pfx_rcd"))
        if None in key[:1]:
            continue
        if key == prev:
            streak += 1
        else:
            streak = 1
        prev = key
        if streak >= stable_n and (r.get("v4_failed") or 0) == 0:
            return round((r.get("t") or 0) - t_from, 2)
    return None


def commit_latencies(records: List[Dict]) -> Dict[str, Any]:
    """Policy-change commit times, per fragment.

    A commit that takes minutes on a full table is an operational finding in its
    own right, independent of whether BGP stayed up.
    """
    per: Dict[str, List[float]] = {}
    split: Dict[Tuple[str, str], List[float]] = {}
    timeouts: List[str] = []
    for rec in records:
        k = rec.get("kind")
        if k in ("policy_churn_applied", "policy_churn_reverted"):
            frag = rec.get("fragment", "?")
            s = rec.get("commit_s")
            if isinstance(s, (int, float)):
                per.setdefault(frag, []).append(float(s))
                # Apply and revert are different operations with very different
                # costs, and averaging them produces a number that describes
                # neither. Observed at T1: community-retag apply ~32.6 s, revert
                # ~0.3 s, reported together as "mean 5.7, max 32.65".
                phase = "apply" if k == "policy_churn_applied" else "revert"
                split.setdefault((frag, phase), []).append(float(s))
        elif k in ("policy_churn_commit_timeout", "policy_churn_revert_timeout"):
            timeouts.append(rec.get("fragment", "?"))
    out: Dict[str, Any] = {"timeouts": timeouts, "per_fragment": {},
                           "per_phase": {}}
    for frag, vals in sorted(per.items()):
        out["per_fragment"][frag] = {
            "n": len(vals), "mean_s": round(statistics.fmean(vals), 2),
            "max_s": round(max(vals), 2),
            "p95_s": round(pct(vals, 0.95) or 0, 2),
        }
    for (frag, phase), vals in sorted(split.items()):
        out["per_phase"][f"{frag} / {phase}"] = {
            "n": len(vals), "mean_s": round(statistics.fmean(vals), 2),
            "max_s": round(max(vals), 2),
            "p95_s": round(pct(vals, 0.95) or 0, 2),
        }
    allv = [v for vals in per.values() for v in vals]
    if allv:
        out["overall"] = {"n": len(allv), "mean_s": round(statistics.fmean(allv), 2),
                          "max_s": round(max(allv), 2)}
    return out


def log_totals(records: List[Dict]) -> Tuple[Dict[str, int], bool, bool]:
    """Total occurrences per signature across the run.

    Returns (totals, unbounded, suspect_constant).

    These counters are per-window, not cumulative, so the run total is a SUM —
    taking the peak reported one window's worth as if it were the whole run. But
    a sum is only meaningful if the windows are actually time-bounded and roughly
    tile the run, so:

    * `unbounded` is set when any sample recorded `_window_unbounded`, meaning
      the DUT read fell back to an untimed tail of /var/log/messages.
    * `suspect_constant` is set when a signature reports the identical non-zero
      value in every window it appears in, which is the signature of a stale
      historical read rather than live activity. That exact pattern was observed:
      62 consecutive windows each reporting `martian_nexthop: 332`.
    """
    totals: Dict[str, int] = {}
    seen: Dict[str, set] = {}
    unbounded = False
    for rec in records:
        logs = rec.get("logs") or {}
        if logs.get("_window_unbounded"):
            unbounded = True
        for k, v in logs.items():
            if k.startswith("_") or not isinstance(v, int):
                continue
            totals[k] = totals.get(k, 0) + v
            if v:
                seen.setdefault(k, set()).add(v)
    suspect = any(len(vals) == 1 and n >= 5
                  for k, vals in seen.items()
                  for n in [sum(1 for r in records
                                if (r.get("logs") or {}).get(k))])
    return ({k: v for k, v in sorted(totals.items()) if v}, unbounded, suspect)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def render_report(d: str) -> str:
    records = read_jsonl(os.path.join(d, "samples.jsonl"))
    run = read_json(os.path.join(d, "run.json"))
    ramp = read_json(os.path.join(d, "ramp.json"))
    probes = read_json(os.path.join(d, "probes.json"))

    rows = [f for f in (flatten(r) for r in records) if f]
    write_csv(rows, os.path.join(d, "timeseries.csv"))
    s = summarise(rows)

    L: List[str] = []
    A = L.append
    A("# VyOS IXP BGP stress run")
    A("")
    meta = run or ramp or {}
    A(f"- results directory: `{d}`")
    if meta.get("lab"):
        A(f"- lab: `{meta['lab']}`")
    for k, v in (meta.get("versions") or {}).items():
        A(f"- {k}: `{v}`")
    A(f"- samples: {s.get('samples', 0)} over {s.get('duration_s', 0)}s")
    A("")

    # -- verdict
    A("## Verdict")
    A("")
    if ramp:
        A(f"Ramp verdict: **{ramp.get('verdict')}** after "
          f"{len(ramp.get('steps') or [])} step(s).")
        lg = ramp.get("last_good_step")
        if lg:
            A("")
            A("Largest configuration that converged inside budget with no failing "
              "predicate:")
            A("")
            A(f"- sessions: **{lg.get('sessions')}**")
            A(f"- IPv4 paths received: **{(lg.get('pfx_rcd_v4') or 0):,}**")
            A(f"- convergence: **{lg.get('convergence_s')}s**")
            A(f"- bgpd RSS: **{lg.get('bgpd_rss_mb')} MB**, "
              f"zebra RSS: {lg.get('zebra_rss_mb')} MB")
    elif run:
        fails = [v for v in (run.get("violations") or [])
                 if v.get("severity") == "fail"]
        A(f"Chaos run: **{'PASS' if not fails else 'FAIL'}** — "
          f"{len(fails)} failing predicate(s), "
          f"{len(run.get('violations') or []) - len(fails)} warning(s).")
        A("")
        # A convergence that did not happen has no duration, only a wait and a
        # blocker. T3 run 1 reported "initial convergence: 4.0s
        # (converged=False)" for a 2,400 s wait — 4.0 s was the *tracker's*
        # back-dated streak figure, which is meaningless once the run is
        # rejected downstream. Report the blocker, which is the result.
        def _conv_line(label, secs, okv, blocked):
            if okv:
                A(f"- {label}: **{secs}s**")
            else:
                A(f"- {label}: **did not converge** — waited {secs}s, "
                  f"blocked by: {blocked or 'not recorded'}")
        _conv_line("initial convergence", run.get("initial_convergence_s"),
                   run.get("initial_converged"),
                   run.get("initial_convergence_blocked_by"))
        # "Nones" is what this printed on T2 run 3, where the operator
        # interrupted a silent 21-minute settle: the key was absent, and the
        # unit got concatenated onto None. An interrupted run has no post-chaos
        # figure, and saying so is more useful than a malformed number.
        pcs = run.get("post_chaos_convergence_s")
        if pcs is None:
            A("- post-chaos re-convergence: **not measured** — the run did not "
              "reach the settle phase, or it was interrupted during it")
        else:
            _conv_line("post-chaos re-convergence", pcs,
                       run.get("post_chaos_converged"),
                       run.get("post_chaos_blocked_by"))
        A(f"- events executed: {len(run.get('events') or [])}")
    A("")

    # -- scale carried
    A("## Scale carried")
    A("")
    A("| metric | value |")
    A("|---|---|")
    for key, label in (
        ("v4_pfx_rcd_peak", "IPv4 paths received (peak)"),
        ("v4_pfx_rcd_final", "IPv4 paths received (final)"),
        ("v6_pfx_rcd_peak", "IPv6 paths received (peak)"),
        ("v4_rib_count_peak", "IPv4 RIB entries (peak)"),
        ("v4_table_version_delta", "IPv4 table changes over the run"),
        ("v4_table_changes_per_s", "IPv4 table changes / s"),
        ("kernel_route_installs_total", "kernel route installs"),
        ("kernel_route_installs_per_s", "kernel route installs / s"),
    ):
        if key in s:
            v = s[key]
            A(f"| {label} | {v:,} |" if isinstance(v, int) else f"| {label} | {v} |")
    A("")
    A("Peak paths received is what arrived, not proven capacity. Read it together "
      "with the convergence figures above.")
    A("")
    acct = (meta or {}).get("accounting") or {}
    if acct:
        A("### Announced vs accepted")
        A("")
        A("| afi | announced | accepted (final) | drift | inherited "
              "| this run |")
        A("|---|---|---|---|---|---|")
        for afi in ("ipv4", "ipv6"):
            a = acct.get(afi) or {}
            if a:
                inh = a.get("drift_inherited")
                tr = a.get("drift_this_run")
                A(f"| {afi} | {a['announced']:,} | {a['accepted']:,} "
                  f"| {a['drift']:+,} "
                  f"| {'-' if inh is None else format(inh, '+,')} "
                  f"| {'-' if tr is None else format(tr, '+,')} |")
        A("")
        if any((acct.get(a) or {}).get("drift") for a in ("ipv4", "ipv6")):
            A("**Non-zero drift.** The table does not hold what the profile "
              "announced, so the peak figures above are not a capacity result. A "
              "positive drift means `walk` churn advertised fresh NLRI whose "
              "matching withdrawals did not land. Run `make peers` for the "
              "per-peer breakdown before quoting any of these numbers.")
            A("")
            if all((acct.get(a) or {}).get("drift_this_run") == 0
                   for a in ("ipv4", "ipv6")):
                A("All of the drift was **inherited** — it was already present "
                  "before chaos began, so this run did not leak anything. The "
                  "lab was not redeployed between runs. Redeploy for a clean "
                  "baseline before quoting scale figures.")
                A("")
    else:
        A("_No announced-vs-accepted accounting in this run's metadata, so the "
          "peak figures are unverified against what the profile declared._")
        A("")

    # -- resources
    A("## Resource envelope")
    A("")
    A("| metric | value |")
    A("|---|---|")
    for key, label, unit in (
        ("bgpd_rss_mb_peak", "bgpd RSS peak", "MB"),
        ("bgpd_rss_mb_final", "bgpd RSS final", "MB"),
        ("zebra_rss_mb_peak", "zebra RSS peak", "MB"),
        ("cgroup_mem_mb_peak", "container memory peak", "MB"),
        ("bgpd_cpu_pct_mean", "bgpd CPU mean", "%"),
        ("bgpd_cpu_pct_p95", "bgpd CPU p95", "%"),
        ("bgpd_cpu_pct_max", "bgpd CPU max", "%"),
        ("bgpd_cpu_pct_saturated_samples", "samples with bgpd CPU >= 95%", ""),
        ("zebra_cpu_pct_p95", "zebra CPU p95", "%"),
    ):
        if key in s:
            A(f"| {label} | {s[key]} {unit} |".replace("  |", " |"))
    A("")

    # Within-run bytes-per-path is only meaningful if the table actually grew
    # during the run. When the table is loaded by `bringup` and the run only
    # churns it, RSS barely moves and the figure measures allocator noise. At T1
    # it read 38 B/path against a real cross-tier slope of ~1.7 KB/path — off by
    # a factor of 45, in the direction that makes the next tier look free.
    peak = s.get("bgpd_rss_mb_peak")
    v4p = s.get("v4_pfx_rcd_peak") or 0
    v6p = s.get("v6_pfx_rcd_peak") or 0
    paths = v4p + v6p
    bpp = s.get("bytes_per_path_estimate")
    if bpp is not None:
        A(f"Within-run bytes-per-path came out at **{bpp} B**. Treat that as "
          f"unusable unless the table grew materially during the run: it is "
          f"derived from RSS growth against received-path growth, and a run that "
          f"loads its table in `bringup` and then only churns it shows almost no "
          f"growth in either. Use the whole-table figure below instead.")
        A("")
    if peak and paths:
        A("### Memory per path, and what the next tier needs")
        A("")
        A("| basis | value |")
        A("|---|---|")
        A(f"| bgpd RSS at peak | {peak} MB |")
        A(f"| paths held (v4 + v6) | {paths:,} |")
        A(f"| bgpd RSS / path, whole table | "
          f"{peak * 1024 * 1024 / paths:,.0f} B |")
        zp = s.get("zebra_rss_mb_peak")
        if zp:
            A(f"| zebra RSS / path, whole table | "
              f"{zp * 1024 * 1024 / paths:,.0f} B |")
        A("")
        A("Whole-table RSS divided by paths held. It includes each daemon's fixed "
          "base cost, so it over-states the *marginal* cost of one more path and "
          "under-states nothing — which makes it the safe direction for sizing "
          "the next tier. For a marginal figure, difference two tiers: "
          "`(RSS_b - RSS_a) / (paths_b - paths_a)`.")
        A("")
        for target, label in ((2_000_000, "T2 (~2M paths)"),
                              (5_000_000, "T3/T4 (~5M paths)")):
            if paths >= target:
                continue
            est = peak * target / paths
            zest = (zp or 0) * target / paths
            A(f"* Linear extrapolation to {label}: bgpd ≈ **{est / 1024:,.1f} GB**"
              + (f", zebra ≈ **{zest / 1024:,.1f} GB**" if zp else "")
              + f" — total ≈ **{(est + zest) / 1024:,.1f} GB** for these two "
                f"daemons alone. Check free RAM on the host and the profile's "
                f"`bgpd_rss_mb` / `zebra_rss_mb` budgets before starting it.")
        A("")
        A("> Linear is the wrong model in both directions and is used only "
          "because it is the conservative one available from a single tier. FRR "
          "interns attributes, AS_PATHs and communities, so paths that share "
          "attributes cost less than the first one did; against that, allocator "
          "fragmentation and per-peer Adj-RIB-In (the template sets "
          "`soft-reconfiguration inbound` on every peer-group) grow with peer "
          "count as well as path count. Differencing two measured tiers beats "
          "extrapolating from one.")
        A("")
    sat = s.get("bgpd_cpu_pct_saturated_samples", 0)
    if sat:
        A(f"> bgpd was at or above 95% CPU in {sat} sample(s). BGP UPDATE parsing, "
          f"bestpath and update generation all run on bgpd's single main thread — "
          f"only socket I/O and keepalive generation are on separate pthreads — so "
          f"this is a hard ceiling that additional cores cannot raise.")
        A("")
    if "bytes_per_path_estimate" in s:
        A(f"> Bytes-per-path is derived from RSS growth against received-path growth "
          f"and is an estimate only. FRR interns attributes, AS_PATHs and "
          f"communities, so the marginal cost of a path depends on how much it "
          f"shares with paths already held; RSS also includes allocator overhead "
          f"and does not shrink eagerly.")
        A("")

    # -- log signals
    lt, lt_unbounded, lt_suspect = log_totals(records)
    A("## Failure signals in the DUT log")
    A("")
    A("Summed across the per-window DUT log reads taken during the run. The "
      "earliest windows reach back slightly before the run began, so a "
      "signature produced by an immediately preceding `make probe` can leak in.")
    A("")
    if lt_unbounded:
        A("> **These counts are not trustworthy.** At least one sample could not "
          "read a time-bounded log window and fell back to an untimed tail of "
          "`/var/log/messages`, so the numbers below include history from before "
          "this run and are summed over overlapping reads. Fix the DUT's "
          "journal access before relying on them.")
        A("")
    if lt_suspect:
        A("> **Suspect: at least one signature reported the identical non-zero "
          "count in every window.** That is the shape of a stale historical read "
          "rather than live activity, not of a signal that recurred at a "
          "perfectly constant rate. Check per-sample values in `samples.jsonl`.")
        A("")
    if not lt:
        A("None of the tracked signatures appeared.")
    else:
        A("| signature | occurrences |")
        A("|---|---|")
        for k, v in lt.items():
            A(f"| `{k}` | {v} |")
        A("")
        if lt.get("sendq_stuck_proper"):
            A("> **`sendq_stuck_proper` is the significant one.** bgpd terminated a "
              "session because its send queue made no progress for twice the "
              "holdtime. That threshold is hardcoded in `bgp_packet.c` "
              "(`sendholdtime = holdtime * 2`), is not configurable, and is absent "
              "from the FRR user documentation. Once this appears, the DUT is past "
              "the point where it can service its own update generation, and the "
              "resulting teardown creates more churn — a self-reinforcing loop.")
        elif lt.get("sendq_stuck_warn"):
            A("> `sendq_stuck_warn` fired without a teardown: the main thread "
              "stalled for a full holdtime but recovered before the 2x threshold. "
              "Treat this as the ceiling indicator — the last configuration without "
              "it is the defensible limit.")
    A("")

    # -- flap recovery
    fr = flap_recovery(records, rows)
    if fr:
        A("## Flap recovery")
        A("")
        A("| session | mode | re-settle (s) |")
        A("|---|---|---|")
        for f in fr[:40]:
            A(f"| {f['session']} | {f['mode']} | {f['resettle_s']} |")
        vals = _num(f["resettle_s"] for f in fr)
        if vals:
            A("")
            A(f"mean {statistics.fmean(vals):.1f}s, p95 {pct(vals, 0.95):.1f}s, "
              f"max {max(vals):.1f}s over {len(vals)} measured flap(s)")
        A("")

    # -- commit latency
    cl = commit_latencies(records)
    if cl.get("per_fragment") or cl.get("timeouts"):
        A("## Policy-change commit latency")
        A("")
        A("Apply and revert are separated: they are different operations and "
          "their costs differ by two orders of magnitude on some fragments, so "
          "a combined mean describes neither.")
        A("")
        A("| fragment / phase | n | mean (s) | p95 (s) | max (s) |")
        A("|---|---|---|---|---|")
        for frag, st in (cl.get("per_phase") or {}).items():
            A(f"| {frag} | {st['n']} | {st['mean_s']} | {st['p95_s']} "
              f"| {st['max_s']} |")
        A("")
        A("Combined, for continuity with earlier runs:")
        A("")
        A("| fragment | n | mean (s) | p95 (s) | max (s) |")
        A("|---|---|---|---|---|")
        for frag, st in cl["per_fragment"].items():
            A(f"| {frag} | {st['n']} | {st['mean_s']} | {st['p95_s']} | {st['max_s']} |")
        budget = ((meta or {}).get("budgets") or {}).get("commit_s")
        worst = max((st["max_s"] for st in cl["per_fragment"].values()),
                    default=0)
        if budget and worst:
            A("")
            frac = worst / float(budget)
            A(f"Worst commit **{worst:.1f} s** against a `commit_s` budget of "
              f"**{budget:.0f} s** — {frac * 100:.0f} % of budget. A commit that "
              f"does not return is an operational failure regardless of BGP "
              f"state: it means the router cannot be changed under this load.")
            if frac >= 0.7:
                A("")
                A("> **This is the metric most likely to fail at the next tier.** "
                  "Policy commit forces a full re-evaluation of the table, so it "
                  "scales with table size while the budget does not. Raise "
                  "`commit_s` in the next profile to something you have actually "
                  "measured, or the run will fail on a threshold rather than on "
                  "a finding.")
        if cl.get("timeouts"):
            A("")
            A(f"**Commit timeouts:** {', '.join(cl['timeouts'])}. A commit that does "
              f"not return is an operational failure regardless of BGP state — it "
              f"means the router cannot be changed while under this load.")
        A("")

    # -- ramp table
    if ramp and ramp.get("steps"):
        A("## Ramp steps")
        A("")
        A("| step | sessions | cap/peer | converged | conv (s) | v4 pfxRcd | "
          "bgpd RSS (MB) | bgpd CPU (%) |")
        A("|---|---|---|---|---|---|---|---|")
        for r in ramp["steps"]:
            A(f"| {r['step']} | {r['sessions']} | {r['prefix_cap']:,} | "
              f"{r['converged']} | {r['convergence_s']} | "
              f"{(r.get('pfx_rcd_v4') or 0):,} | {r.get('bgpd_rss_mb')} | "
              f"{r.get('bgpd_cpu_pct')} |")
        A("")

    # -- violations
    viols = (run or {}).get("violations") or []
    if viols:
        A("## Predicate violations")
        A("")
        for v in viols:
            A(f"### `{v.get('code')}` ({v.get('severity')})")
            A("")
            A(v.get("detail", ""))
            A("")
            if v.get("evidence"):
                A(f"Evidence: `{json.dumps(v['evidence'], default=str)}`")
                A("")

    # -- probes
    if probes:
        A("## Policy correctness")
        A("")
        rowsp = probes.get("probes") or []
        failed = [r for r in rowsp if not r.get("pass")]
        confirmed = [r for r in failed if r.get("template_defect")]
        unexpected = [r for r in failed if not r.get("template_defect")]
        A(f"- probes run: {len(rowsp)}")
        A(f"- confirmed template defects: {len(confirmed)}")
        A(f"- unexplained failures: {len(unexpected)}")
        A("")
        if confirmed:
            A("### Confirmed template defects")
            A("")
            for r in confirmed:
                A(f"**{r['pid']}** (`{r['prefix']}`) — expected {r['expect']}, "
                  f"observed {r['observed']}")
                A("")
                A(f"> {r['template_defect']}")
                A("")
        if unexpected:
            A("### Unexplained failures")
            A("")
            A("These are not attributable to a known template defect and need "
              "investigation.")
            A("")
            for r in unexpected:
                A(f"- **{r['pid']}** (`{r['prefix']}`): expected {r['expect']}, "
                  f"observed {r['observed']}")
            A("")
        mal = probes.get("malformed") or {}
        if mal:
            A("### RFC 7606 malformed-attribute suite")
            A("")
            est = mal.get("session_established_after")
            A(f"Session still established after the burst: **{est}**")
            A("")
            if est is False:
                A("> A session reset following an attribute error is the finding. "
                  "RFC 7606 exists to replace session resets with attribute "
                  "discard and treat-as-withdraw; the only case where a reset is "
                  "clearly conformant here is `unknown-wellknown-attr`.")
                A("")
            bad = [r for r in (mal.get("route_checks") or []) if not r.get("pass")]
            if bad:
                A("| case | expected route | present |")
                A("|---|---|---|")
                for r in bad:
                    A(f"| {r['mid']} | {r['expect_route']} | {r['present']} |")
                A("")
        na = probes.get("not_achievable_with_exabgp") or []
        if na:
            A("### Not covered — needs a byte-level injector")
            A("")
            A("ExaBGP re-decodes any known attribute code passed to "
              "`attribute [ ... ]`, so these cases cannot be emitted from it and "
              "were not tested:")
            A("")
            for item in na:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    A(f"- **{item[0]}** — {item[1]}")
            A("")

    A("## Files")
    A("")
    A("- `samples.jsonl` — raw telemetry and the event timeline")
    A("- `timeseries.csv` — flattened samples for plotting")
    A("- `run.json` / `ramp.json` — run metadata, events, violations")
    A("- `probes.json` — policy-probe and malformed-attribute results")
    A("")
    return "\n".join(L) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Analyse a stress-run results directory")
    ap.add_argument("results_dir")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.results_dir):
        print(f"error: {a.results_dir} is not a directory", file=sys.stderr)
        return 1
    md = render_report(a.results_dir)
    if a.stdout:
        print(md)
    else:
        out = os.path.join(a.results_dir, "report.md")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"written: {out}")
        print(f"written: {os.path.join(a.results_dir, 'timeseries.csv')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
