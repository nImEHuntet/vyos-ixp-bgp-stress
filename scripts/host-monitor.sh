#!/usr/bin/env bash
# Sample host memory, swap, IO and stall pressure onto the SAME clock the
# harness uses, so the two can be joined row by row.
#
# Why this exists
# ---------------
# T3 run 1 left one measurement unexplained, and it is the only observation in
# the project with no candidate cause:
#
#   over the 3,600 s post-chaos settle, bgpd used ~14 seconds of CPU in total
#   (mean 0.4%, one sample above 95% out of 1,182) — and during that same hour
#   its own scheduler reported callbacks running 38,110 ms to 82,607 ms late,
#   with a final one at 75,821 ms late at 17:04:35.
#
# An idle process whose ready callbacks fire 80 seconds late is blocked, not
# busy. The cheapest external explanation is the host: the operator saw memory
# go 24 GB -> 42 GB, and a bgpd with 8 GB resident taking major faults would
# look exactly like this — low CPU, enormous latency. Nothing recorded whether
# that happened, and it cannot be reconstructed afterwards. `free -m` at the
# end says nothing about 17:04.
#
# So: a timeline, not a snapshot, and on the harness's clock.
#
# Usage
# -----
#   ./scripts/host-monitor.sh host-metrics.csv [interval_s] [dut_container] &
#   ...run the test...
#   kill %1        # or Ctrl-C; it flushes every row as it goes
#
# `make run` does not start this — it is deliberately separate so it survives
# the run being interrupted.
set -uo pipefail

OUT="${1:-host-metrics.csv}"
INTERVAL="${2:-5}"
DUT="${3:-}"
PIDFILE="${4:-.host-monitor.pid}"

# Write our own PID rather than letting the caller capture `$!`. Started under
# `setsid nohup`, `$!` is setsid's pid, not this script's, and `make
# monitor-stop` would then kill the wrong thing (or nothing) and the run would
# end with a truncated timeline nobody noticed until analysis.
echo "$$" > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT

# --- locate the DUT container's cgroup, once --------------------------------
# cgroup v2 puts memory.pressure and cpu.stat here. Throttling and per-container
# reclaim are invisible from the host-wide counters.
CG=""
if [ -n "$DUT" ]; then
  CID="$(docker inspect -f '{{.Id}}' "$DUT" 2>/dev/null)"
  if [ -n "$CID" ]; then
    for c in "/sys/fs/cgroup/system.slice/docker-${CID}.scope" \
             "/sys/fs/cgroup/docker/${CID}" \
             "/sys/fs/cgroup/kubepods/${CID}"; do
      [ -d "$c" ] && CG="$c" && break
    done
    [ -z "$CG" ] && CG="$(find /sys/fs/cgroup -maxdepth 4 -type d -name "*${CID:0:12}*" 2>/dev/null | head -1)"
  fi
fi

field() { awk -v k="$2" '$1==k":"{print $2; found=1} END{if(!found)print ""}' "$1"; }
vmstat_f() { awk -v k="$2" '$1==k{print $2; found=1} END{if(!found)print ""}' "$1"; }
# PSI files print "some avg10=.. avg60=.. avg300=.. total=<us>" then "full ...".
# `total` is a monotonic microsecond counter of stalled time, which is exactly
# what a 5 s sample can be differenced into "how long was something stuck".
psi_total() { awk -v t="$2" '$1==t{sub("total=","",$5); print $5; exit}' "$1" 2>/dev/null; }

HDR="epoch,mem_total_kb,mem_available_kb,mem_free_kb,cached_kb,dirty_kb,writeback_kb"
HDR="$HDR,swap_total_kb,swap_free_kb,pswpin,pswpout,pgmajfault,pgscan_direct,pgsteal_direct"
HDR="$HDR,load1,load5,load15,procs_running,procs_blocked"
HDR="$HDR,cpu_user,cpu_system,cpu_idle,cpu_iowait,cpu_steal"
HDR="$HDR,psi_cpu_some_us,psi_mem_some_us,psi_mem_full_us,psi_io_some_us,psi_io_full_us"
HDR="$HDR,dut_mem_current_kb,dut_mem_psi_full_us,dut_cpu_nr_throttled,dut_cpu_throttled_us"
echo "$HDR" > "$OUT"
NCOL=$(awk -F, '{print NF}' <<<"$HDR")

echo "host-monitor: writing $OUT every ${INTERVAL}s" >&2
[ -n "$CG" ] && echo "host-monitor: DUT cgroup $CG" >&2
[ -z "$CG" ] && [ -n "$DUT" ] && echo "host-monitor: DUT cgroup not found; host rows only" >&2

trap 'echo "host-monitor: stopped after $(( $(wc -l < "$OUT") - 1 )) rows" >&2; exit 0' INT TERM

while :; do
  NOW="$(date +%s)"

  MI=/proc/meminfo; VS=/proc/vmstat
  mt=$(field $MI MemTotal);      ma=$(field $MI MemAvailable)
  mf=$(field $MI MemFree);       ca=$(field $MI Cached)
  di=$(field $MI Dirty);         wb=$(field $MI Writeback)
  st=$(field $MI SwapTotal);     sf=$(field $MI SwapFree)

  # pswpin/pswpout are pages swapped in/out since boot; pgmajfault is the one
  # that hurts a resident daemon. pgscan_direct/pgsteal_direct mean the kernel
  # reclaimed *in the allocating process's own context* — a synchronous stall
  # that shows up as latency, not as CPU.
  swin=$(vmstat_f $VS pswpin);   swout=$(vmstat_f $VS pswpout)
  mjf=$(vmstat_f $VS pgmajfault)
  psd=$(vmstat_f $VS pgscan_direct); pst=$(vmstat_f $VS pgsteal_direct)

  read -r l1 l5 l15 procs _ < /proc/loadavg
  run="${procs%%/*}"
  blk=$(awk '/^procs_blocked/{print $2}' /proc/stat)

  read -r _ cu cn cs ci cw _ _ cst _ < <(grep '^cpu ' /proc/stat)
  cu=$((cu+cn))

  pc=$(psi_total  /proc/pressure/cpu    some)
  pms=$(psi_total /proc/pressure/memory some)
  pmf=$(psi_total /proc/pressure/memory full)
  pis=$(psi_total /proc/pressure/io     some)
  pif=$(psi_total /proc/pressure/io     full)

  dmc=""; dmp=""; dth=""; dtu=""
  if [ -n "$CG" ]; then
    [ -f "$CG/memory.current" ] && dmc=$(( $(cat "$CG/memory.current" 2>/dev/null || echo 0) / 1024 ))
    [ -f "$CG/memory.pressure" ] && \
      dmp=$(awk '/^full/{sub("total=","",$5); print $5; exit}' "$CG/memory.pressure" 2>/dev/null)
    if [ -f "$CG/cpu.stat" ]; then
      dth=$(awk '/^nr_throttled/{print $2}' "$CG/cpu.stat")
      dtu=$(awk '/^throttled_usec/{print $2}' "$CG/cpu.stat")
    fi
  fi

  # Join through an array rather than a long printf format. The first version
  # of this had one fewer conversion than argument, and printf *reuses* its
  # format string when it runs out — so every real row was followed by an empty
  # one. Silent, and exactly the class of defect this project keeps finding.
  row=("$NOW" "$mt" "$ma" "$mf" "$ca" "$di" "$wb" "$st" "$sf"
       "$swin" "$swout" "$mjf" "$psd" "$pst"
       "$l1" "$l5" "$l15" "$run" "$blk"
       "$cu" "$cs" "$ci" "$cw" "$cst"
       "$pc" "$pms" "$pmf" "$pis" "$pif"
       "$dmc" "$dmp" "$dth" "$dtu")
  if [ "${#row[@]}" -ne "$NCOL" ]; then
    echo "host-monitor: BUG — ${#row[@]} values for $NCOL columns; stopping" >&2
    exit 2
  fi
  ( IFS=,; echo "${row[*]}" ) >> "$OUT"

  sleep "$INTERVAL"
done
