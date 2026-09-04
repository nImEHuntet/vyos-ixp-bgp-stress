#!/usr/bin/env bash
# Collect everything needed to analyse a run, into one directory.
#
# Written after T3 run 1, where four separate things were missing or truncated
# and each one blocked a conclusion:
#
#   * the journal had been hand-trimmed 19 MB -> 555 KB, so every log-derived
#     count became a lower bound;
#   * `make peers` was never run, so a -51,000 IPv4 / -131,900 IPv6 drift could
#     not be decomposed per peer;
#   * nothing captured the host's memory or kernel log, leaving one measurement
#     (an event 87.7 s late while bgpd sat at 0.4% CPU) unexplained — swap or an
#     IO stall would explain it and there is no way to check after the fact;
#   * nothing captured the DUT's running configuration at the end, so a commit
#     that timed out could only be confirmed reverted from the harness's own
#     bookkeeping.
#
# Usage:
#   sudo ./scripts/collect-run.sh t3-fulltable                 # newest results dir
#   sudo ./scripts/collect-run.sh t3-fulltable 20260901T062300 # a specific one
#
# Run it on the host that ran the test, from the repo root, AFTER `make run`
# and BEFORE `make destroy`. It only reads.
set -uo pipefail

PROFILE="${1:?usage: collect-run.sh <profile> [results-timestamp]}"
BUILD="build/${PROFILE}"
STAMP="${2:-}"
# The DUT container is named after the node in the profile, not "dut". On
# t3-fulltable it is `clab-t3-fulltable-vyos`, so the guess below missed and
# run 2's bundle came back with no DUT journal, no running config and no final
# `show` output at all. Read it from the inventory, which knows.
DUT_NAME=""
if [ -f "build/${PROFILE}/inventory.json" ]; then
  DUT_NAME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["dut"]["name"])' \
              "build/${PROFILE}/inventory.json" 2>/dev/null)"
fi
if [ -z "$DUT_NAME" ]; then
  # Last resort: ask docker which container in this lab runs the VyOS image.
  DUT_NAME="$(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null \
              | awk -v p="clab-${PROFILE}-" '$2 ~ /vyos-stress:/ && index($1,p)==1 {sub(p,"",$1); print $1; exit}')"
fi
DUT_CONTAINER="${DUT_CONTAINER:-clab-${PROFILE}-${DUT_NAME:-dut}}"
echo "  DUT container: ${DUT_CONTAINER}"

if [ -z "$STAMP" ]; then
  STAMP="$(ls -1 "${BUILD}/results" 2>/dev/null | grep -E '^[0-9]{8}T[0-9]{6}$' | sort | tail -1)"
fi
RESULTS="${BUILD}/results/${STAMP}"
[ -d "$RESULTS" ] || { echo "no results directory at ${RESULTS}"; exit 1; }

OUT="collect-${PROFILE}-${STAMP}"
mkdir -p "${OUT}"
echo "collecting into ${OUT}/"

say() { printf '  %-34s %s\n' "$1" "$2"; }

# 1. the run's own artefacts, whole and untouched -----------------------------
cp -a "${RESULTS}/." "${OUT}/results/" 2>/dev/null && \
  say "results/" "$(ls -1 "${OUT}/results" | tr '\n' ' ')"

# 2. per-peer accounting, if it was taken -------------------------------------
# Any results/peers* directory. `make peers` writes to a fixed path, so a
# baseline run before the chaos and an accounting run after it would otherwise
# overwrite each other — PEERS_DIR exists to keep both.
found_peers=0
for d in "${BUILD}"/results/peers*; do
  [ -d "$d" ] || continue
  cp -a "$d" "${OUT}/$(basename "$d")" && say "$(basename "$d")/" "ok"
  found_peers=1
done
[ "$found_peers" = 0 ] && \
  say "peers-results/" "MISSING — run: make peers PROFILE=${PROFILE}"

# 3. the DUT's journal, in full ------------------------------------------------
# --no-pager and no --since: the whole boot. Do not trim it; it compresses to
# almost nothing and a trimmed copy turns every count into a lower bound.
if docker exec "${DUT_CONTAINER}" true 2>/dev/null; then
  docker exec "${DUT_CONTAINER}" journalctl --no-pager -b -o short-precise \
    > "${OUT}/dut-journal-full.log" 2>/dev/null
  say "dut-journal-full.log" "$(wc -l < "${OUT}/dut-journal-full.log") lines"

  # 4. what the DUT is actually configured with, at the end ------------------
  docker exec "${DUT_CONTAINER}" vtysh -c 'show running-config' \
    > "${OUT}/dut-frr-running.conf" 2>/dev/null
  docker exec "${DUT_CONTAINER}" sh -lc \
    '. /opt/vyatta/etc/functions/script-template; show configuration commands' \
    > "${OUT}/dut-vyos-config.txt" 2>/dev/null
  say "dut-frr-running.conf" "$(wc -l < "${OUT}/dut-frr-running.conf") lines"
  say "dut-vyos-config.txt" "$(wc -l < "${OUT}/dut-vyos-config.txt") lines"

  # 5. the state the report quotes, straight from the DUT --------------------
  {
    for c in 'show bgp summary' 'show bgp ipv6 summary' \
             'show ip route summary' 'show ipv6 route summary' \
             'show zebra dplane detailed' 'show thread cpu' \
             'show memory' 'show version'; do
      echo "=== ${c} ==="
      docker exec "${DUT_CONTAINER}" vtysh -c "${c}" 2>&1
      echo
    done
  } > "${OUT}/dut-final-state.txt"
  say "dut-final-state.txt" "ok"
else
  say "dut-*" "DUT container ${DUT_CONTAINER} not reachable — skipped"
fi

# 6. the host: this is the half nothing else records --------------------------
{
  echo "=== date ==="; date -Is
  echo; echo "=== uname -a ==="; uname -a
  echo; echo "=== free -m ==="; free -m
  echo; echo "=== swapon --show ==="; swapon --show 2>/dev/null || echo none
  echo; echo "=== vmstat 1 5 ==="; vmstat 1 5 2>/dev/null
  echo; echo "=== nproc / loadavg ==="; nproc; cat /proc/loadavg
  echo; echo "=== /proc/pressure ==="; cat /proc/pressure/* 2>/dev/null
  echo; echo "=== sysctl (net + vm) ==="
  sysctl net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem \
         net.ipv4.tcp_wmem vm.swappiness vm.max_map_count \
         net.ipv4.neigh.default.gc_thresh3 2>/dev/null
} > "${OUT}/host-state.txt" 2>&1
say "host-state.txt" "ok"

# The kernel log is the only place an OOM kill, a netlink overrun or an IO
# stall will appear. Run 1's host went 24 GB -> 42 GB and nothing recorded it.
( journalctl -k --no-pager -b 2>/dev/null || dmesg -T 2>/dev/null ) \
  > "${OUT}/host-kernel.log"
say "host-kernel.log" "$(wc -l < "${OUT}/host-kernel.log") lines"

# 7. did any container die? fleet_snapshot sees speakers, not containers ------
docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' \
  > "${OUT}/containers.txt" 2>/dev/null
say "containers.txt" "$(wc -l < "${OUT}/containers.txt") containers"

# 8. proof the build that ran is the build that passed ------------------------
for f in inventory.json topology.clab.yml; do
  [ -f "${BUILD}/${f}" ] && cp "${BUILD}/${f}" "${OUT}/" && say "${f}" "ok"
done
[ -f selftest.txt ] && cp selftest.txt "${OUT}/" && say "selftest.txt" "ok"

# 9. the host timeline — the only file here that cannot be reconstructed later
if [ -f host-metrics.csv ]; then
  cp host-metrics.csv "${OUT}/" && \
    say "host-metrics.csv" "$(wc -l < host-metrics.csv) rows"
else
  say "host-metrics.csv" "MISSING — start it before the run: make monitor PROFILE=${PROFILE}"
fi

# ---------------------------------------------------------------------------
TAR="${OUT}.tar.gz"
tar czf "${TAR}" "${OUT}"
echo
echo "written: ${TAR}  ($(du -h "${TAR}" | cut -f1))"
echo
grep -q MISSING <<<"$(ls "${OUT}")" 2>/dev/null
echo "Before sending, check that peers-results/ is present. If it is not:"
echo "    make peers PROFILE=${PROFILE}   # then re-run this script"
