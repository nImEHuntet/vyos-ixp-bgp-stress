#!/usr/bin/env bash
# Check the host can actually run the lab before you spend an hour finding out.
set -uo pipefail
FAIL=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }

echo "== tools"
for t in docker containerlab nsenter ip bsdtar python3; do
  if command -v "$t" >/dev/null; then ok "$t $(command -v $t)"
  elif [ "$t" = bsdtar ]; then warn "bsdtar missing (only needed to build the VyOS image)"
  else bad "$t not found"; fi
done

echo "== python"
python3 - <<'PY' || FAIL=1
import sys
if sys.version_info < (3, 9):
    print("  FAIL  python >= 3.9 required, have", sys.version.split()[0]); raise SystemExit(1)
print("  ok    python", sys.version.split()[0])
try:
    import yaml; print("  ok    pyyaml", yaml.__version__)
except ImportError:
    print("  FAIL  pyyaml missing: pip install -r requirements.txt"); raise SystemExit(1)
PY

echo "== docker"
if docker info >/dev/null 2>&1; then
  ok "docker reachable"
  if docker network inspect bridge -f '{{.EnableIPv6}}' 2>/dev/null | grep -qi true; then
    ok "docker IPv6 enabled on the default bridge"
  else
    warn "docker IPv6 not enabled. containerlab's VyOS kind documents needing an
        IPv6-enabled docker network; most distros do not enable it by default."
  fi
else
  bad "cannot talk to the docker daemon"
fi

echo "== kernel"
K=$(uname -r); ok "kernel $K"
MAJ=${K%%.*}; MIN=$(echo "$K" | cut -d. -f2 | tr -dc 0-9)
if [ "${MAJ:-0}" -gt 6 ] || { [ "${MAJ:-0}" = 6 ] && [ "${MIN:-0}" -ge 3 ]; }; then
  ok "net.ipv6.route.max_size is deprecated on this kernel (>= 6.3); IPv6 FIB is memory-bound"
else
  V6MAX=$(sysctl -n net.ipv6.route.max_size 2>/dev/null || echo 0)
  if [ "${V6MAX:-0}" -lt 262144 ]; then
    bad "net.ipv6.route.max_size=$V6MAX is an ENFORCED ceiling on this kernel and
        is too low for a full IPv6 table. Run scripts/host-tune.sh."
  else ok "net.ipv6.route.max_size=$V6MAX"; fi
fi

echo "== limits"
INST=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo 0)
[ "${INST:-0}" -ge 8192 ] && ok "fs.inotify.max_user_instances=$INST" \
  || warn "fs.inotify.max_user_instances=$INST is low for a multi-node lab; run scripts/host-tune.sh"
OPT=$(sysctl -n net.core.optmem_max 2>/dev/null || echo 0)
[ "${OPT:-0}" -ge 1048576 ] && ok "net.core.optmem_max=$OPT" \
  || warn "net.core.optmem_max=$OPT; FRR documents ENOMEM on TCP-MD5 at scale"
NOF=$(ulimit -n); [ "$NOF" = unlimited ] || [ "$NOF" -ge 65536 ] \
  && ok "ulimit -n = $NOF" || warn "ulimit -n = $NOF is low"

echo "== capacity"
MEMGB=$(awk '/MemTotal/{printf "%.0f", $2/1048576}' /proc/meminfo)
CPUS=$(nproc)
ok "${CPUS} cpu, ${MEMGB} GB RAM"
[ "$MEMGB" -lt 16 ] && warn "under 16 GB: t0/t1 only. A full-table tier needs 64 GB+."
DISK=$(df -BG --output=avail . 2>/dev/null | tail -1 | tr -dc 0-9)
ok "${DISK:-?} GB free on the working filesystem"
[ "${DISK:-0}" -lt 20 ] && warn "under 20 GB free; MRT tables for a full table are large"

echo "== lab images"
echo "  note  this checks the host only. To verify the three locally-built images"
echo "        exist before deploying, run:  make check-images PROFILE=<tier>"
if command -v docker >/dev/null; then
  D=docker; docker info >/dev/null 2>&1 || D="sudo docker"
  found=$($D images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -icE 'vyos-stress' || true)
  if [ "${found:-0}" -gt 0 ]; then
    ok "$found vyos-stress image(s) present:"
    $D images --format '        {{.Repository}}:{{.Tag}}  ({{.Size}})' 2>/dev/null | grep -iE 'vyos-stress' | head -6
  else
    warn "no vyos-stress images built yet — 'make vyos-image ISO=...' and 'make images'"
  fi
fi

echo
[ "$FAIL" = 0 ] && echo "preflight PASSED" || echo "preflight FAILED — fix the items above"
exit $FAIL
