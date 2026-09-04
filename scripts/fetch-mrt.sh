#!/usr/bin/env bash
# Fetch a real BGP table dump for the T3 tier.
#
# Synthetic NLRI understates memory efficiency, because FRR interns attributes,
# AS_PATHs and communities: a real table shares them heavily, synthetic prefixes
# with unique attributes do not. If you want numbers anyone will believe, use a
# real dump.
#
#   ./fetch-mrt.sh [outdir] [YYYY.MM] [YYYYMMDD.HHMM]
#
# RouteViews publishes TABLE_DUMP_V2 RIBs every two hours. A full IPv4+IPv6 RIB is
# roughly 100-200 MB compressed and expands a lot; make sure you have the disk.
set -euo pipefail
OUT="${1:-./mrt}"
MONTH="${2:-$(date -u +%Y.%m)}"
STAMP="${3:-$(date -u -d '6 hours ago' +%Y%m%d.%H00 2>/dev/null || date -u +%Y%m%d.0000)}"
mkdir -p "$OUT"

BASE="https://archive.routeviews.org/route-views2/bgpdata/${MONTH}/RIBS"
FILE="rib.${STAMP}.bz2"

echo "== fetching ${BASE}/${FILE}"
if ! curl -fL --retry 3 -o "${OUT}/${FILE}" "${BASE}/${FILE}"; then
  cat >&2 <<'MSG'
Download failed. RouteViews only keeps recent files at a given path and RIBs are
published on even hours, so try an explicit timestamp:
  ./fetch-mrt.sh ./mrt 2026.08 20260801.0000
Browse https://archive.routeviews.org/route-views2/bgpdata/ to find one that exists.
RIPE RIS is an alternative: https://data.ris.ripe.net/rrc00/
MSG
  exit 1
fi

echo "== decompressing (gobgp mrt inject reads uncompressed MRT)"
bunzip2 -kf "${OUT}/${FILE}"
DEC="${OUT}/rib.${STAMP}"
ls -la "$DEC"

cat <<MSG

Done: $DEC

Next:
  1. Copy or bind-mount it so peer containers see it as /mrt/<name>.
     The generated topology already bind-mounts build/<profile>/mrt to /mrt, so
     simply move it there:
         mv "$DEC" build/t3-fulltable/mrt/
  2. Set 'mrt: /mrt/$(basename "$DEC")' on the route-server and transit fleets in
     profiles/t3-fulltable.yaml.
  3. Regenerate: make generate PROFILE=t3-fulltable

Keep --only-best on (the default). Without it, every collector peer's view of
every prefix is loaded: a GoBGP issue report measured ~16.8 GiB versus ~3 GiB for
the same dump.
MSG
