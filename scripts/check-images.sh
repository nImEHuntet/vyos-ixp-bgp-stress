#!/usr/bin/env bash
# Verify every image a generated topology references exists locally.
#
#   scripts/check-images.sh build/t0-smoke
#
# Why this exists: all three images in this lab are built locally and none of them
# is published anywhere. containerlab's default `image-pull-policy` is
# `IfNotPresent`, so a missing local image makes it ask Docker Hub, and Docker
# reports that as:
#
#   Error response from daemon: pull access denied for vyos-stress,
#   repository does not exist or may require 'docker login'
#
# which reads like an authentication problem rather than "you have not built the
# image, or you built it under a different tag". Generated topologies now pin
# `image-pull-policy: Never`, and this script gives the actionable message.
set -uo pipefail

BUILD="${1:-}"
if [ -z "$BUILD" ]; then
  echo "usage: $0 <build/PROFILE>" >&2
  exit 2
fi
TOPO="$BUILD/topology.clab.yml"
if [ ! -f "$TOPO" ]; then
  echo "no topology at $TOPO — run 'make generate PROFILE=...' first" >&2
  exit 2
fi

DOCKER=docker
if ! $DOCKER info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
  else
    echo "cannot reach the Docker daemon (try running this under sudo)" >&2
    exit 2
  fi
fi

# Images, one per line, deduplicated. Uses python3 for correct YAML rather than
# grepping, so a quoted or unusual tag cannot slip through.
mapfile -t IMAGES < <(python3 - "$TOPO" <<'PY'
import sys, yaml
topo = yaml.safe_load(open(sys.argv[1]))
seen, out = set(), []
for name, node in (topo.get("topology", {}).get("nodes", {}) or {}).items():
    img = (node or {}).get("image")
    if img and img not in seen:
        seen.add(img); out.append(img)
print("\n".join(out))
PY
)

if [ "${#IMAGES[@]}" -eq 0 ]; then
  echo "topology references no images (nothing to check)"
  exit 0
fi

missing=()
echo "== images referenced by $(basename "$BUILD")"
for img in "${IMAGES[@]}"; do
  [ -z "$img" ] && continue
  if id=$($DOCKER image inspect --format '{{.Id}}' "$img" 2>/dev/null); then
    size=$($DOCKER image inspect --format '{{.Size}}' "$img" 2>/dev/null)
    hsize=$(numfmt --to=iec --suffix=B "${size:-0}" 2>/dev/null || echo "${size:-?}")
    printf '  ok      %-34s %s\n' "$img" "$hsize"
  else
    printf '  MISSING %s\n' "$img"
    missing+=("$img")
  fi
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "all images present"
  exit 0
fi

echo
echo "!! ${#missing[@]} image(s) are not present locally. None of them is published to"
echo "   any registry, so containerlab cannot fetch them — build them first."
echo
for img in "${missing[@]}"; do
  case "$img" in
    */gobgp*|*gobgp*)
      echo "   $img"
      echo "     make images        # builds vyos-stress/gobgp and vyos-stress/exabgp"
      ;;
    */exabgp*|*exabgp*)
      echo "   $img"
      echo "     make images        # builds vyos-stress/gobgp and vyos-stress/exabgp"
      ;;
    *)
      echo "   $img   (the VyOS DUT image)"
      # Distinguish "not built" from "built under a different tag" — the second is
      # much more common, because build-image.sh derives the tag from the ISO
      # filename while the profiles declare :latest.
      others=$($DOCKER images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
               | grep -E '^vyos-stress:' | grep -vF "$img" || true)
      if [ -n "$others" ]; then
        echo "     A VyOS image IS built, under a different tag:"
        echo "$others" | sed 's/^/       /'
        echo
        echo "     Re-run generate — it now resolves this automatically:"
        echo "       make generate PROFILE=$(basename "$BUILD")"
        echo "     or name it explicitly:"
        echo "       make generate PROFILE=$(basename "$BUILD") VYOS_IMAGE=$(echo "$others" | head -1)"
        echo "     or tag it and skip regenerating:"
        echo "       $DOCKER tag $(echo "$others" | head -1) $img"
      else
        echo "     Not built at all:"
        echo "       make vyos-image ISO=/path/to/vyos-....iso"
      fi
      ;;
  esac
done
echo
echo "   Locally available VyOS-ish images right now:"
$DOCKER images --format '     {{.Repository}}:{{.Tag}}  ({{.Size}})' 2>/dev/null \
  | grep -iE 'vyos|gobgp|exabgp' || echo "     (none)"
exit 1
