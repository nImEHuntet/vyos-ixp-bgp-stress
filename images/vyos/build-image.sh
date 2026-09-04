#!/usr/bin/env bash
# Build the VyOS container image that containerlab's `vyosnetworks_vyos` kind needs,
# from a VyOS ISO you already have.
#
#   ./build-image.sh <vyos.iso> [image:tag]
#
# If you omit the tag, one is derived from the ISO filename, e.g.
#   vyos-1.5.0-generic-amd64.iso        -> vyos-stress:1.5.0
#   vyos-2026.03-generic-amd64.iso      -> vyos-stress:2026.03
#   vyos-2026.08.05-0033-rolling-...iso -> vyos-stress:2026.08.05-0033-rolling
# so `docker images` tells you which release is which.
#
# Why this step exists at all: there is no usable published VyOS container image.
# vyos-build's flavor system emits qemu-img formats (raw, qcow2, vdi, vhdx) and
# iso — there is no container/OCI flavor — and docker.io/vyos/vyos was last pushed
# in 2021 at 1.3-epa2. So the image is built from the ISO's squashfs, which is the
# path both docs.vyos.io and the containerlab kind page document.
#
# Any ISO works, including LTS. containerlab does carry a version warning: its
# VyOS node "has only been tested with v1.5 Q1 Stream or higher". This script
# checks the built image against that floor and tells you if you are below it.
set -euo pipefail

ISO="${1:?usage: build-image.sh <vyos.iso> [image:tag]}"
[ -f "$ISO" ] || { echo "no such ISO: $ISO" >&2; exit 1; }

# --- derive a tag from the ISO filename unless one was given -----------------
derive_tag() {
  local base ver
  base="$(basename "$1")"
  base="${base%.iso}"
  # strip the leading 'vyos-' and any trailing architecture/flavor suffix
  ver="${base#vyos-}"
  ver="${ver%-generic-amd64}"
  ver="${ver%-amd64}"
  ver="${ver%-generic-arm64}"
  ver="${ver%-arm64}"
  # docker tags allow [A-Za-z0-9_.-] only
  ver="$(printf '%s' "$ver" | tr -c 'A-Za-z0-9_.-' '-')"
  [ -n "$ver" ] || ver="latest"
  printf 'vyos-stress:%s' "$ver"
}

TAG="${2:-$(derive_tag "$ISO")}"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

for t in bsdtar sqfs2tar docker; do
  command -v "$t" >/dev/null || {
    echo "missing $t. Install with:" >&2
    echo "  apt-get install -y squashfs-tools-ng libarchive-tools" >&2
    exit 1; }
done

echo "== ISO   : $ISO"
echo "== tag   : $TAG"
echo
echo "== extracting live/filesystem.squashfs"
bsdtar -xf "$ISO" -C "$WORK" live/filesystem.squashfs

echo "== converting squashfs to a tar layer (this takes a minute)"
sqfs2tar "$WORK/live/filesystem.squashfs" > "$WORK/rootfs.tar"
echo "   rootfs.tar: $(du -h "$WORK/rootfs.tar" | cut -f1)"

cat > "$WORK/Dockerfile" <<'DOCKER'
FROM scratch
ADD rootfs.tar /
# getty and auditd are masked because they are meaningless in a container and
# noisy in the journal. kea-dhcp-ddns is disabled for the same reason. Everything
# else, FRR included, is left enabled so bgpd starts normally.
RUN for service in \
      getty.target \
      auditd.service \
      ; do systemctl mask $service; done && \
    systemctl disable kea-dhcp-ddns-server.service
HEALTHCHECK --start-period=10s CMD systemctl is-system-running
CMD ["/sbin/init"]
DOCKER

echo "== docker build $TAG"
docker build -t "$TAG" "$WORK"

# Also tag :latest. The profiles declare vyos-stress:latest, and requiring
# VYOS_IMAGE=<derived tag> on every `generate` is a footgun — miss it once and the
# topology names a tag that does not exist. The versioned tag stays for
# provenance, and `generate` echoes whichever it resolved.
LATEST="${TAG%%:*}:latest"
if [ "$LATEST" != "$TAG" ]; then
  docker tag "$TAG" "$LATEST"
  echo "== also tagged $LATEST (so the profile default resolves without VYOS_IMAGE)"
fi

# --- report what actually got built -----------------------------------------
# VyOS publishes no per-release FRR version table, so reading it out of the image
# is the only reliable way to know what you are about to test. Doing it here
# rather than after deployment means a mismatch is caught before you spend an
# hour on a large tier.
echo
echo "== image contents"

peek() { docker run --rm --entrypoint "$1" "$TAG" "${@:2}" 2>/dev/null || true; }

VYOS_VER="$(peek cat /usr/share/vyos/version.json)"
if [ -n "$VYOS_VER" ]; then
  if command -v python3 >/dev/null; then
    printf '   VyOS   : '
    printf '%s' "$VYOS_VER" | python3 -c \
      'import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get("version") or d.get("build_version") or "unknown",
          "  flavor=" + str(d.get("flavor", "?")),
          " built=" + str(d.get("built_on", d.get("build_date", "?"))))
except Exception:
    print("unparsed version.json")'
  else
    printf '   VyOS   : %s\n' "$(printf '%s' "$VYOS_VER" | tr -d '\n' | cut -c1-160)"
  fi
else
  LEGACY="$(peek cat /opt/vyatta/etc/version)"
  [ -n "$LEGACY" ] && printf '   VyOS   : %s\n' "$LEGACY" \
                   || echo "   VyOS   : could not read version from the image"
fi

FRR_VER="$(docker run --rm --entrypoint sh "$TAG" -c \
  "dpkg-query -W -f='\${Version}' frr 2>/dev/null" 2>/dev/null || true)"
if [ -n "$FRR_VER" ]; then
  echo "   FRR    : $FRR_VER"
  case "$FRR_VER" in
    8.4*|8.5*)
      echo "   !! FRR 8.4/8.5 shipped Extended Message Support, which increased BGP"
      echo "      memory usage significantly; the FRR 9.0 notes state the footprint"
      echo "      returned to normal. Expect inflated memory at full-table scale." ;;
    8.*|9.0*|9.1*)
      echo "   note: FRR 8.4-9.1 had large-community memory leaks (FRR issues 14828,"
      echo "      15459). Watch bgpd RSS across repeated announce/withdraw cycles." ;;
  esac
else
  echo "   FRR    : could not read the frr package version from the image"
fi

KERNEL="$(peek sh -c 'ls /lib/modules 2>/dev/null | head -1')"
[ -n "$KERNEL" ] && echo "   modules: /lib/modules/$KERNEL (the host kernel must match closely)"

# --- containerlab version floor ---------------------------------------------
BASE="$(basename "$ISO")"
case "$BASE" in
  *1.5*|*2025.*|*2026.*|*2027.*)
    echo
    echo "   containerlab's tested floor (v1.5 Q1 Stream or higher): satisfied." ;;
  *1.4*|*1.3*|*1.2*)
    echo
    echo "   !! containerlab documents its VyOS kind as tested only with 'v1.5 Q1"
    echo "      Stream or higher'. This looks like a 1.4-or-older image, which is"
    echo "      below that floor. It may still work, but you are off the documented"
    echo "      path — if nodes misbehave, retry on 1.5.0 before debugging further." ;;
  *)
    echo
    echo "   could not infer the release from the filename; confirm it is >= 1.5" ;;
esac

cat <<MSG

built: $TAG

Nothing else to do — it is tagged both $TAG and ${TAG%%:*}:latest, and
`make generate` resolves whichever is present. To be explicit anyway:

    make generate PROFILE=t0-smoke VYOS_IMAGE=$TAG

Two host requirements for this kind, neither of which this script can check:
  * containerlab bind-mounts /lib/modules read-only into the node so VyOS can
    load kernel modules such as nft_nat. The host needs /lib/modules for its
    running kernel.
  * Docker needs IPv6 enabled on its networks. Verify with:
        docker network inspect bridge -f '{{.EnableIPv6}}'

Record the FRR version above with any results you publish — VyOS ships no
per-release FRR table, so the image is the only authority, and FRR's BGP update
path is single-threaded, which makes the version and the host's single-core
performance the two numbers that matter most.
MSG
