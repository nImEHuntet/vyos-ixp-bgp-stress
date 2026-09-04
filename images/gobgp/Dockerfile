# GoBGP peer simulator.
#
# There is no official GoBGP container image: the project's .goreleaser.yml has no
# `dockers:` section, its release workflow pushes no image, ghcr.io/osrg/gobgp
# 404s, and docker.io/osrg/gobgp was last pushed in 2019. So we build from the
# release tarball, which ships both `gobgpd` (daemon) and `gobgp` (CLI) as static
# CGO-free binaries.
ARG GOBGP_VERSION=4.8.0
FROM debian:bookworm-slim AS fetch
ARG GOBGP_VERSION
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    url="https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSL "$url" -o /tmp/gobgp.tgz; \
    tar -xzf /tmp/gobgp.tgz -C /usr/local/bin gobgp gobgpd; \
    chmod +x /usr/local/bin/gobgp /usr/local/bin/gobgpd; \
    /usr/local/bin/gobgpd --version

FROM debian:bookworm-slim
COPY --from=fetch /usr/local/bin/gobgp /usr/local/bin/gobgp
COPY --from=fetch /usr/local/bin/gobgpd /usr/local/bin/gobgpd
# iproute2  : peer addressing, VLAN sub-interfaces, tc/netem impairment
# iptables  : the `blackhole` flap primitive (silently drop port 179)
# procps    : pgrep/pkill, used to find and signal individual gobgpd processes
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps iputils-ping tcpdump jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/gobgp /mrt /var/log
# Sleep forever: the harness starts one gobgpd per session explicitly, because
# each needs its own config, its own gRPC port, and its own lifecycle so it can be
# killed and restarted independently as a flap primitive.
CMD ["sleep", "infinity"]
