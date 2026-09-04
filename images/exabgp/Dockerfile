# ExaBGP peer: protocol-nastiness and the policy-probe suite.
#
# Unlike GoBGP, ExaBGP publishes an official image
# (ghcr.io/exa-networks/exabgp), and it pre-creates the CLI named pipes, which is
# the part people trip over. We layer on the tools the harness needs.
ARG EXABGP_VERSION=5.0.9
FROM ghcr.io/exa-networks/exabgp:${EXABGP_VERSION}
USER root

# iproute2  : peer addressing and VLAN sub-interfaces
# iptables  : the `blackhole` flap primitive
# procps    : process inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables procps iputils-ping tcpdump \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/exabgp/run /var/log

# ExaBGP's environment file is INI, parsed with Python's configparser — it is NOT
# a flat key=value file. Writing `exabgp.daemon.user=root` as a bare line makes
# ExaBGP die at startup with:
#
#   configparser.MissingSectionHeaderError: File contains no section headers.
#   file: '/etc/exabgp/exabgp.env', line: 1 'exabgp.daemon.user=root'
#
# Section names and keys below were taken from `exabgp env`, which dumps the
# authoritative defaults in exactly this format.
#
#   daemonize=false  the harness backgrounds the process itself (docker exec -d)
#   user='root'      containers run as root; ExaBGP drops privileges by default
#   destination      left as stdout so the shell redirect owns the log file and
#                    two writers never interleave on it
#   speed=0.5        reactor poll interval; makes API commands land faster than
#                    the 1.0s default, which matters for churn events
RUN printf '%s\n' \
      '[exabgp.daemon]' \
      'daemonize = false' \
      "user = 'root'" \
      '' \
      '[exabgp.log]' \
      "destination = 'stdout'" \
      'level = INFO' \
      'short = true' \
      '' \
      '[exabgp.api]' \
      'ack = true' \
      '' \
      '[exabgp.reactor]' \
      'speed = 0.5' \
      > /etc/exabgp/exabgp.env

# Fail the BUILD, not the run, if that file is unparseable. `env -d` prints the
# delta from the defaults and exits non-zero on a malformed file. Note it does
# NOT catch unknown keys — those are silently ignored by ExaBGP — so this gates
# format only, which is the failure mode that actually occurred.
RUN exabgp --env-file /etc/exabgp/exabgp.env env -d \
    && echo "exabgp.env parsed successfully at build time"

ENTRYPOINT []
CMD ["sleep", "infinity"]
