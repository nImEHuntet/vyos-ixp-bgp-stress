# VyOS IXP BGP stress harness.
#
# Typical first run:
#   make preflight
#   make vyos-image ISO=/path/to/vyos-1.5.0-generic-amd64.iso
#   make images
#   make generate PROFILE=t0-smoke VYOS_IMAGE=vyos-stress:1.5.0
#   make selftest-fast PROFILE=t0-smoke
#   sudo make fabrics PROFILE=t0-smoke
#   sudo make check-images PROFILE=t0-smoke
#   sudo make deploy  PROFILE=t0-smoke
#   sudo make prepare PROFILE=t0-smoke
#   make config  PROFILE=t0-smoke
#   make bringup PROFILE=t0-smoke
#   make converge PROFILE=t0-smoke
#   make probe   PROFILE=t0-smoke
#   make run     PROFILE=t0-smoke

# Bytecode goes outside the repo, always. One `sudo make` leaves root-owned
# __pycache__ directories behind, and every later unprivileged invocation then
# dies with PermissionError before running a single line — which is exactly
# what happened to `make selftest` after a `sudo make generate`. Per-uid so a
# root run and a user run cannot collide either.
PYCACHE   ?= /tmp/vyos-ixp-pycache-$(shell id -u)
export PYTHONPYCACHEPREFIX = $(PYCACHE)

# The offline suite generates its own copies of every profile. Sending those to
# the real build/ meant it fought whatever `make generate` had just written
# there, including its ownership. Keep them separate and disposable.
SELFTEST_OUT ?= /tmp/vyos-ixp-selftest-$(shell id -u)

PROFILE   ?= t0-smoke
STAMP     ?=
PEERS_DIR ?= $(BUILD)/results/peers

# The DUT container is named after the profile's node, not "dut" — on
# t3-fulltable it is `vyos`. Guessing "dut" is why run 2's host-metrics.csv had
# empty dut_* columns and its bundle had no DUT journal. See FINDINGS.md H-60.
DUT_NAME   ?= $(shell python3 -c 'import json;print(json.load(open("$(BUILD)/inventory.json"))["dut"]["name"])' 2>/dev/null || echo dut)
TEMPLATE  ?= Template IXP VyOS Configuration.md
BUILD     ?= build/$(PROFILE)
PY        ?= python3
ISO       ?=
VYOS_TAG   ?=               # empty: build-image.sh derives it from the ISO filename
VYOS_IMAGE ?=               # override dut.image at generate time, e.g. vyos-stress:1.5.0
NODES     ?= 60

.PHONY: help preflight host-tune vyos-image images generate fabrics fabrics-down \
        selftest-fast mrtcheck check-images \
        deploy destroy prepare config bringup converge peers probe exercise run ramp status \
        teardown report clean selftest

help:
	@printf 'VyOS IXP BGP stress harness\n\n'
	@printf '  usage: make <target> PROFILE=<tier> [VYOS_IMAGE=<tag>]\n\n'
	@grep -E '^[a-zA-Z_-]+:[^=]*##' $(MAKEFILE_LIST) \
		| sed -E 's/^([a-zA-Z_-]+):.*##[[:space:]]*/  \1|/' \
		| awk -F'|' '{printf "  %-14s %s\n", $$1, $$2}'
	@printf '\n  profiles: '
	@ls -1 profiles/t*.yaml 2>/dev/null | sed 's|profiles/||; s|\.yaml||' | tr '\n' ' '
	@printf '\n'

preflight: ## check the host can run the lab
	@scripts/preflight.sh

host-tune: ## apply host sysctls / limits (needs root; NODES=60)
	@sudo scripts/host-tune.sh $(NODES)

vyos-image: ## build the DUT image from an ISO you have (ISO=... ; VYOS_TAG optional)
	@test -n "$(ISO)" || { echo "usage: make vyos-image ISO=/path/to/vyos-1.5.0-generic-amd64.iso" >&2; exit 1; }
	@images/vyos/build-image.sh "$(ISO)" $(VYOS_TAG)

images: ## build the GoBGP and ExaBGP peer images
	docker build -t vyos-stress/gobgp:latest images/gobgp
	docker build -t vyos-stress/exabgp:latest images/exabgp

generate: ## render topology, peer configs, MRT tables and DUT config
	$(PY) -m harness.generate profiles/$(PROFILE).yaml --template "$(TEMPLATE)" \
		--out build --force $(if $(VYOS_IMAGE),--dut-image $(VYOS_IMAGE),)

fabrics: ## create the host bridges backing the peering LANs (root)
	@$(BUILD)/fabrics.sh up

fabrics-down: ## remove the host bridges (root)
	@$(BUILD)/fabrics.sh down

check-images: ## verify every image the topology needs exists locally
	@scripts/check-images.sh $(BUILD)

deploy: check-images ## containerlab deploy (root)
	cd $(BUILD) && containerlab deploy -t topology.clab.yml

destroy: ## containerlab destroy (root)
	cd $(BUILD) && containerlab destroy -t topology.clab.yml --cleanup

prepare: ## address the peer containers (root)
	@$(BUILD)/prepare.sh

config: ## push the generated VyOS configuration to the DUT
	$(PY) -m harness.runner --build $(BUILD) config

bringup: ## start generators and load their tables
	$(PY) -m harness.runner --build $(BUILD) bringup

converge: ## wait for the table to settle and report
	$(PY) -m harness.runner --build $(BUILD) converge

exercise: ## run every event kind once; report which log detectors fired
	$(PY) -m harness.runner --build $(BUILD) exercise

peers: ## per-peer accounting: announced vs accepted, and why
	$(PY) -m harness.runner --build $(BUILD) --results $(PEERS_DIR) peers

probe: ## policy-probe + RFC 7606 report
	$(PY) -m harness.runner --build $(BUILD) probe

run: ## warm up, converge, then run the chaos schedule
	$(PY) -m harness.runner --build $(BUILD) run

ramp: ## break-it mode: scale until a predicate trips
	$(PY) -m harness.runner --build $(BUILD) ramp

status: ## what is running
	$(PY) -m harness.runner --build $(BUILD) status

teardown: ## stop generators, clear impairments (lab stays deployed)
	$(PY) -m harness.runner --build $(BUILD) teardown

report: ## analyse the most recent RUN directory (ignores results/peers*)
	@d=$$(ls -1dt $(BUILD)/results/*/ 2>/dev/null \
	      | grep -E '/[0-9]{8}T[0-9]{6}/$$' | head -1); \
	 test -n "$$d" || { echo "no timestamped run directory under $(BUILD)/results" >&2; \
	                    echo "(results/peers* are accounting runs, not chaos runs)" >&2; exit 1; }; \
	 echo "analysing $$d"; \
	 $(PY) -m analysis.analyze "$$d"

selftest: ## validate every profile's artefacts offline (~4 min: builds all MRT tables)
	@$(PY) -m tests.selftest --out $(SELFTEST_OUT) $(if $(STRICT),--strict,)

selftest-fast: ## same checks, t0-smoke only (~20 s)
	@$(PY) -m tests.selftest --out $(SELFTEST_OUT) --only $(PROFILE) $(if $(STRICT),--strict,)

mrtcheck: ## structurally validate the generated MRT tables for PROFILE
	@$(PY) tests/mrtcheck.py $(BUILD)/mrt/*.mrt

monitor: ## start the host memory/stall recorder in the background (before `make run`)
	@if [ -f .host-monitor.pid ] && kill -0 "$$(cat .host-monitor.pid)" 2>/dev/null; then \
	   echo "host-monitor already running (pid $$(cat .host-monitor.pid))"; exit 0; fi; \
	 setsid nohup ./scripts/host-monitor.sh host-metrics.csv 5 "clab-$(PROFILE)-$(DUT_NAME)" \
	   .host-monitor.pid >host-monitor.out 2>&1 </dev/null & \
	 sleep 2; \
	 if [ -s .host-monitor.pid ] && kill -0 "$$(cat .host-monitor.pid)" 2>/dev/null; then \
	   echo "host-monitor pid $$(cat .host-monitor.pid) -> host-metrics.csv"; \
	   echo "  (setsid + nohup: survives make exiting and the SSH session dropping)"; \
	 else \
	   echo "host-monitor FAILED to start — see host-monitor.out" >&2; \
	   cat host-monitor.out >&2; exit 1; \
	 fi

monitor-stop: ## stop it, and say how many rows it captured
	@if [ -s .host-monitor.pid ] && kill -0 "$$(cat .host-monitor.pid)" 2>/dev/null; then \
	   kill "$$(cat .host-monitor.pid)"; sleep 1; \
	 else echo "host-monitor was not running"; fi; \
	 rm -f .host-monitor.pid; \
	 [ -f host-metrics.csv ] && \
	   echo "host-metrics.csv: $$(( $$(wc -l < host-metrics.csv) - 1 )) rows"

monitor-status: ## is it running, and is it still writing?
	@if [ -s .host-monitor.pid ] && kill -0 "$$(cat .host-monitor.pid)" 2>/dev/null; then \
	   echo "running (pid $$(cat .host-monitor.pid)), $$(( $$(wc -l < host-metrics.csv) - 1 )) rows, last row $$(tail -1 host-metrics.csv | cut -d, -f1)"; \
	 else echo "NOT running"; fi

collect: ## bundle everything needed to analyse the last run (root; after run, before destroy)
	./scripts/collect-run.sh $(PROFILE) $(STAMP)

fix-perms: ## reclaim the repo, and clear stale root-owned __pycache__
	@u=$${SUDO_UID:-$$(id -u)}; g=$${SUDO_GID:-$$(id -g)}; \
	 echo "chown -R $$u:$$g ."; sudo chown -R "$$u:$$g" .
	@sudo find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null; true
	@sudo rm -rf $(PYCACHE) $(SELFTEST_OUT)
	@echo "done. Bytecode now goes to $(PYCACHE), selftest scratch to $(SELFTEST_OUT)."

clean: ## remove generated build artefacts
	rm -rf build
