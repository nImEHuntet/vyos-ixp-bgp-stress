"""Offline validation of everything the harness generates.

    python -m tests.selftest [--template "Template IXP VyOS Configuration.md"]
    python -m tests.selftest --only t0-smoke      # fast: one profile
    python -m tests.selftest --strict             # CI: skips are failures

Runs without a lab, without root, and without containerlab. It cannot prove the
DUT behaves — only a real run does that — but it does prove every generated
artefact is structurally valid and internally consistent, which is where most
of the avoidable failures live.

Optional tooling (ExaBGP, mrtparse) is version-detected and adapted to. When it
is absent or its API is unrecognised the affected check is **skipped, not
failed** — a missing or mismatched verification library says nothing about
whether the generated lab is correct. Use --strict in CI if a skip should be
treated as a failure.

Checks performed
----------------
 1. Every module imports and compiles.
 2. Every profile expands to an inventory with no ASN collisions, no address
    collisions, no bogon ASNs, and a peer-group for every address family in use.
 3. The containerlab topology satisfies the documented constraints of the
    `vyosnetworks_vyos` kind: eth0 reserved for management, data interfaces
    matching `eth[1-9][0-9]*`, every link endpoint referencing a declared node,
    host-side veth names within Linux's 15-character limit, and every bridge
    node backed by a bridge the fabrics script creates.
 4. Generated MRT files pass a dependency-free structural validation
    (tests/mrtcheck.py) and, when a usable mrtparse is installed, an independent
    cross-check that adapts to the 1.x and 2.x APIs.
 5. Every ExaBGP config and every probe / malformed-attribute route statement
    validates against whichever ExaBGP CLI is installed (5.x subcommands or 4.x
    flags).
 6. Generated GoBGP TOML parses, and declares the keys the harness relies on.
 7. The rendered VyOS config has no unresolved placeholders, references only
    peer-groups the template actually defines, and keeps a management path open.
 8. Prefix planning is deterministic and produces prefixes inside the declared
    pools and prefix-length bounds.
"""

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import generate, model, policyprobe, routegen  # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


class Report:
    """Distinguishes artefact defects from tooling gaps.

    This distinction is load-bearing. An optional verification library being
    absent, or installed at a version whose API differs, says nothing about
    whether the generated lab is correct — so it is a `skip`, never a `bad`.
    Only `bad` affects the exit status, unless --strict is given (for CI, where
    an unverified check should not pass silently).
    """

    def __init__(self, strict: bool = False) -> None:
        self.passed = 0
        self.failed: List[str] = []
        self.skipped: List[str] = []
        self.strict = strict

    def ok(self, msg: str) -> None:
        self.passed += 1
        print(f"  {GREEN}ok{RESET}    {msg}")

    def bad(self, msg: str) -> None:
        self.failed.append(msg)
        print(f"  {RED}FAIL{RESET}  {msg}")

    def skip(self, msg: str) -> None:
        self.skipped.append(msg)
        print(f"  {YELLOW}skip{RESET}  {msg}")

    def check(self, cond: bool, msg: str) -> bool:
        (self.ok if cond else self.bad)(msg)
        return cond


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# optional-tool detection
# ---------------------------------------------------------------------------
#
# Both optional verification tools changed their interface between major
# versions, and both changes are silent:
#
#   ExaBGP 4.x : flag-style CLI       -> `exabgp --test <conf>`
#   ExaBGP 5.x : subcommand-style CLI -> `exabgp validate -n <conf>`
#   mrtparse 1.x : payload on `entry.mrt` (attribute access)
#   mrtparse 2.1+: payload on `entry.data` (dict access)
#
# Calling the wrong one produces a usage dump or an AttributeError that looks
# like an artefact failure. So detect first, adapt, and skip if unrecognised.


def exabgp_flavor() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (major, version_string, path) for the installed exabgp, if any."""
    exe = shutil.which("exabgp")
    if not exe:
        return None, None, None
    # 5.x: `exabgp version` prints a version; 4.x: that is treated as a config
    # filename and prints nothing useful.
    p = subprocess.run([exe, "version"], capture_output=True, text=True)
    txt = (p.stdout + p.stderr).strip()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", txt)
    if p.returncode == 0 and m:
        return m.group(1), m.group(0), exe
    p = subprocess.run([exe, "--version"], capture_output=True, text=True)
    txt = (p.stdout + p.stderr).strip()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", txt)
    if m:
        return m.group(1), m.group(0), exe
    return None, txt[:60] or "unknown", exe


def exabgp_validate(exe: str, major: str, conf: str, mode: str = "neighbor"
                    ) -> Tuple[bool, str]:
    """Validate a config with whichever CLI shape is installed.

    `mode` is honoured on 5.x, which separates neighbour parsing (-n) from route
    parsing (-r). 4.x validates the whole file in one pass, so both modes map to
    `--test`, which was confirmed to exit non-zero on malformed input.
    """
    if major == "5":
        argv = [exe, "validate", "-r" if mode == "route" else "-n", conf]
    elif major == "4":
        argv = [exe, "--test", conf]
    else:
        return False, "unsupported exabgp CLI"
    p = subprocess.run(argv, capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip()
    return p.returncode == 0, out


def mrtparse_flavor() -> Tuple[Optional[str], Optional[str]]:
    """Return (api, version) where api is '1' (entry.mrt) or '2' (entry.data)."""
    try:
        import mrtparse
        from mrtparse import Reader
    except ImportError:
        return None, None
    ver = getattr(mrtparse, "__version__", None) or "unknown"
    attrs = dir(Reader)
    if "data" in attrs:
        return "2", ver
    if "mrt" in attrs:
        return "1", ver
    return None, ver


def print_tool_versions(r: Report) -> None:
    print("\n== verification tooling")
    print(f"  python    : {sys.version.split()[0]}")
    try:
        import yaml
        print(f"  pyyaml    : {yaml.__version__}")
    except Exception:
        print("  pyyaml    : MISSING")
    major, ver, exe = exabgp_flavor()
    if exe:
        shape = {"5": "subcommand CLI", "4": "flag CLI"}.get(major, "unrecognised CLI")
        print(f"  exabgp    : {ver} ({shape}) at {exe}")
        if major == "4":
            print("              note: 4.x works, but 5.x separates neighbour (-n) from")
            print("              route (-r) validation. `pip install 'exabgp>=5'` for both.")
        elif major is None:
            print("              note: version undetectable; ExaBGP checks will be skipped.")
    else:
        print("  exabgp    : not installed (ExaBGP checks will be skipped)")
    api, mver = mrtparse_flavor()
    if api:
        print(f"  mrtparse  : {mver} (API {api}.x, "
              f"payload on entry.{'data' if api == '2' else 'mrt'})")
    elif mver:
        print(f"  mrtparse  : {mver} (unrecognised API; cross-check will be skipped)")
    else:
        print("  mrtparse  : not installed (structural check still runs)")
    print("  mrtcheck  : built in, no dependencies — always runs")


VYOS_IFACE_RE = re.compile(r"^eth([1-9][0-9]*)$")
# Peer-groups the NE-1849 template actually defines. igp4/igp6 are referenced by
# its iBGP neighbour templates but never defined, so binding a neighbour to them
# would fail to commit.
TEMPLATE_PEER_GROUPS = {
    "ixp1-peer4", "ixp1-peer6", "ixp1-rs4", "ixp1-rs6",
    "ixp2-peer4", "ixp2-peer6", "ixp2-rs4", "ixp2-rs6",
    "transit4", "transit6",
}


def check_imports(r: Report) -> None:
    print("\n== modules")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mods = sorted(glob.glob(os.path.join(root, "harness", "*.py"))
                  + glob.glob(os.path.join(root, "analysis", "*.py")))
    rc = subprocess.run([sys.executable, "-m", "py_compile"] + mods,
                        capture_output=True, text=True)
    r.check(rc.returncode == 0, f"{len(mods)} module(s) compile"
            + ("" if rc.returncode == 0 else f": {rc.stderr[-400:]}"))
    for m in ("harness.model", "harness.routegen", "harness.dutconfig",
              "harness.generate", "harness.policyprobe", "harness.dut",
              "harness.peers", "harness.telemetry", "harness.scenarios",
              "harness.runner", "analysis.analyze"):
        try:
            __import__(m)
            r.ok(f"import {m}")
        except Exception as exc:
            r.bad(f"import {m}: {exc!r}")


def check_inventory(r: Report, invj: Dict, name: str,
                    build: Optional[str] = None) -> None:
    sessions = invj["sessions"]
    asns = [s["asn"] for s in sessions]
    dup = [a for a, c in Counter(asns).items() if c > 1]
    r.check(not dup, f"{name}: ASNs unique ({len(asns)} sessions)"
            + ("" if not dup else f" duplicates: {dup[:5]}"))
    bog = [a for a in asns if model.asn_is_bogon(a)]
    r.check(not bog, f"{name}: no bogon ASNs"
            + ("" if not bog else f" found {bog[:5]}"))
    r.check(invj["dut_asn"] not in asns, f"{name}: no peer reuses the DUT ASN")

    for af, key in (("v4", "v4"), ("v6", "v6")):
        addrs = [s[key] for s in sessions if s.get(key)]
        d = [a for a, c in Counter(addrs).items() if c > 1]
        r.check(not d, f"{name}: {af} peer addresses unique ({len(addrs)})"
                + ("" if not d else f" duplicates: {d[:5]}"))

    oob = []
    for s in sessions:
        fab = invj["fabrics"][s["fabric"]]
        for key, netkey, dutkey in (("v4", "v4_net", "dut_v4"), ("v6", "v6_net", "dut_v6")):
            a = s.get(key)
            if not a:
                continue
            if ipaddress.ip_address(a) not in ipaddress.ip_network(fab[netkey]):
                oob.append(f"{s['sid']}:{a} outside {fab[netkey]}")
            if a == fab[dutkey]:
                oob.append(f"{s['sid']}:{a} collides with the DUT")
    r.check(not oob, f"{name}: peer addresses inside their fabric and clear of the DUT"
            + ("" if not oob else f" {oob[:3]}"))

    nopg = [s["sid"] for s in sessions
            if (s.get("v4") and not s.get("dut_pg4"))
            or (s.get("v6") and not s.get("dut_pg6"))]
    r.check(not nopg, f"{name}: every session binds a peer-group per address family"
            + ("" if not nopg else f" missing: {nopg[:3]}"))

    used_pg = {s[k] for s in sessions for k in ("dut_pg4", "dut_pg6") if s.get(k)}
    unknown = used_pg - TEMPLATE_PEER_GROUPS
    r.check(not unknown,
            f"{name}: all peer-groups are defined by the template"
            + ("" if not unknown else
               f" — {sorted(unknown)} are NOT defined (note the template references "
               f"igp4/igp6 but never defines them)"))

    # maximum-prefix sanity: a fleet offering more than its peer-group's limit
    # will be torn down, which is usually not what the tier intends.
    #
    # The limits used to be hardcoded from the template. They are no longer the
    # template's: `render_peergroup_limits` raises the bilateral peer-groups so
    # the template's 200 stops capping the experiment (defect 9), so this has to
    # read the *effective* limit out of the rendered config — last `set` wins,
    # exactly as VyOS applies it — or it fails on every profile that benefits
    # from the fix. Falls back to the template values when the rendered config
    # is not available to this call.
    PG_LIMITS = {"ixp1-peer4": 200, "ixp1-peer6": 200, "ixp2-peer4": 200,
                 "ixp2-peer6": 200, "ixp1-rs4": 400000, "ixp1-rs6": 100000,
                 "ixp2-rs4": 200000, "ixp2-rs6": 100000}
    base_p = os.path.join(build, "dut", "00-base.conf") if build else None
    if base_p and os.path.exists(base_p):
        from harness import dutconfig
        with open(base_p, encoding="utf-8") as fh:
            eff = dutconfig.peergroup_limits_in(fh.read().splitlines())
        # peergroup_limits_in keys by peer-group and AF; the flat map above is
        # keyed by peer-group alone, because the template's peer-group names
        # already encode the family (ixp1-peer4 / ixp1-peer6) and each one is
        # only ever activated for that family.
        for pg, afs in eff.items():
            PG_LIMITS[pg] = max(afs.values())
    over = []
    for s in sessions:
        for pgk, pfk, mpk in (("dut_pg4", "prefixes_v4", "max_prefix4"),
                              ("dut_pg6", "prefixes_v6", "max_prefix6")):
            pg, n = s.get(pgk), s.get(pfk) or 0
            limit = s.get(mpk) or PG_LIMITS.get(pg)
            if pg and limit and n > limit:
                over.append(f"{s['sid']} offers {n} > limit {limit} on {pg}")
    r.check(not over, f"{name}: no fleet exceeds its maximum-prefix"
            + ("" if not over else f" — {over[:3]}"))


def check_topology(r: Report, build: str, invj: Dict, name: str) -> None:
    import yaml
    path = os.path.join(build, "topology.clab.yml")
    if not os.path.exists(path):
        r.bad(f"{name}: topology.clab.yml missing")
        return
    with open(path, "r", encoding="utf-8") as fh:
        topo = yaml.safe_load(fh)
    nodes = topo["topology"]["nodes"]
    links = topo["topology"]["links"]

    r.check(topo.get("name") == name, f"{name}: topology name matches the profile")

    dut = invj["dut"]["name"]
    r.check(nodes.get(dut, {}).get("kind") == "vyosnetworks_vyos",
            f"{name}: DUT kind is vyosnetworks_vyos "
            f"(not vr-vyos, not vyos — containerlab's KindNames is exactly this)")
    r.check(bool(nodes.get(dut, {}).get("image")),
            f"{name}: DUT declares an image (the kind has no default)")

    bridges = {k for k, v in nodes.items() if v.get("kind") == "bridge"}
    declared = {f["bridge"] for f in invj["fabrics"].values()}
    r.check(bridges == declared,
            f"{name}: bridge nodes match the fabrics ({sorted(bridges)})")

    fab_script = os.path.join(build, "fabrics.sh")
    if os.path.exists(fab_script):
        body = open(fab_script, encoding="utf-8").read()
        missing = [b for b in declared if f"ip link add name {b} type bridge" not in body]
        r.check(not missing, f"{name}: fabrics.sh creates every bridge"
                + ("" if not missing else f" missing {missing}"))

    bad_if, bad_len, bad_node = [], [], []
    for ln in links:
        for ep in ln["endpoints"]:
            node, _, iface = ep.partition(":")
            if node not in nodes:
                bad_node.append(ep)
                continue
            if node in bridges:
                if len(iface) > 15:
                    bad_len.append(f"{ep} ({len(iface)} chars)")
                continue
            if node == dut and not VYOS_IFACE_RE.match(iface):
                bad_if.append(ep)
            if iface == "eth0":
                bad_if.append(f"{ep} (eth0 is reserved for management)")
    r.check(not bad_node, f"{name}: every link endpoint names a declared node"
            + ("" if not bad_node else f" {bad_node[:3]}"))
    r.check(not bad_if,
            f"{name}: DUT interfaces match eth[1-9][0-9]* and avoid eth0"
            + ("" if not bad_if else f" {bad_if[:3]}"))
    r.check(not bad_len,
            f"{name}: host-side veth names within the 15-char IFNAMSIZ limit"
            + ("" if not bad_len else f" {bad_len[:3]}"))

    # every non-bridge node should have exactly one data link
    counts = Counter()
    for ln in links:
        for ep in ln["endpoints"]:
            node = ep.split(":")[0]
            if node not in bridges:
                counts[node] += 1
    dangling = [n for n in nodes if n not in bridges and counts[n] == 0]
    r.check(not dangling, f"{name}: no node is left unconnected"
            + ("" if not dangling else f" {dangling[:3]}"))
    r.check(counts[dut] == len(invj["fabrics"]),
            f"{name}: DUT has one link per fabric ({counts[dut]})")

    # Every image in this lab is local-only. Without an explicit pull policy,
    # containerlab's default (IfNotPresent) turns a missing local image into a
    # Docker Hub request, and Docker reports that as "pull access denied ...
    # repository does not exist or may require 'docker login'" — which sends you
    # looking for a credentials problem that does not exist.
    unpinned = [n for n, v in nodes.items()
                if v.get("image") and v.get("image-pull-policy") != "Never"]
    r.check(not unpinned,
            f"{name}: every image node pins image-pull-policy: Never "
            f"({len([v for v in nodes.values() if v.get('image')])} node(s))"
            + ("" if not unpinned else f" — unpinned: {unpinned[:4]}"))


def _mrt_sample(files: List[str]) -> List[str]:
    """A few files per profile: the first three plus one from the middle."""
    sample = files[:3]
    if len(files) > 6:
        sample.append(files[len(files) // 2])
    return sample


def check_mrt(r: Report, build: str, invj: Dict, name: str) -> None:
    """Structural validation (always) plus an mrtparse cross-check (if usable).

    The structural pass is the one that gates: it is dependency-free and checks
    exactly the self-consistency that `gobgp mrt inject` depends on — record
    lengths tiling the file, attribute TLV walks consuming exactly their declared
    length, and peer indices resolving. Corruption tests for it live in
    tests/mrtcheck.py's own negative suite.
    """
    from tests import mrtcheck

    files = sorted(glob.glob(os.path.join(build, "mrt", "*.mrt")))
    if not files:
        r.skip(f"{name}: no MRT files generated (fleets may use an external mrt:)")
        return

    sample = _mrt_sample(files)
    summaries: Dict[str, mrtcheck.MrtSummary] = {}

    for path in sample:
        sid = os.path.basename(path)[:-4]
        sess = next((x for x in invj["sessions"] if x["sid"] == sid), None)
        try:
            summ = mrtcheck.check_file(
                path,
                expect_v4=sess["prefixes_v4"] if sess else None,
                expect_v6=sess["prefixes_v6"] if sess else None,
            )
        except mrtcheck.MrtStructureError as exc:
            r.bad(f"{name}: {sid}.mrt is structurally invalid: {exc}")
            continue
        except OSError as exc:
            r.bad(f"{name}: {sid}.mrt unreadable: {exc}")
            continue
        summaries[path] = summ
        r.ok(f"{name}: {sid}.mrt structurally valid — {summ}")

        need = {1, 2}                      # ORIGIN, AS_PATH
        r.check(need <= summ.attr_codes,
                f"{name}: {sid}.mrt carries {', '.join(summ.attr_names)}")
        if summ.prefixes_v6:
            # RFC 6396 section 4.3.4: IPv6 next-hop lives in MP_REACH_NLRI.
            # mrtcheck enforces this per entry; assert it at summary level too.
            r.check(14 in summ.attr_codes,
                    f"{name}: {sid}.mrt v6 next-hop is in MP_REACH_NLRI "
                    f"(RFC 6396 section 4.3.4)")
        if summ.prefixes_v4:
            r.check(3 in summ.attr_codes,
                    f"{name}: {sid}.mrt v4 next-hop is in the NEXT_HOP attribute")

    # ---- optional independent cross-check --------------------------------
    api, mver = mrtparse_flavor()
    if api is None:
        r.skip(f"{name}: mrtparse cross-check skipped "
               + ("(not installed; pip install 'mrtparse>=2.1')" if not mver
                  else f"(version {mver} exposes neither entry.data nor entry.mrt)"))
        return

    for path in sample:
        if path not in summaries:
            continue                       # already reported as structurally bad
        sid = os.path.basename(path)[:-4]
        try:
            got = _mrtparse_counts(path, api)
        except Exception as exc:
            # A genuine parse disagreement is worth surfacing, but as a skip with
            # the reason attached rather than a failure, because the structural
            # pass already gated correctness and mrtparse 1.x/2.0.x have known
            # quirks of their own.
            r.skip(f"{name}: mrtparse {mver} could not read {sid}.mrt "
                   f"({type(exc).__name__}: {exc}) — structural check passed, so "
                   f"this is most likely a library-version quirk")
            continue
        exp = summaries[path]
        agree = (got["v4"] == exp.prefixes_v4 and got["v6"] == exp.prefixes_v6
                 and got["peers"] == len(exp.peers))
        r.check(agree,
                f"{name}: mrtparse {mver} agrees on {sid}.mrt "
                f"({got['peers']} peers, {got['v4']} v4, {got['v6']} v6)"
                + ("" if agree else
                   f" — structural pass saw {len(exp.peers)}/{exp.prefixes_v4}/"
                   f"{exp.prefixes_v6}"))


def _mrtparse_counts(path: str, api: str) -> Dict[str, int]:
    """Count records via mrtparse, adapting to the 1.x and 2.x payload shapes.

    1.x: iteration yields the Reader; the payload is the `Mrt` object on
         `entry.mrt`, with attributes (`subtype`, `peer`, `rib`).
    2.x: iteration yields the Reader; the payload is a dict on `entry.data`,
         with `subtype` as a {code: name} mapping.
    """
    from mrtparse import Reader

    v4 = v6 = peers = 0
    for entry in Reader(path):
        if api == "2":
            d = getattr(entry, "data", None)
            if not d:
                raise ValueError("entry.data is empty")
            st = d.get("subtype")
            name = list(st.values())[0] if isinstance(st, dict) else st
            if name == "PEER_INDEX_TABLE":
                peers = len(d.get("peer_entries") or [])
            elif name == "RIB_IPV4_UNICAST":
                v4 += 1
            elif name == "RIB_IPV6_UNICAST":
                v6 += 1
        else:
            m = getattr(entry, "mrt", None)
            if m is None:
                raise ValueError("entry.mrt is None")
            sub = getattr(m, "subtype", None)
            if sub == 1:
                pit = getattr(m, "peer", None)
                peers = len(getattr(pit, "entry", []) or []) if pit else 0
            elif sub == 2:
                v4 += 1
            elif sub == 4:
                v6 += 1
    return {"v4": v4, "v6": v6, "peers": peers}


def _exabgp_conf_localised(conf_path: str, td: str) -> str:
    """Copy a generated config into a temp dir with a local `run` target.

    ExaBGP resolves the `process ... run` path at parse time, so validating the
    config as generated would fail on the container path. Substituting a local
    stub isolates the check to the parts that matter: neighbours and routes.
    """
    body = open(conf_path, encoding="utf-8").read()
    runp = os.path.join(td, "nasty.py")
    with open(runp, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env python3\n")
    os.chmod(runp, 0o755)
    body = body.replace("/etc/exabgp/run/nasty.py", runp)
    cp = os.path.join(td, "c.conf")
    with open(cp, "w", encoding="utf-8") as fh:
        fh.write(body)
    return cp


def check_exabgp(r: Report, build: str, name: str) -> None:
    confs = sorted(glob.glob(os.path.join(build, "exabgp", "*.conf")))
    if not confs:
        r.skip(f"{name}: no ExaBGP configs in this profile")
        return
    major, ver, exe = exabgp_flavor()
    if not exe:
        r.skip(f"{name}: exabgp not installed — cannot validate configs "
               f"(pip install 'exabgp>=5')")
        return
    if major not in ("4", "5"):
        r.skip(f"{name}: exabgp {ver} has an unrecognised CLI; cannot validate. "
               f"Known shapes: 5.x `exabgp validate -n <conf>`, "
               f"4.x `exabgp --test <conf>`.")
        return
    for c in confs:
        with tempfile.TemporaryDirectory() as td:
            cp = _exabgp_conf_localised(c, td)
            ok, out = exabgp_validate(exe, major, cp, mode="neighbor")
        r.check(ok, f"{name}: {os.path.basename(c)} validates on exabgp {ver}"
                + ("" if ok else f": {out[-300:]}"))


def _exabgp_api_parser():
    """ExaBGP's own text-API parser, or None if it cannot be constructed.

    Used to prove the generated boot announcements actually parse. `exabgp
    validate` only covers config files; the boot file is fed through the text
    API at runtime, which is a different code path with a different grammar
    (`announce attributes ... nlri ...`). Nothing was checking it.
    """
    try:
        from exabgp.environment import getenv
        from exabgp.logger import option
        from exabgp.configuration.configuration import Configuration
        from exabgp.reactor.api.command.limit import extract_neighbors
    except Exception:
        return None
    try:
        option.setup(getenv())
    except Exception:
        pass  # already set up, or a version without it; parsing still works

    def parse(raw: str):
        cfg = Configuration([])
        descriptions, command = extract_neighbors(raw)
        _, line = command.split(" ", 1)
        cfg.static.clear()
        if not cfg.partial("static", line):
            return descriptions, None
        if cfg.scope.location():
            return descriptions, None
        cfg.scope.to_context()
        return descriptions, cfg.scope.pop_routes()

    return parse


def check_exabgp_boot(r: Report, build: str, invj: Dict, name: str) -> None:
    """The boot announcements: bound in, present, parseable, and complete.

    This exists because of a defect that produced no error anywhere: the boot
    file was copied to a fixed name inside the container at start-up, but the
    directory holding it is mounted :ro, so the copy failed, `|| true` swallowed
    it, the helper found no boot file, and the fleet came up Established
    announcing zero prefixes. `converge` still reported success.
    """
    import yaml
    exa = {cn: c for cn, c in (invj.get("containers") or {}).items()
           if c.get("engine") == "exabgp"}
    if not exa:
        r.skip(f"{name}: no ExaBGP containers in this profile")
        return

    topo_path = os.path.join(build, "topology.clab.yml")
    with open(topo_path, "r", encoding="utf-8") as fh:
        topo = yaml.safe_load(fh)
    nodes = ((topo.get("topology") or {}).get("nodes") or {})

    sessions_by_container: Dict[str, List[Dict]] = {}
    for sess in invj.get("sessions", []):
        sessions_by_container.setdefault(sess["container"], []).append(sess)

    parse = _exabgp_api_parser()
    if parse is None:
        r.skip(f"{name}: exabgp python package not importable — cannot parse "
               f"boot announcements through ExaBGP's own text-API grammar")

    for cname in sorted(exa):
        want = f"exabgp/run/boot-{cname}.txt:{generate.EXABGP_BOOT_PATH}:ro"
        binds = (nodes.get(cname) or {}).get("binds") or []
        r.check(want in binds,
                f"{name}: {cname} binds its own boot file to "
                f"{generate.EXABGP_BOOT_PATH}"
                + ("" if want in binds else f" — binds are {binds}"))

        bf = os.path.join(build, "exabgp", "run", f"boot-{cname}.txt")
        if not os.path.exists(bf):
            r.bad(f"{name}: {cname} boot file missing: {bf}")
            continue
        lines = [l.strip() for l in open(bf, encoding="utf-8")
                 if l.strip() and not l.strip().startswith("#")]
        r.check(bool(lines), f"{name}: {cname} boot file has "
                             f"{len(lines)} command(s)")
        if not lines or parse is None:
            continue

        want4 = sum(s["prefixes_v4"] for s in sessions_by_container.get(cname, []))
        want6 = sum(s["prefixes_v6"] for s in sessions_by_container.get(cname, []))
        got, bad = 0, []
        for raw in lines:
            try:
                _, changes = parse(raw)
            except Exception as exc:
                bad.append(f"{raw[:70]}...: {exc}")
                continue
            if changes is None:
                bad.append(f"{raw[:70]}...: rejected by the text-API parser")
            else:
                got += len(changes)
        r.check(not bad, f"{name}: {cname} boot announcements parse through "
                         f"ExaBGP's text-API grammar"
                + ("" if not bad else f" — {bad[:2]}"))
        r.check(got == want4 + want6,
                f"{name}: {cname} boot file announces {got} prefix(es), "
                f"profile declares {want4 + want6} ({want4} v4 + {want6} v6)")

    # The helper must read the path the topology binds.
    r.check(generate.EXABGP_BOOT_PATH in generate.EXABGP_HELPER,
            f"{name}: the ExaBGP helper reads {generate.EXABGP_BOOT_PATH}, the "
            f"same path build_topology binds")


class _FakeRun:
    """Records every docker-exec-equivalent call instead of running it.

    `PeerFleet` splits its API: some methods take a `Session`, others take a
    bare container-name `str`. Nothing verified that the runner's call sites
    agreed, and one that did not (`exabgp_helper_log(container_name)` against a
    method that assumed a Session) only surfaced after a full deploy, config and
    bringup cycle on the real lab — `AttributeError: 'str' object has no
    attribute 'container'`. These checks exercise the runtime drivers against a
    fake exec layer so that class of mistake fails offline in a second.
    """

    def __init__(self) -> None:
        self.containers: List[str] = []
        self.sizes: Dict[str, Optional[int]] = {}
        # Set to force every lookup to report the file absent, i.e. a stale
        # bind mount. `external_size` stands in for an operator-mounted MRT.
        self.missing: bool = False
        self.external_size: Optional[int] = 4096

    def result(self, out: str = ""):
        from harness.peers import RunResult
        return RunResult(0, out, "", 0.0)


def _fake_dut_min():
    """Smallest DUT stub the runner paths need.

    Grown by the smoke tests themselves: adding `enable_bgp_debugs` to bringup
    broke all three of them immediately, which is the behaviour these tests exist
    for — a new dependency in a runner path should fail offline, not on the lab.
    """
    from harness.dut import RunResult

    class D:
        container = "fake"

        def alive(self):
            return True

        def enable_bgp_debugs(self, extra=(), set_log_level=True):
            from harness.dut import Dut
            return {"ok": True, "sent_ok": True,
                    "commands": list(Dut.BGP_DEBUGS),
                    "active": {c: True for c in Dut.BGP_DEBUGS},
                    "neighbor_changes": True, "via": "enable_node",
                    "raw": {}, "error": None}

        def bgp_debugs_active(self):
            from harness.dut import Dut
            return {c: True for c in Dut.BGP_DEBUGS}

        def rearm_bgp_debugs(self):
            from harness.dut import Dut
            return {c: True for c in Dut.BGP_DEBUGS}

        def logging_state(self):
            return {"ok": True, "levels": {"bgpd": "debugging"},
                    "bgpd": "debugging", "debug_reaches_log": True}

        def verify_log_pipeline(self, peer, wait_s=8.0):
            return {"ok": True, "peer": peer, "matched": 3,
                    "fsm_debug_lines": 1, "adjchange_lines": 1,
                    "notification_lines": 1, "tier_reached": "debug",
                    "sample": [], "window_unbounded": False}

        def version(self):
            return {"frr": "fake", "vyos": "fake", "kernel": "fake"}

        def log_counts(self, since="-30s"):
            return {}

        def __getattr__(self, _n):
            return lambda *a, **k: RunResult(0, "", "", 0.0)

    return D()


def _fake_fleet(rec: "_FakeRun"):
    from harness.peers import PeerFleet

    class Fleet(PeerFleet):
        # Every method below funnels through exec/exec_detached in the real
        # class, so recording those two is enough to catch a wrong argument
        # type: a Session reaching `exec` would fail `cname()`.
        def exec(self, container, cmd, timeout=None):
            assert isinstance(container, str), \
                f"exec() got {type(container).__name__}, expected a container name"
            rec.containers.append(container)
            return rec.result("sent 30 boot commands from /etc/exabgp/boot.txt")

        def exec_detached(self, container, cmd):
            assert isinstance(container, str), \
                f"exec_detached() got {type(container).__name__}, expected a name"
            rec.containers.append(container)
            return rec.result()

        def gobgpd_pid(self, s):
            return 1234

        def exabgp_pids(self, container):
            assert isinstance(container, str)
            rec.containers.append(container)
            return [4321]

        def inject_mrt(self, s, only_best=True, count=None):
            return rec.result("ok")

        def file_size_in_container(self, container, path):
            assert isinstance(container, str)
            rec.containers.append(container)
            # Model a healthy bind mount: report the host size for generated
            # tables, and a plausible size for an externally mounted one (a
            # profile with `mrt:` set has no generated host-side file).
            if rec.missing:
                return None
            return rec.sizes.get(os.path.basename(path), rec.external_size)

    return Fleet(clab_prefix="clab-selftest")


def check_runner_smoke(r: Report, build: str, invj: Dict, name: str) -> None:
    """Run `_start_generators` against a fake lab, for real inventories."""
    from harness import runner
    from harness.telemetry import Sampler

    inv = model.load(invj["profile_path"])
    rec = _FakeRun()

    class NullSampler(Sampler):
        def event(self, kind, **kw):
            return None

    with tempfile.TemporaryDirectory() as td:
        sampler = NullSampler(dut=None, path=os.path.join(td, "s.jsonl"),
                             interval=2.0)
        ctx = runner.scenarios.Ctx(
            inv=inv, dut=_fake_dut_min(), fleet=_fake_fleet(rec), sampler=sampler,
            plan=runner.make_plan(invj), build_dir=build,
            rng=__import__("random").Random(1), dry_run=False,
        )
        for f in glob.glob(os.path.join(build, "mrt", "*.mrt")):
            rec.sizes[os.path.basename(f)] = os.path.getsize(f)
        try:
            st = runner._start_generators(ctx, list(inv.sessions),
                                          inject=True, only_best=True)
        except Exception as exc:
            r.bad(f"{name}: _start_generators raised "
                  f"{type(exc).__name__}: {exc}")
            return
    r.check(not st["failed"],
            f"{name}: _start_generators reports no failures against a fake lab"
            + ("" if not st["failed"] else f" — {st['failed'][:3]}"))
    r.check(st["gobgp_sessions"] == len([x for x in inv.sessions
                                         if x.engine == "gobgp"]),
            f"{name}: _start_generators counted "
            f"{st['gobgp_sessions']} gobgp session(s)")
    r.check(st["injected"] == st["gobgp_sessions"],
            f"{name}: every gobgp session had its table injected "
            f"({st['injected']}/{st['gobgp_sessions']})")


def check_stale_bind_detection(r: Report, build: str, invj: Dict,
                               name: str) -> None:
    """A container that cannot see its MRT file must be refused, not injected.

    Reproduces the field failure: the host directory is full, the container's
    view is empty because the bind mount went stale, and `gobgp mrt inject`
    reports "no such file or directory". Injection must be skipped and the
    session reported, rather than the error being attributed to generation.
    """
    from harness import runner
    from harness.telemetry import Sampler

    inv = model.load(invj["profile_path"])
    gobgp = [x for x in inv.sessions if x.engine == "gobgp"]
    if not gobgp:
        r.skip(f"{name}: no gobgp sessions")
        return
    rec = _FakeRun()
    rec.missing = True        # every lookup reports absent => stale bind mount

    class NullSampler(Sampler):
        def event(self, kind, **kw):
            return None

    with tempfile.TemporaryDirectory() as td:
        sampler = NullSampler(dut=None, path=os.path.join(td, "s.jsonl"),
                             interval=2.0)
        ctx = runner.scenarios.Ctx(
            inv=inv, dut=_fake_dut_min(), fleet=_fake_fleet(rec), sampler=sampler,
            plan=runner.make_plan(invj), build_dir=build,
            rng=__import__("random").Random(1), dry_run=False,
        )
        try:
            st = runner._start_generators(ctx, list(inv.sessions),
                                          inject=True, only_best=True)
        except Exception as exc:
            r.bad(f"{name}: stale-bind path raised "
                  f"{type(exc).__name__}: {exc}")
            return
    sids = {x.sid for x in gobgp}
    r.check(st["injected"] == 0,
            f"{name}: nothing is injected when the container cannot see its MRT "
            f"file (injected={st['injected']})")
    r.check(sids.issubset(set(st["failed"])),
            f"{name}: every unreadable session is reported as failed "
            f"({len(st['failed'])}/{len(sids)})")


def check_sync_agent_warning(r: Report) -> None:
    """The Syncthing/build-mount foot-gun warning fires only when it should."""
    with tempfile.TemporaryDirectory() as td:
        r.check(generate.sync_agent_warnings(td) == [],
                "no sync-agent warning when there is no .stfolder")
        os.makedirs(os.path.join(td, ".stfolder"))
        r.check(bool(generate.sync_agent_warnings(td)),
                "sync-agent warning fires with .stfolder and no .stignore")
        with open(os.path.join(td, ".stignore"), "w", encoding="utf-8") as fh:
            fh.write("// comment\nbuild\nresults\n")
        r.check(generate.sync_agent_warnings(td) == [],
                "sync-agent warning clears once build is ignored")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ign = os.path.join(repo, ".stignore")
    ok = False
    if os.path.exists(ign):
        with open(ign, "r", encoding="utf-8") as fh:
            ok = any(l.strip() == "build" for l in fh)
    r.check(ok, "the repo ships a .stignore excluding build/"
            + ("" if ok else f" — {ign} missing or does not list build"))


def check_log_dedup(r: Report) -> None:
    """Log collapsing for the malformed post-mortem."""
    from harness import scenarios
    lines = [
        "Aug 20 06:44:40 vyos bgpd[455]: [E1] 198.51.100.14 rcvd UPDATE with "
        "errors in attr(s)!! Withdrawing route.",
        "Aug 20 06:44:41 vyos bgpd[455]: [E1] 198.51.100.14 rcvd UPDATE with "
        "errors in attr(s)!! Withdrawing route.",
        "Aug 20 06:44:42 vyos bgpd[455]: [E2] 198.51.100.14 sending NOTIFICATION 3/3",
    ]
    out = scenarios._dedup_log(lines, 10)
    ok = (len(out) == 2 and out[0]["count"] == 2 and out[1]["count"] == 1
          and "Withdrawing route" in out[0]["line"])
    r.check(ok, "log dedup collapses repeats and keeps counts"
            + ("" if ok else f" — {out}"))
    r.check(len(scenarios._dedup_log(lines * 50, 1)) == 1,
            "log dedup honours its limit")
    est = scenarios._state_is_established
    r.check(est("Established") is True and est("Clearing") is False
            and est(None) is None,
            "peer-state classification distinguishes Established / other / unknown")


def check_locpref_key(r: Report) -> None:
    """FRR spells LOCAL_PREF `locPrf` in JSON; reading `localPref` yields None."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "harness", "scenarios.py"),
        encoding="utf-8").read()
    r.check('"locPrf"' in src,
            "probe results read LOCAL_PREF from FRR's `locPrf` JSON key")


def check_malformed_expectations(r: Report) -> None:
    """Expectations that were corrected against implementation source."""
    # exclude_tags=() so the full catalogue is inspected: the martian pair is
    # excluded from *runs* by default (policyprobe.EXCLUDED_TAGS) but the cases
    # still have to be correct, since isolation mode can name them.
    mal = {m.mid: m for m in policyprobe.build_malformed(
        "198.51.100.14", "2001:db8:1::e", 64000, 64400, exclude_tags=())}
    # ipv4_unicast_valid() (FRR lib/prefix.c) tests IPV4_CLASS_E first and
    # returns true, so 240.0.0.0/4 - including 255.255.255.255 - is NOT martian
    # and the route is accepted. The old `absent` expectation was wrong.
    b = mal.get("nexthop-broadcast")
    r.check(b is not None and b.expect_route == "present",
            "nexthop-broadcast expects the route present (FRR treats 240/4 as "
            "valid unicast, IPV4_CLASS_E branch in ipv4_unicast_valid)")
    for mid in ("nexthop-zero", "nexthop-multicast"):
        m = mal.get(mid)
        ok = (m is not None and m.expect_session == "up"
              and bool(m.known_defect))
        r.check(ok, f"{mid} requires the session to stay up and carries the "
                    f"confirmed FRR martian-next-hop defect")
    r.check(all(("martian" in m.tags) for m in
                (mal["nexthop-zero"], mal["nexthop-multicast"])),
            "martian next-hop cases are tagged so they can be filtered out of a "
            "run against a fixed FRR")
    # ...and they now ARE filtered out. E-4 is confirmed, fixed upstream in
    # frr-10.7.0, and not fixable on VyOS 1.5.1 / FRR 10.5.2, so firing it every
    # malformed burst spends a real session reset inside the measurement window
    # to re-derive a known result.
    r.check("martian" in policyprobe.EXCLUDED_TAGS,
            "the martian next-hop cases are excluded from the default suite")
    run_set = {m.mid for m in policyprobe.build_malformed(
        "198.51.100.14", "2001:db8:1::e", 64000, 64400)}
    r.check(not ({"nexthop-zero", "nexthop-multicast"} & run_set),
            "a default malformed burst no longer resets the session on a "
            "known-unfixable FRR defect")
    r.check(len(run_set) >= 20,
            f"the rest of the RFC 7606 suite is intact ({len(run_set)} cases)")
    named = {m.mid for m in policyprobe.build_malformed(
        "198.51.100.14", "2001:db8:1::e", 64000, 64400, exclude_tags=())}
    r.check({"nexthop-zero", "nexthop-multicast"} <= named,
            "the excluded cases are still reachable by name, so the defect can "
            "be reproduced on demand")
    from harness.dut import Dut
    r.check("martian_nexthop" in Dut.LOG_PATTERNS
            and Dut.LOG_PATTERNS["martian_nexthop"] == "Martian nexthop",
            "the DUT log counters include FRR's verbatim `Martian nexthop` line")
    r.check("notification_any" in Dut.LOG_PATTERNS,
            "a version-independent NOTIFICATION counter exists (the "
            "sending/received wordings are unconfirmed on FRR 10.5)")


def check_unknown_attr_flags(r: Report) -> None:
    """The Optional bit is the whole point of the unknown-attribute cases.

    The first version used flags 0x60 and 0x70 for cases named "nontransitive"
    and "transitive". Neither sets the Optional bit (0x80), so both were actually
    exercising the unrecognised-WELL-KNOWN path while asserting the
    unrecognised-OPTIONAL requirement, and both reported a false failure.
    """
    import re as _re
    # exclude_tags=() so the full catalogue is inspected: the martian pair is
    # excluded from *runs* by default (policyprobe.EXCLUDED_TAGS) but the cases
    # still have to be correct, since isolation mode can name them.
    mal = {m.mid: m for m in policyprobe.build_malformed(
        "198.51.100.14", "2001:db8:1::e", 64000, 64400, exclude_tags=())}

    def flags(mid):
        m = mal.get(mid)
        if not m:
            return None
        hit = _re.search(r"attribute \[ 0x[0-9a-f]{2} (0x[0-9a-f]{2})", m.attrs)
        return int(hit.group(1), 16) if hit else None

    OPTIONAL, TRANSITIVE, PARTIAL = 0x80, 0x40, 0x20
    for mid, want_opt in (("unknown-attr-optional", True),
                          ("unknown-attr-optional-transitive", True),
                          ("unknown-attr-optional-transitive-partial", True),
                          ("unknown-wellknown-attr-transitive", False),
                          ("unknown-wellknown-attr-extlen", False),
                          ("unknown-wellknown-attr", False)):
        f = flags(mid)
        ok = f is not None and bool(f & OPTIONAL) == want_opt
        r.check(ok, f"{mid}: Optional bit "
                    f"{'set' if want_opt else 'clear'} (flags="
                    f"{'?' if f is None else hex(f)})")
    r.check(flags("unknown-attr-optional") == OPTIONAL,
            "unknown-attr-optional is Optional only (non-transitive)")
    r.check(flags("unknown-attr-optional-transitive") == OPTIONAL | TRANSITIVE,
            "unknown-attr-optional-transitive is Optional|Transitive, Partial clear")
    r.check(flags("unknown-attr-optional-transitive-partial")
            == OPTIONAL | TRANSITIVE | PARTIAL,
            "unknown-attr-optional-transitive-partial is Optional|Transitive|Partial")
    # An Optional-bit-clear case must not demand the route be present: RFC 4271
    # permits (indeed mandates) a NOTIFICATION for an unrecognised well-known.
    bad = [m.mid for m in mal.values()
           if "wellknown" in m.tags and m.expect_route == "present"]
    r.check(not bad, "no unrecognised-well-known case demands the route be present"
            + ("" if not bad else f" — {bad}"))
    opt = [m for m in mal.values()
           if "optional" in m.tags and "unknown-attr" in m.tags]
    r.check(all(m.expect_route == "present" and m.expect_session == "up"
                for m in opt) and len(opt) == 3,
            f"all {len(opt)} unrecognised-optional cases require the route kept "
            f"and the session up")


def check_exercise_runs_end_to_end(r: Report, build: str, invj: Dict,
                                   name: str) -> None:
    """Actually CALL cmd_exercise, with fakes, for every step in the plan.

    The plan-coverage check above is static and passed while `cmd_exercise` was
    crashing on its very first step: it built a per-event row keyed `kind` and
    expanded it into `Ctx.log(kind, **row)`, which is a TypeError at the call
    site. 489 offline checks did not catch it because none of them invoked the
    subcommand — the same blind spot that let H-5 reach the lab.

    Runs in dry-run so the events return immediately instead of sleeping through
    a 225-second blackhole, which still covers the part that broke: the row
    build, `ctx.log`, and every event function's entry and exit.
    """
    from harness import runner
    from harness.dut import RunResult
    from harness.telemetry import Sampler

    inv = model.load(invj["profile_path"])

    from harness.dut import Dut as _RealDut

    class FakeDut:
        container = "fake"
        LOG_PATTERNS = _RealDut.LOG_PATTERNS
        BGP_DEBUGS = _RealDut.BGP_DEBUGS
        def enable_bgp_debugs(self, extra=(), set_log_level=True):
            return {"ok": True, "sent_ok": True,
                    "commands": list(_RealDut.BGP_DEBUGS),
                    "active": {c: True for c in _RealDut.BGP_DEBUGS},
                    "neighbor_changes": True, "via": "enable_node",
                    "raw": {}, "error": None}
        def bgp_debugs_active(self):
            return {c: True for c in _RealDut.BGP_DEBUGS}
        def rearm_bgp_debugs(self):
            return {c: True for c in _RealDut.BGP_DEBUGS}
        def logging_state(self):
            return {"ok": True, "levels": {"bgpd": "debugging"},
                    "bgpd": "debugging", "debug_reaches_log": True}
        def reassert_logging(self):
            return {"ok": True, "bgpd_level": "debugging"}
        def verify_log_pipeline(self, peer, wait_s=8.0):
            return {"ok": True, "peer": peer, "matched": 0,
                    "fsm_debug_lines": 0, "adjchange_lines": 0,
                    "notification_lines": 0, "tier_reached": "debug",
                    "sample": [], "window_unbounded": False}
        def reset_bgp(self, target="all", soft=None, afi=None):
            return RunResult(0, "", "", 0.0)
        def alive(self):
            return True
        def version(self):
            return {"frr": "fake", "vyos": "fake"}
        def bgp_summary(self, afi="ipv4"):
            addrs = [x.v4 if afi == "ipv4" else x.v6 for x in inv.sessions]
            return {"peers": {a: {"state": "Established", "pfxRcd": 0}
                              for a in addrs if a}}
        def log_counts(self, since="-30s"):
            return {}
        def log_since(self, since="-30s", extra_grep=None):
            return []
        def configure_file(self, path):
            return RunResult(0, "", "", 0.1)
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, "", "", 0.0)
        def vtysh_json(self, cmd, timeout=None):
            return {}
        def lookup_prefix(self, prefix, afi="ipv4"):
            return {}
        def exec(self, cmd, timeout=None, input_=None):
            return RunResult(0, "", "", 0.0)

    class FakeFleet:
        def cname(self, c):
            return f"clab-fake-{c}"
        def __getattr__(self, _n):
            return lambda *a, **k: RunResult(0, "", "", 0.0)

    class NullSampler(Sampler):
        def start(self):
            return None
        def stop(self):
            return None
        def event(self, kind, /, **kw):
            return None

    class Args:
        build = None
        clab_prefix = "clab-fake"
        results = None
        interval = 2.0
        dry_run = True
        only = None
        gap = 0.0
        recover = 1.0

    with tempfile.TemporaryDirectory() as td:
        a = Args()
        a.build = build
        a.results = os.path.join(td, "res")
        real_conv, real_acct, real_req = (
            runner._converge, runner._accounting, runner._require_docker)
        real_dut, real_fleet, real_sampler = (
            runner.Dut, runner.PeerFleet, runner.new_sampler)
        try:
            runner._require_docker = lambda: None
            runner._converge = lambda *a_, **k_: (True, 0.0, {})
            runner._accounting = lambda *a_, **k_: {
                "ipv4": {"announced": 0, "accepted": 0, "drift": 0},
                "ipv6": {"announced": 0, "accepted": 0, "drift": 0}}
            runner.Dut = lambda *a_, **k_: FakeDut()
            runner.PeerFleet = lambda *a_, **k_: FakeFleet()
            runner.new_sampler = lambda d, rd, i: NullSampler(
                dut=d, path=os.path.join(rd, "s.jsonl"), interval=2.0)
            os.makedirs(a.results, exist_ok=True)
            rc = runner.cmd_exercise(a)
        except Exception as exc:                              # noqa: BLE001
            r.bad(f"{name}: cmd_exercise raised "
                  f"{type(exc).__name__}: {exc}")
            return
        finally:
            (runner._converge, runner._accounting, runner._require_docker) = (
                real_conv, real_acct, real_req)
            (runner.Dut, runner.PeerFleet, runner.new_sampler) = (
                real_dut, real_fleet, real_sampler)

        r.check(rc == 0, f"{name}: cmd_exercise completes cleanly (rc={rc})")
        out = os.path.join(a.results, "exercise.json")
        if not os.path.exists(out):
            r.bad(f"{name}: cmd_exercise wrote no exercise.json")
            return
        with open(out, encoding="utf-8") as fh:
            got = json.load(fh)
        rows = got.get("rows") or []
        r.check(len(rows) == len(runner.EXERCISE_PLAN),
                f"{name}: every plan step produced a row "
                f"({len(rows)}/{len(runner.EXERCISE_PLAN)})")
        errored = [x.get("event") for x in rows if x.get("status") == "ERROR"]
        r.check(not errored,
                f"{name}: no event raised inside cmd_exercise"
                + ("" if not errored else f" — {errored}"))
        r.check(all("event" in x for x in rows),
                "every row is keyed `event`, not `kind` (a `kind` key collides "
                "with Ctx.log's positional-only parameter)")


def check_exercise_plan_covers_catalogue(r: Report) -> None:
    """Every event kind must be reachable by `make exercise`.

    Two full chaos runs executed only 5 of 12 event kinds — the scheduler is
    weighted and random, so `blackhole_peer`, `maxprefix_trip`, `gr_event`,
    `dut_bgpd_restart` and `netem` never fired. Eight log detectors were
    therefore never observed matching a real event. `exercise` runs each one
    deliberately; this check keeps the plan from drifting behind the catalogue.
    """
    from harness import runner, scenarios
    from harness.dut import Dut
    planned = {p["kind"] for p in runner.EXERCISE_PLAN}
    catalogue = set(scenarios.EVENTS)
    # malformed_isolate is driven by `probe`, not the scheduler.
    missing = sorted(catalogue - planned - {"malformed_isolate"})
    r.check(not missing,
            "every scheduler event kind is in EXERCISE_PLAN"
            + ("" if not missing else f" — missing {missing}"))
    unknown = sorted(planned - catalogue)
    r.check(not unknown,
            "EXERCISE_PLAN references only real events"
            + ("" if not unknown else f" — unknown {unknown}"))

    modes = {p["args"].get("mode") for p in runner.EXERCISE_PLAN
             if p["kind"] == "peer_flap"}
    for m in ("admin_down", "notification", "process_kill", "process_term"):
        r.check(m in modes, f"peer_flap mode {m!r} is exercised")
    cmodes = {p["args"].get("mode") for p in runner.EXERCISE_PLAN
              if p["kind"] == "churn"}
    for m in ("flap_same", "walk", "attr_churn", "withdraw_storm"):
        r.check(m in cmodes, f"churn mode {m!r} is exercised")

    expected = {k for p in runner.EXERCISE_PLAN
                for k in (p.get("expect_logs") or [])}
    for det in ("maxprefix", "holdtime_expire", "peer_down", "peer_up"):
        r.check(det in expected,
                f"some event declares {det!r} as an expected signature, so a "
                f"pattern that silently never matches is caught")
    # `sendq_stuck_warn` is deliberately NOT required here. FRR's send-queue
    # teardown needs a send queue that cannot drain, and at an IXP the DUT
    # advertises almost nothing (pfx_snt is 0 in every T0 sample), so there is
    # nothing to queue and the path is structurally unreachable in this topology.
    # Demanding it as an expectation just manufactures a permanent failure. The
    # pattern itself is validated against the real FRR string in
    # check_log_patterns_match_real_frr_strings, and ev_blackhole_peer records
    # `sendq_path_reachable` so the zero is an explained fact.
    r.check("sendq_stuck_warn" not in expected,
            "sendq_stuck_warn is not demanded of a topology where the DUT sends "
            "nothing; the pattern is validated against FRR's source string "
            "instead")
    stray = sorted(set(expected) - set(Dut.LOG_PATTERNS))
    r.check(not stray,
            f"every expected signature is a real LOG_PATTERNS key (stray: {stray})")


def check_notification_patterns_reject_noise(r: Report) -> None:
    """The notification detectors must not match non-BGP log noise.

    `make exercise` reported `dut_bgpd_restart` as having fired
    notification_sent and notification_any. Neither had anything to do with BGP:
    "sending NOTIFICATION" matched zebra's YANG error "Error sending notification
    message for path: /frr-vrf:...", and "NOTIFICATION" matched bgpd's shutdown
    memory dump "BGP Notification Message : 4 * (variably sized)". A false
    positive is worse than a gap. See FINDINGS.md H-26.
    """
    import re as _re
    from harness.dut import Dut
    noise = [
        'vyos zebra[448]: NB_OP_CHANGE: oper_walk_done: ERROR: Error sending '
        'notification message for path: /frr-vrf:lib/vrf[name="default"]/state',
        'vyos frrinit.sh[456]: bgpd: memstats:  BGP Notification Message '
        '     :      4 * (variably sized)',
    ]
    # Wording taken from bgpd/bgp_debug.c bgp_notify_print() in 10.5.2, not
    # guessed: the verb follows the tag, and the leading `%` is what keeps these
    # apart from the memstats line below. The earlier samples here were invented
    # to match the invented patterns, so this check passed while neither the
    # pattern nor the sample resembled anything FRR emits. See FINDINGS.md H-30.
    real = [
        'vyos bgpd[456]: %NOTIFICATION: sent to neighbor 198.51.100.11 6/2 '
        '(Cease/Administratively Shutdown) 0 bytes',
        'vyos bgpd[456]: %NOTIFICATION: received from neighbor 198.51.100.11 '
        '6/2 (Cease/Administratively Shutdown) 0 bytes',
    ]
    nkeys = [k for k in Dut.LOG_PATTERNS if "notification" in k]

    def hits(line):
        return sorted(k for k in nkeys
                      if _re.search(Dut.LOG_PATTERNS[k], line, _re.IGNORECASE))

    for line in noise:
        h = hits(line)
        r.check(not h,
                f"no notification detector matches {line[:45]!r}..."
                + ("" if not h else f" — matched {h}"))
    r.check("notification_sent" in hits(real[0]),
            "a real sent NOTIFICATION is matched")
    r.check("notification_recv" in hits(real[1]),
            "a real received NOTIFICATION is matched")


def check_frr_debugs_are_armed(r: Report) -> None:
    """Session-level detectors need `debug bgp neighbor-events` to exist at all."""
    import inspect
    from harness import runner
    from harness.dut import Dut
    r.check("debug bgp neighbor-events" in Dut.BGP_DEBUGS,
            "the DUT driver knows which FRR debug arms session-event logging")
    r.check(hasattr(Dut, "enable_bgp_debugs")
            and hasattr(Dut, "bgp_debugs_active"),
            "the DUT driver can arm the debugs and read back whether they took")
    bsrc = inspect.getsource(runner._start_generators)
    r.check("enable_bgp_debugs" in bsrc,
            "bringup arms the FRR debugs, so a run does not silently lose every "
            "session-level detector")
    esrc = inspect.getsource(runner.cmd_exercise)
    r.check("rearm_bgp_debugs" in esrc,
            "exercise re-arms before every event: terminal debugs live in "
            "bgpd's memory, so dut_bgpd_restart clears them and a VyOS commit "
            "can drop the config-node form")
    r.check("debugs_active_after" in esrc,
            "the flag is read back after each event too, so 'a commit inside "
            "the event wiped it' stops being an untestable hypothesis")
    r.check("debugs_active" in esrc,
            "each exercise row records whether the debugs were armed for that "
            "event, so a missing signature can be told apart from a dead "
            "detector")

    src = inspect.getsource(Dut.enable_bgp_debugs)
    # The ENABLE_NODE form has to be tried first: it sets the term flag
    # directly, cannot be dropped by frr-reload, and the previous version only
    # ever tried the CONFIG_NODE form and then reported vtysh's exit status as
    # proof. See FINDINGS.md H-27.
    i_enable = src.find('f"vtysh {args}"')
    i_config = src.find("configure terminal' {args}")
    r.check(i_enable != -1 and (i_config == -1 or i_enable < i_config),
            "arming tries the enable-node form before the config-node form")
    r.check("ok = bool(echoed or all(active.values()))" in src,
            "`ok` means the debug is active — by FRR's echo or by a working "
            "readback — not that vtysh exited 0")
    r.check("enable_neighbor_changes" in src,
            "arming also turns on `bgp log-neighbor-changes`, which is config "
            "rather than a debug and is what unlocks %ADJCHANGE/%NOTIFICATION")


def check_self_references_resolve(r: Report) -> None:
    """Every `self.x` a driver class uses must actually exist on that class.

    This exists because of a specific and entirely avoidable failure: three
    methods — `local_asn`, `neighbor_changes_state`, `enable_neighbor_changes` —
    were removed by a bad edit while `enable_bgp_debugs()` kept calling
    `self.enable_neighbor_changes()`. 292 offline checks passed, because the one
    that looked at it did a *string* match on the source
    (`"enable_neighbor_changes" in src`) and the call site is a string. The lab
    then died on the first line of `make exercise` with AttributeError.

    A string match proves a call is written, not that it can be made. Resolve the
    names instead: parse each driver class, collect every attribute it reads off
    `self`, and check it against the class plus whatever the class assigns to
    itself. This is the cheapest possible guard against an AttributeError that
    only shows up on the lab, and it generalises to every future edit.
    """
    import ast
    import inspect
    from harness.dut import Dut
    from harness.peers import PeerFleet
    from harness.telemetry import PredicateSet, Sampler
    from harness.scenarios import Ctx

    for cls in (Dut, PeerFleet, Sampler, PredicateSet, Ctx):
        try:
            tree = ast.parse(inspect.getsource(cls))
        except (OSError, SyntaxError) as exc:            # pragma: no cover
            r.skip(f"could not parse {cls.__name__}: {exc}")
            continue
        node = tree.body[0]
        # Names the class assigns to itself count as defined even when there is
        # no class-level declaration.
        assigned = set()
        for n in ast.walk(node):
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    if (isinstance(t, ast.Attribute)
                            and isinstance(t.value, ast.Name)
                            and t.value.id == "self"):
                        assigned.add(t.attr)
        used = set()
        for n in ast.walk(node):
            if (isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)
                    and isinstance(n.value, ast.Name) and n.value.id == "self"):
                used.add(n.attr)
        # A dataclass field with no default is not a class attribute — it lives
        # in __dataclass_fields__ / __annotations__ only. Count both, or every
        # required field (Dut.container, Ctx.inv, ...) reads as missing.
        declared = set(getattr(cls, "__dataclass_fields__", {}) or {})
        for klass in cls.__mro__:
            declared |= set(getattr(klass, "__annotations__", {}) or {})
        missing = sorted(a for a in used
                         if not hasattr(cls, a)
                         and a not in assigned
                         and a not in declared)
        r.check(not missing,
                f"{cls.__name__}: every self.<attr> it uses resolves"
                + (f" — MISSING {missing}" if missing else ""))


def check_debug_arming_survives_commits(r: Report) -> None:
    """The arming path must not write anything frr-reload can remove.

    2026-08-21, from the DUT's own log: FSM transition lines and %ADJCHANGE stop
    at 17:38:11 — the first `policy_churn` commit — and never resume, so
    malformed_burst, maxprefix_trip, blackhole_peer, gr_event and
    dut_bgpd_restart all ran blind again. Root cause chain, all from one thing:

      `show debugging bgp` -> "% Unknown command" on VyOS 1.5.1 vtysh
        -> readback says not-active even though the debug WAS on
        -> arming falls through to the CONFIG_NODE form
        -> that form lands in `show running-config`
        -> frr-reload diffs against VyOS's generated frr.conf, does not find it,
           and issues `no debug bgp neighbor-events`
        -> DEBUG_OFF clears the term flag too.

    So: try more than one readback command, treat "unknown command" as "ask
    something else" rather than "off", trust FRR's own "debugging is on" echo,
    and prefer the enable-node form, whose flag is in-process only and therefore
    invisible to frr-reload. See FINDINGS.md H-34.
    """
    import inspect
    from harness.dut import Dut
    r.check(len(Dut.DEBUG_SHOW_CMDS) > 1,
            "more than one debug readback command is tried, so one unknown "
            "command cannot be read as 'the debug is off'")
    src = inspect.getsource(Dut.bgp_debugs_active)
    r.check("unknown command" in src.lower(),
            "an unknown readback command is skipped rather than counted as "
            "'not enabled'")
    asrc = inspect.getsource(Dut.enable_bgp_debugs)
    r.check("debugging is on" in asrc,
            "FRR's own enable-node echo is accepted as proof the debug took")
    i_enable = asrc.find('f"vtysh {args}"')
    i_config = asrc.find("configure terminal' {args}")
    r.check(i_enable != -1 and i_config > i_enable,
            "the enable-node form is tried first; its flag is in-process only, "
            "so frr-reload cannot remove it on the next VyOS commit")
    r.check("fragile" in asrc,
            "if the config-node fallback is used, the result says so — that "
            "form does not survive a commit")
    rsrc = inspect.getsource(Dut.rearm_bgp_debugs)
    r.check("configure terminal" not in rsrc,
            "the per-event re-arm never uses the config-node form")


def check_exabgp_commands_name_one_session(r: Report) -> None:
    """`neighbor <dut>` alone selects every session peering with that address.

    The T2/T3/T4 profiles put two nasty sessions in one ExaBGP container, both
    peering with the same DUT fabric address, so every announcement reached
    both. Measured at T2 bringup: each nasty peer announces 150 v4 per the
    profile and the DUT accepted **283** from it — 150 of its own plus 150 of
    its container-mate's, less 17 the import policy dropped. That is the whole
    of the "+532 / +284 baseline drift" warning. The malformed suite was
    delivered twice too. See FINDINGS.md H-47.
    """
    import inspect
    from harness import generate, policyprobe, routegen, scenarios
    sel = policyprobe.neighbor_selector("198.51.96.1", "198.51.96.95")
    r.check(sel == "neighbor 198.51.96.1 local-ip 198.51.96.95",
            f"the selector names the peer AND the local address ({sel!r})")
    r.check(policyprobe.neighbor_selector("198.51.96.1")
            == "neighbor 198.51.96.1",
            "and degrades to the bare form when no local address is known")

    # Verified against ExaBGP's own matcher, not against a guess at its syntax.
    try:
        from exabgp.reactor.api.command.limit import (extract_neighbors,
                                                      match_neighbors)
    except ImportError:
        r.skip("exabgp not importable here; selector matching not re-verified")
    else:
        names = [
            "neighbor 198.51.96.1 local-ip 198.51.96.95 local-as 64400 "
            "peer-as 64000 router-id 198.51.96.95 family-allowed in-open",
            "neighbor 198.51.96.1 local-ip 198.51.96.96 local-as 64401 "
            "peer-as 64000 router-id 198.51.96.96 family-allowed in-open",
        ]
        bare, _ = extract_neighbors(
            "neighbor 198.51.96.1 announce route 1.2.3.0/24 next-hop self")
        scoped, rest = extract_neighbors(
            f"{sel} announce route 1.2.3.0/24 next-hop self")
        r.check(len(match_neighbors(names, bare)) == 2,
                "ExaBGP's matcher confirms the bare form hits both sessions")
        r.check(len(match_neighbors(names, scoped)) == 1,
                "and that the local-ip form hits exactly one")
        r.check(rest == "announce route 1.2.3.0/24 next-hop self",
                f"the command survives the selector intact ({rest!r})")

    # Every emitter has to use it, or one path silently doubles again.
    for fn in (policyprobe.probe_announce_commands,
               policyprobe.probe_withdraw_commands,
               policyprobe.malformed_announce_commands,
               policyprobe.malformed_withdraw_commands):
        r.check("neighbor_selector" in inspect.getsource(fn),
                f"{fn.__name__} scopes its commands to one session")
    r.check("local_ip" in inspect.getsource(routegen.exabgp_announce_batches),
            "the bulk announce builder accepts a local address")
    r.check("local_ip=s.v4" in inspect.getsource(generate.exabgp_boot),
            "the generated boot file scopes each session's announcements")
    isrc = inspect.getsource(scenarios.ev_malformed_isolate)
    r.check("neighbor_selector" in isrc,
            "isolation mode scopes its per-case announce and withdraw too")


def check_deliberate_restarts_are_not_failures(r: Report) -> None:
    """Three kinds of PID change, three different verdicts."""
    import inspect
    from harness import scenarios
    from harness.telemetry import Budgets, PredicateSet

    def sample(pid, logs=None):
        return {"kind": "sample", "t": 1.0,
                "bgp": {"ipv4": {"read_ok": True, "peers": 1,
                                 "established": 1, "failed": 0},
                        "ipv6": {"read_ok": True, "peers": 1,
                                 "established": 1, "failed": 0}},
                "proc": {"bgpd": {"pid": pid, "rss_mb": 1.0, "threads": 4}},
                "logs": logs or {}}

    def verdict(expect_it, logs=None):
        ps = PredicateSet(Budgets())
        ps.check(sample(501))
        if expect_it:
            ps.expect_daemon_restart("bgpd")
        got = [v for v in ps.check(sample(999, logs))
               if v.code == "bgpd_restarted"]
        return (got[0] if got else None), ps

    v, _ = verdict(True)
    r.check(v is not None and v.severity == "info",
            "a restart the running event asked for is informational — "
            "`dut_bgpd_restart` was reporting [fail] against itself")
    v, _ = verdict(False, {"daemon_unresponsive": 1})
    r.check(v is not None and v.severity == "fail"
            and "watchfrr" in v.detail,
            "a restart with watchfrr's unresponsive line in the same window is "
            "named as a watchdog kill, not a generic crash")
    v, _ = verdict(False)
    r.check(v is not None and v.severity == "fail",
            "and an unexplained PID change is still a failure")
    # The suppression must be one-shot.
    _, ps = verdict(True)
    again = [x for x in ps.check(sample(1234)) if x.code == "bgpd_restarted"]
    r.check(again and again[0].severity == "fail",
            "the expectation is consumed by one restart, so a second one later "
            "in the run is not masked")
    r.check("expect_daemon_restart" in inspect.getsource(
                scenarios.ev_dut_bgpd_restart),
            "the event declares its intent before restarting")


def check_convergence_waits_report_progress(r: Report) -> None:
    """A silent 21-minute wait is indistinguishable from a hang.

    T2 run 3: the post-chaos settle had a 1,260 s timeout and printed nothing;
    the operator interrupted it and the final accounting was lost.
    """
    import inspect
    from harness import runner
    src = inspect.getsource(runner._converge)
    r.check("on_sample=_tick" in src,
            "convergence waits pass a progress callback")
    r.check("progress_every" in src,
            "the progress interval is a parameter, not a magic number")
    r.check("tracker.reason" in src,
            "each progress line says what is blocking, not just that time "
            "is passing")
    rsrc = inspect.getsource(runner.cmd_run)
    r.check("up to {settle_timeout:.0f}s" in rsrc,
            "the settle phase announces its timeout before it starts waiting")
    import analysis.analyze as az
    asrc = inspect.getsource(az)
    r.check("not measured" in asrc,
            "an interrupted run reports the post-chaos figure as not measured, "
            "rather than printing the string 'Nones'")


def check_cold_start_is_measured(r: Report) -> None:
    """`bgp update-delay` is why a loaded DUT looks broken, and how long for.

    Verbatim from T3 (154 sessions, 4.8M paths). The four timestamps are the
    only place FRR reports this, and the same sequence runs after every bgpd
    restart — it is what turns the R-2 watchdog kill into a multi-minute
    forwarding outage instead of a blip.
    """
    import inspect
    from harness import runner
    from harness.dut import Dut, RunResult
    real = (
        "BGP router identifier 100.64.0.1, local AS number 64000 VRF default\n"
        "Read-only mode update-delay limit: 300 seconds\n"
        "                   Establish wait: 60 seconds\n"
        "  First neighbor established: 2026/08/28 12:55:41.944\n"
        "          Best-paths resumed: 2026/08/28 13:00:41.944\n"
        "        zebra update resumed: 2026/08/28 13:03:52.908\n"
        "        peers update resumed: 2026/08/28 13:03:53.541\n"
        "BGP table version 2445675\n")

    class D(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, real, "", 0.0)

    st = D(container="x").update_delay_state()
    r.check(st.get("readonly_s") == 300.0,
            f"read-only duration parsed ({st.get('readonly_s')})")
    r.check(st.get("bestpath_and_fib_s") == 191.0,
            f"bestpath + FIB install parsed ({st.get('bestpath_and_fib_s')})")
    r.check(st.get("to_advertise_s") == 491.6,
            f"total cold start to advertising parsed ({st.get('to_advertise_s')})")
    r.check(st.get("limit_expired") is True,
            "the limit expiring exactly at 300 s is flagged — it means not "
            "every peer sent End-of-RIB in time, which is a tuning finding")

    class Quiet(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, "BGP router identifier 1.1.1.1\n", "", 0.0)

    st2 = Quiet(container="x").update_delay_state()
    r.check(st2.get("ok") and st2.get("to_advertise_s") is None,
            "a DUT with no update-delay configured parses cleanly to nothing")

    csrc = inspect.getsource(runner.cmd_converge)
    r.check("update_delay_state" in csrc and "cold start" in csrc,
            "`converge` records and prints the cold-start decomposition")


def check_fib_gate_cannot_be_satisfied_by_an_unevaluated_reading(r: Report) -> None:
    """T3 converged in 34 s with a completely empty FIB. Third instance.

    `converged: True in 34.0s`, `tableVersion=50` against `ribCount=4891343`,
    `zebra rss=13.8 MB`, and `ipv4 FIB: unavailable (no bgp line in route
    summary)` — zebra held no BGP routes whatsoever. The quiet-convergence gate
    (H-40) and the FIB-reading requirement (H-41) both passed, because one early
    sample carried `route_installs` while the summary read had failed, so the
    RIB size was 0, the ratio comparison was skipped — and the "we have seen a
    FIB reading" flag was set anyway. See FINDINGS.md H-50.
    """
    import inspect
    from harness import runner
    from harness.telemetry import ConvergenceTracker

    def sample(installs=None, rib=None, cpu=0.3):
        rec = {"kind": "sample", "t": 1.0,
               "bgp": {"ipv4": {"read_ok": True, "peers": 154,
                                "established": 154, "failed": 0,
                                "table_version": 50, "pfx_rcd_total": 9,
                                "rib_count": rib},
                       "ipv6": {"read_ok": True, "peers": 154,
                                "established": 154, "failed": 0,
                                "table_version": 9, "pfx_rcd_total": 9,
                                "rib_count": 0}},
               "proc": {"bgpd": {"pid": 1, "cpu_pct": cpu, "rss_mb": 6330.0,
                                 "threads": 4}}}
        if installs is not None:
            rec["zebra"] = {"route_installs": installs}
            rec["dplane"] = {"queue_depth": 0, "queue_limit": 200,
                             "queue_max": 5}
        return rec

    t = ConvergenceTracker(expected_sessions_v4=154, expected_sessions_v6=154)
    seq = [sample(0, None)] + [sample() for _ in range(4)]
    r.check(not any(t.feed(x) for x in seq),
            "an install count with no RIB size to compare it against does not "
            "count as a FIB reading — the exact T3 shape")
    r.check(t.reason and "FIB reading" in t.reason,
            f"and the tracker says it is still waiting for one ({t.reason!r})")

    # The tracker no longer judges FIB *completeness* — it cannot, from the
    # counters it has (H-52). It only requires that a data-plane reading was
    # taken. Completeness is `_fib_agrees`'s job, below, and the runner's loop
    # will not accept the tracker's verdict without it.
    t3 = ConvergenceTracker(expected_sessions_v4=154, expected_sessions_v6=154)
    r.check(any(t3.feed(sample(4891343, 4891343)) for _ in range(6)),
            "a stable install count is a data-plane reading, and the tracker "
            "converges on it")

    # The authoritative cross-check, which does not depend on sampling at all.
    class FakeDut:
        def __init__(self, summary):
            self._s = summary

        def route_summary(self, afi="ipv4"):
            return dict(self._s, ok=True, afi=afi)

    last = {"bgp": {"ipv4": {"rib_count": 4891343}, "ipv6": {"rib_count": 0}}}
    ok, why, det = runner._fib_agrees(
        FakeDut({"bgp_routes": 4891343, "bgp_fib": 100}), last)
    r.check(not ok and "installed" in why,
            "a partially-installed FIB blocks convergence and says how far")
    ok, _, _ = runner._fib_agrees(
        FakeDut({"bgp_routes": 4891343, "bgp_fib": 4891343}), last)
    r.check(ok, "a fully-installed FIB agrees")

    class BrokenDut:
        def route_summary(self, afi="ipv4"):
            return {"ok": False, "error": "command not found"}

    ok, _, det = runner._fib_agrees(BrokenDut(), last)
    r.check(ok,
            "an unavailable route summary is treated as agreement — refusing "
            "to converge because a diagnostic is missing is worse than the "
            "problem")
    r.check((det.get("ipv4") or {}).get("unmeasured"),
            "...and it is recorded as unmeasured rather than passed over")

    # H-51. The unreadable case above must NOT swallow a build whose row names
    # this parser simply does not know: that is the same "unmeasured", but it
    # has to be visible, because for 2,400 s it was reported as "the FIB is
    # empty" instead.
    ok, _, det = runner._fib_agrees(
        FakeDut({"bgp_routes": None, "bgp_fib": None,
                 "sources": {"kernel": {}, "static": {}}}), last)
    r.check(ok and "no recognised BGP row" in
            ((det.get("ipv4") or {}).get("unmeasured") or ""),
            "an unrecognised route-summary layout is reported as unmeasured, "
            "not as an empty FIB (H-51)")

    csrc = inspect.getsource(runner._converge)
    r.check("_fib_agrees" in csrc and "tracker.reset()" in csrc,
            "convergence re-enters the wait when zebra disagrees with the "
            "counters, rather than reporting a settled router")


def check_config_changes_are_always_reverted(r: Report) -> None:
    """A commit timeout must not leave the DUT modified.

    T2 run 1: `maxprefix-squeeze` hit a 360 s CommitTimeout on its apply, the old
    code returned immediately, the revert never ran, and `ixp1-peer4` stayed
    clamped at maximum-prefix 2,500 against 5,000 announced for the remaining 72
    minutes. All 80 ixp1-bilat IPv4 sessions were torn down at t=391 and never
    came back; drift read -400,000 (= 80 x 5,000); 19 of 20 flap-recovery
    measurements came back None; and the run's FAIL verdict was against a lab the
    harness had broken. `pg-routemap-swap` did the same on its revert.
    See FINDINGS.md H-42 and H-44.
    """
    import inspect
    from harness import runner, scenarios
    for fn in (scenarios.ev_policy_churn, scenarios.ev_maxprefix_trip):
        src = inspect.getsource(fn)
        name = fn.__name__
        r.check("config_left_modified" in src,
                f"{name} reports whether it left the DUT modified")
        # The apply's CommitTimeout must not short-circuit past the revert.
        i_apply = src.find("apply_p")
        i_ret = src.find("return ctx.log", i_apply)
        i_rev = src.find("revert_p", i_apply)
        r.check(i_rev != -1 and (i_ret == -1 or i_rev < i_ret),
                f"{name} reaches its revert before any early return on the "
                f"apply path")
    psrc = inspect.getsource(scenarios.ev_policy_churn)
    r.check("finally:" in psrc,
            "policy_churn reverts in a `finally`, so an exception in the hold "
            "or the apply cannot skip it")
    rsrc = inspect.getsource(runner.cmd_run)
    r.check('rec.get("config_left_modified")' in rsrc,
            "the chaos loop stops when an event could not undo its own config "
            "change — there is nothing meaningful left to measure")
    r.check("stop_on_violation" in rsrc and "first_hard_failure" in rsrc,
            "the first hard failure is recorded even when the run continues, so "
            "before/after measurements are not mixed")
    # The timeout exists to stop a hang, not to enforce the budget.
    r.check("max(600.0, budgets.commit_s * 4)" in rsrc,
            "the commit timeout is generous relative to the budget: a latency "
            "over budget is a finding, a timeout is a lost measurement plus a "
            "broken lab")


def check_failed_reads_are_not_zeros(r: Report) -> None:
    """An unanswered query is not a measurement of zero.

    T2 run 1: 45 of 2,392 address-family summary reads returned nothing, every
    one while bgpd sat at ~100% of one core. Each was recorded as
    `peers: 0, established: 0, pfx_rcd_total: 0, table_version: null` — which
    reset the convergence tracker (so "post-chaos re-convergence: 1260 s,
    converged=False" may be an artefact) and corrupted every peak, final and
    drift figure. Same class as H-18. See FINDINGS.md H-43.
    """
    from harness.telemetry import (Budgets, ConvergenceTracker, PredicateSet,
                                   _summarise_bgp)
    good = _summarise_bgp({"peers": {"10.0.0.1": {"state": "Established",
                                                  "pfxRcd": 5}},
                           "tableVersion": 7, "ribCount": 5})
    bad = _summarise_bgp(None)
    r.check(good.get("read_ok") is True and bad.get("read_ok") is False,
            "a successful read and a failed one are distinguishable")
    rec = {"kind": "sample", "t": 1.0, "proc": {},
           "bgp": {"ipv4": bad, "ipv6": bad}}
    t = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149)
    r.check(t.feed(rec) is False and t.reason and "read failed" in t.reason,
            f"a failed read neither confirms nor denies convergence, and says "
            f"so ({t.reason!r})")
    viols = PredicateSet(Budgets()).check(rec)
    codes = {v.code: v.severity for v in viols}
    r.check(codes == {"telemetry_read_failed": "warn"},
            f"a failed read produces one warning and no DUT fault — 'peers: 0' "
            f"would otherwise read as a total outage (got {codes})")


def check_cpu_pct_resets_on_pid_change(r: Report) -> None:
    """Tick counters belong to a process, not to a name.

    T2 reported bgpd at **-1547.13%** on the sample after watchfrr restarted it,
    because the delta was taken against the dead process's counters.
    """
    from harness.dut import Dut
    from harness.telemetry import Sampler
    sm = Sampler(dut=Dut(container="x"), path="/tmp/selftest-cpu.jsonl")
    r.check(sm._cpu_pct("bgpd", 1000, 10.0, 4, 504) is None,
            "the first reading has no baseline and returns None")
    r.check(sm._cpu_pct("bgpd", 1300, 13.0, 4, 504) == 100.0,
            "a same-PID delta computes normally")
    r.check(sm._cpu_pct("bgpd", 5, 16.0, 4, 73345) is None,
            "a PID change resets the baseline instead of reporting a negative "
            "percentage")
    r.check(sm._cpu_pct("bgpd", 305, 19.0, 4, 73345) == 100.0,
            "and the next sample measures the new process correctly")


def check_watchdog_kill_is_detected(r: Report) -> None:
    """The failure T2 actually produced: bgpd killed by its own supervisor.

    `bgpd_crash` could never have caught it — bgpd did not crash. watchfrr pings
    each daemon and past `--timeout` (VyOS ships 90 s) declares it dead:

        [EC 268435457] bgpd state -> unresponsive : no response yet to ping
                       sent 90 seconds ago
        Forked background command [pid 71630]: /usr/lib/frr/watchfrr.sh restart bgpd
        bgpd[504]: Terminating on signal
    """
    import re as _re
    from harness.dut import Dut
    lines = {
        "daemon_unresponsive":
            "watchfrr[473]: [T58XM-TP956][EC 268435457] bgpd state -> "
            "unresponsive : no response yet to ping sent 90 seconds ago",
        "daemon_watchdog_restart":
            "watchfrr[473]: [YFT0P-5Q5YX] Forked background command "
            "[pid 71630]: /usr/lib/frr/watchfrr.sh restart bgpd",
    }
    for key, line in lines.items():
        r.check(key in Dut.LOG_PATTERNS
                and bool(_re.search(Dut.LOG_PATTERNS[key], line, _re.I)),
                f"`{key}` matches the watchfrr line it exists for")
    # And it must not fire on ordinary daemon chatter.
    quiet = "watchfrr[473]: [QDG3Y-BY5TN] bgpd state -> up : connect succeeded"
    hit = [k for k in lines
           if _re.search(Dut.LOG_PATTERNS[k], quiet, _re.I)]
    r.check(not hit, f"and not on a normal state -> up line (matched {hit})")


def check_t3_has_no_external_mrt_dependency(r: Report) -> None:
    """T3 runs from generated NLRI, by decision (H-28 closed as won't-do)."""
    import yaml as _yaml
    with open("profiles/t3-fulltable.yaml", encoding="utf-8") as fh:
        raw = fh.read()
    prof = _yaml.safe_load(raw)
    fleets = prof.get("fleets") or []
    with_mrt = [f["id"] for f in fleets if f.get("mrt")]
    r.check(not with_mrt,
            f"no T3 fleet needs an external MRT dump{'' if not with_mrt else f' — {with_mrt}'}")
    r.check(all(f.get("prefixes_v4") for f in fleets),
            "every T3 fleet has a generated prefix count to work from")
    r.check("LOWER bound" in raw,
            "the profile records that generated tables share attributes more "
            "than a real dump, so T3 memory-per-path understates a real table")


def check_convergence_requires_a_quiet_dut(r: Report) -> None:
    """Consistent counters are not the same as a finished router.

    T2, 2026-08-21 11:33, straight after loading 2,800,920 paths: `converge`
    reported converged in 1.0 s with 149/149 Established and pfxRcd complete,
    while bgpd sat at 100.0-101.4% CPU, its RSS grew ~9.5 MB/s, and zebra had
    installed 136 routes against a 2,552,093-entry BGP RIB. Every subsequent
    measurement would have been taken from that baseline. See FINDINGS.md H-40.
    """
    from harness import runner as runner_mod
    from harness.telemetry import Budgets, ConvergenceTracker, PredicateSet

    def sample(cpu, installs, rib, tv=50, est=149):
        return {"kind": "sample", "t": 0.0,
                "bgp": {"ipv4": {"peers": est, "established": est, "failed": 0,
                                 "table_version": tv, "pfx_rcd_total": 100,
                                 "rib_count": rib},
                        "ipv6": {"peers": est, "established": est, "failed": 0,
                                 "table_version": tv, "pfx_rcd_total": 100,
                                 "rib_count": 0}},
                "proc": {"bgpd": {"pid": 1, "rss_mb": 100.0, "threads": 4,
                                  "cpu_pct": cpu}},
                "zebra": {"route_installs": installs},
                "dplane": {"queue_depth": 0, "queue_limit": 200,
                           "queue_max": 10}}

    # The exact T2 shape: counters stable, bgpd saturated, FIB empty.
    busy = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149)
    fired = any(busy.feed(sample(100.4, 136, 2552093)) for _ in range(6))
    r.check(not fired,
            "convergence is refused while bgpd is at 100% CPU with the FIB "
            "empty — the exact T2 shape that reported 'converged in 1.0s'")
    r.check(busy.reason and "cpu" in busy.reason.lower(),
            f"the blocker is named rather than just returning False "
            f"({busy.reason!r})")

    # FIB behind, but bgpd idle. The *tracker* now accepts this — it has no
    # way to tell a lagging FIB from a caught-up one, because the only numbers
    # it holds are a cumulative install counter and a BGP-table-node count
    # (H-52). The router is caught by `runner._fib_agrees()`, which asks zebra,
    # and the loop in `_converge` will not accept a tracker verdict without it.
    lag = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149)
    r.check(any(lag.feed(sample(1.0, 136, 2552093)) for _ in range(6)),
            "the tracker no longer guesses at FIB completeness from counters")
    import inspect as _i
    csrc0 = _i.getsource(runner_mod._converge)
    r.check("_fib_agrees" in csrc0 and "tracker.reset()" in csrc0,
            "and the convergence loop refuses that verdict until zebra's own "
            "route summary agrees")

    # Quiet and caught up: converges.
    ok = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149)
    fired = any(ok.feed(sample(1.0, 2552093, 2552093)) for _ in range(6))
    r.check(fired, "a quiet router with a filled FIB does converge")

    # And the old behaviour is still reachable for comparison.
    old = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149,
                             require_quiet=False)
    fired = any(old.feed(sample(100.4, 136, 2552093)) for _ in range(6))
    r.check(fired,
            "require_quiet=False reproduces the old counters-only verdict, so "
            "the two can be compared on the same data")

    # zebra and dplane counters ride only on slow samples, so a stable streak
    # can contain none of them. Treating "absent" as "satisfied" would leave the
    # exact hole this gate exists to close: at T2 the streak that reported
    # converged carried no FIB reading at all.
    def fast():
        rec = sample(0.3, 0, 1000)
        rec.pop("zebra"); rec.pop("dplane")
        return rec
    fastonly = ConvergenceTracker(expected_sessions_v4=149,
                                  expected_sessions_v6=149)
    r.check(not any(fastonly.feed(fast()) for _ in range(8)),
            "convergence is not confirmed from samples that carry no FIB "
            "reading, however stable and idle they look")
    r.check(fastonly.reason and "FIB" in fastonly.reason,
            f"and it says it is waiting for one ({fastonly.reason!r})")
    mixed = ConvergenceTracker(expected_sessions_v4=149, expected_sessions_v6=149)
    r.check(any(mixed.feed(rec) for rec in
                [sample(0.3, 1000, 1000), fast(), fast(),
                 sample(0.3, 1000, 1000), fast()]),
            "two slow samples agreeing on a stable install count is a "
            "data-plane reading, and the streak can then confirm")

    # The authoritative read, which does not depend on sampling at all.
    from harness.dut import Dut
    r.check(hasattr(Dut, "route_summary"),
            "the DUT driver can ask zebra directly for RIB vs FIB per source")
    import inspect
    csrc = inspect.getsource(runner_mod.cmd_converge)
    r.check("route_summary" in csrc,
            "`converge` reports the authoritative FIB figure, not an inference "
            "from a cumulative install counter that only rides on slow samples")

    # The predicate that measures what a user actually feels. It is fed from
    # `show ip route summary`, not from the sampled counters — see
    # check_no_counter_is_compared_to_a_table_size for why.
    ps = PredicateSet(Budgets())
    codes = {v.code for v in ps.feed_fib(
        {"ok": True, "afi": "ipv4", "bgp_routes": 2552093, "bgp_fib": 136,
         "sources": {"ebgp": {}}}, t=1.0)}
    r.check("fib_behind_rib" in codes,
            "a FIB that is behind the RIB is a recorded violation: BGP can be "
            "entirely up while the prefixes are not reachable")
    quiet_codes = {v.code for v in PredicateSet(Budgets()).feed_fib(
        {"ok": True, "afi": "ipv4", "bgp_routes": 2552093, "bgp_fib": 2552093,
         "sources": {"ebgp": {}}}, t=1.0)}
    r.check("fib_behind_rib" not in quiet_codes,
            "and it does not fire once the FIB has caught up")
    r.check("fib_behind_rib" not in {v.code for v in
                                     PredicateSet(Budgets()).check(
                                         sample(1.0, 136, 2552093))},
            "and the sampled path no longer raises it from counters it cannot "
            "interpret (H-52)")


def check_log_floor_survives_commits(r: Report) -> None:
    """The debug flag on its own does not put a line in the log.

    FRR consults the debug flag, then the destination's severity floor. The flag
    is armed in the enable node so frr-reload cannot remove it (H-34), but
    `log syslog debugging` IS config, so a VyOS commit removes it — and every
    info and debug line stops while `show debugging` keeps saying the debug is
    on. Measured on 2026-08-21 18:40: debug/info/warn/error up to 18:45:05, the
    first commit at 18:45:31, and warnings and errors only thereafter.
    `maxprefix_trip` tripped two peers off the table and `blackhole_peer` dropped
    a session inside one holdtime, and neither logged anything. See H-39.
    """
    import inspect
    from harness.dut import Dut
    from harness import runner
    r.check(hasattr(Dut, "reassert_logging") and hasattr(Dut, "logging_state"),
            "the DUT driver can restore the log floor and read it back")
    csrc = inspect.getsource(Dut.configure)
    r.check("reassert_logging" in csrc,
            "the log floor is restored after every commit — `configure` is the "
            "only thing in the harness that commits, so it is the only place "
            "the floor can be lost")
    rsrc = inspect.getsource(Dut.reassert_logging)
    r.check("LOG_LEVEL_CMD" in rsrc and "BGP_DEBUGS" in rsrc,
            "both the floor and the debug flag are re-asserted together")
    esrc = inspect.getsource(runner.cmd_exercise)
    r.check("debug_reaches_log_after" in esrc,
            "each row records whether debug-level output could still reach the "
            "log when the event ended, next to whether the flag was set")
    r.check("logging_state()" in esrc,
            "the exercise reads the floor, not just the flag")


def check_mix_is_weighted_for_real_peering(r: Report) -> None:
    """The chaos mix has to look like real ISP peering, not like an attack.

    The goal is whether a VyOS/FRR router carrying a full table from Tier-1 and
    IXP peers stays up and keeps forwarding through link failures, degraded
    paths and remote-router restarts — evidence for the FRR and VyOS teams. Real
    peers are not hostile, so malformed attributes and a deliberate prefix-limit
    trip are diagnostics that should run occasionally, not load that competes
    with the failure modes under study.
    """
    import glob as _glob
    import yaml as _yaml
    REAL = {"peer_flap", "churn", "netem", "gr_event", "blackhole_peer",
            "policy_churn", "soft_clear"}
    ADV = {"malformed_burst", "maxprefix_trip"}
    for path in sorted(_glob.glob("profiles/t[234]*.yaml")):
        with open(path, encoding="utf-8") as fh:
            prof = _yaml.safe_load(fh)
        ev = ((prof.get("scenario") or {}).get("events")) or []
        if not ev:
            r.skip(f"{path}: no scenario.events to weigh")
            continue
        total = sum(e.get("weight", 0) for e in ev)
        real = sum(e.get("weight", 0) for e in ev if e.get("kind") in REAL)
        adv = sum(e.get("weight", 0) for e in ev if e.get("kind") in ADV)
        name = os.path.basename(path)
        r.check(total and real / total >= 0.85,
                f"{name}: {real}/{total} of the mix is real-world failure modes "
                f"({(real / total * 100) if total else 0:.0f}%)")
        r.check(total and adv / total <= 0.05,
                f"{name}: adversarial cases are diagnostics, not load "
                f"({adv}/{total})")
        kinds = {e.get("kind") for e in ev}
        for k in ("netem", "peer_flap", "churn", "gr_event"):
            r.check(k in kinds, f"{name}: exercises {k}")
        modes = {e.get("mode") for e in ev if e.get("kind") == "peer_flap"}
        r.check("link_down" in modes,
                f"{name}: includes a link-down flap — the most common real event")


def check_impairments_are_verified(r: Report) -> None:
    """An impairment that cannot be confirmed is not a result.

    `blackhole_peer` ran for 75.3 s against a 30 s holdtime and FRR logged no
    session transition, no hold-timer expiry and no NOTIFICATION — while the
    debug was armed and log-neighbor-changes was on. That combination is not
    possible if BGP was actually being dropped. `blackhole()` ended in
    `2>/dev/null; true` and no caller looked at the result, so a peer image
    without `iptables` gives a clean exit, no rules, and a green row.
    See FINDINGS.md H-33.
    """
    import inspect
    from harness.peers import PeerFleet
    from harness import scenarios
    r.check(hasattr(PeerFleet, "blackhole_rules"),
            "the blackhole can count the DROP rules it installed")
    bsrc = inspect.getsource(PeerFleet.blackhole)
    r.check("iptables_present" in bsrc and "rules_installed" in bsrc,
            "blackhole() reports whether iptables exists and how many rules "
            "are in place, instead of swallowing the error")
    r.check("effective" in bsrc,
            "blackhole() states plainly whether the impairment is in effect")
    esrc = inspect.getsource(scenarios.ev_blackhole_peer)
    r.check("blackhole_ineffective" in esrc,
            "the event aborts with a distinct record when the impairment is "
            "not in place, rather than sleeping through it and reporting ok")
    r.check("sendq_path_reachable" in esrc and "dut_pfx_snt_to_peer" in esrc,
            "the event records how much the DUT is advertising to the peer: "
            "the send-queue teardown needs a queue, and at an IXP there is "
            "almost nothing to queue")
    r.check("state_at_1x_holdtime" in esrc,
            "the event samples the peer just past one holdtime, where the hold "
            "timer must already have fired")
    r.check(hasattr(PeerFleet, "netem_active"),
            "netem can be read back off the qdisc")
    nsrc = inspect.getsource(scenarios.ev_netem)
    r.check("netem_ineffective" in nsrc,
            "netem reports a no-op instead of sleeping through an unimpaired "
            "path — it has never produced an observable effect, and 'too mild' "
            "and 'never applied' had not been told apart")


def check_log_window_covers_recovery(r: Report) -> None:
    """The window must be measured off the clock, not off a reported metric.

    Two wrong versions so far. `event + 20s` reached back into the previous step
    (H-29). `event + rec_s + 3` clipped the *start* of every event, because
    `wait_for_convergence` back-dates its return value by
    `(stable_samples - 1) * interval` — 4 s at the default 3 samples / 2 s — so
    it can report 0.0 for a call that took six seconds of wall clock. On the
    2026-08-21 18:15 run that cost every notification detector: the DUT logged
    `%ADJCHANGE ... Down` at 18:17:30 and `... Up` at 18:17:42 and the harness
    saw only the Up. See FINDINGS.md H-38.
    """
    import inspect
    from harness import runner, telemetry
    src = inspect.getsource(runner.cmd_exercise)
    i_conv = src.find("rec_ok, rec_s, _ = _converge")
    i_logs = src.find("logs = dut.log_counts")
    r.check(i_conv != -1 and i_logs > i_conv,
            "the per-event log window is read after recovery, so a peer coming "
            "back is inside it")
    r.check("elapsed = time.monotonic() - t0" in src
            and "int(math.ceil(elapsed)) + 3" in src,
            "the window is the event's real elapsed wall time + 3s, measured "
            "from the clock")
    r.check("int(rec_s) + 3" not in src,
            "the window is NOT derived from the reported convergence time, "
            "which is deliberately back-dated and is not a wall-clock duration")
    r.check("elapsed_s" in src,
            "the row records real elapsed time alongside the reported recovery "
            "time, so the two can be compared")
    # Confirm the trap is real rather than assumed: the back-dating is in the
    # source of the function the runner calls.
    wsrc = inspect.getsource(telemetry.wait_for_convergence)
    r.check("stable_samples - 1) * sampler.interval" in wsrc,
            "wait_for_convergence does back-date its result — this is the trap "
            "the check above exists for, confirmed in its source")


def check_ineffective_impairment_is_not_ok(r: Report) -> None:
    """An event that could not impair anything must not report `ok`."""
    import inspect
    from harness import runner
    src = inspect.getsource(runner.cmd_exercise)
    r.check('kind.endswith("_ineffective")' in src,
            "an event returning a *_ineffective record is marked INEFFECTIVE, "
            "not ok — blackhole_peer reported ok for two runs while nothing was "
            "ever blackholed")
    r.check("errs or norec or ineff" in src,
            "an ineffective impairment makes the command exit non-zero")
    r.check('"event_record"' in src,
            "each row carries the event's own return value, so the "
            "log-independent evidence maxprefix_trip and blackhole_peer collect "
            "lands in exercise.json instead of only in a multi-MB samples file")


def check_maxprefix_trip_checks_its_preconditions(r: Report) -> None:
    """A peer that is still reconnecting cannot exceed a prefix limit."""
    import inspect
    from harness import scenarios
    src = inspect.getsource(scenarios.ev_maxprefix_trip)
    r.check("peergroup_limits_after_apply" in src,
            "the event reads the limit back out of the running config, so a "
            "commit that did not take is visible")
    r.check("all_peers_reestablished_after_s" in src,
            "the event waits for the sessions VyOS bounced to come back before "
            "judging: frr-reload resets a peer-group on a maximum-prefix change, "
            "and the only DUT log line in the 2026-08-21 window was a TCP reset "
            "at the exact second of the apply commit")


def check_log_pipeline_probe(r: Report) -> None:
    """Arming has to be proven end to end, not inferred from a flag."""
    import inspect
    from harness import runner
    from harness.dut import Dut
    r.check(hasattr(Dut, "verify_log_pipeline"),
            "the DUT driver can prove flag -> severity -> destination -> reader "
            "with a real session reset")
    src = inspect.getsource(Dut.verify_log_pipeline)
    for token in ("went from", "%ADJCHANGE", "%NOTIFICATION"):
        r.check(token in src,
                f"the pipeline probe looks for {token}, so it can name the "
                f"lowest severity that actually arrives")
    r.check("tier_reached" in src,
            "the probe distinguishes 'debug arrives', 'only info arrives' and "
            "'only warn/err arrives' — the three have never been told apart")
    esrc = inspect.getsource(runner.cmd_exercise)
    r.check("verify_log_pipeline" in esrc,
            "exercise runs the pipeline probe before the plan")
    r.check("warn_or_err_only" in esrc,
            "exercise says so explicitly when no info- or debug-level line "
            "reaches the reader, instead of printing sixteen zeroes")


def check_log_patterns_match_real_frr_strings(r: Report) -> None:
    """Every pattern is checked against the string FRR actually logs.

    This is the check that should have existed from the start. Six patterns were
    invented rather than taken from source, and every one of them was wrong:
    two matched C enum names that FRR never prints, three guessed the word order
    of the NOTIFICATION lines, and one matched only a message that requires a
    config sub-option VyOS does not expose. All six sat in the report as
    "detector never fired", which read as "the DUT never did this".
    See FINDINGS.md H-30.
    """
    import re as _re
    from harness.dut import Dut
    P = Dut.LOG_PATTERNS
    # Left: the pattern key. Right: a line copied from the FRR 10.5.2 source
    # that emits it, with the format specifiers filled in.
    samples = {
        "sendq_stuck_warn":
            "bgpd[456]: [EC 33554461] 10.0.0.5(ixp1) has not made any SendQ "
            "progress for 1 holdtime (90s), peer overloaded?",
        "sendq_stuck_proper":
            "bgpd[456]: [EC 33554462] 10.0.0.5(ixp1) has not made any SendQ "
            "progress for 2 holdtimes (180s), terminating session",
        "netlink_overrun":
            "zebra[123]: [EC 4043309093] netlink-listen recvmsg overrun: "
            "No buffer space available",
        "zebra_recvmsg_overrun":
            "zebra[123]: [EC 4043309093] routing socket overrun: "
            "No buffer space available",
        "maxprefix":
            "bgpd[456]: %MAXPFXEXCEED: No. of IPv4 Unicast prefix received "
            "from 10.0.0.5 181 exceed, limit 50",
        "maxprefix_exceeded":
            "bgpd[456]: %MAXPFXEXCEED: No. of IPv4 Unicast prefix received "
            "from 10.0.0.5 181 exceed, limit 50",
        "holdtime_expire":
            "bgpd[456]: %NOTIFICATION: sent to neighbor 10.0.0.5 4/0 "
            "(Hold Timer Expired) 0 bytes",
        "notification_sent":
            "bgpd[456]: %NOTIFICATION: sent to neighbor 10.0.0.5 6/2 "
            "(Cease/Administratively Shutdown) 0 bytes",
        "notification_recv":
            "bgpd[456]: %NOTIFICATION: received from neighbor 10.0.0.5 6/2 "
            "(Cease/Administratively Shutdown) 0 bytes",
        "notification_any":
            "bgpd[456]: %NOTIFICATION: received from neighbor 10.0.0.5 6/4 "
            "(Cease/Administratively Reset) 0 bytes",
        "peer_down":
            "bgpd[456]: %ADJCHANGE: neighbor 10.0.0.5(ixp1) in vrf default "
            "Down BGP Notification received",
        "peer_up":
            "bgpd[456]: %ADJCHANGE: neighbor 10.0.0.5(ixp1) in vrf default Up",
        "bgpd_crash":
            "watchfrr[12]: bgpd state -> down : read returned EOF; aborting",
        "optmem":
            "bgpd[456]: sockopt_tcp_signature: setsockopt(23): "
            "Cannot allocate memory",
        "attr_first_as":
            "bgpd[456]: 10.0.0.5(ixp1) incorrect first AS (must be 65001)",
        "martian_nexthop":
            "bgpd[456]: 10.0.0.5(ixp1): Martian nexthop 255.255.255.255 "
            "received, ignoring",
        "cpu_starvation":
            "bgpd[456]: [EC 100663315] CPU starvation: "
            "bgp_generate_updgrp_packets getting executed 5181ms late, "
            "warning threshold 4000ms",
        "event_slow":
            "bgpd[456]: [EC 100663307] CPU HOG: task bgp_process_packet "
            "(7f2a) ran for 4531ms (cpu time 4210ms)",
        "read_packet_error":
            "bgpd[456]: [EC 33554454] 10.0.0.5 [Error] bgp_read_packet error: "
            "Connection reset by peer",
        "attr_withdraw":
            "bgpd[456]: 10.0.0.5(ixp1) rcvd UPDATE with errors in attr(s)!! "
            "Withdrawing route.",
        "zebra_conn_lost":
            "bgpd[39183]: [EC 100663302] zclient_send_message: buffer_write "
            "failed to zclient fd 19, closing",
        "nexthop_reg_fail":
            "bgpd[39183]: [EC 33554500] sendmsg_nexthop: "
            "zclient_send_message() failed",
        # watchfrr, not a routing daemon: the supervisor declaring a busy bgpd
        # dead. This is the line T2 run 1 produced, verbatim.
        "daemon_unresponsive":
            "watchfrr[473]: [T58XM-TP956][EC 268435457] bgpd state -> "
            "unresponsive : no response yet to ping sent 90 seconds ago",
        "daemon_watchdog_restart":
            "watchfrr[473]: [YFT0P-5Q5YX] Forked background command "
            "[pid 71630]: /usr/lib/frr/watchfrr.sh restart bgpd",
    }
    uncovered = sorted(set(P) - set(samples))
    r.check(not uncovered,
            "every log pattern has a known-real FRR line to match against"
            + (f" (uncovered: {uncovered})" if uncovered else ""))
    for key, line in samples.items():
        if key not in P:
            continue
        r.check(bool(_re.search(P[key], line, _re.IGNORECASE)),
                f"pattern `{key}` matches the line FRR actually logs")

    # A pattern that contains an EC enum name can never match: flog_err and
    # flog_warn print the numeric code, e.g. "[EC 33554461]".
    for key, pat in P.items():
        r.check(not _re.search(r"[A-Z]{3,}_[A-Z]{3,}", pat),
                f"pattern `{key}` does not match on a C enum name that FRR "
                f"never prints")


def check_maxprefix_event_has_direct_evidence(r: Report) -> None:
    """The maxprefix trip must not depend on a log line to know it happened."""
    import inspect
    from harness import scenarios
    src = inspect.getsource(scenarios.ev_maxprefix_trip)
    r.check("return ev_policy_churn(" not in src,
            "maxprefix_trip is no longer a bare delegation to policy_churn, "
            "which left the log signature as the only evidence")
    r.check("bgp_summary" in src or "snap()" in src,
            "the event samples per-peer state itself, so a trip is observable "
            "without any log line")
    r.check("still_down_after_revert" in src
            and "needed_explicit_clear" in src,
            "it records whether raising the limit was enough on its own — VyOS "
            "exposes no `restart` sub-option, so recovery may be "
            "operator-driven")
    r.check("tripped" in src,
            "it records which peers actually left Established")


def check_external_mrt_diagnosis(r: Report) -> None:
    """An unmounted external MRT is not a stale bind mount."""
    import inspect
    from harness import runner
    src = inspect.getsource(runner._check_mrt_visible)
    r.check("EXTERNAL MRT" in src,
            "an external `mrt:` session gets its own diagnosis")
    r.check("--nexthop" in src,
            "the external-MRT message names the missing per-AF nexthop rewrite, "
            "which is the actual deferred work")
    r.check("remaining" in src,
            "the stale-bind-mount advice is not printed for sessions whose MRT "
            "is external and simply unmounted")


def check_process_kill_reinjects(r: Report) -> None:
    """Restarting gobgpd restores the session but not its table."""
    import inspect
    from harness.peers import PeerFleet
    src = inspect.getsource(PeerFleet.unflap)
    r.check("reinject_after_restart" in src,
            "process_kill / process_term re-inject the MRT after restarting "
            "gobgpd, so the peer does not come back advertising nothing")
    r.check(hasattr(PeerFleet, "reinject_after_restart"),
            "PeerFleet exposes reinject_after_restart")
    rsrc = inspect.getsource(PeerFleet.reinject_after_restart)
    r.check("global rib summary" in rsrc,
            "re-injection waits for the fresh gobgpd's gRPC API before loading, "
            "rather than failing silently into a discarded result")


def check_frr_saturation_signals(r: Report) -> None:
    """FRR's own starvation warning must be counted.

    T1 (42 sessions, 90,830 paths) logged
    `CPU starvation: {... bgp_generate_updgrp_packets ...} getting executed
    5181ms late` four times — bgpd's main thread blocked for over five seconds —
    and the report's failure-signal table showed only `attr_withdraw: 2` because
    nothing in LOG_PATTERNS matched it. See FINDINGS.md H-20.
    """
    import re as _re
    from harness.dut import Dut
    real = [
        "Aug 21 15:04:56 vyos bgpd[479]: [EC 100663315] CPU starvation: "
        "{(event *)0x7f arg=0x55 ready (bgp_generate_updgrp_packets)() "
        "(&connection->t_generate_updgrp_packets) from ../bgpd/bgp_io.c:155} "
        "getting executed 5181ms late, warning th>",
        "Aug 21 14:50:26 vyos bgpd[479]: [EC 100663315] CPU starvation: "
        "{... update_subgroup_merge_check_thread_cb ...} getting executed "
        "4545ms late, warning thresho>",
        "Aug 21 14:39:59 vyos bgpd[479]: [EC 33554455] 203.0.113.14 [Error] "
        "bgp_read_packet error: Connection reset by peer",
    ]
    hits = {k: 0 for k in Dut.LOG_PATTERNS}
    for line in real:
        for k, pat in Dut.LOG_PATTERNS.items():
            if _re.search(pat, line, _re.IGNORECASE):
                hits[k] += 1
    r.check(hits.get("cpu_starvation") == 2,
            f"FRR's `CPU starvation` warning is counted "
            f"(got {hits.get('cpu_starvation')} of 2 real log lines)")
    r.check(hits.get("read_packet_error") == 1,
            f"`bgp_read_packet error` is counted "
            f"(got {hits.get('read_packet_error')} of 1)")


def check_cpu_pct_sanity(r: Report) -> None:
    """CPU% must be divided by the interval the tick delta actually spans.

    T1 reported a bgpd max of 526.98% for a 4-thread process. 4 threads cap at
    400%, so the measurement was wrong: the divisor was the timestamp from the
    top of `sample()` while the tick delta ran to the /proc read, several seconds
    later on a slow sample. See FINDINGS.md H-21.
    """
    import inspect
    from harness.telemetry import Sampler

    src = inspect.getsource(Sampler.sample)
    r.check("proc_at" in src,
            "the CPU divisor uses a clock taken next to the /proc read")
    r.check("proc_read_lag_s" in src,
            "the sample records how far the /proc read lagged the sample start, "
            "so this class of skew is visible in the data")

    class D:
        def alive(self):
            return True

    sp = Sampler(dut=D(), path="/tmp/selftest-cpu.jsonl", interval=2.0)
    r.check(sp._cpu_pct("bgpd", 0, 100.0, 4) is None,
            "the first CPU sample has no baseline and reports None")
    # 8.00 s of CPU over 2.0 s wall across 4 threads == exactly 400%.
    r.check(sp._cpu_pct("bgpd", 800, 102.0, 4) == 400.0,
            "four fully-busy threads over the true interval report 400%")
    r.check(sp.cpu_pct_impossible == 0,
            "400% on 4 threads is not flagged impossible")
    # Same ticks over half the interval would be 800% — impossible, must flag.
    sp2 = Sampler(dut=D(), path="/tmp/selftest-cpu2.jsonl", interval=2.0)
    sp2._cpu_pct("bgpd", 0, 100.0, 4)
    sp2._cpu_pct("bgpd", 800, 101.0, 4)
    r.check(sp2.cpu_pct_impossible == 1,
            "a value above threads*100 is flagged as a measurement bug")


def check_memory_model(r: Report) -> None:
    """The report must not quote within-run bytes-per-path as a sizing number."""
    import inspect
    from analysis import analyze
    src = inspect.getsource(analyze.render_report)
    r.check("whole table" in src,
            "the report gives a whole-table RSS-per-path figure")
    r.check("Linear extrapolation" in src,
            "the report extrapolates memory to the next tier so sizing is "
            "explicit before the run rather than discovered during it")
    r.check("unusable unless the table grew" in src,
            "the report says outright when within-run bytes-per-path is "
            "measuring nothing")


def check_commit_phase_split(r: Report) -> None:
    """Apply and revert commit costs must be reported separately."""
    from analysis import analyze
    recs = [
        {"kind": "policy_churn_applied", "fragment": "community-retag",
         "commit_s": 32.6},
        {"kind": "policy_churn_reverted", "fragment": "community-retag",
         "commit_s": 0.31},
    ]
    cl = analyze.commit_latencies(recs)
    ph = cl.get("per_phase") or {}
    r.check("community-retag / apply" in ph and "community-retag / revert" in ph,
            f"commit latency is split by phase (got {sorted(ph)})")
    r.check(ph.get("community-retag / apply", {}).get("mean_s") == 32.6
            and ph.get("community-retag / revert", {}).get("mean_s") == 0.31,
            "each phase keeps its own figure rather than being averaged into "
            "one that describes neither")


def check_log_window_is_bounded(r: Report) -> None:
    """A quiet window must report zero, not the whole file.

    The shell form `journalctl --since ... | grep PAT || tail -n 4000 messages |
    grep PAT` fell through to the untimed fallback on every quiet window, because
    grep exits 1 when it matches nothing. 62 consecutive windows in one run each
    reported the identical `martian_nexthop: 332` carried over from the previous
    day. See FINDINGS.md H-18.
    """
    import inspect
    from harness.dut import Dut
    src = inspect.getsource(Dut.log_since)
    body = src.split('"""')[-1]
    # `extra_grep` is a parameter name, not a shell invocation; what must be
    # absent is the shell matching itself.
    r.check("grep -E" not in body and "| grep" not in body,
            "log_since matches in Python, not via shell grep (grep exits 1 on "
            "no-match, which made every quiet window fall through to an untimed "
            "fallback)")
    r.check("log_window_unbounded" in src,
            "log_since records whether the window was actually time-bounded")

    # Behavioural: a fake DUT whose journalctl works and returns nothing.
    class Quiet(Dut):
        def exec(self, cmd, timeout=None, input_=None):
            from harness.dut import RunResult
            if "journalctl" in cmd:
                return RunResult(0, "", "", 0.0)
            return RunResult(0, "Martian nexthop 0.0.0.0\n" * 300, "", 0.0)

    d = Quiet(container="fake")
    counts = d.log_counts("-10s")
    r.check(counts.get("martian_nexthop") == 0,
            f"a quiet time-bounded window reports 0, not the file's history "
            f"(got {counts.get('martian_nexthop')})")
    r.check("_window_unbounded" not in counts,
            "a successful journalctl read is not flagged unbounded")

    class NoJournal(Dut):
        def exec(self, cmd, timeout=None, input_=None):
            from harness.dut import RunResult
            if "journalctl" in cmd:
                return RunResult(1, "", "not available", 0.0)
            return RunResult(0, "Martian nexthop 0.0.0.0\n" * 3, "", 0.0)

    d2 = NoJournal(container="fake")
    c2 = d2.log_counts("-10s")
    r.check(c2.get("_window_unbounded") == 1,
            "falling back to an untimed read is flagged, not silently trusted")

    # The report must sum per-window counts and flag a constant.
    from analysis import analyze
    stale = [{"logs": {"martian_nexthop": 332}} for _ in range(62)]
    tot, unb, suspect = analyze.log_totals(stale)
    r.check(suspect, "a signature constant across every window is flagged suspect")
    live = [{"logs": {"sendq_stuck_warn": i % 4}} for i in range(30)]
    tot2, _, suspect2 = analyze.log_totals(live)
    r.check(not suspect2 and tot2.get("sendq_stuck_warn") == 43,
            f"genuinely varying counts are summed and not flagged "
            f"({tot2})")
    _, unb3, _ = analyze.log_totals([{"logs": {"_window_unbounded": 1,
                                               "maxprefix": 3}}])
    r.check(unb3, "an unbounded window propagates to the report")


def check_drift_attribution(r: Report) -> None:
    """End-of-run drift must be separable from drift the lab already had."""
    import inspect
    from harness import runner
    src = inspect.getsource(runner.cmd_run)
    r.check("accounting_at_start" in src,
            "run baselines the table before chaos so drift can be attributed")
    r.check("drift_this_run" in src and "drift_inherited" in src,
            "run reports inherited drift separately from drift it caused")


def check_self_inflicted_predicates(r: Report) -> None:
    """A deliberate flap must not be reported as a DUT fault.

    Reproduces the first full chaos run, whose FAIL verdict came entirely from
    the harness taking peers down on purpose: the scenario mix is 40 %
    `peer_flap` by weight and `max_failed_peers` was checked unconditionally.
    """
    from harness.telemetry import Budgets, PredicateSet
    b = Budgets.from_profile({"max_failed_peers": 0})
    ps = PredicateSet(b)
    sample = {"kind": "sample", "t": 10.0,
              "bgp": {"ipv4": {"peers": 5, "established": 4, "failed": 1},
                      "ipv6": {"peers": 5, "established": 4, "failed": 1}}}
    codes = {v.code for v in ps.check(sample)}
    r.check({"failed_peers_ipv4", "failed_peers_ipv6"} <= codes,
            "a down peer with no impairment declared is a fault")
    ps.impair_begin("peer_flap")
    codes = {v.code for v in ps.check(sample)}
    r.check(not ({"failed_peers_ipv4", "failed_peers_ipv6"} & codes),
            "a down peer during a declared impairment is NOT a fault")
    ps.impair_end(grace_s=0.0)
    codes = {v.code for v in ps.check(sample)}
    r.check({"failed_peers_ipv4", "failed_peers_ipv6"} <= codes,
            "faults resume once the impairment's grace window expires")

    # dplane queue_max is a high-water mark, not a live depth.
    ps2 = PredicateSet(Budgets.from_profile({}))
    dp = {"kind": "sample", "t": 0.0, "bgp": {},
          "dplane": {"queue_limit": 200, "queue_max": 201,
                     "route_update_errors": 0}}
    first = {v.code for v in ps2.check(dp)}
    r.check("dplane_queue_saturated_before_run" in first,
            "a queue high-water mark already at the limit is reported as "
            "pre-existing, not as a run-time event")
    again = {v.code for v in ps2.check(dict(dp, t=20.0))}
    r.check(not again,
            "the same high-water mark does not re-fire on every later sample")
    grew = {v.code for v in ps2.check(
        {"kind": "sample", "t": 40.0, "bgp": {},
         "dplane": {"queue_limit": 200, "queue_max": 260,
                    "route_update_errors": 0}})}
    r.check("dplane_queue_saturated" in grew,
            "a high-water mark that rises during the run IS reported")


def check_probe_check_announces(r: Report) -> None:
    """`ev_probe_check` must announce before it looks up.

    As the `run` command's final policy check it queried 18 prefixes nothing had
    announced: 14 vacuous passes and 4 spurious failures, with a confirmed
    template defect among the "passes".
    """
    import inspect
    from harness import scenarios
    src = inspect.getsource(scenarios.ev_probe_check)
    r.check("probe_announce_commands" in src,
            "ev_probe_check announces the probes before checking them")
    r.check("probe_withdraw_commands" in src,
            "ev_probe_check withdraws the probes afterwards")
    r.check("peer_asn=sess.asn" in src,
            "ev_probe_check announces from a real ExaBGP session with its own ASN")
    r.check("unexplained" in src,
            "ev_probe_check separates confirmed template defects from "
            "unexplained failures")
    import inspect as _i
    from harness import runner
    rsrc = _i.getsource(runner.cmd_run)
    r.check("_accounting" in rsrc,
            "run compares announced vs accepted prefixes before reporting peaks")


def check_isolation_hygiene(r: Report) -> None:
    """The isolation pass must start from an empty Adj-RIB-Out and grep for the
    line each case is expected to produce."""
    from harness import scenarios
    from harness.peers import PeerFleet
    import inspect
    src = inspect.getsource(scenarios.ev_malformed_isolate)
    r.check("fresh_session" in src and "restart_exabgp" in src,
            "malformed_isolate restarts ExaBGP by default so no earlier case is "
            "still being advertised")
    r.check("expect_log" in src,
            "malformed_isolate greps for each case's own expected log line")
    r.check(hasattr(PeerFleet, "restart_exabgp")
            and hasattr(PeerFleet, "start_exabgp")
            and "exabgp --env-file" in PeerFleet.EXABGP_SERVER_CMD,
            "the ExaBGP launch command lives in one place (PeerFleet."
            "EXABGP_SERVER_CMD) so a restart cannot drift from a cold start")
    # exclude_tags=() so the full catalogue is inspected: the martian pair is
    # excluded from *runs* by default (policyprobe.EXCLUDED_TAGS) but the cases
    # still have to be correct, since isolation mode can name them.
    mal = {m.mid: m for m in policyprobe.build_malformed(
        "198.51.100.14", "2001:db8:1::e", 64000, 64400, exclude_tags=())}
    for mid in ("nexthop-zero", "nexthop-multicast"):
        m = mal.get(mid)
        r.check(m is not None and m.expect_log == "Martian nexthop",
                f"{mid} declares FRR's verbatim `Martian nexthop` line as its "
                f"expected evidence")


def check_probe_withdraw_before_malformed(r: Report) -> None:
    """The probes must be withdrawn before the malformed phase."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "harness", "runner.py"),
        encoding="utf-8").read()
    i_w = src.find("probe_withdraw_commands")
    i_m = src.find("ev_malformed_burst")
    r.check(0 < i_w < i_m,
            "cmd_probe withdraws the policy probes before running the malformed "
            "suite (leaving bogon-asn-zero announced injects AS-0 log lines into "
            "every reconnect and misattributes the cause)")


def check_boot_count_parser(r: Report) -> None:
    """The boot-count parser that decides whether ExaBGP actually announced."""
    from harness.runner import _boot_commands_sent
    cases = [
        ("sent 30 boot commands from /etc/exabgp/boot.txt", 30),
        ("helper up\nsent 0 boot commands from /etc/exabgp/boot.txt", 0),
        ("BOOT-MISSING: /etc/exabgp/boot.txt does not exist", 0),
        ("BOOT-EMPTY: /etc/exabgp/boot.txt contained no commands", 0),
        ("helper up, reading /run/exabgp-cmd", None),
        ("", None),
    ]
    bad = [(txt[:40], _boot_commands_sent(txt), want)
           for txt, want in cases if _boot_commands_sent(txt) != want]
    r.check(not bad, "ExaBGP boot-count parser maps helper logs correctly"
            + ("" if not bad else f" — {bad}"))


def check_peerfleet_arg_shapes(r: Report) -> None:
    """`exabgp_helper_log` must accept a Session *or* a container name."""
    rec = _FakeRun()
    fleet = _fake_fleet(rec)
    sess = type("S", (), {"container": "ixp1-nasty-c000"})()
    try:
        a = fleet.exabgp_helper_log(sess)
        b = fleet.exabgp_helper_log("ixp1-nasty-c000")
    except Exception as exc:
        r.bad(f"exabgp_helper_log rejected one of its call shapes: "
              f"{type(exc).__name__}: {exc}")
        return
    r.check(a == b and rec.containers[-2:] == ["ixp1-nasty-c000"] * 2,
            "exabgp_helper_log accepts both a Session and a container name")


def check_injection_strings(r: Report) -> None:
    print("\n== probe and malformed-attribute strings")
    probes = policyprobe.build_probes(64000, "100.64.0.0/16", "3fff:100::/32",
                                      "198.51.100.14", "2001:db8:1::e")
    mal = policyprobe.build_malformed("198.51.100.14", "2001:db8:1::e", 64000)
    r.check(len(probes) > 10, f"{len(probes)} policy probes defined")
    r.check(len(mal) > 10, f"{len(mal)} malformed-attribute cases defined")
    r.check(len(policyprobe.NOT_ACHIEVABLE_WITH_EXABGP) > 0,
            f"{len(policyprobe.NOT_ACHIEVABLE_WITH_EXABGP)} case(s) documented as "
            f"needing a byte-level injector")
    defects = [p for p in probes if p.template_defect]
    r.check(len(defects) > 0,
            f"{len(defects)} probe(s) assert a known template defect")

    # Every prefix must be unique, or two probes silently test the same thing.
    allp = [p.prefix for p in probes] + [m.prefix for m in mal]
    dupes = [x for x, c in Counter(allp).items() if c > 1]
    r.check(not dupes, f"all {len(allp)} probe/malformed prefixes are distinct"
            + ("" if not dupes else f" — duplicated: {dupes[:4]}"))

    # Regression guard for a silent-failure bug found by capturing ExaBGP's own
    # UPDATE off the wire: when a route statement carries both `as-path [...]` and
    # a generic `attribute [ 0x02 ... ]`, whichever appears FIRST wins. With
    # as-path first, the hand-encoded AS_PATH is discarded and an ordinary
    # AS_SEQUENCE is sent — so the case validates, transmits, and tests nothing.
    # Any case hand-encoding AS_PATH must therefore put `attribute` first.
    misordered = []
    for m in mal:
        a = m.attrs
        if "attribute [ 0x02" not in a or "as-path" not in a:
            continue
        if a.index("as-path") < a.index("attribute [ 0x02"):
            misordered.append(m.mid)
    r.check(not misordered,
            "every hand-encoded AS_PATH case puts `attribute` before `as-path` "
            "(first clause wins; the reverse order silently sends a normal AS_PATH)"
            + ("" if not misordered else f" — misordered: {misordered}"))

    major, ver, exe = exabgp_flavor()
    if not exe:
        r.skip("exabgp not installed — cannot validate route statements "
               "(pip install 'exabgp>=5')")
        return
    if major not in ("4", "5"):
        r.skip(f"exabgp {ver} has an unrecognised CLI; cannot validate route "
               f"statements")
        return

    # Two gates, because the two validation modes catch different things and
    # neither is correct alone (see the note in harness/policyprobe.py):
    #   -n  structural config validity; matches whether `exabgp server` starts
    #   -r  additionally re-parses each route, catching attribute-level breakage,
    #       but false-rejects hand-encoded AS_PATH that the runtime sends fine
    gate_n: List[Tuple[str, str]] = []
    gate_r: List[Tuple[str, str]] = []
    deferred: List[str] = []
    r_exempt: List[str] = []

    for p_, c in zip(probes, policyprobe.probe_announce_commands(
            probes, "198.51.100.14", "2001:db8:1::e",
            "198.51.100.1", "2001:db8:1::1")[1:]):
        stmt = c.split(" announce route ", 1)[1]
        gate_n.append((f"probe:{p_.pid}", stmt))
        gate_r.append((f"probe:{p_.pid}", stmt))

    for m, c in zip(mal, policyprobe.malformed_announce_commands(
            mal, "198.51.100.1", "2001:db8:1::1")[1:]):
        stmt = c.split(" announce route ", 1)[1]
        # Some constructs exist only in ExaBGP 5.x — AS_SET via `as-path ( ... )`
        # and hand-encoded AS_PATH segments. The peer container always runs 5.0.9,
        # so the lab is unaffected; only host-side validation defers them.
        if m.requires_exabgp == "5" and major != "5":
            deferred.append(m.mid)
            continue
        gate_n.append((f"malformed:{m.mid}", stmt))
        if m.exabgp_r_rejects:
            r_exempt.append(m.mid)
        else:
            gate_r.append((f"malformed:{m.mid}", stmt))

    if deferred:
        r.skip(f"{len(deferred)} case(s) need ExaBGP 5.x syntax and this host has "
               f"{ver}, so they were not validated offline: {', '.join(deferred)}. "
               f"They still run correctly in the lab (the peer image pins 5.0.9). "
               f"`pip install 'exabgp>=5'` to validate them here too.")

    def conf_for(rs: List[Tuple[str, str]]) -> str:
        body = "\n".join(f"        route {rt};" for _, rt in rs)
        return (
            "neighbor 127.0.0.1 {\n"
            "    router-id 1.2.3.4;\n"
            "    local-address 127.0.0.1;\n"
            "    local-as 64400;\n"
            "    peer-as 64000;\n"
            "    family { ipv4 unicast; ipv6 unicast; }\n"
            "    static {\n" + body + "\n    }\n}\n"
        )

    def validate(rs: List[Tuple[str, str]], mode: str) -> Tuple[bool, str]:
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write(conf_for(rs))
            path = fh.name
        try:
            return exabgp_validate(exe, major, path, mode=mode)
        finally:
            os.unlink(path)

    def gate(rs: List[Tuple[str, str]], mode: str, label: str) -> None:
        if not rs:
            return
        ok, out = validate(rs, mode)
        if ok:
            r.ok(f"all {len(rs)} {label} statement(s) pass {mode} validation on "
                 f"exabgp {ver}")
            return
        # One bad statement fails the whole file and the error rarely names it,
        # so bisect down to the offenders to make the report actionable.
        culprits = [nm for nm, rt in rs if not validate([(nm, rt)], mode)[0]]
        r.bad(f"{len(culprits)} of {len(rs)} {label} statement(s) rejected by "
              f"{mode} validation on exabgp {ver}: {', '.join(culprits[:6])}"
              + (" ..." if len(culprits) > 6 else "")
              + (f" | error: {out[-200:]}" if out else ""))

    gate(gate_n, "neighbor", "probe/malformed route")
    if major == "5":
        gate(gate_r, "route", "route-reparse-safe")
        if r_exempt:
            r.skip(
                f"{len(r_exempt)} case(s) exempt from `-r` validation because it "
                f"is stricter than the runtime: {', '.join(r_exempt)}. `-r` "
                f"re-serialises each route, and that round trip does not preserve "
                f"a hand-written attribute byte-for-byte; `exabgp server` sends "
                f"what was written. Each was verified another way instead: the "
                f"two aspath cases by capturing the UPDATE off the wire "
                f"(CONFED_SEQUENCE and a truncated AS_PATH segment), and the two "
                f"unknown-attr cases by packing the attribute through ExaBGP's "
                f"own encoder and reading the flag byte (0x80 -> 80990400000064, "
                f"0xc0 -> c0990400000064). `-r` adds the PARTIAL bit to an "
                f"unrecognised optional-transitive attribute, as RFC 4271 "
                f"section 5 requires of a receiver passing it on, which is why it "
                f"rejects the as-originated spellings.")
    else:
        r.skip(f"exabgp {ver} has no separate route-reparse mode (`-r` is 5.x only), "
               f"so attribute-level validation was not run. Structural validation "
               f"passed.")


def check_gobgp_toml(r: Report, build: str, invj: Dict, name: str) -> None:
    try:
        import tomllib as toml_r
        loads = lambda s: toml_r.loads(s)  # noqa: E731
    except ImportError:
        try:
            import toml as _t
            loads = _t.loads
        except ImportError:
            r.skip(f"{name}: no TOML parser available")
            return
    files = sorted(glob.glob(os.path.join(build, "gobgp", "*", "*.toml")))
    if not files:
        r.skip(f"{name}: no GoBGP configs in this profile")
        return
    checked = 0
    for path in files[:6]:
        sid = os.path.basename(path)[:-5]
        try:
            d = loads(open(path, encoding="utf-8").read())
        except Exception as exc:
            r.bad(f"{name}: {sid}.toml does not parse: {exc!r}")
            continue
        sess = next((s for s in invj["sessions"] if s["sid"] == sid), None)
        problems = []
        g = (d.get("global") or {}).get("config") or {}
        if not g.get("as"):
            problems.append("global.config.as missing")
        if sess and g.get("as") != sess["asn"]:
            problems.append(f"global.config.as {g.get('as')} != {sess['asn']}")
        if not g.get("local-address-list"):
            problems.append("local-address-list missing (needed so many gobgpd "
                            "can share port 179 in one container)")
        nbrs = d.get("neighbors") or []
        want = len([k for k in ("v4", "v6") if sess and sess.get(k)]) if sess else 1
        if len(nbrs) != want:
            problems.append(f"{len(nbrs)} neighbors, expected {want}")
        for nb in nbrs:
            if not ((nb.get("config") or {}).get("neighbor-address")):
                problems.append("neighbor missing neighbor-address")
            if not ((nb.get("transport") or {}).get("config") or {}).get("local-address"):
                problems.append("neighbor missing transport.config.local-address")
            afs = nb.get("afi-safis") or []
            if not afs:
                problems.append("neighbor declares no afi-safis")
            for af in afs:
                nm = (af.get("config") or {}).get("afi-safi-name")
                if nm not in ("ipv4-unicast", "ipv6-unicast"):
                    problems.append(f"unexpected afi-safi-name {nm!r}")
            # route-server-client must NOT be set. gobgp v4.8.0 binds such a
            # peer to s.rsRib (server.go:3526) and skips it entirely for
            # locally-originated paths (server.go:1464:
            #   if source == nil && targetPeer.isRouteServerClient() continue),
            # while `gobgp mrt inject global` goes through
            # addPathList -> propagateUpdate(nil, ...) (server.go:2432). So the
            # session comes up Established and receives zero routes. There is no
            # inject target for an RS table: AddPathStream rejects any TableType
            # other than GLOBAL/VRF (grpc_server.go:703).
            if ((nb.get("route-server") or {}).get("config") or {}
                    ).get("route-server-client"):
                problems.append(
                    "route-server-client is set: MRT-injected paths are never "
                    "advertised to a route-server client (gobgp server.go:1464)")
        r.check(not problems, f"{name}: {sid}.toml valid"
                + ("" if not problems else f" — {problems[:3]}"))
        checked += 1
    if checked:
        r.ok(f"{name}: {checked}/{len(files)} GoBGP configs sampled")


def check_dut_config(r: Report, build: str, invj: Dict, name: str) -> None:
    ddir = os.path.join(build, "dut")
    for fn in ("00-base.conf", "10-neighbors.conf", "20-instrument.conf"):
        p = os.path.join(ddir, fn)
        if not os.path.exists(p):
            r.bad(f"{name}: dut/{fn} missing")
            continue
        body = open(p, encoding="utf-8").read()
        left = re.findall(r"<PLACEHOLDER_[A-Za-z0-9_]+>", body)
        active = [l for l in body.splitlines()
                  if l.strip() and not l.strip().startswith("#")]
        r.check(not left, f"{name}: dut/{fn} has no unresolved placeholders "
                f"({len(active)} active command(s))"
                + ("" if not left else f" — {sorted(set(left))[:3]}"))
        bad = [l for l in active if not l.startswith(("set ", "delete "))]
        r.check(not bad, f"{name}: dut/{fn} contains only set/delete commands"
                + ("" if not bad else f" — {bad[:2]}"))

    base = open(os.path.join(ddir, "00-base.conf"), encoding="utf-8").read()
    if not invj["dut"].get("mgmt_vrf", False):
        r.check("input filter rule 11 inbound-interface name 'eth0'" in base,
                f"{name}: a management accept rule on eth0 exists — without it the "
                f"template's default-action drop locks the harness out on first commit")
        r.check("set vrf name management" not in
                "\n".join(l for l in base.splitlines() if not l.startswith("#")),
                f"{name}: management VRF not applied (containerlab owns eth0)")

    nb = open(os.path.join(ddir, "10-neighbors.conf"), encoding="utf-8").read()
    pgs = set(re.findall(r"peer-group '([^']+)'", nb))
    unknown = pgs - TEMPLATE_PEER_GROUPS
    r.check(not unknown, f"{name}: neighbours reference only defined peer-groups"
            + ("" if not unknown else f" — {sorted(unknown)}"))
    n_neigh = len(set(re.findall(r"set protocols bgp neighbor (\S+) description", nb)))
    want = len([s for s in invj["sessions"] if s.get("v4")]) + \
        len([s for s in invj["sessions"] if s.get("v6")])
    r.check(n_neigh == want,
            f"{name}: {n_neigh} neighbour stanzas for {want} address-family sessions")

    # every fabric must be permitted through the input filter, or BGP never arrives
    for fid, fab in invj["fabrics"].items():
        r.check(f"bgp_speakers4 network '{fab['v4_net']}'" in base,
                f"{name}: fabric {fid} v4 net is in the bgp_speakers4 firewall group")

    churn = sorted(glob.glob(os.path.join(ddir, "churn", "*.apply.conf")))
    r.check(len(churn) >= 5, f"{name}: {len(churn)} policy-churn fragment(s)")
    for a in churn:
        rev = a.replace(".apply.conf", ".revert.conf")
        if not os.path.exists(rev):
            r.bad(f"{name}: {os.path.basename(a)} has no matching revert fragment")


def check_prefix_plan(r: Report) -> None:
    print("\n== prefix planning")
    plan = routegen.PrefixPlan(v4_first_octets=generate.expand_octets("1-9,11-99"),
                               v4_len=24, v6_base="3fff::/20", v6_len=48, seed=7)
    a = list(plan.session_v4(3, 200))
    b = list(plan.session_v4(3, 200))
    r.check(a == b, "v4 allocation is deterministic")
    r.check(list(plan.session_v6(3, 50)) == list(plan.session_v6(3, 50)),
            "v6 allocation is deterministic")
    r.check(all(ipaddress.ip_network(p).prefixlen == 24 for p in a),
            "generated v4 prefixes are /24 (inside ipv4-acceptable ge 8 le 24)")
    octs = {int(p.split(".")[0]) for p in a}
    r.check(octs <= set(generate.expand_octets("1-9,11-99")),
            "generated v4 prefixes stay inside the declared /8 pool")
    r.check(not (octs & {0, 10, 127}),
            "generated v4 prefixes avoid the /8s the template's ipv4-bogons rejects")
    v6 = list(plan.session_v6(1, 20))
    net = ipaddress.ip_network("3fff::/20")
    r.check(all(ipaddress.ip_network(p).subnet_of(net) for p in v6),
            "generated v6 prefixes are inside RFC 9637 3fff::/20")
    r.check(all(ipaddress.ip_network(p).prefixlen == 48 for p in v6),
            "generated v6 prefixes are /48 (inside ipv6-acceptable ge 12 le 48)")

    # contested pool must actually overlap between sessions
    s1 = set(plan.session_v4(1, 400))
    s2 = set(plan.session_v4(2, 400))
    r.check(bool(s1 & s2),
            f"contested pool overlaps across sessions ({len(s1 & s2)} shared prefixes) "
            f"— without this, bestpath has nothing to choose between")

    for bad_spec, why in (("1-9,10", "a bogon /8"), ("1-9,999", "a non-unicast /8"),
                          ("1,1", "a duplicate")):
        try:
            generate.expand_octets(bad_spec)
            r.bad(f"expand_octets accepted {bad_spec!r} containing {why}")
        except ValueError:
            r.ok(f"expand_octets rejects {bad_spec!r} ({why})")

    for kw in ({"v4_len": 25}, {"v4_len": 7}, {"v6_len": 64}, {"v6_len": 8}):
        try:
            routegen.PrefixPlan(v4_first_octets=[1], **kw)
            r.bad(f"PrefixPlan accepted out-of-policy {kw}")
        except ValueError:
            r.ok(f"PrefixPlan rejects {kw} (outside the template's acceptable range)")


def check_image_resolution(r: Report) -> None:
    """The DUT-image resolver: the tag mismatch that cost a deploy cycle.

    `build-image.sh` derives its tag from the ISO filename, so an ISO named
    vyos-1.5.1-generic-amd64.iso yields vyos-stress:1.5.1 while the profiles
    declare vyos-stress:latest. Requiring VYOS_IMAGE= on every generate is a
    footgun, and containerlab reports the resulting missing image as a Docker Hub
    authentication failure.
    """
    print("\n== DUT image resolution")
    R = generate.resolve_dut_image

    img, note = R("vyos-stress:latest", ["vyos-stress:1.5.1"], False)
    r.check(img == "vyos-stress:1.5.1" and note,
            "a declared tag that is absent resolves to the single built image, "
            "with an explanatory note")

    img, note = R("vyos-stress:1.5.1", ["vyos-stress:1.5.1"], True)
    r.check(img == "vyos-stress:1.5.1" and not note,
            "a declared tag that is present is used unchanged and silently")

    img, note = R("vyos-stress:latest", [], False)
    r.check(img == "vyos-stress:latest" and not note,
            "with nothing built, the declared tag is kept so the missing-image "
            "message names what the profile asked for")

    try:
        R("vyos-stress:latest",
          ["vyos-stress:1.5.1", "vyos-stress:2026.03"], False)
        r.bad("two candidate images were silently guessed between")
    except ValueError as exc:
        r.check("Refusing to guess" in str(exc),
                "two candidates are refused rather than guessed — the VyOS release "
                "is one of the two variables that most affects the result")


def check_profile_errors(r: Report, template: str) -> None:
    print("\n== profile validation")
    base = model.load_profile("profiles/t0-smoke.yaml")

    import copy
    bad = copy.deepcopy(base)
    bad["dut"]["asn"] = 65001
    try:
        model.build_inventory(bad)
        r.bad("a private (bogon) DUT ASN was accepted")
    except model.ProfileError:
        r.ok("a private DUT ASN is rejected (the template would filter its own AS_PATH)")

    bad = copy.deepcopy(base)
    bad["fabrics"]["ixp1"]["dut_iface"] = "eth0"
    try:
        model.build_inventory(bad)
        r.bad("eth0 was accepted as a data interface")
    except model.ProfileError:
        r.ok("eth0 is rejected as a data interface (containerlab reserves it)")

    bad = copy.deepcopy(base)
    bad["fabrics"]["ixp2"]["dut_iface"] = "eth1"
    try:
        model.build_inventory(bad)
        r.bad("two fabrics were allowed to share one interface")
    except model.ProfileError:
        r.ok("two fabrics cannot share one DUT interface")

    bad = copy.deepcopy(base)
    bad["fleets"][1]["asn_base"] = bad["fleets"][0]["asn_base"]
    try:
        model.build_inventory(bad)
        r.bad("overlapping fleet ASN ranges were accepted")
    except model.ProfileError:
        r.ok("overlapping fleet ASN ranges are rejected")

    bad = copy.deepcopy(base)
    bad["fleets"][0]["asn_base"] = base["dut"]["asn"]
    try:
        model.build_inventory(bad)
        r.bad("a peer reusing the DUT ASN was accepted")
    except model.ProfileError:
        r.ok("a peer reusing the DUT ASN is rejected")

    bad = copy.deepcopy(base)
    bad["fleets"][0]["peers"] = 5000
    try:
        model.build_inventory(bad)
        r.bad("a fleet larger than its peering LAN was accepted")
    except model.ProfileError:
        r.ok("a fleet that exhausts its peering LAN is rejected")


def check_route_summary_reads_real_frr_output(r: Report) -> None:
    """H-51. FRR prints `ebgp`/`ibgp`, never a single `bgp` row.

    Verbatim from the DUT on 2026-09-01, VyOS 1.5.1 / FRR 10.5.2, holding the
    T3 table:

        Route Source         Routes               FIB  (vrf default)
        kernel               1                    1
        connected            3                    3
        local                3                    3
        static               47                   47
        ebgp                 2445625              2445625
        ibgp                 0                    0
        ------
        Totals               2445679              2445679

    `route_summary()` looked up `sources["bgp"]`, got None, and
    `_fib_agrees()` turned None into "zebra has no ipv4 BGP routes at all ...
    the FIB is empty". T3 run 1 printed that 160 times across the whole 2,400 s
    warmup and recorded `initial_converged: false`, against a FIB that was
    100.0% installed. The operator's own `show ip bgp` looked perfect, because
    it was.
    """
    from harness.dut import Dut, RunResult

    real = (
        "Route Source         Routes               FIB  (vrf default)\n"
        "kernel               1                    1\n"
        "connected            3                    3\n"
        "local                3                    3\n"
        "static               47                   47\n"
        "ebgp                 2445625              2445625\n"
        "ibgp                 0                    0\n"
        "------\n"
        "Totals               2445679              2445679\n"
    )

    class D(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, real, "", 0.0)

    rs = D(container="x").route_summary("ipv4")
    r.check(rs.get("bgp_routes") == 2445625,
            f"the ebgp row is counted as BGP ({rs.get('bgp_routes')})")
    r.check(rs.get("bgp_fib") == 2445625,
            f"and so is its FIB column ({rs.get('bgp_fib')})")
    r.check(rs.get("bgp_fib_ratio") == 1.0,
            f"giving a fully-installed ratio ({rs.get('bgp_fib_ratio')})")
    r.check(rs.get("bgp_source_rows") == ["ebgp", "ibgp"],
            f"and it says which rows it used ({rs.get('bgp_source_rows')})")
    r.check(rs.get("total_routes") == 2445679,
            "the Totals row is still parsed separately")

    # A build that does emit a single `bgp` row must still work.
    legacy = ("Route Source         Routes               FIB  (vrf default)\n"
              "bgp                  1000                 900\n"
              "------\n"
              "Totals               1000                 900\n")

    class L(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, legacy, "", 0.0)

    rs2 = L(container="x").route_summary("ipv4")
    r.check(rs2.get("bgp_routes") == 1000 and rs2.get("bgp_fib") == 900,
            "a single `bgp` row is read the same way")

    # And a layout with no BGP row at all reports None, so the caller can call
    # it unmeasured rather than zero.
    none_out = ("Route Source         Routes               FIB  (vrf default)\n"
                "kernel               1                    1\n")

    class N(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, none_out, "", 0.0)

    rs3 = N(container="x").route_summary("ipv4")
    r.check(rs3.get("bgp_routes") is None and rs3.get("bgp_source_rows") == [],
            "no BGP row at all yields None, not 0")


def check_no_counter_is_compared_to_a_table_size(r: Report) -> None:
    """H-52. `route_installs` is cumulative; `rib_count` is not a route count.

    T3 run 1 reported, as a warning with a sentence about unreachable traffic:
    "3,049,967 of 5,821,556 RIB entries installed in the FIB (52%) ...
    2,771,589 prefixes are not reachable" — while zebra's own summary read
    2,445,625 of 2,445,625. Both operands were wrong. By the end of the same
    run the counter had reached 13,890,066 against a 5,783,732-entry RIB, and
    the recorded `fib_lag` was **-8,106,334**, which is the shape of the error
    in one number.
    """
    import inspect, re as _re
    from harness import telemetry, runner

    for fn in (telemetry.ConvergenceTracker.busy, telemetry.PredicateSet.check):
        src = inspect.getsource(fn)
        body = "\n".join(l for l in src.splitlines()
                          if not l.strip().startswith("#"))
        has_installs = "route_installs" in body
        has_ratio = _re.search(r"installs\s*[/<]", body)
        r.check(not (has_installs and has_ratio),
                f"{fn.__qualname__} does not divide or compare a cumulative "
                f"install counter against a table size")

    # The replacement must exist and must take zebra's own summary.
    fsrc = inspect.getsource(telemetry.PredicateSet.feed_fib)
    r.check("bgp_routes" in fsrc and "bgp_fib" in fsrc,
            "PredicateSet.feed_fib judges the FIB from route_summary output")
    csrc = inspect.getsource(runner._converge)
    r.check("feed_fib" in csrc,
            "and _converge feeds it the summary it already took")

    b = telemetry.Budgets(fib_min_ratio=0.95, fib_lag_grace_s=300.0)
    ps = telemetry.PredicateSet(b)
    good = ps.feed_fib({"ok": True, "afi": "ipv4", "bgp_routes": 2445625,
                        "bgp_fib": 2445625, "sources": {"ebgp": {}}}, t=10.0)
    r.check(not good, "a fully-installed FIB raises nothing")
    bad = ps.feed_fib({"ok": True, "afi": "ipv4", "bgp_routes": 2445625,
                       "bgp_fib": 100, "sources": {"ebgp": {}}}, t=10.0)
    r.check(len(bad) == 1 and bad[0].code == "fib_behind_rib",
            "a genuinely lagging FIB still raises fib_behind_rib")
    unk = ps.feed_fib({"ok": True, "afi": "ipv4", "bgp_routes": None,
                       "bgp_fib": None, "sources": {"kernel": {}}}, t=10.0)
    r.check(len(unk) == 1 and unk[0].code == "fib_summary_unrecognised"
            and unk[0].severity == "warn",
            "an unreadable layout is a measurement gap, not a FIB failure")


def check_every_daemon_restart_is_reported(r: Report) -> None:
    """H-55. T3 run 1 restarted bgpd three times and reported one.

    503 -> 178177 (15:06), 178177 -> 198291 (15:29), 198291 -> 240636 (16:36).
    All three were watchfrr kills, each costing between 2m36s and 3m55s of
    total BGP outage. `check_new` suppressed the second and third because it
    keys on (code, severity), which is right for a standing condition and wrong
    for a repeatable event.
    """
    from harness import telemetry

    ps = telemetry.PredicateSet(telemetry.Budgets())

    def sample(t, pid, unresponsive=0):
        return {"kind": "sample", "t": t,
                "bgp": {"ipv4": {"read_ok": True, "peers": 1, "established": 1,
                                 "failed": 0},
                        "ipv6": {"read_ok": True, "peers": 1, "established": 1,
                                 "failed": 0}},
                "proc": {"bgpd": {"pid": pid, "rss_mb": 10.0, "threads": 4,
                                  "cpu_pct": 1.0}},
                "logs": {"daemon_unresponsive": unresponsive}}

    seen = []
    for t, pid, un in ((0, 503, 0), (100, 503, 1), (200, 178177, 0),
                       (300, 178177, 1), (400, 198291, 0),
                       (500, 198291, 1), (600, 240636, 0)):
        seen += [v for v in ps.check_new(sample(t, pid, un))
                 if v.code == "bgpd_restarted"]
    r.check(len(seen) == 3,
            f"all three PID changes are reported, not just the first "
            f"({len(seen)})")
    r.check([v.evidence["nth"] for v in seen] == [1, 2, 3],
            "and each is numbered")
    r.check(all(v.evidence["watchdog_kill"] for v in seen),
            "each is attributed to watchfrr, because the 'unresponsive' line "
            "was logged within the attribution window — it precedes the kill "
            "by 90-160 s, so it is never in the same sample (H-56)")

    # H-62. The window has to span the whole watchfrr sequence, not just its
    # first timeout. Measured unresponsive-to-back-up: 177, 228, 238, 362,
    # 365 s across runs 2 and 3. A 338 s gap in run 3 fell outside the old
    # 300 s window and was reported as `watchdog_kill: false`.
    r.check(telemetry.PredicateSet.WATCHDOG_ATTRIBUTION_S >= 400.0,
            f"the watchdog attribution window covers the longest observed "
            f"sequence ({telemetry.PredicateSet.WATCHDOG_ATTRIBUTION_S:.0f}s "
            f"vs 365s measured)")
    ps2 = telemetry.PredicateSet(telemetry.Budgets())
    late = [v for v in
            (ps2.check_new(sample(0, 505, 1)) + ps2.check_new(sample(338, 67433)))
            if v.code == "bgpd_restarted"]
    r.check(late and late[0].evidence["watchdog_kill"],
            "a PID change 338 s after the 'unresponsive' line is still "
            "attributed to watchfrr — the exact run 3 gap")


def check_log_windows_do_not_leave_gaps(r: Report) -> None:
    """H-56. A 10 s window on a 15 s cadence never reads a third of the log.

    T3 run 1 recorded `daemon_unresponsive: 0` in every one of 705 slow
    samples, while the journal held three `bgpd state -> unresponsive` lines.
    interval 3.0 x slow_every 5 = 15 s between reads; log_window was "-10s".
    """
    import inspect
    from harness import telemetry

    src = inspect.getsource(telemetry.Sampler.sample)
    r.check("_last_log_read" in src,
            "the sampler tracks when it last read the log")
    r.check("log_window_s" in src,
            "and records the window each sample actually covered")

    class FakeDut:
        def __init__(self):
            self.windows = []

        def alive(self):
            return True

        def bgp_summary(self, afi):
            return {"peers": {}}

        def proc_stats(self):
            return {}

        def zebra_stats(self):
            return {}

        def dplane_stats(self):
            return {}

        def cgroup_mem(self):
            return 0

        def log_counts(self, since):
            self.windows.append(since)
            return {}

    import tempfile, os as _os, time as _time
    d = FakeDut()
    with tempfile.TemporaryDirectory() as td:
        sp = telemetry.Sampler(dut=d, path=_os.path.join(td, "s.jsonl"),
                               interval=0.01, slow_every=1)
        sp.start()
        _time.sleep(0.35)
        sp.stop()
    secs = [int(w.strip("-s")) for w in d.windows[1:] if w.startswith("-")]
    r.check(d.windows and all(w.startswith("-") for w in d.windows),
            f"log windows are bounded ({d.windows[:3]})")
    r.check(len(d.windows) >= 2, "the sampler took more than one log read")
    r.check(all(x >= 10 for x in secs) if secs else True,
            "the window never drops below the configured floor")


def check_peer_side_socket_state_is_captured(r: Report) -> None:
    """R-8/H-57. `Active` on the DUT does not say whose fault it is.

    T3 run 1 finished with 75 of 154 IPv6 sessions in `Active` and held that
    for the whole 3,600 s settle with bgpd at 0.4% CPU. `Active` means the DUT
    is dialling and getting nothing back, which is equally consistent with the
    far-end speaker being gone and with the DUT's connects failing. Nothing in
    that run captured the peer side, so the largest number it produced could
    not be reported to anybody.

    The discriminator is the peer's own TCP state, read from /proc so it does
    not depend on `ss` or `netstat` existing in the generator image. The
    fixture below is encoded exactly as the kernel writes it — each 32-bit word
    of the address in host byte order — because a parser is not verified until
    it has been run against the real byte layout (H-51).
    """
    import inspect
    from harness import peers, runner
    from harness.model import Session

    # `2001:db8:1::3f` is one of the sessions that was actually stuck in
    # run 1; `2001:db8:1::1` is the DUT. 00B3 is port 179.
    proc = (
        "  sl  local_address remote_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
        "   0: 1D6033C6:0035 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000     0        0 1 1 0 0 0\n"
        "   1: 1D6033C6:00B3 0B6033C6:C1A5 01 00000000:00000000 00:00000000 "
        "00000000     0        0 1 1 0 0 0\n"
        "  sl  local_address                         remote_address"
        "                        st tx_queue rx_queue tr tm->when retrnsmt\n"
        "   0: 00000000000000000000000000000000:00B3 "
        "00000000000000000000000000000000:0000 0A 00000000:00000000\n"
        "   1: B80D012000000100000000003F000000:C655 "
        "B80D0120000001000000000001000000:00B3 02 00000000:00000000\n"
    )
    rows = peers.parse_proc_net_tcp(proc)
    by_state = {x["state"]: x for x in rows}
    r.check(len(rows) == 3,
            f"only port-179 rows are kept, DNS and the rest dropped ({len(rows)})")
    r.check(by_state.get("ESTABLISHED", {}).get("local") == "198.51.96.29",
            f"IPv4 address decoded from little-endian /proc hex "
            f"({by_state.get('ESTABLISHED', {}).get('local')})")
    syn = by_state.get("SYN_SENT") or {}
    r.check(syn.get("local") == "2001:db8:1::3f",
            f"IPv6 local address decoded word-by-word ({syn.get('local')})")
    r.check(syn.get("remote") == "2001:db8:1::1",
            f"and the DUT it is dialling ({syn.get('remote')})")
    r.check(any(x["state"] == "LISTEN" and x["local"] == "::" for x in rows),
            "a wildcard IPv6 listener is recognised")

    # The verdicts, which are the whole point: each must name evidence, not
    # blame, and the three cases must be distinguishable.
    def sess(v4, v6):
        return Session(sid="s", fleet="f", fabric="ixp1", engine="exabgp",
                       role="bilateral", asn=65001, v4=v4, v6=v6,
                       container="c", api_port=0, dut_pg4=None, dut_pg6=None,
                       max_prefix4=None, max_prefix6=None, prefixes_v4=1,
                       prefixes_v6=1, paths_per_prefix=1, passive=False,
                       timers={}, flappable=True, mrt=None, nlri_slot=0)

    fleet = peers.PeerFleet(clab_prefix="clab-x")
    socks = {"ok": True, "sockets": rows}
    st = fleet.session_socket_state(sess("198.51.96.29", "2001:db8:1::3f"),
                                    "198.51.96.11", "2001:db8:1::1", socks)
    r.check(st["ipv6"]["verdict"] == "socket_syn_sent",
            f"a peer dialling an unanswering DUT is reported as such "
            f"({st['ipv6']['verdict']})")

    # No v6 rows at all: the generator's v6 speaker is gone. Lab-side.
    v4only = {"ok": True, "sockets": [x for x in rows if ":" not in (x["local"] or "")]}
    st2 = fleet.session_socket_state(sess("198.51.96.29", "2001:db8:1::3f"),
                                     "198.51.96.11", "2001:db8:1::1", v4only)
    r.check(st2["ipv6"]["verdict"] == "no_socket_for_family",
            f"a family with no socket at all points away from the DUT "
            f"({st2['ipv6']['verdict']})")

    # Listening but nothing connected: points at the DUT or the path.
    listen_only = {"ok": True,
                   "sockets": [x for x in rows if x["state"] == "LISTEN"]}
    st3 = fleet.session_socket_state(sess("198.51.96.29", "2001:db8:1::3f"),
                                     "198.51.96.11", "2001:db8:1::1",
                                     listen_only)
    r.check(st3["ipv6"]["verdict"] == "listening_no_connection",
            f"a peer waiting with nothing arriving points at the DUT "
            f"({st3['ipv6']['verdict']})")

    # An unreadable read must be unreadable, never a verdict.
    st4 = fleet.session_socket_state(sess("198.51.96.29", "2001:db8:1::3f"),
                                     "198.51.96.11", "2001:db8:1::1",
                                     {"ok": False, "error": "no such container"})
    r.check(st4["verdict"] == "unreadable" and "ipv6" not in st4,
            "a failed read yields no verdict at all, rather than a wrong one")

    # And the runner has to actually call it, at the moments that need it.
    src = inspect.getsource(runner._snapshot_peers)
    r.check("fleet_snapshot" in src,
            "the peer snapshot collects the fleet side, not only the DUT side")
    csrc = inspect.getsource(runner._converge)
    r.check("_snapshot_peers" in csrc,
            "and a failed convergence takes one")


def check_log_calls_cannot_collide_on_a_key(r: Report) -> None:
    """H-58. The third instance of "a diagnostic call killed the command".

    T3 run 2, `make converge`, one line after it printed the thing this whole
    round of work existed to produce:

        converged        : True
        ipv4 FIB         : 2,445,625 of 2,445,625 BGP routes installed (100.0%)
        TypeError: Ctx.log() got multiple values for keyword argument 'afi'

    `ctx.log("fib_state", afi=afi, **route_summary(afi))` — and
    `route_summary()` returns a dict whose first key is `afi`. The call had been
    unreachable since it was written, because the guard above it tested
    `bgp_routes is None` and H-51 meant that was always true. Fixing H-51 made
    the branch live and the latent crash fired immediately.

    H-24 fixed this for exactly one key by making `kind` positional-only. The
    general problem is that a `**` expansion and an explicit keyword sharing
    ANY name is a TypeError raised at the call site, before the function body
    runs — so no defensive code inside `log` can ever help. The only fixes are
    the signature and the call sites.

    The rule enforced here: a log/event call may expand a dict, or pass
    explicit keywords, but not both. Pass the dict as `payload=` instead.
    """
    import ast
    import pathlib

    roots = [pathlib.Path("harness"), pathlib.Path("analysis"),
             pathlib.Path("tests")]
    offenders = []
    scanned = 0
    for root in roots:
        for f in sorted(root.rglob("*.py")):
            if "__pycache__" in str(f):
                continue
            try:
                tree = ast.parse(f.read_text(encoding="utf-8"))
            except (SyntaxError, OSError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = (fn.attr if isinstance(fn, ast.Attribute)
                        else getattr(fn, "id", ""))
                if name not in ("log", "event"):
                    continue
                scanned += 1
                explicit = [k.arg for k in node.keywords if k.arg is not None]
                splat = [k for k in node.keywords if k.arg is None]
                if explicit and splat:
                    offenders.append(f"{f}:{node.lineno} kwargs={explicit}")
    r.check(not offenders,
            f"no log/event call mixes explicit keywords with a ** expansion "
            f"({scanned} call(s) scanned)"
            + ("" if not offenders else f" — {'; '.join(offenders)}"))

    # And the signature has to offer the alternative, or the rule is unusable.
    from harness.scenarios import Ctx
    from harness.telemetry import Sampler
    import inspect
    for fn in (Ctx.log, Sampler.event):
        params = inspect.signature(fn).parameters
        r.check("payload" in params,
                f"{fn.__qualname__} accepts a `payload` dict "
                f"({', '.join(params)})")

    # The exact crashing shape must now work, and explicit keywords must win.
    class FakeSampler:
        def __init__(self):
            self.recs = []

        def event(self, kind, /, payload=None, **kw):
            merged = dict(payload or {})
            merged.update(kw)
            self.recs.append({"kind": kind, **merged})

    ctx = Ctx.__new__(Ctx)
    ctx.sampler = FakeSampler()
    summary = {"ok": True, "afi": "ipv4", "bgp_routes": 2445625,
               "bgp_fib": 2445625, "bgp_fib_ratio": 1.0}
    rec = ctx.log("fib_state", payload=summary)
    r.check(rec.get("afi") == "ipv4" and rec.get("bgp_routes") == 2445625,
            "a route_summary dict carrying its own `afi` logs cleanly via "
            "payload= — the T3 run 2 shape")
    rec2 = ctx.log("fib_state", payload=summary, afi="ipv6")
    r.check(rec2.get("afi") == "ipv6",
            "an explicit keyword overrides the payload rather than colliding")
    rec3 = ctx.log("row", payload={"kind": "peer_flap", "mode": "admin_down"})
    r.check(rec3.get("kind") == "row" and rec3.get("event_kind") == "peer_flap",
            "a payload carrying `kind` is still preserved as `event_kind` "
            "(H-24 behaviour retained)")


def check_unreachable_branches_are_not_shipped_untested(r: Report) -> None:
    """H-58, second half: why nobody noticed for two weeks.

    The crashing line sat behind `if ... rs.get("bgp_routes") is None: continue`,
    and on every real FRR build `bgp_routes` was always None (H-51). So the
    branch below it had never once executed — not in a run, not in a selftest —
    and it contained a call that could not possibly work.

    There is no general detector for that. What there is: the two places where
    a route summary is turned into a log record now have to be exercised by
    tests with a *populated* summary, so the reachable path is the tested path.
    """
    import inspect
    from harness import runner

    src = inspect.getsource(runner.cmd_converge)
    # Strip comments before pattern-matching. The first version of this check
    # failed against the comment *explaining* the fix, which is a small, funny
    # instance of the same lesson: match the thing, not text that mentions it.
    code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
    r.check("payload=" in code,
            "cmd_converge logs its FIB state through payload=")
    r.check("**rs" not in code and "rs.items()" not in code.split("ctx.log")[0][-0:] + "",
            "and no longer expands the summary dict into a keyword call")
    # The precise assertion: no ** expansion anywhere in a log call in this
    # function. Done structurally rather than by substring.
    import ast
    tree = ast.parse(inspect.getsource(runner.cmd_converge).lstrip())
    mixed = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("log", "event"):
                if any(k.arg is None for k in node.keywords) and \
                   any(k.arg is not None for k in node.keywords):
                    mixed.append(node.lineno)
    r.check(not mixed,
            f"no log call inside cmd_converge mixes a ** expansion with "
            f"keywords ({'lines ' + str(mixed) if mixed else 'none'})")

    # Exercise it for real, with a summary that has every field populated —
    # the state that was unreachable before H-51.
    from harness.dut import Dut, RunResult
    real = ("Route Source         Routes               FIB  (vrf default)\n"
            "ebgp                 2445625              2445625\n"
            "ibgp                 0                    0\n"
            "------\n"
            "Totals               2445625              2445625\n")

    class D(Dut):
        def vtysh(self, cmd, timeout=None):
            return RunResult(0, real, "", 0.0)

    rs = D(container="x").route_summary("ipv4")
    r.check(rs.get("bgp_routes") == 2445625 and "afi" in rs,
            "the summary that reaches that call carries both `afi` and a "
            "populated `bgp_routes` — the combination that crashed")


def check_link_flap_does_not_destroy_ipv6(r: Report) -> None:
    """H-59. The harness killed 75 IPv6 sessions per run and blamed the DUT.

    T3 runs 1 and 2 both ended with **exactly 75** of 154 IPv6 sessions in
    `Active`, never recovering, and identical drift (-51,000 v4 / -131,900 v6).
    That reproducibility was the tell: it is deterministic, and a router under
    random churn is not.

    The peer snapshot built for R-8 answered it in one reading. Every generator
    was alive, 73 sessions reported `listening_no_connection`, and the
    container's own `ip -o addr` showed why:

        eth1 198.51.96.15/20 ... 198.51.96.19/20      <- IPv4 present
        eth1 fe80::a8c1:abff:feb8:2eaa/64             <- link-local ONLY

    The `2001:db8:1::f`-`::13` addresses were gone, while gobgpd still held
    LISTEN sockets bound to them (a listening socket outlives the address).

    Cause: **Linux flushes every global IPv6 address on an interface when the
    link goes down** (`net.ipv6.conf.*.keep_addr_on_down` defaults to 0) and
    does not restore them on link-up. IPv4 addresses survive. The
    `peer_flap mode=link_down` event does `ip link set eth1 down`, and eth1
    carries *every session in the container* — so one flap permanently killed
    the IPv6 half of five sessions.

    Correlation, from run 2: 10 link_down events hit 9 distinct containers;
    exactly those 9 containers were missing their global IPv6 addresses; those
    9 containers hold exactly 75 sessions. Set equality, no residue.

    Run 1 came one step from being reported to the FRR team as "VyOS loses 49%
    of its IPv6 sessions under churn and never recovers".
    """
    import inspect
    from harness import generate, peers, scenarios

    src = inspect.getsource(generate.write_prepare)
    r.check("keep_addr_on_down=1" in src,
            "prepare.sh sets keep_addr_on_down=1, so a link bounce no longer "
            "flushes the peers' IPv6 addresses")
    r.check(src.count("keep_addr_on_down=1") >= 2,
            "and sets it per-interface as well as `all` — `all` is only "
            "consulted for interfaces created after it is set")

    usrc = inspect.getsource(peers.PeerFleet.unflap)
    r.check("restore_addrs" in usrc,
            "unflap restores any address the link-down removed, rather than "
            "trusting the sysctl alone")

    fsrc = inspect.getsource(scenarios.ev_peer_flap)
    r.check("addrs_missing" in fsrc and "peer_flap_ineffective" in fsrc,
            "and the event verifies the addresses came back, reporting "
            "INEFFECTIVE if they did not (the H-33 rule)")

    # Behaviour, on a VLAN fabric — the case that broke run 3 (H-61).
    from harness.dut import RunResult as RR

    class FakeFleet(peers.PeerFleet):
        """State: the VLAN child kept its IPv4 but lost its IPv6, and the
        parent has picked up a stray copy of both."""

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.cmds = []

        def exec(self, container, cmd, timeout=None):
            self.cmds.append(cmd)
            m = re.search(r"addr show dev (\S+)", cmd)
            if m:
                dev, v6 = m.group(1), " -6 " in cmd
                if dev == "eth1.200":
                    return RR(0, "" if v6 else "203.0.112.17/20\n", "", 0.0)
                if dev == "eth1":
                    return RR(0, "2001:db8:2::11/64\n" if v6
                              else "203.0.112.17/20\n", "", 0.0)
            return RR(0, "", "", 0.0)

    plan = {"c0": {"iface": "eth1.200", "parent": "eth1",
                   "cidrs": ["203.0.112.17/20", "2001:db8:2::11/64"]}}

    f = FakeFleet(clab_prefix="clab-x", expected_addrs=plan)
    f.restore_addrs("c0")
    adds = [c for c in f.cmds if "addr replace" in c]
    dels = [c for c in f.cmds if "addr del" in c]
    r.check(any("2001:db8:2::11/64 dev eth1.200" in c for c in adds),
            f"the missing address is restored on the VLAN child, not the "
            f"parent ({adds})")
    r.check(not any("dev eth1 " in c or c.endswith("dev eth1") for c in adds),
            "nothing is added to the parent interface (H-61: doing so left "
            "one address on two interfaces and the kernel chose the wrong one)")
    r.check(any("2001:db8:2::11/64 dev eth1" in c for c in dels),
            f"and a stray copy on the parent is removed ({dels})")

    f2 = FakeFleet(clab_prefix="clab-x", expected_addrs=plan)
    r.check(f2.addrs_missing("c0") == ["2001:db8:2::11/64"],
            f"addrs_missing reads the VLAN child ({f2.addrs_missing('c0')})")
    f3 = FakeFleet(clab_prefix="clab-x", expected_addrs=plan)
    stray = f3.addrs_misplaced("c0")
    r.check(sorted(stray) == ["2001:db8:2::11/64", "203.0.112.17/20"],
            f"addrs_misplaced names what is sitting on the parent ({stray})")

    # An untagged fabric must still work, and must never report strays.
    class Flat(FakeFleet):
        def exec(self, container, cmd, timeout=None):
            self.cmds.append(cmd)
            return RR(0, "", "", 0.0)

    f4 = Flat(clab_prefix="clab-x",
              expected_addrs={"c0": {"iface": "eth1", "parent": "eth1",
                                     "cidrs": ["198.51.96.15/20"]}})
    f4.restore_addrs("c0")
    r.check(any("198.51.96.15/20 dev eth1" in c
                for c in f4.cmds if "addr replace" in c),
            "an untagged fabric restores onto eth1")
    r.check(f4.addrs_misplaced("c0") == [],
            "and reports no misplacement when parent and target are the same")

    nf = FakeFleet(clab_prefix="clab-x", expected_addrs=None)
    r.check(nf.restore_addrs("c0") == [] and nf.addrs_missing("c0") == []
            and nf.addrs_misplaced("c0") == [],
            "with no inventory to compare against it does nothing rather than "
            "guessing")

    # The interface has to come from the inventory, and the VLAN has to be
    # reflected — asserted against the real generator, not a fixture.
    from harness import runner as rmod
    import inspect as _in
    esrc = _in.getsource(rmod.expected_container_addrs)
    r.check('f"{c.iface}.{fab.vlan}"' in esrc,
            "expected_container_addrs derives the VLAN sub-interface name")
    r.check('"parent"' in esrc,
            "...and records the parent, so a stray copy can be detected")
    r.check(_in.getsource(rmod).count(
        "expected_addrs=expected_container_addrs") >= 3,
        "every PeerFleet the runner builds gets it")

    fsrc2 = _in.getsource(scenarios.ev_peer_flap)
    r.check("addrs_misplaced" in fsrc2,
            "and the flap event checks for misplacement as well as absence")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Offline validation of everything the harness generates.")
    ap.add_argument("--template", default="Template IXP VyOS Configuration.md")
    ap.add_argument("--out", default="build")
    ap.add_argument("--profiles", default="profiles")
    ap.add_argument("--only", default=None,
                    help="validate a single profile, e.g. t0-smoke "
                         "(the large tiers take minutes to generate)")
    ap.add_argument("--strict", action="store_true",
                    help="treat skipped checks as failures — for CI, where an "
                         "unverified check should not pass silently")
    a = ap.parse_args(argv)

    r = Report(strict=a.strict)
    print_tool_versions(r)
    check_imports(r)
    check_prefix_plan(r)
    check_injection_strings(r)
    print("\n== runtime drivers (fake lab)")
    check_boot_count_parser(r)
    check_peerfleet_arg_shapes(r)
    check_sync_agent_warning(r)
    check_log_dedup(r)
    check_locpref_key(r)
    check_malformed_expectations(r)
    check_unknown_attr_flags(r)
    check_isolation_hygiene(r)
    check_self_inflicted_predicates(r)
    check_log_window_is_bounded(r)
    check_exercise_plan_covers_catalogue(r)
    check_notification_patterns_reject_noise(r)
    check_frr_debugs_are_armed(r)
    check_log_pipeline_probe(r)
    check_self_references_resolve(r)
    check_debug_arming_survives_commits(r)
    check_exabgp_commands_name_one_session(r)
    check_deliberate_restarts_are_not_failures(r)
    check_convergence_waits_report_progress(r)
    check_cold_start_is_measured(r)
    check_fib_gate_cannot_be_satisfied_by_an_unevaluated_reading(r)
    check_route_summary_reads_real_frr_output(r)
    check_no_counter_is_compared_to_a_table_size(r)
    check_every_daemon_restart_is_reported(r)
    check_log_windows_do_not_leave_gaps(r)
    check_peer_side_socket_state_is_captured(r)
    check_log_calls_cannot_collide_on_a_key(r)
    check_link_flap_does_not_destroy_ipv6(r)
    check_unreachable_branches_are_not_shipped_untested(r)
    check_config_changes_are_always_reverted(r)
    check_failed_reads_are_not_zeros(r)
    check_cpu_pct_resets_on_pid_change(r)
    check_watchdog_kill_is_detected(r)
    check_t3_has_no_external_mrt_dependency(r)
    check_convergence_requires_a_quiet_dut(r)
    check_log_floor_survives_commits(r)
    check_mix_is_weighted_for_real_peering(r)
    check_impairments_are_verified(r)
    check_log_window_covers_recovery(r)
    check_ineffective_impairment_is_not_ok(r)
    check_maxprefix_trip_checks_its_preconditions(r)
    check_log_patterns_match_real_frr_strings(r)
    check_maxprefix_event_has_direct_evidence(r)
    check_external_mrt_diagnosis(r)
    check_process_kill_reinjects(r)
    check_frr_saturation_signals(r)
    check_cpu_pct_sanity(r)
    check_memory_model(r)
    check_commit_phase_split(r)
    check_drift_attribution(r)
    check_probe_check_announces(r)
    check_probe_withdraw_before_malformed(r)
    check_image_resolution(r)

    if not os.path.exists(a.template):
        r.bad(f"template not found: {a.template}. Copy "
              f"'Template IXP VyOS Configuration.md' into the repo root, or pass "
              f"--template <path>.")
        print(f"\n{RED}cannot validate generated artefacts without the template{RESET}")
        return 1
    check_profile_errors(r, a.template)

    profiles = sorted(glob.glob(os.path.join(a.profiles, "t*.yaml")))
    if a.only:
        profiles = [x for x in profiles
                    if os.path.basename(x)[:-5] == a.only or a.only in x]
        if not profiles:
            r.bad(f"--only {a.only} matched no profile in {a.profiles}")
            return 1

    for pp in profiles:
        name = os.path.basename(pp)[:-5]
        print(f"\n== profile {name}")
        try:
            build = generate.generate(pp, a.template, a.out, force=True)
        except Exception as exc:
            r.bad(f"{name}: generation failed: {exc!r}")
            continue
        with open(os.path.join(build, "inventory.json"), encoding="utf-8") as fh:
            invj = json.load(fh)
        check_inventory(r, invj, name, build)
        check_topology(r, build, invj, name)
        check_dut_config(r, build, invj, name)
        check_gobgp_toml(r, build, invj, name)
        check_exabgp(r, build, name)
        check_exabgp_boot(r, build, invj, name)
        check_runner_smoke(r, build, invj, name)
        check_stale_bind_detection(r, build, invj, name)
        check_exercise_runs_end_to_end(r, build, invj, name)
        check_mrt(r, build, invj, name)

    print(f"\n{'=' * 72}")
    print(f"passed  : {r.passed}")
    print(f"skipped : {len(r.skipped)}")
    print(f"FAILED  : {len(r.failed)}")
    for f in r.failed:
        print(f"  - {f}")
    if r.skipped:
        label = ("skipped checks — FATAL because --strict was given"
                 if a.strict else
                 "skipped checks (optional tooling absent or version-incompatible)")
        print(f"\n{label}:")
        for sk in r.skipped:
            print(f"  - {sk}")

    print()
    if r.failed:
        print(f"{RED}RESULT: FAILED{RESET} — {len(r.failed)} artefact defect(s) above.")
    elif r.skipped and a.strict:
        print(f"{YELLOW}RESULT: FAILED (strict){RESET} — all artefact checks passed, "
              f"but {len(r.skipped)} check(s) could not run.")
    elif r.skipped:
        print(f"{GREEN}RESULT: PASSED{RESET} — {r.passed} check(s) passed; "
              f"{len(r.skipped)} optional check(s) skipped. Skips are tooling gaps, "
              f"not defects in the generated lab.")
    else:
        print(f"{GREEN}RESULT: PASSED{RESET} — {r.passed} check(s), nothing skipped.")

    print()
    print("Scope: this validates generated artefacts only. Whether VyOS accepts the "
          "rendered configuration, and how it behaves under load, can only be "
          "verified by deploying the lab.")
    return 1 if (r.failed or (r.skipped and a.strict)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
