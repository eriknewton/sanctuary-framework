#!/usr/bin/env python3
"""Fail when the read-only guard's bounded paths drift from daemon/unit source."""

import ast
import hashlib
import re
import sys
from pathlib import Path


# Exact byte identity of daemon nft source at repository baseline
# 17d251f50514a885d0cd9666e363d19dbc963574. This source pin is not a Rust
# parser or a claim of whole-file review. Any edit requires source review and
# an explicit pin refresh before a package can be asserted.
# Refreshed for PR-3a (2026-09-18): the only nftables.rs change since the baseline above is
# four `else { return None; }` arms of recognized_net_json rewritten with the `?` operator to
# satisfy the clippy gate; two independent-family source reviews accepted it as
# semantics-preserving before this pin moved. The guard constants it mirrors are unchanged.
NFTABLES_SOURCE_SHA256 = "9f1d5f2b972b496ca7bcad8cfe4f054e8ee1dab0661961eabe435438823ee2a1"


def fail(message):
    raise ValueError(message)


def one(pattern, text, label):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        fail(f"expected one parseable {label}; found {len(matches)}")
    return matches[0]


def main():
    here = Path(__file__).resolve().parent
    crate = here.parent.parent
    guard = ast.parse((here / "lifecycle-guard.py").read_text())
    constants = {}
    for node in guard.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    unit = (crate / "systemd/sanctuary-castle-wall.service").read_text()
    config = (crate / "src/config.rs").read_text()
    journal = (crate / "src/ownership_journal.rs").read_text()
    lock = (crate / "src/runtime_lock.rs").read_text()
    nft_bytes = (crate / "src/nftables.rs").read_bytes()
    nft_sha256 = hashlib.sha256(nft_bytes).hexdigest()
    if nft_sha256 != NFTABLES_SOURCE_SHA256:
        fail(f"nftables.rs source differs from pinned baseline: {nft_sha256} != {NFTABLES_SOURCE_SHA256}")
    nft = nft_bytes.decode("utf-8")
    env = one(r"^EnvironmentFile=(\S+)$", unit, "EnvironmentFile")
    start = one(r"^ExecStart=(.+)$", unit, "ExecStart")
    runtime_dir = one(r"^RuntimeDirectory=(\S+)$", unit, "RuntimeDirectory")
    state_dir = one(r"^StateDirectory=(\S+)$", unit, "StateDirectory")
    if one(r"^WantedBy=(\S+)$", unit, "WantedBy") != "multi-user.target" or unit.count("[Install]") != 1:
        fail("pinned unit is not installable under its expected target")
    runtime_root = one(r'let runtime_dir = PathBuf::from\(format!\("(/run/[^"{]+)/\{\}"', config, "fortress runtime root")
    state_root = one(r'let state_dir = PathBuf::from\(format!\("(/var/lib/[^"{]+)/\{\}"', config, "fortress state root")
    expected = {
        "ENV_PATH": env,
        "DAEMON_PATH": start.split()[0],
        "RUN_ROOT": "/run/" + runtime_dir,
        "STATE_ROOT": "/var/lib/" + state_dir,
        "JOURNAL_PATH": one(r'^pub const DEFAULT_OWNERSHIP_JOURNAL_PATH: &str = "([^"]+)";', journal, "ownership journal"),
        "AUTH_KEY_PATH": one(r'^pub const DEFAULT_JOURNAL_AUTH_KEY_PATH: &str = "([^"]+)";', journal, "journal auth key"),
        "HOST_LOCK_PATH": one(r'^pub const DEFAULT_HOST_LOCK_PATH: &str = "([^"]+)";', lock, "host lock"),
        "NFT_TABLE": one(r'^pub const CASTLE_TABLE: &str = "([^"]+)";', nft, "nft table"),
    }
    if runtime_root != expected["RUN_ROOT"] or state_root != expected["STATE_ROOT"]:
        fail("fortress roots differ from unit RuntimeDirectory/StateDirectory")
    if constants.get("UNIT_PATH") != "/etc/systemd/system/sanctuary-castle-wall.service":
        fail("unit path changed outside first-slice contract")
    family = one(r'^pub const CASTLE_FAMILY: &str = "([^"]+)";', nft, "nft family")
    if family != "inet" or constants.get("NFT_FAMILY") != family:
        fail("nft family changed outside first-slice contract")
    supported_unit_roots = (
        "/etc/systemd/system.control", "/run/systemd/system.control",
        "/run/systemd/transient", "/run/systemd/generator.early",
        "/etc/systemd/system", "/etc/systemd/system.attached",
        "/run/systemd/system", "/run/systemd/system.attached",
        "/run/systemd/generator", "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system", "/run/systemd/generator.late",
    )
    if constants.get("SYSTEMD_ROOTS") != supported_unit_roots:
        fail("systemd search-root inventory drifted from pinned supported set")
    for name, value in expected.items():
        if constants.get(name) != value:
            fail(f"guard/source divergence for {name}: {constants.get(name)!r} != {value!r}")
    for name in ("JOURNAL_PATH", "AUTH_KEY_PATH", "HOST_LOCK_PATH"):
        if not constants[name].startswith(constants["STATE_ROOT"] + "/"):
            fail(f"host-global path outside bounded state root: {name}")
    if 'host_lock_path: PathBuf::from(crate::runtime_lock::DEFAULT_HOST_LOCK_PATH)' not in config or 'crate::ownership_journal::DEFAULT_OWNERSHIP_JOURNAL_PATH' not in config or 'crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH' not in config:
        fail("LinuxRuntimePaths::production no longer uses checked constants")
    print("guard paths match the pinned unit and daemon source")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, SyntaxError) as exc:
        print(f"guard source parity refused: {exc}", file=sys.stderr)
        sys.exit(1)
