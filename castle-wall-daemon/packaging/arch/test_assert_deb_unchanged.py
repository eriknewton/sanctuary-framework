from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
CLI_PATH = "fs/usr/sbin/sanctuary-linux"
DAEMON_PATH = "fs/usr/local/libexec/sanctuary/castle-wall-daemon"
IDENTITY_PATH = "fs/usr/share/doc/sanctuary-castle-wall/build-identity"

spec = importlib.util.spec_from_file_location("assert_deb_unchanged", HERE / "assert-deb-unchanged.py")
gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(gate)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity_bytes(source_commit: str, payload: dict[str, bytes], *, extra: dict | None = None) -> bytes:
    identity = {
        "artifact_kind": "ubuntu-install-deb-v1",
        "features": [],
        "guard_sha256": "f" * 64,
        "install_ready": True,
        "package": "sanctuary-castle-wall",
        "package_version": "0.1.0-1",
        "payload_sha256": {path.removeprefix("fs/"): sha(content) for path, content in sorted(payload.items())},
        "source_commit": source_commit,
    }
    if extra:
        identity.update(extra)
    return (json.dumps(identity, sort_keys=True, indent=2) + "\n").encode()


def script_bytes(role: str, identity: bytes) -> bytes:
    return (
        "#!/usr/bin/python3 -I\n"
        f"ROLE = '{role}'\n"
        f"IDENTITY_SHA256 = '{sha(identity)}'\n"
        "print('guard')\n"
    ).encode()


def write_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def write_tree(
    root: Path,
    source_commit: str,
    payload: dict[str, bytes] | None = None,
    *,
    identity_raw: bytes | None = None,
    script_hash_override: str | None = None,
    extra_control: str | None = None,
) -> bytes:
    payload = dict(
        payload
        or {
            CLI_PATH: b"cli\n",
            DAEMON_PATH: b"daemon\n",
        }
    )
    identity = identity_raw if identity_raw is not None else identity_bytes(source_commit, payload)
    for path, content in payload.items():
        write_file(root / path, content, 0o755)
    write_file(root / IDENTITY_PATH, identity, 0o644)
    write_file(root / "control/control", b"Package: sanctuary-castle-wall\n", 0o644)
    for role in ("preinst", "prerm"):
        content = script_bytes(role, identity)
        if script_hash_override is not None:
            content = content.replace(sha(identity).encode(), script_hash_override.encode())
        write_file(root / "control" / role, content, 0o755)
    if extra_control:
        write_file(root / "control" / extra_control, b"extra\n", 0o644)
    return identity


def compare(base: Path, head: Path, declaration=None) -> None:
    gate.compare_extracted(base, head, BASE_SHA, HEAD_SHA, declaration)


def declared(*paths: str):
    return gate.DeltaDeclaration(frozenset(paths), "Review/Sanctuary/Ubuntu_Reproof_2026-10-06.md")


def test_strict_mode_passes_with_only_source_commit_and_script_hashes_differing(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)

    compare(base, head)


def test_strict_mode_fails_and_names_payload_path_when_one_payload_byte_differs(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"})

    with pytest.raises(gate.DebCompareError, match="fs/usr/sbin/sanctuary-linux"):
        compare(base, head)


def test_identity_byte_change_outside_source_commit_is_refused(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    raw = identity_bytes(HEAD_SHA, {CLI_PATH: b"cli\n", DAEMON_PATH: b"daemon\n"}).replace(
        b'"guard_sha256": ', b'"guard_sha256" : ', 1
    )
    write_tree(head, HEAD_SHA, identity_raw=raw)

    with pytest.raises(gate.DebCompareError, match="build-identity changed"):
        compare(base, head)


def test_extra_control_member_is_refused(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, extra_control="postinst")

    with pytest.raises(gate.DebCompareError, match="control member set changed"):
        compare(base, head)


def test_script_identity_hash_must_match_side_identity_hash(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, script_hash_override="0" * 64)

    with pytest.raises(gate.DebCompareError, match="control/preinst head IDENTITY_SHA256"):
        compare(base, head)


def test_declared_mode_passes_for_declared_cli_change_with_matching_identity_entry(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"})

    compare(base, head, declared(CLI_PATH))


def test_declared_mode_refuses_declared_cli_plus_undeclared_daemon_change(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon changed\n"})

    with pytest.raises(gate.DebCompareError, match="castle-wall-daemon"):
        compare(base, head, declared(CLI_PATH))


def test_declaration_absent_from_changed_path_list_is_ignored_and_strict_mode_fails(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"})
    declaration_file = tmp_path / "deb-delta-declaration.json"
    declaration_file.write_text(json.dumps({"paths": [CLI_PATH], "document": "Review/Sanctuary/Reproof.md"}))

    declaration = gate.active_declaration(["castle-wall-daemon/packaging/arch/assert-deb-unchanged.py"], declaration_file)
    assert declaration is None
    with pytest.raises(gate.DebCompareError, match="fs/usr/sbin/sanctuary-linux"):
        compare(base, head, declaration)


@pytest.mark.parametrize("bad_path", ["control/preinst", IDENTITY_PATH])
def test_declaration_refuses_control_or_identity_paths(tmp_path: Path, bad_path: str) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)

    with pytest.raises(gate.DebCompareError, match="declared path"):
        compare(base, head, declared(bad_path))


def test_declared_identity_hex_must_equal_declared_file_hash(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    payload = {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"}
    raw = identity_bytes(HEAD_SHA, payload).replace(sha(payload[CLI_PATH]).encode(), ("0" * 64).encode(), 1)
    write_tree(head, HEAD_SHA, payload, identity_raw=raw)

    with pytest.raises(gate.DebCompareError, match="declared identity entry usr/sbin/sanctuary-linux"):
        compare(base, head, declared(CLI_PATH))


def test_arch_predicates_and_workflow_derive_from_python_predicates() -> None:
    trigger_paths = [
        ".github/workflows/linux-arch-package.yml",
        "castle-wall-daemon/packaging/arch/PKGBUILD",
        "castle-wall-daemon/src/linux_install/arch/command.rs",
        "castle-wall-daemon/src/bin/sanctuary-linux-arch.rs",
        "castle-wall-daemon/tests/linux_install_arch_cli.rs",
        "castle-wall-daemon/tests/fixtures/substrate/login.defs",
    ]
    allowed_only_paths = [
        ".github/workflows/castle-wall-linux.yml",
        "castle-wall-daemon/Cargo.toml",
        "castle-wall-daemon/src/linux_install/mod.rs",
    ]
    refused_paths = [
        "castle-wall-daemon/src/linux_install/command.rs",
        "castle-wall-daemon/Cargo.lock",
        "castle-wall-daemon/packaging/ubuntu/build-install-deb.py",
    ]
    assert all(gate.is_arch_trigger_path(path) for path in trigger_paths)
    assert all(gate.is_arch_allowed_path(path) for path in trigger_paths + allowed_only_paths)
    assert not any(gate.is_arch_trigger_path(path) for path in allowed_only_paths + refused_paths)
    assert not any(gate.is_arch_allowed_path(path) for path in refused_paths)

    workflow = yaml.safe_load((REPO / ".github/workflows/linux-arch-package.yml").read_text())
    deb_job = workflow["jobs"]["deb-unchanged-gate"]
    runs = "\n".join(step.get("run", "") for step in deb_job["steps"])
    assert "is_arch_trigger_path" in runs
    assert "is_arch_allowed_path" in runs
    assert "assert-deb-unchanged.py" in runs
    assert "def is_slice_path" not in runs
