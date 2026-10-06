"""Capability tests for the Arch .deb inheritance gate's raw-byte comparison rules."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

# arch-package-build (linux-arch-package.yml, the Arch container step "python3 -m unittest
# discover -s castle-wall-daemon/packaging/arch") imports every test_*.py with a bare
# interpreter that has neither pytest nor PyYAML; a module-level ImportError there is a
# FAILED (errors=1) run and a red job. Raising SkipTest at import makes unittest skip the
# module and pytest skip it the same way; deb-unchanged-gate installs both packages and runs it.
try:
    import pytest
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only by the Arch container
    raise unittest.SkipTest("pytest is provided only in deb-unchanged-gate") from exc

# Imported outside the guard on purpose: under pytest a missing PyYAML must be a collection
# error, never a silent skip of the thirty gate tests (closure read, Claude 1).
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

layout_spec = importlib.util.spec_from_file_location(
    "install_layout", HERE.parent / "ubuntu" / "install-layout.py"
)
install_layout = importlib.util.module_from_spec(layout_spec)
assert layout_spec.loader is not None
layout_spec.loader.exec_module(install_layout)
UBUNTU = HERE.parent / "ubuntu"


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


def payload_hashes(payload: dict[str, bytes]) -> dict[str, str]:
    return {path.removeprefix("fs/"): sha(content) for path, content in sorted(payload.items())}


def script_bytes(role: str, identity: bytes, payload: dict[str, bytes]) -> bytes:
    return install_layout.guard_bytes(role, "0.1.0-1", identity, payload_hashes(payload), UBUNTU)


def write_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def write_symlink(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)


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
        content = script_bytes(role, identity, payload)
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


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.replace(b'"guard_sha256": ', b'"guard_sha256" : ', 1),
        lambda raw: json.dumps(
            {
                "source_commit": HEAD_SHA,
                "payload_sha256": {
                    CLI_PATH.removeprefix("fs/"): sha(b"cli\n"),
                    DAEMON_PATH.removeprefix("fs/"): sha(b"daemon\n"),
                },
                "package_version": "0.1.0-1",
                "package": "sanctuary-castle-wall",
                "install_ready": True,
                "guard_sha256": "f" * 64,
                "features": [],
                "artifact_kind": "ubuntu-install-deb-v1",
            },
            sort_keys=False,
            indent=2,
        ).encode()
        + b"\n",
        lambda raw: raw.replace(
            b'"package": "sanctuary-castle-wall",',
            b'"package": "sanctuary-castle-wall",\n  "package": "sanctuary-castle-wall",',
            1,
        ),
    ],
)
def test_identity_byte_change_outside_source_commit_is_refused(tmp_path: Path, mutate) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    raw = mutate(identity_bytes(HEAD_SHA, {CLI_PATH: b"cli\n", DAEMON_PATH: b"daemon\n"}))
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


def test_script_identity_line_must_occur_once(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)
    preinst = head / "control/preinst"
    content = preinst.read_bytes()
    line = next(line for line in content.splitlines() if line.startswith(b"IDENTITY_SHA256 = "))
    preinst.write_bytes(content.replace(line + b"\n", line + b"\n" + line + b"\n", 1))

    with pytest.raises(gate.DebCompareError, match="control/preinst head has 2 IDENTITY_SHA256 lines"):
        compare(base, head)


def test_script_body_must_match_after_permitted_substitutions(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)
    preinst = head / "control/preinst"
    preinst.write_bytes(preinst.read_bytes() + b"# unexpected body drift\n")

    with pytest.raises(gate.DebCompareError, match="control/preinst changed outside the permitted substitutions"):
        compare(base, head)


def test_declared_mode_passes_for_declared_cli_change_with_matching_identity_entry(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"})

    compare(base, head, declared(CLI_PATH))


def test_declared_mode_substitutes_real_guard_payload_hash_entries(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"})

    for role in ("preinst", "prerm"):
        assert gate.guard_payload_hash_entry(CLI_PATH, sha(b"cli\n")) in (base / "control" / role).read_bytes()
        assert gate.guard_payload_hash_entry(CLI_PATH, sha(b"cli changed\n")) in (head / "control" / role).read_bytes()
    compare(base, head, declared(CLI_PATH))


def test_declared_mode_refuses_declared_cli_plus_undeclared_daemon_change(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon changed\n"})

    with pytest.raises(gate.DebCompareError, match="undeclared differences: fs/usr/local/libexec/sanctuary/castle-wall-daemon"):
        compare(base, head, declared(CLI_PATH))


def test_declared_mode_refuses_a_declared_path_that_did_not_change(tmp_path: Path) -> None:
    # Brief item 8: a declared difference that did not occur fails (the set must be EQUAL).
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)

    with pytest.raises(gate.DebCompareError, match="declared paths did not differ: fs/usr/sbin/sanctuary-linux"):
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


@pytest.mark.parametrize(
    ("bad_path", "match"),
    [
        ("control/preinst", r"declared path control/preinst is not under fs/"),
        (IDENTITY_PATH, rf"declared path {IDENTITY_PATH} names the build identity"),
        ("fs/not-present", r"declared path fs/not-present is not present"),
        ("fs/usr", r"declared path fs/usr is not a regular file"),
    ],
)
def test_declaration_shape_refusals_are_specific(tmp_path: Path, bad_path: str, match: str) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)

    with pytest.raises(gate.DebCompareError, match=match):
        compare(base, head, declared(bad_path))


def test_declared_identity_hex_must_equal_declared_file_hash(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    payload = {CLI_PATH: b"cli changed\n", DAEMON_PATH: b"daemon\n"}
    raw = identity_bytes(HEAD_SHA, payload).replace(sha(payload[CLI_PATH]).encode(), ("0" * 64).encode(), 1)
    write_tree(head, HEAD_SHA, payload, identity_raw=raw)

    with pytest.raises(gate.DebCompareError, match="declared identity entry usr/sbin/sanctuary-linux"):
        compare(base, head, declared(CLI_PATH))


@pytest.mark.parametrize("document", ["[]", "null", '"str"', "1", "true"])
def test_declaration_must_be_a_json_object(tmp_path: Path, document: str) -> None:
    declaration = tmp_path / "deb-delta-declaration.json"
    declaration.write_text(document)

    with pytest.raises(gate.DebCompareError, match="must be a JSON object"):
        gate.active_declaration([gate.DECLARATION_PATH], declaration)


def test_deleted_declaration_file_is_strict_mode(tmp_path: Path) -> None:
    missing = tmp_path / "deb-delta-declaration.json"

    declaration = gate.active_declaration([gate.DECLARATION_PATH], missing)

    assert declaration is None


def test_duplicate_declared_paths_are_refused(tmp_path: Path) -> None:
    declaration_file = tmp_path / "deb-delta-declaration.json"
    declaration_file.write_text(json.dumps({"paths": [CLI_PATH, CLI_PATH], "document": "Review/Sanctuary/Reproof.md"}))

    with pytest.raises(gate.DebCompareError, match="duplicate declared paths"):
        gate.active_declaration([gate.DECLARATION_PATH], declaration_file)


@pytest.mark.parametrize(
    "extra",
    [
        {"payload_sha256": {}},
        {"guard_sha256": ""},
    ],
)
def test_required_identity_fields_are_non_empty_raw_bytes(tmp_path: Path, extra: dict) -> None:
    # Both sides carry the SAME empty value, so the raw-byte comparison alone would pass and only
    # the non-empty check can refuse (round-2 Grok 1: a one-sided emptiness was caught by the byte
    # diff instead and did not witness this check).
    base, head = tmp_path / "base", tmp_path / "head"
    files = {CLI_PATH: b"cli\n", DAEMON_PATH: b"daemon\n"}
    write_tree(base, BASE_SHA, identity_raw=identity_bytes(BASE_SHA, files, extra=extra))
    write_tree(head, HEAD_SHA, identity_raw=identity_bytes(HEAD_SHA, files, extra=extra))

    with pytest.raises(gate.DebCompareError, match="missing or empty in a build identity"):
        compare(base, head)


def test_source_commit_substitution_must_occur_once(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    raw = identity_bytes(BASE_SHA, {CLI_PATH: b"cli\n", DAEMON_PATH: b"daemon\n"}).replace(
        b'"source_commit": "' + BASE_SHA.encode() + b'"',
        b'"source_commit": "' + BASE_SHA.encode() + b'",\n  "source_commit": "' + BASE_SHA.encode() + b'"',
        1,
    )
    write_tree(base, BASE_SHA, identity_raw=raw)
    write_tree(head, HEAD_SHA)

    with pytest.raises(gate.DebCompareError, match="source_commit substitution occurs 2 times"):
        compare(base, head)


def test_fs_path_set_must_match(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA, {CLI_PATH: b"cli\n", DAEMON_PATH: b"daemon\n", "fs/usr/share/extra": b"extra\n"})

    with pytest.raises(gate.DebCompareError, match="fs/ path set changed"):
        compare(base, head)


def test_per_path_mode_and_kind_must_match(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)
    (head / CLI_PATH).chmod(0o644)

    with pytest.raises(gate.DebCompareError, match="metadata changed"):
        compare(base, head)


def test_control_control_bytes_must_match(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)
    (head / "control/control").write_bytes(b"Package: sanctuary-castle-wall\nVersion: drift\n")

    with pytest.raises(gate.DebCompareError, match="control/control changed; first differing line"):
        compare(base, head)


def test_symlink_targets_must_match(tmp_path: Path) -> None:
    base, head = tmp_path / "base", tmp_path / "head"
    write_tree(base, BASE_SHA)
    write_tree(head, HEAD_SHA)
    write_symlink(base / "fs/usr/share/sanctuary-link", "target-a")
    write_symlink(head / "fs/usr/share/sanctuary-link", "target-b")

    with pytest.raises(gate.DebCompareError, match="symlink target changed"):
        compare(base, head)


def test_refused_paths_are_repr_safe_for_github_env_hazards() -> None:
    bad = [
        "server/evil\nARCH_ALLOWLIST_EOF\nARCH_ALLOWLIST=ok",
        "server/bad\udcffname.ts",
    ]

    rendered = gate.repr_path_lines(bad)

    assert "ARCH_ALLOWLIST=ok" in rendered
    assert "\nARCH_ALLOWLIST=ok\n" not in rendered
    assert "\\udcff" in rendered


def disposition_script() -> str:
    workflow = yaml.safe_load((REPO / ".github/workflows/linux-arch-package.yml").read_text())
    steps = workflow["jobs"]["deb-unchanged-gate"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Record gate disposition")
    return script.replace("${{ steps.resolve.outputs.touched }}", "yes").replace(
        "${{ steps.resolve.outputs.base }}", BASE_SHA
    )


def run_disposition(tmp_path: Path, *, allowlist: str, comparator: str, inheritance: str, declared: bool) -> subprocess.CompletedProcess:
    tmp_path.mkdir()
    (tmp_path / "allowlist-refused.txt").write_text("'castle-wall-daemon/src/linux_install/command.rs'\n")
    (tmp_path / "deb-comparator.log").write_text("deb comparator: PASS declared delta: fs/usr/sbin/sanctuary-linux\n")
    (tmp_path / "deb-inheritance.log").write_text("inheritance table\n")
    if declared:
        (tmp_path / "deb-declared-summary.txt").write_text(
            "fs/usr/sbin/sanctuary-linux, Review/Sanctuary/Ubuntu_Reproof_2026-10-06.md\n"
        )
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_SHA": HEAD_SHA,
        "ARCH_ALLOWLIST": allowlist,
        "ARCH_COMPARATOR": comparator,
        "ARCH_INHERITANCE": inheritance,
    }
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", disposition_script()],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def test_disposition_allows_refused_allowlist_only_for_declared_delta(tmp_path: Path) -> None:
    declared = run_disposition(tmp_path / "declared", allowlist="refused", comparator="ok", inheritance="ok", declared=True)
    assert declared.returncode == 0, declared.stderr + declared.stdout
    assert (
        "ENFORCED, DECLARED DELTA: fs/usr/sbin/sanctuary-linux, "
        "Review/Sanctuary/Ubuntu_Reproof_2026-10-06.md"
    ) in declared.stdout

    strict = run_disposition(tmp_path / "strict", allowlist="refused", comparator="ok", inheritance="ok", declared=False)
    assert strict.returncode == 1

    failed_inheritance = run_disposition(
        tmp_path / "inheritance", allowlist="refused", comparator="ok", inheritance="refused", declared=True
    )
    assert failed_inheritance.returncode == 1

    # The comparator verdict is never optional: a refused comparator fails even with a clean
    # allowlist, and a declared summary never rescues a refused comparator.
    failed_comparator = run_disposition(
        tmp_path / "comparator", allowlist="ok", comparator="refused", inheritance="ok", declared=False
    )
    assert failed_comparator.returncode == 1
    stale_summary = run_disposition(
        tmp_path / "stale", allowlist="refused", comparator="refused", inheritance="ok", declared=True
    )
    assert stale_summary.returncode == 1
    # A refused comparator never earns the declared-delta line, whatever the summary file says.
    assert "DECLARED DELTA" not in stale_summary.stdout


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
        "castle-wall-daemon/tests/linux_install_arch_cli.txt",
        "castle-wall-daemon/tests/linux_install_arch_cli/fixture.rs",
    ]
    assert all(gate.is_arch_trigger_path(path) for path in trigger_paths)
    assert all(gate.is_arch_allowed_path(path) for path in trigger_paths + allowed_only_paths)
    assert not any(gate.is_arch_trigger_path(path) for path in allowed_only_paths + refused_paths)
    assert not any(gate.is_arch_allowed_path(path) for path in refused_paths)

    workflow = yaml.safe_load((REPO / ".github/workflows/linux-arch-package.yml").read_text())
    deb_job = workflow["jobs"]["deb-unchanged-gate"]
    runs = "\n".join(step.get("run", "") for step in deb_job["steps"])
    assert "spec_from_file_location" in runs
    # Both probes (trigger and allowlist) load THIS comparator, so the target appears exactly twice;
    # a probe pointed elsewhere would leave one occurrence.
    assert runs.count('"deb_gate", "castle-wall-daemon/packaging/arch/assert-deb-unchanged.py"') == 2
    # The exact predicate lines, not only the call forms: an added disjunct on either line breaks
    # the derive and shows up here.
    assert 'print("yes" if any(gate.is_arch_trigger_path(p) for p in paths) else "no")' in runs
    assert "bad = [p for p in paths if not gate.is_arch_allowed_path(p)]" in runs
    assert "def is_slice_path" not in runs
    mirrored_literals = [
        *gate.ARCH_TRIGGER_EXACT_PATHS,
        ".github/workflows/castle-wall-linux.yml",
        "castle-wall-daemon/Cargo.toml",
        "castle-wall-daemon/src/linux_install/mod.rs",
        "castle-wall-daemon/src/linux_install/arch/",
        "castle-wall-daemon/tests/linux_install_arch_",
        "castle-wall-daemon/tests/fixtures/substrate/",
    ]
    for literal in mirrored_literals:
        assert literal not in runs
