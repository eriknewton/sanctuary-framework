#!/usr/bin/env python3
"""Compare base/head install .debs while allowing only declared raw-byte deltas."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple

IDENTITY_PATH = "fs/usr/share/doc/sanctuary-castle-wall/build-identity"  # Must match install-layout.py IDENTITY with fs/ prepended.
DECLARATION_PATH = "castle-wall-daemon/packaging/arch/deb-delta-declaration.json"
CONTROL_MEMBERS = frozenset({"control", "preinst", "prerm"})
SCRIPT_NAMES = ("preinst", "prerm")

# 64 hex chars = SHA-256's 32 bytes rendered as two lowercase hex chars each.
SHA256_HEX = rb"[0-9a-f]{64}"
SCRIPT_IDENTITY_RE = re.compile(
    rb"(?m)^IDENTITY_SHA256 = '(" + SHA256_HEX + rb")'$"
)  # Must match install-layout.py guard_bytes' IDENTITY_SHA256 header line.
GUARD_SHA256_RE = re.compile(rb'"guard_sha256"\s*:\s*"[0-9a-f]{64}"')
PAYLOAD_SHA256_NONEMPTY_RE = re.compile(
    rb'"payload_sha256"\s*:\s*\{\s*"[^"]+"\s*:\s*"[0-9a-f]{64}"', re.DOTALL
)

# Must match the derived predicate calls in .github/workflows/linux-arch-package.yml.
ARCH_TRIGGER_EXACT_PATHS = (
    ".github/workflows/linux-arch-package.yml",
    "castle-wall-daemon/src/bin/sanctuary-linux-arch.rs",
)
ARCH_TRIGGER_PREFIXES = (
    "castle-wall-daemon/packaging/arch/",
    "castle-wall-daemon/src/linux_install/arch/",
    "castle-wall-daemon/tests/fixtures/substrate/",
)
ARCH_ALLOWED_EXACT_PATHS = ARCH_TRIGGER_EXACT_PATHS + (
    ".github/workflows/castle-wall-linux.yml",
    "castle-wall-daemon/Cargo.toml",
    "castle-wall-daemon/src/linux_install/mod.rs",
)
ARCH_ALLOWED_PREFIXES = ARCH_TRIGGER_PREFIXES


class DebCompareError(ValueError):
    pass


class Entry(NamedTuple):
    kind: str
    mode: int


class DeltaDeclaration(NamedTuple):
    paths: frozenset[str]
    document: str


def is_arch_trigger_path(path: str) -> bool:
    return (
        path in ARCH_TRIGGER_EXACT_PATHS
        or any(path.startswith(prefix) for prefix in ARCH_TRIGGER_PREFIXES)
        or is_linux_install_arch_test(path)
    )


def is_arch_allowed_path(path: str) -> bool:
    return (
        path in ARCH_ALLOWED_EXACT_PATHS
        or any(path.startswith(prefix) for prefix in ARCH_ALLOWED_PREFIXES)
        or is_linux_install_arch_test(path)
    )


def is_linux_install_arch_test(path: str) -> bool:
    prefix = "castle-wall-daemon/tests/linux_install_arch_"
    if not path.startswith(prefix) or not path.endswith(".rs"):
        return False
    rest = path[len(prefix) :]
    return "/" not in rest


def repr_path_lines(paths: list[str]) -> str:
    return "".join(f"{path!r}\n" for path in paths)


def extract(deb: Path, out: Path) -> None:
    # dpkg-deb creates only the last path component; the parent must already exist.
    (out / "fs").mkdir(parents=True, exist_ok=True)
    subprocess.run(["dpkg-deb", "-x", str(deb), str(out / "fs")], check=True)
    subprocess.run(["dpkg-deb", "-e", str(deb), str(out / "control")], check=True)


def read_nul_paths(path: Path) -> list[str]:
    raw = path.read_bytes()
    return [item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item]


def active_declaration(changed_paths: list[str], declaration_path: Path) -> DeltaDeclaration | None:
    if DECLARATION_PATH not in changed_paths:
        return None
    if not declaration_path.is_file():
        return None
    try:
        data = json.loads(declaration_path.read_text())
    except json.JSONDecodeError as exc:
        raise DebCompareError(f"{DECLARATION_PATH} is not valid JSON: {exc}") from exc
    raw_paths = data.get("paths", data.get("declared_paths"))
    document = data.get("document", data.get("review_document"))
    if not isinstance(raw_paths, list) or not raw_paths or not all(isinstance(path, str) for path in raw_paths):
        raise DebCompareError(f"{DECLARATION_PATH} must contain a non-empty string list named paths")
    if not isinstance(document, str) or not document:
        raise DebCompareError(f"{DECLARATION_PATH} must name its review document")
    paths = frozenset(raw_paths)
    if len(paths) != len(raw_paths):
        raise DebCompareError(f"{DECLARATION_PATH} contains duplicate declared paths")
    return DeltaDeclaration(paths=paths, document=document)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def entry_kind(path: Path) -> str:
    st = path.lstat()
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    return "other"


def entry_map(root: Path, prefix: str) -> dict[str, Entry]:
    base = root / prefix
    if not base.is_dir():
        raise DebCompareError(f"{prefix}/ missing from extracted archive")
    entries: dict[str, Entry] = {}
    for path in sorted(base.rglob("*")):
        rel = f"{prefix}/{path.relative_to(base).as_posix()}"
        st = path.lstat()
        entries[rel] = Entry(kind=entry_kind(path), mode=stat.S_IMODE(st.st_mode))
    return entries


def file_bytes(root: Path, rel: str) -> bytes:
    return (root / rel).read_bytes()


def replace_once(haystack: bytes, needle: bytes, replacement: bytes, label: str) -> bytes:
    count = haystack.count(needle)
    if count != 1:
        raise DebCompareError(f"{label} occurs {count} times, expected exactly once")
    return haystack.replace(needle, replacement, 1)


def identity_entry(path: str, digest: str) -> bytes:
    key = path.removeprefix("fs/")
    return json.dumps(key).encode() + b": " + json.dumps(digest).encode()


def guard_payload_hash_entry(path: str, digest: str) -> bytes:
    key = path.removeprefix("fs/")
    return repr(key).encode() + b": " + repr(digest).encode()


def first_differing_line(base: bytes, head: bytes) -> str:
    base_lines = base.splitlines()
    head_lines = head.splitlines()
    matcher = difflib.SequenceMatcher(a=base_lines, b=head_lines, autojunk=False)
    for tag, base_start, _base_end, head_start, _head_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        base_line = base_lines[base_start] if base_start < len(base_lines) else b"<missing>"
        head_line = head_lines[head_start] if head_start < len(head_lines) else b"<missing>"
        return (
            f"; first differing line base {base_start + 1}, head {head_start + 1}: "
            f"base={base_line[:160]!r} head={head_line[:160]!r}"
        )
    return "; no differing line found"


def assert_required_identity_fields(identity: bytes) -> None:
    if PAYLOAD_SHA256_NONEMPTY_RE.search(identity) is None:
        raise DebCompareError("payload_sha256 missing or empty in a build identity")
    if GUARD_SHA256_RE.search(identity) is None:
        raise DebCompareError("guard_sha256 missing or empty in a build identity")


def verify_identity(
    base_root: Path,
    head_root: Path,
    base_source_commit: str,
    head_source_commit: str,
    declaration: DeltaDeclaration | None,
) -> tuple[str, str]:
    base = file_bytes(base_root, IDENTITY_PATH)
    head = file_bytes(head_root, IDENTITY_PATH)
    assert_required_identity_fields(base)
    assert_required_identity_fields(head)
    base_hash, head_hash = sha256_bytes(base), sha256_bytes(head)
    # Must match build-install-deb.py's json.dumps(..., sort_keys=True, indent=2) colon-space rendering.
    rewritten = replace_once(
        base,
        json.dumps("source_commit").encode() + b": " + json.dumps(base_source_commit).encode(),
        json.dumps("source_commit").encode() + b": " + json.dumps(head_source_commit).encode(),
        "source_commit substitution",
    )
    declared_head_entries: dict[str, bytes] = {}
    if declaration is not None:
        for path in sorted(declaration.paths):
            fs_prefixed = json.dumps(path).encode()
            if fs_prefixed in base or fs_prefixed in head:
                raise DebCompareError(f"declared identity entry {path} must use the installed path without fs/")
            base_digest = sha256_bytes(file_bytes(base_root, path))
            head_digest = sha256_bytes(file_bytes(head_root, path))
            declared_head_entries[path] = identity_entry(path, head_digest)
            rewritten = replace_once(
                rewritten,
                identity_entry(path, base_digest),
                declared_head_entries[path],
                f"declared identity entry {path.removeprefix('fs/')}",
            )
    if rewritten != head:
        for path, expected in sorted(declared_head_entries.items()):
            if expected not in head:
                raise DebCompareError(
                    f"declared identity entry {path.removeprefix('fs/')} does not equal that file's SHA-256"
                )
        raise DebCompareError(
            f"{IDENTITY_PATH} changed outside the permitted substitutions{first_differing_line(rewritten, head)}"
        )
    return base_hash, head_hash


def script_identity_line(script: bytes, expected_identity_hash: str, label: str) -> bytes:
    matches = list(SCRIPT_IDENTITY_RE.finditer(script))
    if len(matches) != 1:
        raise DebCompareError(f"{label} has {len(matches)} IDENTITY_SHA256 lines, expected exactly one")
    actual = matches[0].group(1).decode()
    if actual != expected_identity_hash:
        raise DebCompareError(f"{label} IDENTITY_SHA256 is {actual}, expected {expected_identity_hash}")
    return matches[0].group(0)


def verify_script(
    base_root: Path,
    head_root: Path,
    script: str,
    base_identity_hash: str,
    head_identity_hash: str,
    declaration: DeltaDeclaration | None,
) -> None:
    rel = f"control/{script}"
    base = file_bytes(base_root, rel)
    head = file_bytes(head_root, rel)
    base_line = script_identity_line(base, base_identity_hash, f"{rel} base")
    head_line = script_identity_line(head, head_identity_hash, f"{rel} head")
    rewritten = replace_once(base, base_line, head_line, f"{rel} IDENTITY_SHA256 substitution")
    if declaration is not None:
        for path in sorted(declaration.paths):
            base_digest = sha256_bytes(file_bytes(base_root, path))
            head_digest = sha256_bytes(file_bytes(head_root, path))
            head_entry = guard_payload_hash_entry(path, head_digest)
            if head.count(head_entry) != 1:
                raise DebCompareError(
                    f"{rel} declared guard entry {path.removeprefix('fs/')} occurs "
                    f"{head.count(head_entry)} times in head, expected exactly once"
                )
            rewritten = replace_once(
                rewritten,
                guard_payload_hash_entry(path, base_digest),
                head_entry,
                f"{rel} declared guard entry {path.removeprefix('fs/')}",
            )
    if rewritten != head:
        raise DebCompareError(f"{rel} changed outside the permitted substitutions{first_differing_line(rewritten, head)}")


def assert_declaration_paths(entries: dict[str, Entry], declaration: DeltaDeclaration | None) -> None:
    if declaration is None:
        return
    for path in sorted(declaration.paths):
        if not path.startswith("fs/"):
            raise DebCompareError(f"declared path {path} is not under fs/")
        if path == IDENTITY_PATH:
            raise DebCompareError(f"declared path {path} names the build identity")
        entry = entries.get(path)
        if entry is None:
            raise DebCompareError(f"declared path {path} is not present in the extracted payload")
        if entry.kind != "file":
            raise DebCompareError(f"declared path {path} is not a regular file")


def compare_entry_metadata(base_entries: dict[str, Entry], head_entries: dict[str, Entry], prefix: str) -> None:
    base_paths = set(base_entries)
    head_paths = set(head_entries)
    if base_paths != head_paths:
        missing = sorted(base_paths - head_paths)
        added = sorted(head_paths - base_paths)
        detail = []
        if missing:
            detail.append("missing from head: " + ", ".join(missing))
        if added:
            detail.append("added in head: " + ", ".join(added))
        raise DebCompareError(f"{prefix}/ path set changed: {'; '.join(detail)}")
    for path in sorted(base_paths):
        if base_entries[path] != head_entries[path]:
            raise DebCompareError(
                f"{path} metadata changed: base {base_entries[path].kind} {oct(base_entries[path].mode)}, "
                f"head {head_entries[path].kind} {oct(head_entries[path].mode)}"
            )


def compare_payload_bytes(
    base_root: Path,
    head_root: Path,
    entries: dict[str, Entry],
    declaration: DeltaDeclaration | None,
) -> None:
    differing_regular_files: set[str] = set()
    for path, entry in sorted(entries.items()):
        if entry.kind == "file":
            if file_bytes(base_root, path) != file_bytes(head_root, path):
                differing_regular_files.add(path)
        elif entry.kind == "symlink" and os.readlink(base_root / path) != os.readlink(head_root / path):
            raise DebCompareError(f"{path} symlink target changed")
    differing_without_identity = differing_regular_files - {IDENTITY_PATH}
    if declaration is None:
        if differing_without_identity:
            raise DebCompareError(f"{min(differing_without_identity)} changed")
        return
    if differing_without_identity != set(declaration.paths):
        undeclared = sorted(differing_without_identity - declaration.paths)
        not_observed = sorted(declaration.paths - differing_without_identity)
        detail = []
        if undeclared:
            detail.append("undeclared differences: " + ", ".join(undeclared))
        if not_observed:
            detail.append("declared paths did not differ: " + ", ".join(not_observed))
        raise DebCompareError("declared delta mismatch: " + "; ".join(detail))


def compare_control(base_root: Path, head_root: Path) -> None:
    base_entries = entry_map(base_root, "control")
    head_entries = entry_map(head_root, "control")
    base_members = {path.removeprefix("control/") for path in base_entries}
    head_members = {path.removeprefix("control/") for path in head_entries}
    if base_members != CONTROL_MEMBERS or head_members != CONTROL_MEMBERS:
        raise DebCompareError(
            "control member set changed: "
            f"base={sorted(base_members)} head={sorted(head_members)} expected={sorted(CONTROL_MEMBERS)}"
        )
    compare_entry_metadata(base_entries, head_entries, "control")
    if file_bytes(base_root, "control/control") != file_bytes(head_root, "control/control"):
        raise DebCompareError(
            "control/control changed" + first_differing_line(file_bytes(base_root, "control/control"), file_bytes(head_root, "control/control"))
        )


def compare_extracted(
    base_root: Path,
    head_root: Path,
    base_source_commit: str,
    head_source_commit: str,
    declaration: DeltaDeclaration | None = None,
) -> None:
    fs_base_entries = entry_map(base_root, "fs")
    fs_head_entries = entry_map(head_root, "fs")
    compare_entry_metadata(fs_base_entries, fs_head_entries, "fs")
    assert_declaration_paths(fs_base_entries, declaration)
    compare_control(base_root, head_root)
    compare_payload_bytes(base_root, head_root, fs_base_entries, declaration)
    base_identity_hash, head_identity_hash = verify_identity(
        base_root, head_root, base_source_commit, head_source_commit, declaration
    )
    for script in SCRIPT_NAMES:
        verify_script(base_root, head_root, script, base_identity_hash, head_identity_hash, declaration)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_deb", type=Path)
    parser.add_argument("head_deb", type=Path)
    parser.add_argument("--base-source-commit", required=True)
    parser.add_argument("--head-source-commit", required=True)
    parser.add_argument("--changed-paths-nul", type=Path)
    parser.add_argument("--declaration", type=Path, default=Path(DECLARATION_PATH))
    parser.add_argument("--declared-paths-json", type=Path)
    parser.add_argument("--declared-summary", type=Path)
    args = parser.parse_args()
    declaration = None
    if args.changed_paths_nul is not None:
        declaration = active_declaration(read_nul_paths(args.changed_paths_nul), args.declaration)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        base, head = root / "base", root / "head"
        extract(args.base_deb, base)
        extract(args.head_deb, head)
        compare_extracted(base, head, args.base_source_commit, args.head_source_commit, declaration)
    if declaration is not None:
        if args.declared_paths_json is not None:
            args.declared_paths_json.write_text(json.dumps(sorted(declaration.paths)) + "\n")
        if args.declared_summary is not None:
            args.declared_summary.write_text(", ".join(sorted(declaration.paths)) + f", {declaration.document}\n")
    if declaration is None:
        print("deb comparator: PASS strict raw-byte comparison")
    else:
        print(
            "deb comparator: PASS declared delta: "
            + ", ".join(sorted(declaration.paths))
            + f"; document: {declaration.document}"
        )


if __name__ == "__main__":
    try:
        main()
    except DebCompareError as exc:
        raise SystemExit(f"deb comparator: REFUSED: {exc}") from exc
