#!/usr/bin/env python3
"""Stage the Arch package payload and bind the libalpm guard constants."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

PACKAGE = "sanctuary-castle-wall"
KIND = "arch-install-pkg-v1"
TARGET = "x86_64-unknown-linux-gnu"
PRIVATE = "usr/lib/" + PACKAGE
SHARE = "usr/share/" + PACKAGE
# Must match pacman::ARCH_BUILD_IDENTITY when that P2a Rust constant exists.
IDENTITY = PRIVATE + "/build-identity"
# Must match GUARD_PATH in sanctuary-castle-wall-guard.py.
GUARD = "usr/share/libalpm/scripts/sanctuary-castle-wall-guard"
HOOKS = (
    "00-sanctuary-castle-wall-upgrade-guard.hook",
    "00-sanctuary-castle-wall-remove-guard.hook",
)

# Must match the Ubuntu install-layout.py payload paths except CLI_PATH, which
# D4 Q9 moves from usr/sbin/sanctuary-linux to usr/bin/sanctuary-linux on Arch.
BINARIES = {
    "castle-wall-daemon": "usr/local/libexec/sanctuary/castle-wall-daemon",
    "protected-agent-v1": "usr/local/libexec/sanctuary/protected-agent-v1",
    "network-agent-standin": "usr/local/libexec/sanctuary/network-agent-standin",
    "sanctuary-linux": "usr/bin/sanctuary-linux",
}
MOUNT_NAME = r"var-lib-sanctuary\x2dagent\x2dworkspace.mount"
SOURCES = {
    "etc/systemd/system/sanctuary-castle-wall.service": "systemd/sanctuary-castle-wall.service",
    "etc/systemd/system/sanctuary-agent@.service": "systemd/sanctuary-agent@.service",
    "etc/systemd/system/" + MOUNT_NAME: "systemd/" + MOUNT_NAME,
    SHARE + "/schemas/contract.rs": "src/linux_install/contract.rs",
    SHARE + "/operator-guide.md": "packaging/ubuntu/README.md",
}
HOOK_DESTINATIONS = {"usr/share/libalpm/hooks/" + name: name for name in HOOKS}
WORKSPACE_DIRECTORY = "var/lib/sanctuary-agent-workspace"
PAYLOAD_MODES = {
    **{path: 0o755 for path in BINARIES.values()},
    **{path: 0o644 for path in SOURCES},
    **{path: 0o644 for path in HOOK_DESTINATIONS},
    IDENTITY: 0o644,
    GUARD: 0o755,
}
PAYLOAD_DIRS = {str(parent) for path in PAYLOAD_MODES for parent in Path(path).parents if str(parent) != "."}
PAYLOAD_DIRS |= {
    "var",
    "var/lib",
    WORKSPACE_DIRECTORY,
    "usr/share/libalpm",
    "usr/share/libalpm/hooks",
    "usr/share/libalpm/scripts",
    PRIVATE,
    SHARE,
}


RUST_CONST = re.compile(r'pub const (ARCH_BUILD_IDENTITY|ARCH_CLI_PATH): &str = "([^"]+)";')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    # The package records directory modes; an inherited restrictive umask would make guarded removal refuse.
    path.chmod(0o755)


def write_file(destination: Path, data: bytes, mode: int) -> None:
    ensure_directory(destination.parent)
    destination.write_bytes(data)
    destination.chmod(mode)


def copy_file(source: Path, destination: Path, mode: int) -> None:
    ensure_directory(destination.parent)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def guard_static_bytes(version: str, here: Path) -> bytes:
    template = (here / "sanctuary-castle-wall-guard.py").read_bytes()
    # Must match the STATIC definition in brief 3.1 and the CLI pin in P2a.
    return (
        f"PACKAGE_VERSION = {version!r}\n"
        + f"IDENTITY_PATH = {('/' + IDENTITY)!r}\n"
        + f"PAYLOAD_MODES = {PAYLOAD_MODES!r}\n"
    ).encode() + template


def guard_bytes(version: str, identity_bytes: bytes, here: Path) -> bytes:
    # The identity intentionally omits the guard hash because this header embeds
    # the identity hash; including both would make a self-referential digest loop.
    return (
        "#!/usr/bin/python3 -I\n"
        + f"IDENTITY_SHA256 = {hashlib.sha256(identity_bytes).hexdigest()!r}\n"
    ).encode() + guard_static_bytes(version, here)


def binary_features(cargo_json: Path) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = {}
    for line in cargo_json.read_text().splitlines():
        record = json.loads(line)
        target = record.get("target", {})
        name = target.get("name")
        if record.get("reason") == "compiler-artifact" and name in BINARIES and record.get("executable"):
            features = record.get("features")
            profile = record.get("profile", {})
            if features != [] or profile.get("test"):
                raise ValueError(f"unexpected feature or test artifact for {name}")
            seen[name] = features
    if set(seen) != set(BINARIES):
        missing = sorted(set(BINARIES) - set(seen))
        raise ValueError(f"Cargo did not witness every binary: {missing}")
    return {name: seen[name] for name in sorted(seen)}


def package_file_count(root: Path) -> int:
    count = 0
    for path in root.rglob("*"):
        if path.is_dir() or path.is_file() or path.is_symlink():
            count += 1
    return count


def check_optional_rust_constants(crate: Path) -> None:
    expected = {
        "ARCH_BUILD_IDENTITY": IDENTITY,
        # Rust verifies opened absolute paths; payload keys remain relative.
        "ARCH_CLI_PATH": "/" + BINARIES["sanctuary-linux"],
    }
    found: dict[str, str] = {}
    src = crate / "src"
    if not src.exists():
        return
    for path in src.rglob("*.rs"):
        for match in RUST_CONST.finditer(path.read_text()):
            found[match.group(1)] = match.group(2)
    for name, value in found.items():
        if value != expected[name]:
            raise ValueError(f"{name} must be {expected[name]!r}, got {value!r}")


def stage(args: argparse.Namespace) -> None:
    crate = args.crate.resolve()
    here = Path(__file__).resolve().parent
    dest = args.dest.resolve()
    target_dir = args.target_dir.resolve()
    version = f"{args.pkgver}-{args.pkgrel}"
    check_optional_rust_constants(crate)

    for directory in PAYLOAD_DIRS:
        ensure_directory(dest / directory)

    for name, rel in BINARIES.items():
        copy_file(target_dir / TARGET / "release" / name, dest / rel, PAYLOAD_MODES[rel])
    for rel, source in SOURCES.items():
        copy_file(crate / source, dest / rel, PAYLOAD_MODES[rel])
    for rel, hook in HOOK_DESTINATIONS.items():
        copy_file(here / hook, dest / rel, PAYLOAD_MODES[rel])

    hook_hashes = {name: sha(dest / ("usr/share/libalpm/hooks/" + name)) for name in HOOKS}
    # Must match expected_payloads in sanctuary-castle-wall-guard.py.
    hashed_paths = sorted(set(PAYLOAD_MODES) - {IDENTITY, GUARD})
    payload_hashes = {path: sha(dest / path) for path in hashed_paths}
    features = binary_features(args.cargo_json)
    rustflags_file = args.rustflags_file.resolve()
    if not rustflags_file.is_file():
        raise ValueError("scrubbed RUSTFLAGS witness is absent")
    rustflags = rustflags_file.read_text()
    if rustflags:
        raise ValueError("RUSTFLAGS must be scrubbed before staging the Arch package")
    identity = {
        "artifact_kind": KIND,
        "install_ready": False,
        "binary_features": features,
        "package": PACKAGE,
        "package_version": version,
        "source_commit": args.source_commit,
        "cargo_lock_sha256": sha(crate / "Cargo.lock"),
        "rustc_version": args.rustc_version,
        "rustflags": rustflags,
        "target": TARGET,
        # identity and guard are written after the identity bytes are serialized;
        # both are package files and must be counted for pacman -Qkk parity.
        "file_count": package_file_count(dest) + 2,
        "glibc_floor": args.glibc_floor,
        "payload_sha256": payload_hashes,
        "hook_sha256": hook_hashes,
        "cli_path_deviation": {
            "ubuntu_path": "usr/sbin/sanctuary-linux",
            "arch_path": BINARIES["sanctuary-linux"],
            "reason": "Arch /usr/sbin is owned as a filesystem symlink; D4 Q9 chooses usr/bin.",
        },
    }
    identity_bytes = (json.dumps(identity, sort_keys=True, indent=2) + "\n").encode()
    write_file(dest / IDENTITY, identity_bytes, PAYLOAD_MODES[IDENTITY])
    write_file(dest / GUARD, guard_bytes(version, identity_bytes, here), PAYLOAD_MODES[GUARD])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", type=Path, required=True)
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--pkgver", required=True)
    parser.add_argument("--pkgrel", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--rustc-version", required=True)
    parser.add_argument("--glibc-floor", required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--cargo-json", type=Path, required=True)
    parser.add_argument("--rustflags-file", type=Path, required=True)
    stage(parser.parse_args())


if __name__ == "__main__":
    main()
