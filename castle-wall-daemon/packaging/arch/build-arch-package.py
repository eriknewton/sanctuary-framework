#!/usr/bin/env python3
"""Stage the Arch package payload and bind the libalpm guard constants."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

PACKAGE = "sanctuary-castle-wall"
KIND = "arch-install-pkg-v1"
TARGET = "x86_64-unknown-linux-gnu"
PRIVATE = "usr/lib/" + PACKAGE
SHARE = "usr/share/" + PACKAGE
# Must match pacman::ARCH_BUILD_IDENTITY.
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
CLI_SOURCE_BIN = "sanctuary-linux-arch"
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
# Must match pacman::expected_payloads(), plus IDENTITY and GUARD.
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


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def binary_features(paths: list[Path]) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = {}
    # Must match pacman::required_binary_features().
    expected = {
        "castle-wall-daemon": [],
        "protected-agent-v1": [],
        "network-agent-standin": [],
        CLI_SOURCE_BIN: ["arch-install"],
    }
    for cargo_json in paths:
        for line in cargo_json.read_text().splitlines():
            record = json.loads(line)
            target = record.get("target", {})
            name = target.get("name")
            if record.get("reason") == "compiler-artifact" and name in expected and record.get("executable"):
                features = record.get("features")
                profile = record.get("profile", {})
                if features != expected[name] or profile.get("test"):
                    raise ValueError(f"unexpected feature or test artifact for {name}")
                seen[name] = features
    if set(seen) != set(expected):
        missing = sorted(set(expected) - set(seen))
        raise ValueError(f"Cargo did not witness every binary: {missing}")
    return {name: seen[name] for name in sorted(seen)}


def package_file_count(root: Path) -> int:
    count = 0
    for path in root.rglob("*"):
        if path.is_dir() or path.is_file() or path.is_symlink():
            count += 1
    return count


def check_required_rust_constants(crate: Path) -> None:
    expected = {
        "ARCH_BUILD_IDENTITY": IDENTITY,
        # Rust verifies opened absolute paths; payload keys remain relative.
        "ARCH_CLI_PATH": "/" + BINARIES["sanctuary-linux"],
    }
    found: dict[str, list[tuple[Path, str]]] = {name: [] for name in expected}
    src = crate / "src"
    if not src.exists():
        raise ValueError("Rust source directory absent for Arch path constant check")
    for path in src.rglob("*.rs"):
        for match in RUST_CONST.finditer(path.read_text()):
            found[match.group(1)].append((path, match.group(2)))
    for name, matches in found.items():
        if len(matches) != 1:
            raise ValueError(f"{name} must appear exactly once in Rust source")
        value = matches[0][1]
        if value != expected[name]:
            raise ValueError(f"{name} must be {expected[name]!r}, got {value!r}")


def payload_hashes_for_pins(crate: Path, target_dir: Path, dest: Path | None = None) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, rel in BINARIES.items():
        if name == "sanctuary-linux":
            continue
        hashes[rel] = sha(target_dir / TARGET / "release" / name)
    for rel, source in SOURCES.items():
        source_path = dest / rel if dest is not None else crate / source
        hashes[rel] = sha(source_path)
    here = Path(__file__).resolve().parent
    for rel, hook in HOOK_DESTINATIONS.items():
        source_path = dest / rel if dest is not None else here / hook
        hashes[rel] = sha(source_path)
    return {path: hashes[path] for path in sorted(hashes)}


def payload_pin_from_hashes(hashes: dict[str, str]) -> str:
    # Must match pacman::payload_pin: path, NUL, lowercase SHA-256 hex, newline.
    canonical = b"".join(path.encode() + b"\0" + digest.encode() + b"\n" for path, digest in sorted(hashes.items()))
    return sha_bytes(canonical)


def payload_pin_from_staged_hashes(payload_hashes: dict[str, str]) -> str:
    return payload_pin_from_hashes(
        {path: digest for path, digest in payload_hashes.items() if path != BINARIES["sanctuary-linux"]}
    )


def compute_pins(crate: Path, target_dir: Path, version: str) -> dict[str, str]:
    here = Path(__file__).resolve().parent
    return {
        "package_version": version,
        "payload_sha256": payload_pin_from_hashes(payload_hashes_for_pins(crate, target_dir)),
        "guard_static_sha256": sha_bytes(guard_static_bytes(version, here)),
    }


def pin(args: argparse.Namespace) -> None:
    crate = args.crate.resolve()
    target_dir = args.target_dir.resolve()
    version = f"{args.pkgver}-{args.pkgrel}"
    check_required_rust_constants(crate)
    args.output.write_text(json.dumps(compute_pins(crate, target_dir, version), sort_keys=True, indent=2) + "\n")


def read_pins(path: Path) -> dict[str, str]:
    pins = json.loads(path.read_text())
    required = {"package_version", "payload_sha256", "guard_static_sha256"}
    if set(pins) != required:
        raise ValueError("pin file shape mismatch")
    for key, value in pins.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"pin {key} missing")
    return pins


def verify_pins_in_binary(binary: Path, pins: dict[str, str]) -> None:
    data = binary.read_bytes()
    for key in ("payload_sha256", "guard_static_sha256"):
        needle = pins[key].encode()
        if data.count(needle) == 0:
            raise ValueError(f"pin {key} absent from built CLI")
    if data.count(pins["package_version"].encode()) == 0:
        raise ValueError("package version pin absent from built CLI")


def stage(args: argparse.Namespace) -> None:
    crate = args.crate.resolve()
    here = Path(__file__).resolve().parent
    dest = args.dest.resolve()
    shared_target_dir = args.shared_target_dir.resolve()
    cli_target_dir = args.cli_target_dir.resolve()
    version = f"{args.pkgver}-{args.pkgrel}"
    check_required_rust_constants(crate)
    pins = read_pins(args.pins.resolve())
    if pins != compute_pins(crate, shared_target_dir, version):
        raise ValueError("compiled Arch pins differ from staged payload inputs")

    for directory in PAYLOAD_DIRS:
        ensure_directory(dest / directory)

    for name, rel in BINARIES.items():
        source_name = CLI_SOURCE_BIN if name == "sanctuary-linux" else name
        target_dir = cli_target_dir if name == "sanctuary-linux" else shared_target_dir
        copy_file(target_dir / TARGET / "release" / source_name, dest / rel, PAYLOAD_MODES[rel])
    for rel, source in SOURCES.items():
        copy_file(crate / source, dest / rel, PAYLOAD_MODES[rel])
    for rel, hook in HOOK_DESTINATIONS.items():
        copy_file(here / hook, dest / rel, PAYLOAD_MODES[rel])

    hook_hashes = {name: sha(dest / ("usr/share/libalpm/hooks/" + name)) for name in HOOKS}
    # Must match expected_payloads in sanctuary-castle-wall-guard.py.
    hashed_paths = sorted(set(PAYLOAD_MODES) - {IDENTITY, GUARD})
    payload_hashes = {path: sha(dest / path) for path in hashed_paths}
    verify_pins_in_binary(cli_target_dir / TARGET / "release" / CLI_SOURCE_BIN, pins)
    if payload_pin_from_staged_hashes(payload_hashes) != pins["payload_sha256"]:
        raise ValueError("staged payload bytes differ from compiled Arch payload pin")
    features = binary_features([args.shared_cargo_json, args.cli_cargo_json])
    rustflags_file = args.rustflags_file.resolve()
    if not rustflags_file.is_file():
        raise ValueError("scrubbed RUSTFLAGS witness is absent")
    rustflags = rustflags_file.read_text()
    if rustflags:
        raise ValueError("RUSTFLAGS must be scrubbed before staging the Arch package")
    identity = {
        "artifact_kind": KIND,
        "install_ready": True,
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
        "cli_source_bin": CLI_SOURCE_BIN,
        "cli_pins": pins,
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
    sub = parser.add_subparsers(dest="command", required=True)
    pin_parser = sub.add_parser("pin")
    pin_parser.add_argument("--crate", type=Path, required=True)
    pin_parser.add_argument("--pkgver", required=True)
    pin_parser.add_argument("--pkgrel", required=True)
    pin_parser.add_argument("--target-dir", type=Path, required=True)
    pin_parser.add_argument("--output", type=Path, required=True)
    stage_parser = sub.add_parser("stage")
    stage_parser.add_argument("--crate", type=Path, required=True)
    stage_parser.add_argument("--dest", type=Path, required=True)
    stage_parser.add_argument("--pkgver", required=True)
    stage_parser.add_argument("--pkgrel", required=True)
    stage_parser.add_argument("--source-commit", required=True)
    stage_parser.add_argument("--rustc-version", required=True)
    stage_parser.add_argument("--glibc-floor", required=True)
    stage_parser.add_argument("--shared-target-dir", type=Path, required=True)
    stage_parser.add_argument("--cli-target-dir", type=Path, required=True)
    stage_parser.add_argument("--shared-cargo-json", type=Path, required=True)
    stage_parser.add_argument("--cli-cargo-json", type=Path, required=True)
    stage_parser.add_argument("--rustflags-file", type=Path, required=True)
    stage_parser.add_argument("--pins", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "pin":
        pin(args)
    elif args.command == "stage":
        stage(args)
    else:
        sys.exit(f"unknown command {args.command}")


if __name__ == "__main__":
    main()
