#!/usr/bin/env python3
"""Stage the Arch package payload and bind the libalpm guard constants."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


PACKAGE = "sanctuary-castle-wall"
KIND = "arch-install-pkg-v1"
TARGET = "x86_64-unknown-linux-gnu"
DOC = "usr/share/doc/" + PACKAGE
IDENTITY = DOC + "/build-identity"
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
    DOC + "/schemas/contract.rs": "src/linux_install/contract.rs",
    DOC + "/operator-guide.md": "packaging/ubuntu/README.md",
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
PAYLOAD_DIRS |= {"var", "var/lib", WORKSPACE_DIRECTORY, "usr/share/libalpm", "usr/share/libalpm/hooks", "usr/share/libalpm/scripts"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_file(destination: Path, data: bytes, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(mode)


def copy_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def guard_bytes(version: str, identity_bytes: bytes, payload_hashes: dict[str, str], here: Path) -> bytes:
    # The identity intentionally omits the guard hash because this header embeds
    # the identity hash; including both would make a self-referential digest loop.
    header = (
        "#!/usr/bin/python3 -I\n"
        + f"PACKAGE_VERSION = {version!r}\n"
        + f"IDENTITY_SHA256 = {hashlib.sha256(identity_bytes).hexdigest()!r}\n"
        + f"PAYLOAD_MODES = {PAYLOAD_MODES!r}\n"
        + f"PAYLOAD_HASHES = {payload_hashes!r}\n"
    )
    return header.encode() + (here / "sanctuary-castle-wall-guard.py").read_bytes()


def stage(args: argparse.Namespace) -> None:
    crate = args.crate.resolve()
    here = Path(__file__).resolve().parent
    dest = args.dest.resolve()
    version = f"{args.pkgver}-{args.pkgrel}"

    for directory in PAYLOAD_DIRS:
        (dest / directory).mkdir(parents=True, exist_ok=True)

    for name, rel in BINARIES.items():
        copy_file(crate / "target" / TARGET / "release" / name, dest / rel, PAYLOAD_MODES[rel])
    for rel, source in SOURCES.items():
        copy_file(crate / source, dest / rel, PAYLOAD_MODES[rel])
    for rel, hook in HOOK_DESTINATIONS.items():
        copy_file(here / hook, dest / rel, PAYLOAD_MODES[rel])

    hook_hashes = {name: sha(dest / ("usr/share/libalpm/hooks/" + name)) for name in HOOKS}
    hashed_paths = sorted(set(PAYLOAD_MODES) - {IDENTITY, GUARD})
    payload_hashes = {path: sha(dest / path) for path in hashed_paths if (dest / path).is_file()}
    identity = {
        "artifact_kind": KIND,
        "install_ready": False,
        "package": PACKAGE,
        "package_version": version,
        "source_commit": args.source_commit,
        "cargo_lock_sha256": sha(crate / "Cargo.lock"),
        "rustc_version": args.rustc_version,
        "target": TARGET,
        "features": [],
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
    write_file(dest / GUARD, guard_bytes(version, identity_bytes, payload_hashes, here), PAYLOAD_MODES[GUARD])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate", type=Path, required=True)
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--pkgver", required=True)
    parser.add_argument("--pkgrel", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--rustc-version", required=True)
    parser.add_argument("--glibc-floor", required=True)
    stage(parser.parse_args())


if __name__ == "__main__":
    main()
