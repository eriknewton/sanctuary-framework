#!/usr/bin/env python3
"""Read-only exact archive and source-identity check for the internal .deb."""

import hashlib
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path


PACKAGE = "sanctuary-castle-wall-internal"
PAYLOAD_FILES = {
    "usr/local/libexec/sanctuary/castle-wall-daemon": 0o755,
    "etc/systemd/system/sanctuary-castle-wall.service": 0o644,
    "usr/share/doc/sanctuary-castle-wall-internal/build-identity": 0o644,
}
PAYLOAD_DIRS = {
    "etc", "etc/systemd", "etc/systemd/system", "usr", "usr/local",
    "usr/local/libexec", "usr/local/libexec/sanctuary", "usr/share",
    "usr/share/doc", "usr/share/doc/sanctuary-castle-wall-internal",
}
CONTROL_FILES = {"control": 0o644, "preinst": 0o755, "prerm": 0o755}


def fail(message):
    raise ValueError(message)


def field(deb, name):
    result = subprocess.run(["dpkg-deb", "-f", str(deb), name], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def validate_runtime_depends(depends):
    # The builder emits only plain, exact package names. Reject relationship
    # syntax (including versioned -dev packages) instead of trying to guess
    # whether a more complex expression has an acceptable alternative.
    if "\r" in depends or "\n" in depends:
        fail("runtime Depends must be a single line")
    names = [part.strip() for part in depends.split(",")]
    if not names or any(not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::amd64)?", name) for name in names):
        fail("runtime Depends is not a plain package-name list")
    if len(names) != len(set(names)) or any(name.removesuffix(":amd64").endswith("-dev") or name.removesuffix(":amd64") in ("systemd", "nftables") for name in names):
        fail("runtime Depends contains duplicate, probe or -dev package")
    return names


def archive(deb, option):
    result = subprocess.run(["dpkg-deb", option, str(deb)], capture_output=True, check=True)
    answer = {}
    saw_root = False
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as tar:
        for entry in tar:
            # dpkg-deb can emit the archive root as `.` rather than `./`.
            # It is not payload, but still must have exact safe metadata.
            if entry.name in (".", "./"):
                if saw_root or not entry.isdir() or entry.uid != 0 or entry.gid != 0 or (entry.mode & 0o7777) != 0o755:
                    fail("unsafe or duplicate archive root")
                saw_root = True
                continue
            name = entry.name.removeprefix("./").rstrip("/")
            if not name:
                fail("unexpected empty archive path")
            if name in answer:
                fail(f"duplicate archive entry: {name}")
            if not entry.isfile() and not entry.isdir():
                fail(f"unexpected archive member type: {name}")
            if entry.uid != 0 or entry.gid != 0:
                fail(f"non-root archive member: {name}")
            data = tar.extractfile(entry).read() if entry.isfile() else b""
            answer[name] = (entry, data)
    return answer


def check_members(entries, files, dirs):
    if set(entries) != set(files) | set(dirs):
        fail(f"archive allowlist mismatch: {sorted(set(entries) ^ (set(files) | set(dirs)))}")
    for name, (entry, _) in entries.items():
        expected = files.get(name, 0o755)
        if (entry.mode & 0o7777) != expected:
            fail(f"wrong archive mode for {name}")
        if name in files and not entry.isfile():
            fail(f"expected regular file: {name}")
        if name in dirs and not entry.isdir():
            fail(f"expected directory: {name}")


def parse_identity(raw):
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("build identity is not ASCII")
    fields = {}
    for line in lines:
        if "=" not in line:
            fail("malformed build identity")
        key, value = line.split("=", 1)
        if not key or key in fields:
            fail("duplicate or malformed build identity field")
        fields[key] = value
    required = {
        "artifact_kind", "install_ready", "package", "package_version",
        "source_commit", "daemon_sha256", "unit_sha256", "cargo_lock_sha256",
        "runtime_depends", "pre_depends", "unit_source", "rustc_version",
    }
    if set(fields) != required:
        fail("build identity field allowlist mismatch")
    if fields["artifact_kind"] != "internal-structural-deb" or fields["install_ready"] != "false" or fields["package"] != PACKAGE:
        fail("build identity claims wrong kind/readiness/package")
    if not re.fullmatch(r"[0-9a-f]{40}", fields["source_commit"]):
        fail("malformed source commit")
    for key in ("daemon_sha256", "unit_sha256", "cargo_lock_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", fields[key]):
            fail(f"malformed {key}")
    return fields


def main(deb):
    here = Path(__file__).resolve().parent
    crate = here.parent.parent
    unit_source = crate / "systemd/sanctuary-castle-wall.service"
    guard_source = (here / "lifecycle-guard.py").read_bytes()
    control = archive(deb, "--ctrl-tarfile")
    payload = archive(deb, "--fsys-tarfile")
    check_members(control, CONTROL_FILES, set())
    check_members(payload, PAYLOAD_FILES, PAYLOAD_DIRS)
    identity = parse_identity(payload["usr/share/doc/sanctuary-castle-wall-internal/build-identity"][1])
    version = field(deb, "Version")
    if field(deb, "Package") != PACKAGE or field(deb, "Architecture") != "amd64" or identity["package_version"] != version:
        fail("package metadata/build identity mismatch")
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*-[1-9][0-9]*", version):
        fail("package version is not explicit increasing-revision form")
    if field(deb, "Pre-Depends") != "systemd, nftables, python3" or identity["pre_depends"] != "systemd, nftables, python3":
        fail("early probe dependency metadata mismatch")
    depends = field(deb, "Depends")
    depends_names = validate_runtime_depends(depends)
    identity_names = validate_runtime_depends(identity["runtime_depends"])
    if depends_names != identity_names:
        fail(f"runtime dependency metadata/build identity mismatch: {depends_names!r} != {identity_names!r}")
    daemon = payload["usr/local/libexec/sanctuary/castle-wall-daemon"][1]
    unit = payload["etc/systemd/system/sanctuary-castle-wall.service"][1]
    if hashlib.sha256(daemon).hexdigest() != identity["daemon_sha256"] or hashlib.sha256(unit).hexdigest() != identity["unit_sha256"]:
        fail("payload/build identity SHA mismatch")
    if unit != unit_source.read_bytes() or identity["unit_source"] != "castle-wall-daemon/systemd/sanctuary-castle-wall.service":
        fail("unit differs from exact source bytes")
    for role in ("preinst", "prerm"):
        expected = (
            "#!/usr/bin/python3\n"
            f'ROLE = "{role}"\n'
            f'PACKAGE_VERSION = "{version}"\n'
            f'DAEMON_SHA256 = "{identity["daemon_sha256"]}"\n'
            f'UNIT_SHA256 = "{identity["unit_sha256"]}"\n'
        ).encode() + guard_source
        if control[role][1] != expected:
            fail(f"{role} is not the exact source guard with bound constants")
    print("internal guarded package archive is structurally valid; no service action was run")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            fail("usage: assert-archive.py <deb>")
        main(Path(sys.argv[1]))
    except (ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"package structure refused: {exc}", file=sys.stderr)
        sys.exit(1)
