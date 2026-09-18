"""Source template embedded verbatim in each generated Debian maintainer script.

The generated preinst/prerm add a shebang and immutable package constants above
this file. This template is never shipped as a payload file or imported from a
mutable checkout on the target host.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


PACKAGE = "sanctuary-castle-wall-internal"
ARCHITECTURE = "amd64"
UNIT_NAME = "sanctuary-castle-wall.service"
DAEMON_PATH = "/usr/local/libexec/sanctuary/castle-wall-daemon"
UNIT_PATH = "/etc/systemd/system/sanctuary-castle-wall.service"
IDENTITY_PATH = "/usr/share/doc/sanctuary-castle-wall-internal/build-identity"
ENV_PATH = "/etc/sanctuary/castle-wall.env"
STATE_ROOT = "/var/lib/sanctuary"
RUN_ROOT = "/run/sanctuary"
JOURNAL_PATH = "/var/lib/sanctuary/nft-ownership.json"
AUTH_KEY_PATH = "/var/lib/sanctuary/nft-journal-auth.key"
HOST_LOCK_PATH = "/var/lib/sanctuary/castle-wall.nft.lock"
NFT_FAMILY = "inet"
NFT_TABLE = "sanctuary-castle"
STATUS_PATH = "/var/lib/dpkg/status"
INFO_PATH = "/var/lib/dpkg/info"
PAYLOAD = (DAEMON_PATH, UNIT_PATH, IDENTITY_PATH)
SYSTEMD_ROOTS = (
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/run/systemd/system", "/run/systemd/system.attached",
    "/run/systemd/generator", "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system", "/run/systemd/generator.late",
)
STATUS_WANTS = {"install", "deinstall", "purge"}


class Refusal(Exception):
    pass


def refuse(reason):
    raise Refusal(reason)


def command(argv):
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        refuse(f"probe unavailable: {argv[0]}: {exc}")
    if result.returncode != 0 or not result.stdout or len(result.stdout) > 2_000_000:
        refuse(f"probe failed or incomplete: {argv[0]}")
    return result.stdout


def lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        refuse(f"cannot inspect {path}: {exc}")


def check_ancestors(path):
    current = Path(path)
    for parent in reversed(current.parents):
        if str(parent) == "/":
            continue
        info = lstat(parent)
        if info is None:
            return False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse(f"unsafe path ancestor: {parent}")
    return True


def checked_file(path, required):
    ancestors_exist = check_ancestors(path)
    info = lstat(path) if ancestors_exist else None
    if info is None:
        if required:
            refuse(f"required package file absent: {path}")
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        refuse(f"unsafe package file: {path}")
    if path == DAEMON_PATH and not info.st_mode & 0o111:
        refuse("installed daemon is not executable")
    return info


def stable_read(path, limit=2_000_000):
    try:
        before = os.stat(path, follow_symlinks=False)
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        refuse(f"cannot read {path}: {exc}")
    if len(data) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        refuse(f"unstable or oversized file: {path}")
    return data


def dpkg_status():
    checked_file(STATUS_PATH, True)
    first = stable_read(STATUS_PATH, 40_000_000)
    if first != stable_read(STATUS_PATH, 40_000_000):
        refuse("dpkg status changed during observation")
    try:
        text = first.decode("utf-8")
    except UnicodeDecodeError:
        refuse("dpkg status is not UTF-8")
    matches = []
    for stanza in text.split("\n\n"):
        if not stanza.strip():
            continue
        fields = {}
        seen_names = set()
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                if not fields:
                    refuse("orphan dpkg continuation line")
                continue
            if ":" not in line:
                refuse("malformed dpkg status line")
            key, suffix = line.split(":", 1)
            # Debian Policy 5.1 permits ASCII graphic field names other than
            # colon, with neither '#' nor '-' in the first position.
            if (not key or key[0] in "#-" or
                    any(not (33 <= ord(char) <= 126) or char == ":" for char in key)):
                refuse("malformed dpkg field name")
            folded = key.lower()
            if folded in seen_names:
                refuse("duplicate or malformed dpkg field")
            seen_names.add(folded)
            canonical = {"package": "Package", "status": "Status", "version": "Version",
                         "architecture": "Architecture"}.get(folded, key)
            fields[canonical] = suffix.lstrip(" \t").rstrip(" \t")
        if not fields.get("Package") or not fields.get("Status"):
            refuse("incomplete dpkg status stanza")
        if fields.get("Package") == PACKAGE:
            matches.append(fields)
    if len(matches) > 1:
        refuse("duplicate package status stanzas")
    if not matches:
        return None
    fields = matches[0]
    parts = fields.get("Status", "").split()
    if len(parts) != 3 or parts[0] not in STATUS_WANTS or parts[1] != "ok":
        refuse("unadmitted dpkg status selection/error")
    if fields.get("Architecture") not in (ARCHITECTURE, None):
        refuse("unexpected package architecture")
    return fields, parts


def package_owners():
    if not check_ancestors(INFO_PATH):
        refuse("dpkg info directory absent")
    info = lstat(INFO_PATH)
    if info is None or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        refuse("unsafe dpkg info directory")
    owners = {path: set() for path in PAYLOAD}
    try:
        entries = list(os.scandir(INFO_PATH))
    except OSError as exc:
        refuse(f"cannot list dpkg info directory: {exc}")
    if len(entries) > 100_000:
        refuse("dpkg info directory exceeds inventory bound")
    for entry in entries:
        if not entry.name.endswith(".list"):
            continue
        checked_file(entry.path, True)
        content = stable_read(entry.path, 10_000_000)
        try:
            lines = content.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            refuse("non-UTF-8 dpkg ownership list")
        owner = entry.name[:-5]
        for line in lines:
            if line in owners:
                owners[line].add(owner)
    return owners


def require_owners(owners, installed):
    for path, found in owners.items():
        expected = {PACKAGE, f"{PACKAGE}:{ARCHITECTURE}"}
        if installed:
            if len(found) != 1 or not found <= expected:
                refuse(f"package leaf not solely owned by expected package: {path}")
        elif found:
            refuse(f"absent package leaf still dpkg-owned: {path}")


def build_identity():
    checked_file(IDENTITY_PATH, True)
    try:
        lines = stable_read(IDENTITY_PATH, 10_000).decode("ascii").splitlines()
    except UnicodeDecodeError:
        refuse("non-ASCII build identity")
    fields = {}
    for line in lines:
        if "=" not in line:
            refuse("malformed build identity")
        key, value = line.split("=", 1)
        if not key or key in fields or "\x00" in value:
            refuse("duplicate or malformed build identity field")
        fields[key] = value
    required = {"artifact_kind", "install_ready", "package", "package_version", "source_commit", "daemon_sha256", "unit_sha256"}
    if not required <= fields.keys() or fields["artifact_kind"] != "internal-structural-deb" or fields["install_ready"] != "false" or fields["package"] != PACKAGE:
        refuse("unbound build identity")
    if not re.fullmatch(r"[0-9a-f]{40}", fields["source_commit"]):
        refuse("malformed source identity")
    for key in ("daemon_sha256", "unit_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", fields[key]):
            refuse("malformed payload hash")
    return fields


def hash_file(path):
    return hashlib.sha256(stable_read(path, 100_000_000)).hexdigest()


def installed_identity(fields, phase):
    identity = build_identity()
    if fields.get("Architecture") != ARCHITECTURE or not fields.get("Version") or identity["package_version"] != fields["Version"]:
        refuse("installed package/version identity mismatch")
    if phase == "prerm" and (identity["package_version"] != PACKAGE_VERSION or identity["daemon_sha256"] != DAEMON_SHA256 or identity["unit_sha256"] != UNIT_SHA256):
        refuse("old hook does not match installed payload identity")
    if hash_file(DAEMON_PATH) != identity["daemon_sha256"] or hash_file(UNIT_PATH) != identity["unit_sha256"]:
        refuse("installed payload differs from bound identity")
    return identity


def systemd_files(installed):
    # The running manager may have a different UnitPath from the compiled
    # default. Accept only paths this bounded inventory actually traverses.
    manager_paths = command(["/usr/bin/systemctl", "show", "--property=UnitPath",
                             "--value", "--no-pager"]).split()
    if not manager_paths or len(manager_paths) > len(SYSTEMD_ROOTS) + 1 or len(set(manager_paths)) != len(manager_paths):
        refuse("incomplete or duplicate systemd manager UnitPath")
    for path in manager_paths:
        if path == "/lib/systemd/system":
            if os.path.realpath(path) != "/usr/lib/systemd/system":
                refuse("unsupported systemd manager UnitPath alias")
            path = "/usr/lib/systemd/system"
        if path not in SYSTEMD_ROOTS:
            refuse(f"unsupported systemd manager UnitPath: {path}")
    seen = set()
    for root in SYSTEMD_ROOTS:
        if root in seen:
            continue
        seen.add(root)
        if not check_ancestors(root):
            continue
        root_info = lstat(root)
        if root_info is None:
            continue
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o022:
            refuse(f"unsafe systemd unit root: {root}")
        count = 0
        def walk_error(exc):
            refuse(f"unreadable systemd unit tree: {exc}")

        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            directory_info = lstat(directory)
            if (directory_info is None or not stat.S_ISDIR(directory_info.st_mode)
                    or directory_info.st_uid != 0 or directory_info.st_mode & 0o022):
                refuse(f"unsafe traversed systemd directory: {directory}")
            count += len(dirs) + len(files)
            if count > 100_000:
                refuse("systemd unit inventory exceeds bound")
            for name in dirs + files:
                path = os.path.join(directory, name)
                info = lstat(path)
                if info is None:
                    refuse("systemd path changed during inventory")
                relevant = name == UNIT_NAME or name == UNIT_NAME + ".d"
                if stat.S_ISLNK(info.st_mode):
                    # os.walk will not follow this directory, so it cannot
                    # establish that an alias is absent beneath it.
                    if name in dirs:
                        refuse(f"symlinked systemd directory: {path}")
                    try:
                        target = os.readlink(path)
                    except OSError:
                        refuse("unreadable systemd symlink")
                    if relevant or UNIT_NAME in target or os.path.realpath(path) == UNIT_PATH:
                        refuse(f"systemd alias or enablement symlink: {path}")
                elif name in dirs and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                    refuse(f"unsafe systemd directory: {path}")
                elif relevant and path != UNIT_PATH:
                    refuse(f"alternate systemd unit or drop-in: {path}")
            if directory == root and UNIT_NAME + ".d" in dirs:
                refuse("unit drop-in directory present")
    if not installed and lstat(UNIT_PATH) is not None:
        refuse("unit still exists on disk")


def systemd_manager(installed):
    try:
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            refuse("systemd is not PID 1")
    except OSError:
        refuse("cannot verify systemd PID 1")
    properties = ("Id", "Names", "Following", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "Job", "NeedDaemonReload")
    output = command(["/usr/bin/systemctl", "show", UNIT_NAME, "--no-pager", "--all", "--property=" + ",".join(properties)])
    fields = {}
    for line in output.splitlines():
        if "=" not in line:
            refuse("malformed systemctl output")
        key, value = line.split("=", 1)
        if key not in properties or key in fields:
            refuse("unexpected systemctl output")
        fields[key] = value
    if set(fields) != set(properties):
        refuse("incomplete systemctl output")
    if fields["Id"] not in ("", UNIT_NAME) or fields["Names"] not in ("", UNIT_NAME) or fields["Following"] or fields["DropInPaths"] or fields["Job"] not in ("", "0"):
        refuse("unit aliases, drop-ins or jobs present")
    if fields["ActiveState"] != "inactive" or fields["SubState"] != "dead":
        refuse("unit not positively inactive")
    if fields["NeedDaemonReload"] not in ("yes", "no"):
        refuse("unknown daemon-reload state")
    if installed:
        if fields["LoadState"] not in ("loaded", "not-found") or fields["UnitFileState"] != "disabled" or fields["FragmentPath"] not in ("", UNIT_PATH):
            refuse("installed unit not exact, inert and disabled")
        if fields["LoadState"] == "loaded" and fields["FragmentPath"] != UNIT_PATH:
            refuse("loaded unit fragment is not package path")
        if fields["LoadState"] == "not-found" and fields["FragmentPath"]:
            refuse("not-found manager unit reports a fragment")
    elif fields["LoadState"] != "not-found" or fields["FragmentPath"] or fields["UnitFileState"] not in ("", "not-found") or fields["NeedDaemonReload"] != "no":
        refuse("fresh unit is still effective or stale")
    return fields


def empty_runtime_root(path):
    if not check_ancestors(path):
        return
    info = lstat(path)
    if info is None:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        refuse(f"unsafe runtime root: {path}")
    try:
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                refuse(f"runtime/config entry present under {path}")
    except OSError as exc:
        refuse(f"unreadable runtime root {path}: {exc}")


def runtime_absent():
    checked_file(ENV_PATH, False)
    if lstat(ENV_PATH) is not None:
        refuse("Castle Wall environment present")
    empty_runtime_root(STATE_ROOT)
    empty_runtime_root(RUN_ROOT)


def nft_absent():
    executable = "/usr/sbin/nft" if os.access("/usr/sbin/nft", os.X_OK) else "/usr/bin/nft"
    output = command([executable, "-j", "list", "tables"])
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        refuse("malformed nft JSON")
    if not isinstance(parsed, dict) or not isinstance(parsed.get("nftables"), list):
        refuse("incomplete nft table inventory")
    for item in parsed["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            refuse("unexpected nft table inventory item")
        if "metainfo" in item:
            continue
        table = item.get("table")
        if not isinstance(table, dict) or not isinstance(table.get("family"), str) or not isinstance(table.get("name"), str):
            refuse("malformed nft table entry")
        if table["family"] == NFT_FAMILY and table["name"] == NFT_TABLE:
            refuse("Castle Wall nft table exists")


def version_is_newer(old, new):
    try:
        result = subprocess.run(["/usr/bin/dpkg", "--compare-versions", old, "lt", new], timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        refuse("dpkg version comparison unavailable")
    if result.returncode == 1:
        refuse("target package version is not newer")
    if result.returncode != 0:
        refuse("dpkg version comparison failed")


def inspect(installed, phase, expected_old=None):
    status = dpkg_status()
    owners = package_owners()
    if installed:
        if status is None:
            refuse("installed package status absent")
        fields, parts = status
        if parts[2] != "installed" or (phase != "remove" and parts[0] != "install"):
            refuse("installed package not in admitted dpkg state")
        if expected_old is not None and fields.get("Version") != expected_old:
            refuse("old version argument does not match dpkg")
        for path in PAYLOAD:
            checked_file(path, True)
        require_owners(owners, True)
        identity = installed_identity(fields, "prerm" if ROLE == "prerm" else "preinst")
    else:
        if status is not None:
            fields, parts = status
            if parts[2] != "not-installed" or fields.get("Version"):
                refuse("package status not positively absent")
        for path in PAYLOAD:
            checked_file(path, False)
            if lstat(path) is not None:
                refuse(f"package payload already exists: {path}")
        require_owners(owners, False)
        identity = None
    systemd_files(installed)
    manager_first = systemd_manager(installed)
    runtime_absent()
    nft_absent()
    # A second complete read catches ordinary observation churn. The manager
    # may cache an inert unit merely because the first show queried it, so only
    # LoadState/FragmentPath may make the documented not-found→loaded change.
    systemd_files(installed)
    manager_second = systemd_manager(installed)
    stable_keys = set(manager_first) - {"LoadState", "FragmentPath"}
    if any(manager_first[key] != manager_second[key] for key in stable_keys):
        refuse("systemd manager state changed during observation")
    runtime_absent()
    nft_absent()
    if dpkg_status() != status:
        refuse("dpkg package status changed during observation")
    if package_owners() != owners:
        refuse("dpkg ownership changed during observation")
    return identity


def main(argv):
    if os.geteuid() != 0:
        refuse("package guard requires root")
    if ROLE == "preinst" and argv and argv[0] == "abort-upgrade":
        if len(argv) != 2:
            refuse("unsupported abort-upgrade arguments")
        return
    if ROLE == "prerm" and argv and argv[0] == "failed-upgrade":
        refuse("failed-upgrade veto")
    if ROLE == "preinst" and argv == ["install"]:
        inspect(False, "install")
        return
    if ROLE == "preinst" and len(argv) == 3 and argv[0] == "upgrade":
        if argv[2] != PACKAGE_VERSION:
            refuse("incoming package version argument mismatch")
        version_is_newer(argv[1], argv[2])
        inspect(True, "upgrade", argv[1])
        return
    if ROLE == "prerm" and len(argv) == 2 and argv[0] == "upgrade":
        version_is_newer(PACKAGE_VERSION, argv[1])
        inspect(True, "upgrade", PACKAGE_VERSION)
        return
    if ROLE == "prerm" and argv == ["remove"]:
        inspect(True, "remove", PACKAGE_VERSION)
        return
    refuse("unsupported maintainer-script action")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refusal as exc:
        print(f"Castle Wall package guard refused: {exc}", file=sys.stderr)
        sys.exit(1)
