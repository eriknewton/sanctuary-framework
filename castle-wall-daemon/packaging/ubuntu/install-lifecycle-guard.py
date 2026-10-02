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


# This is the install-only guard. The internal guard remains independently
# closed. Install paths must match install-layout.py and the shared Rust contract.
# Low-level observation shapes retain the internal guard's fail-closed semantics.
PACKAGE = "sanctuary-castle-wall"
ARCHITECTURE = "amd64"
UNIT_NAME = "sanctuary-castle-wall.service"
# The agent template unit (slice B). Every agent rule below matches this exact
# prefix, so it covers `sanctuary-agent@<uid>.service` instances only; the
# cgroup-scope and stop-owner name grammars that share the stem are not shipped.
AGENT_UNIT_PREFIX = "sanctuary-agent@"
DAEMON_PATH = "/usr/local/libexec/sanctuary/castle-wall-daemon"
UNIT_PATH = "/etc/systemd/system/sanctuary-castle-wall.service"
AGENT_UNIT_PATH = "/etc/systemd/system/sanctuary-agent@.service"
IDENTITY_PATH = "/usr/share/doc/sanctuary-castle-wall/build-identity"
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
# Immutable inventory is supplied by build-install-deb.py, never by host state.
# Must match install-layout.py and src/linux_install/contract.rs.
PAYLOAD = tuple("/" + path for path in PAYLOAD_MODES)
MOUNT_NAME = r"var-lib-sanctuary\x2dagent\x2dworkspace.mount"
MOUNT_PATH = "/etc/systemd/system/" + MOUNT_NAME
WORKSPACE_PATH = "/var/lib/sanctuary-agent-workspace"
CONFIG_ROOT = "/etc/sanctuary"
# An agent instance in any of these states is a running or transitioning agent
# process; no package operation may proceed under it.
AGENT_BUSY_STATES = {"active", "activating", "deactivating", "reloading", "refreshing"}
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


def command_allow_empty(argv):
    """`command()`'s exact environment, timeout and output cap, but an empty
    stdout is a valid answer. Only for a probe whose "nothing matched" is
    naturally empty; a nonzero return still refuses (fail-closed). Exactly one
    caller, agent_instances_inactive, pinned by test-lifecycle-guard.py."""
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        refuse(f"probe unavailable: {argv[0]}: {exc}")
    if result.returncode != 0 or len(result.stdout) > 2_000_000:
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
    # Multiple links, non-root group, or privilege bits can change custody even
    # when content still hashes correctly; payload modes are an exact contract.
    expected_mode = PAYLOAD_MODES.get(str(path).lstrip("/"))
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or info.st_mode & 0o7022
            or (expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode)):
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
        # The internal variant is a different closed artifact, never an upgrade source.
        if fields.get("Package") == "sanctuary-castle-wall-internal":
            if fields.get("Status") != "deinstall ok not-installed" or fields.get("Version"):
                refuse("conflicting internal package footprint")
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
    raw = stable_read(IDENTITY_PATH, 64 * 1024)  # One bounded manifest, not host input history.
    # The executing hook binds identity bytes; an artifact boolean cannot choose
    # this guard's variant or authorize replacing installed files.
    if hashlib.sha256(raw).hexdigest() != IDENTITY_SHA256:
        refuse("installed identity differs from hook binding")
    try:
        identity = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        refuse("invalid install identity")
    if (identity.get("package") != PACKAGE or identity.get("artifact_kind") != "ubuntu-install-deb-v1"
            or identity.get("install_ready") is not True or identity.get("package_version") != PACKAGE_VERSION
            or identity.get("payload_sha256") != PAYLOAD_HASHES):
        refuse("wrong install identity")
    return identity


def hash_file(path):
    return hashlib.sha256(stable_read(path, 100_000_000)).hexdigest()


def installed_identity(fields, phase):
    identity = build_identity()
    if fields.get("Architecture") != ARCHITECTURE or fields.get("Version") != PACKAGE_VERSION:
        refuse("installed package/version identity mismatch")
    for path, digest in PAYLOAD_HASHES.items():
        if hash_file("/" + path) != digest:
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
                relevant = name in (UNIT_NAME, UNIT_NAME + ".d", MOUNT_NAME, MOUNT_NAME + ".d")
                # Generic drop-ins also affect effective units without sharing
                # their full names, so the install lifecycle admits none.
                if name in ("service.d", "mount.d", "sanctuary-.service.d"):
                    refuse(f"inherited unit drop-in: {path}")
                # Agent rules: the package's template is the ONLY entry named
                # `sanctuary-agent@...` allowed anywhere. A template or instance
                # drop-in directory, an alternate fragment or an instance
                # enablement symlink would change what the agent unit runs, or
                # start it at boot. BOUND: the prefix drop-in
                # `sanctuary-.service.d/` and the top-level `service.d/` also
                # apply to agent instances and are NOT refused here; host
                # acceptance checks the unit's DropInPaths instead (README).
                if name.startswith(AGENT_UNIT_PREFIX) and path != AGENT_UNIT_PATH:
                    if name.endswith(".service.d"):
                        refuse(f"agent unit drop-in directory present: {path}")
                    refuse(f"alternate agent unit, alias or instance enablement: {path}")
                if stat.S_ISLNK(info.st_mode):
                    # os.walk will not follow this directory, so it cannot
                    # establish that an alias is absent beneath it.
                    if name in dirs:
                        refuse(f"symlinked systemd directory: {path}")
                    try:
                        target = os.readlink(path)
                    except OSError:
                        refuse("unreadable systemd symlink")
                    if relevant or UNIT_NAME in target or MOUNT_NAME in target or os.path.realpath(path) in (UNIT_PATH, MOUNT_PATH):
                        refuse(f"systemd alias or enablement symlink: {path}")
                    if AGENT_UNIT_PREFIX in target:
                        refuse(f"agent unit alias or enablement symlink: {path}")
                elif name in dirs and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                    refuse(f"unsafe systemd directory: {path}")
                elif relevant and path not in (UNIT_PATH, MOUNT_PATH):
                    refuse(f"alternate systemd unit or drop-in: {path}")
            if directory == root and UNIT_NAME + ".d" in dirs:
                refuse("unit drop-in directory present")
    if not installed and lstat(UNIT_PATH) is not None:
        refuse("unit still exists on disk")
    if not installed and lstat(AGENT_UNIT_PATH) is not None:
        refuse("agent unit still exists on disk")


def systemd_manager(installed, unit_name=UNIT_NAME, unit_path=UNIT_PATH):
    try:
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            refuse("systemd is not PID 1")
    except OSError:
        refuse("cannot verify systemd PID 1")
    properties = ("Id", "Names", "Following", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "Job", "NeedDaemonReload")
    output = command(["/usr/bin/systemctl", "show", unit_name, "--no-pager", "--all", "--property=" + ",".join(properties)])
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
    if fields["Id"] not in ("", unit_name) or fields["Names"] not in ("", unit_name) or fields["Following"] or fields["DropInPaths"] or fields["Job"] not in ("", "0"):
        refuse("unit aliases, drop-ins or jobs present")
    if fields["ActiveState"] != "inactive" or fields["SubState"] != "dead":
        refuse("unit not positively inactive")
    if fields["NeedDaemonReload"] not in ("yes", "no"):
        refuse("unknown daemon-reload state")
    if installed:
        if fields["LoadState"] not in ("loaded", "not-found") or fields["UnitFileState"] != ("static" if unit_name == MOUNT_NAME else "disabled") or fields["FragmentPath"] not in ("", unit_path):
            refuse("installed unit not exact, inert and disabled")
        if fields["LoadState"] == "loaded" and fields["FragmentPath"] != unit_path:
            refuse("loaded unit fragment is not package path")
        if fields["LoadState"] == "not-found" and fields["FragmentPath"]:
            refuse("not-found manager unit reports a fragment")
    elif fields["LoadState"] != "not-found" or fields["FragmentPath"] or fields["UnitFileState"] not in ("", "not-found") or fields["NeedDaemonReload"] != "no":
        refuse("fresh unit is still effective or stale")
    return fields


def agent_instances_inactive():
    """No loaded agent instance may be running or transitioning. Empty output
    with return code 0 means no instance is loaded (systemd 255 prints nothing
    for a pattern with no match); a nonzero return refuses."""
    output = command_allow_empty(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend",
                                  "--full", "--no-pager", AGENT_UNIT_PREFIX + "*.service"])
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 4 or not re.fullmatch(r"sanctuary-agent@[^ ]+\.service", fields[0]):
            refuse("unparseable agent instance listing")
        if fields[2] in AGENT_BUSY_STATES:
            refuse(f"agent instance not inactive: {fields[0]} {fields[2]}")


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


def mount_absent():
    # A stopped service is insufficient: a retained mount can still expose agent state.
    raw = stable_read("/proc/self/mountinfo", 2_000_000).decode("utf-8")
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 10 or "-" not in parts:
            refuse("incomplete mount inventory")
        if parts[4] == WORKSPACE_PATH or parts[4].startswith(WORKSPACE_PATH + "/"):
            refuse("agent workspace mounted")


def runtime_absent():
    for root in (CONFIG_ROOT, STATE_ROOT, RUN_ROOT):
        empty_runtime_root(root)
    # Even an empty workspace is provisioner-owned state; removal is unsupported.
    if lstat(WORKSPACE_PATH) is not None:
        refuse("agent workspace footprint present")
    mount_absent()


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
    agent_instances_inactive()
    mount_first = systemd_manager(installed, MOUNT_NAME, MOUNT_PATH)
    no_queued_jobs()
    runtime_absent()
    nft_absent()
    # A second complete read catches ordinary observation churn. The manager
    # may cache an inert unit merely because the first show queried it, so only
    # LoadState/FragmentPath may make the documented not-found→loaded change.
    systemd_files(installed)
    manager_second = systemd_manager(installed)
    agent_instances_inactive()
    mount_second = systemd_manager(installed, MOUNT_NAME, MOUNT_PATH)
    no_queued_jobs()
    if mount_first != mount_second:
        refuse("mount manager state changed during observation")
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


def no_queued_jobs():
    output = command_allow_empty(["/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager", "--full"])
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 4 or not parts[0].isdecimal():
            refuse("unparseable manager jobs")
        if parts[1] in (UNIT_NAME, MOUNT_NAME) or parts[1].startswith(AGENT_UNIT_PREFIX):
            refuse("product manager job queued")


def main(argv):
    if os.geteuid() != 0:
        refuse("package guard requires root")
    # Abort unwinds no product action because hooks never mutate host state.
    if ROLE == "preinst" and len(argv) == 2 and argv[0] == "abort-upgrade":
        return
    if ROLE == "preinst" and argv == ["install"]:
        inspect(False, "install")
        return
    if ROLE == "prerm" and argv == ["remove"]:
        inspect(True, "remove", PACKAGE_VERSION)
        return
    # A cold-install-only artifact must also veto dpkg's failed-upgrade fallback.
    refuse("unsupported install-package lifecycle action")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refusal as exc:
        print(f"Castle Wall package guard refused: {exc}", file=sys.stderr)
        sys.exit(1)
