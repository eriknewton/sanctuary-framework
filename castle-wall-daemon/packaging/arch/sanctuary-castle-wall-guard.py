"""Template embedded in the Arch libalpm guard.

The generated package prepends immutable constants above this file. The guard is
read-only: hooks may admit or refuse a transaction, never mutate host state.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


PACKAGE = "sanctuary-castle-wall"
IDENTITY_PATH = "/usr/share/doc/sanctuary-castle-wall/build-identity"
GUARD_PATH = "/usr/share/libalpm/scripts/sanctuary-castle-wall-guard"
UNIT_NAME = "sanctuary-castle-wall.service"
AGENT_UNIT_PREFIX = "sanctuary-agent@"
UNIT_PATH = "/etc/systemd/system/sanctuary-castle-wall.service"
AGENT_UNIT_PATH = "/etc/systemd/system/sanctuary-agent@.service"
MOUNT_NAME = r"var-lib-sanctuary\x2dagent\x2dworkspace.mount"
MOUNT_PATH = "/etc/systemd/system/" + MOUNT_NAME
WORKSPACE_PATH = "/var/lib/sanctuary-agent-workspace"
CONFIG_ROOT = "/etc/sanctuary"
STATE_ROOT = "/var/lib/sanctuary"
RUN_ROOT = "/run/sanctuary"
NFT_FAMILY = "inet"
NFT_TABLE = "sanctuary-castle"
OBSERVATION_SECONDS = 15
OBSERVATION_BYTES = 2_000_000
PAYLOAD_BYTES = 100_000_000
INVENTORY_ENTRIES = 100_000
NSS_ROWS = 4_096
SYSTEMD_ROOTS = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/generator.late",
)


class Refusal(Exception):
    pass


def refuse(reason: str) -> None:
    raise Refusal(reason)


def bounded_capture(argv, *, timeout, limit, env=None):
    # Draining both streams with one combined cap bounds hostile probe output;
    # a timeout by itself does not bound memory.
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 0)
            selector.register(child.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("probe capture deadline exceeded")
                for key, _ in selector.select(remaining):
                    room = limit + 1 - sum(map(len, output))
                    chunk = os.read(key.fileobj.fileno(), min(64 * 1024, room))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        if sum(map(len, output)) > limit:
                            raise ValueError("probe capture output cap exceeded")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("probe capture deadline exceeded")
            if hasattr(os, "waitid"):
                while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("probe capture deadline exceeded")
                    time.sleep(min(0.01, remaining))  # 0.01s bounds readiness polling latency.
            else:
                child.wait(timeout=remaining)
    finally:
        if child.returncode is None:
            try:
                if sys.platform == "linux":
                    os.killpg(child.pid, signal.SIGKILL)
                elif child.poll() is None:
                    child.kill()
            except ProcessLookupError:
                pass
        try:
            child.wait(timeout=1)  # One second beyond the observation deadline.
        finally:
            child.stdout.close()
            child.stderr.close()
    return child.returncode, bytes(output[0]), bytes(output[1])


def probe(argv, allow_empty=False):
    try:
        status, raw, error = bounded_capture(
            argv,
            timeout=OBSERVATION_SECONDS,
            limit=OBSERVATION_BYTES,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        refuse(f"probe unavailable: {argv[0]}: {exc}")
    output = raw.decode("utf-8", "strict")
    if status != 0 or error or (not allow_empty and not output):
        refuse(f"probe failed or incomplete: {argv[0]}")
    return output


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
        info = lstat(str(parent))
        if info is None:
            return False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse(f"unsafe path ancestor: {parent}")
    return True


def stable_read(path, limit=OBSERVATION_BYTES):
    descriptor = None
    try:
        # The descriptor pins one inode; otherwise a rename race can make a
        # correct hash describe bytes no longer named by the package path.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            refuse(f"non-regular read input: {path}")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        named = os.stat(path, follow_symlinks=False)

        def snapshot(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_nlink,
            )

        if len(data) > limit or snapshot(before) != snapshot(after) or snapshot(after) != snapshot(named):
            refuse(f"unstable or oversized file: {path}")
        return data
    except (OSError, UnicodeDecodeError) as exc:
        refuse(f"cannot read {path}: {exc}")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def checked_payload_path(relpath, required):
    path = "/" + relpath
    ancestors_exist = check_ancestors(path)
    info = lstat(path) if ancestors_exist else None
    if info is None:
        if required:
            refuse(f"required package path absent: {path}")
        return None
    mode = PAYLOAD_MODES.get(relpath)
    if relpath == "var/lib/sanctuary-agent-workspace":
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o755):
            refuse("unsafe underlying workspace directory")
        return info
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o7022
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
    ):
        refuse(f"unsafe package file: {path}")
    return info


def package_query():
    output = probe(["/usr/bin/pacman", "-Q", PACKAGE])
    parts = output.strip().split()
    if parts != [PACKAGE, PACKAGE_VERSION]:
        refuse("installed package/version identity mismatch")


def package_integrity():
    # pacman -Qkk is the Arch package database witness for leaves this guard
    # does not hash directly, including the guard file executing now.
    output = probe(["/usr/bin/pacman", "-Qkk", PACKAGE])
    if "0 altered files" not in output:
        refuse("pacman package integrity is not clean")


def package_owner(relpath):
    output = probe(["/usr/bin/pacman", "-Qo", "--", "/" + relpath])
    if f" is owned by {PACKAGE} {PACKAGE_VERSION}" not in output:
        refuse(f"package path not owned by expected package: /{relpath}")


def build_identity():
    checked_payload_path(IDENTITY_PATH.lstrip("/"), True)
    raw = stable_read(IDENTITY_PATH, 64 * 1024)  # 64 KiB is a bounded package manifest, not host history.
    if hashlib.sha256(raw).hexdigest() != IDENTITY_SHA256:
        refuse("installed identity differs from hook binding")
    try:
        identity = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        refuse("invalid Arch install identity")
    if (
        identity.get("artifact_kind") != "arch-install-pkg-v1"
        or identity.get("package") != PACKAGE
        or identity.get("package_version") != PACKAGE_VERSION
        or identity.get("payload_sha256") != PAYLOAD_HASHES
        or "guard_sha256" in identity
    ):
        refuse("wrong Arch install identity")
    return identity


def hash_file(relpath):
    return hashlib.sha256(stable_read("/" + relpath, PAYLOAD_BYTES)).hexdigest()


def installed_identity():
    identity = build_identity()
    for relpath in sorted(PAYLOAD_MODES):
        checked_payload_path(relpath, True)
        package_owner(relpath)
    for relpath, digest in PAYLOAD_HASHES.items():
        if hash_file(relpath) != digest:
            refuse(f"installed payload differs from bound identity: /{relpath}")
    return identity


def systemd_files():
    manager_paths = probe(["/usr/bin/systemctl", "show", "--property=UnitPath", "--value", "--no-pager"]).split()
    if not manager_paths or len(manager_paths) > len(SYSTEMD_ROOTS) + 1 or len(set(manager_paths)) != len(manager_paths):
        refuse("incomplete or duplicate systemd manager UnitPath")
    for path in manager_paths:
        if path == "/lib/systemd/system":
            if os.path.realpath(path) != "/usr/lib/systemd/system":
                refuse("unsupported systemd manager UnitPath alias")
            path = "/usr/lib/systemd/system"
        if path not in SYSTEMD_ROOTS:
            refuse(f"unsupported systemd manager UnitPath: {path}")
    for root in SYSTEMD_ROOTS:
        if not check_ancestors(root):
            continue
        info = lstat(root)
        if info is None:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            refuse(f"unsafe systemd unit root: {root}")
        count = 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            directory_info = lstat(directory)
            if directory_info is None or not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or directory_info.st_mode & 0o022:
                refuse(f"unsafe traversed systemd directory: {directory}")
            count += len(dirs) + len(files)
            if count > INVENTORY_ENTRIES:
                refuse("systemd unit inventory exceeds bound")
            for name in dirs + files:
                path = os.path.join(directory, name)
                info = lstat(path)
                if info is None:
                    refuse("systemd path changed during inventory")
                relevant = name.startswith(("sanctuary-castle-wall.", MOUNT_NAME, AGENT_UNIT_PREFIX))
                if name in ("service.d", "mount.d", "sanctuary-.service.d", "sanctuary-castle-.service.d", "var-.mount.d", "var-lib-.mount.d"):
                    refuse(f"inherited unit drop-in: {path}")
                if name.startswith(AGENT_UNIT_PREFIX) and path != AGENT_UNIT_PATH:
                    if name.endswith(".service.d"):
                        refuse(f"agent unit drop-in directory present: {path}")
                    refuse(f"alternate agent unit, alias or instance enablement: {path}")
                if stat.S_ISLNK(info.st_mode):
                    if name in dirs:
                        refuse(f"symlinked systemd directory: {path}")
                    try:
                        target = os.readlink(path)
                    except OSError:
                        refuse("unreadable systemd symlink")
                    if relevant or "sanctuary-castle-wall." in target or MOUNT_NAME in target or os.path.realpath(path) in (UNIT_PATH, MOUNT_PATH, AGENT_UNIT_PATH):
                        refuse(f"systemd alias or enablement symlink: {path}")
                    if AGENT_UNIT_PREFIX in target:
                        refuse(f"agent unit alias or enablement symlink: {path}")
                elif name in dirs and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                    refuse(f"unsafe systemd directory: {path}")
                elif relevant and path not in (UNIT_PATH, MOUNT_PATH, AGENT_UNIT_PATH):
                    refuse(f"alternate systemd unit or drop-in: {path}")
            if directory == root and UNIT_NAME + ".d" in dirs:
                refuse("unit drop-in directory present")


def systemd_manager(unit_name=UNIT_NAME, unit_path=UNIT_PATH):
    try:
        if Path("/proc/1/comm").read_text().strip() != "systemd":
            refuse("systemd is not PID 1")
    except OSError:
        refuse("cannot verify systemd PID 1")
    properties = ("Id", "Names", "Following", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "Job", "NeedDaemonReload")
    output = probe(["/usr/bin/systemctl", "show", unit_name, "--no-pager", "--all", "--property=" + ",".join(properties)])
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
    expected_names = json.dumps(unit_name) if "\\" in unit_name else unit_name
    if fields["Id"] not in ("", unit_name) or fields["Names"] not in ("", expected_names) or fields["Following"] or fields["DropInPaths"] or fields["Job"] not in ("", "0"):
        refuse("unit aliases, drop-ins or jobs present")
    if fields["ActiveState"] != "inactive" or fields["SubState"] != "dead":
        refuse("unit not positively inactive")
    expected_file_state = "static" if unit_name == MOUNT_NAME else "disabled"
    if fields["LoadState"] not in ("loaded", "not-found") or fields["UnitFileState"] != expected_file_state or fields["FragmentPath"] not in ("", unit_path):
        refuse("installed unit not exact, inert and disabled")
    if fields["LoadState"] == "loaded" and fields["FragmentPath"] != unit_path:
        refuse("loaded unit fragment is not package path")
    return fields


def no_queued_jobs():
    output = probe(["/usr/bin/systemctl", "list-jobs", "--no-legend", "--no-pager", "--full"], allow_empty=True)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 4 or not parts[0].isdecimal():
            refuse("unparseable manager jobs")
        if parts[1] in (UNIT_NAME, MOUNT_NAME) or parts[1].startswith(AGENT_UNIT_PREFIX):
            refuse("product manager job queued")


def agent_instances_inactive():
    output = probe(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--full", "--no-pager", AGENT_UNIT_PREFIX + "*.service"], allow_empty=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].startswith(AGENT_UNIT_PREFIX) or not fields[0].endswith(".service"):
            refuse("unparseable agent instance listing")
        if fields[2:4] != ["inactive", "dead"]:
            refuse(f"agent instance not positively inactive: {fields[0]} {fields[2]}")


def accounts_absent():
    for database, width in (("passwd", 7), ("group", 4)):
        text = probe(["/usr/bin/getent", database], allow_empty=True)
        if text and not text.endswith("\n"):
            refuse("incomplete NSS inventory")
        rows = text.splitlines()
        if len(rows) > NSS_ROWS:
            refuse("NSS inventory exceeds quota")
        for line in rows:
            fields = line.split(":")
            if len(fields) != width:
                refuse("malformed NSS inventory")
            if fields[0] == "sanctuary" or fields[0].startswith("sanctuary-agent-"):
                refuse("product account footprint present")
    try:
        status, raw, error = bounded_capture(
            ["/usr/bin/getent", "group", "sanctuary"],
            timeout=OBSERVATION_SECONDS,
            limit=64 * 1024,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        refuse(f"account observation unavailable: {exc}")
    if status != 2 or raw or error:
        refuse("product group exists or NSS absence is unavailable")


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
    raw = stable_read("/proc/self/mountinfo", OBSERVATION_BYTES).decode("utf-8")
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 10 or "-" not in parts:
            refuse("incomplete mount inventory")
        if parts[4] == WORKSPACE_PATH or parts[4].startswith(WORKSPACE_PATH + "/"):
            refuse("agent workspace mounted")


def nft_absent():
    output = probe(["/usr/bin/nft", "-j", "list", "tables"])
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


def runtime_absent():
    accounts_absent()
    for parent in ("/var/lib", "/run"):
        try:
            with os.scandir(parent) as entries:
                for count, entry in enumerate(entries):
                    if count >= 10_000:  # Fixed upper bound on each host-root inventory.
                        refuse("legacy state inventory exceeds bound")
                    if entry.name.startswith("sanctuary-agent-") and entry.path != WORKSPACE_PATH:
                        refuse("legacy agent state footprint present")
        except OSError as exc:
            refuse(f"legacy state inventory unavailable: {exc}")
    for root in (CONFIG_ROOT, STATE_ROOT, RUN_ROOT, WORKSPACE_PATH):
        empty_runtime_root(root)
    mount_absent()
    nft_absent()


def state_UPGRADE():
    # The upgrade state reads no host state: an unconditional hold must not be
    # weakened by a stale or attacker-shaped local observation.
    refuse("in-place Castle Wall upgrade, reinstall and downgrade are unsupported; retire this host and cold-install a new package")


def state_REMOVE():
    targets = [line.strip() for line in sys.stdin if line.strip()]
    if targets != [PACKAGE]:
        refuse("unclear libalpm remove target set")
    package_query()
    package_integrity()
    identity_first = installed_identity()
    systemd_files()
    manager_first = systemd_manager()
    mount_first = systemd_manager(MOUNT_NAME, MOUNT_PATH)
    agent_instances_inactive()
    no_queued_jobs()
    runtime_absent()
    systemd_files()
    manager_second = systemd_manager()
    mount_second = systemd_manager(MOUNT_NAME, MOUNT_PATH)
    agent_instances_inactive()
    no_queued_jobs()
    runtime_absent()
    if manager_first != manager_second or mount_first != mount_second:
        refuse("systemd manager state changed during observation")
    if installed_identity() != identity_first:
        refuse("installed identity changed during observation")


def main(argv):
    if argv == ["upgrade"]:
        state_UPGRADE()
    if os.geteuid() != 0:
        refuse("package guard requires root")
    if argv == ["remove"]:
        state_REMOVE()
        return
    refuse("unsupported Arch package guard phase")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Refusal as exc:
        print(f"Castle Wall package guard refused: {exc}", file=sys.stderr)
        sys.exit(1)
