#!/usr/bin/env python3
# ruff: noqa: SIM117, EXE001, B023
"""Arch guard unit tests: refusal and bounded-observation witnesses. ARCH-HOLD-01."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BUILD_SPEC = importlib.util.spec_from_file_location("build_arch_package", HERE / "build-arch-package.py")
BUILD = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILD)
IDENTITY = {
    "artifact_kind": "arch-install-pkg-v1",
    "package": "sanctuary-castle-wall",
    "package_version": "0.1.0-1",
    "file_count": 3,
    "payload_sha256": {"usr/bin/sanctuary-linux": "b" * 64},
}
IDENTITY_BYTES = (json.dumps(IDENTITY, sort_keys=True, indent=2) + "\n").encode()
FC1BC892_FIXTURE = HERE / "fixtures" / "pre_p2b_guard_fc1bc892.py"
SCRATCH_INERT_MISSING_IDENTITY_GUARD_TEXT = """
# Scratch model for the dangerous missing-identity fallback; not fc1bc892.
class Refusal(Exception):
    pass


PACKAGE = "sanctuary-castle-wall"
IDENTITY_PATH = "/usr/lib/sanctuary-castle-wall/build-identity"
MOUNT_NAME = r"var-lib-sanctuary\\\\x2dagent\\\\x2dworkspace.mount"


def refuse(reason):
    raise Refusal(reason)


def systemd_manager(unit_name="sanctuary-castle-wall.service", unit_path="/etc/systemd/system/sanctuary-castle-wall.service"):
    output = probe([])
    fields = dict(line.split("=", 1) for line in output.splitlines())
    if fields["ActiveState"] != "inactive" or fields["SubState"] != "dead":
        refuse("unit not positively inactive")
    if fields["LoadState"] not in ("loaded", "not-found") or fields["FragmentPath"] not in ("", unit_path):
        refuse("installed unit not exact, inert and disabled")
    return fields


def build_identity():
    if lstat(IDENTITY_PATH) is None:
        return None
    return {"file_count": 3}


def installed_identity():
    return build_identity()


def state_REMOVE():
    installed_identity()
    first = systemd_manager()
    mount_first = systemd_manager(MOUNT_NAME, "/etc/systemd/system/" + MOUNT_NAME)
    second = systemd_manager()
    systemd_manager(MOUNT_NAME, "/etc/systemd/system/" + MOUNT_NAME)
    if first["LoadState"] == "loaded" and second["LoadState"] == "not-found":
        pass
    runtime_absent()
"""


def fc1bc892_header_constants() -> tuple[dict[str, int], dict[str, str], bytes]:
    # Recreates the fc1bc892 builder's generated header constants so the fixture
    # below is run the way that commit's build-arch-package.py rendered it.
    package = "sanctuary-castle-wall"
    doc = "usr/share/doc/" + package
    identity = doc + "/build-identity"
    guard = "usr/share/libalpm/scripts/sanctuary-castle-wall-guard"
    mount_name = r"var-lib-sanctuary\x2dagent\x2dworkspace.mount"
    binaries = {
        "castle-wall-daemon": "usr/local/libexec/sanctuary/castle-wall-daemon",
        "protected-agent-v1": "usr/local/libexec/sanctuary/protected-agent-v1",
        "network-agent-standin": "usr/local/libexec/sanctuary/network-agent-standin",
        "sanctuary-linux": "usr/bin/sanctuary-linux",
    }
    sources = {
        "etc/systemd/system/sanctuary-castle-wall.service": "systemd/sanctuary-castle-wall.service",
        "etc/systemd/system/sanctuary-agent@.service": "systemd/sanctuary-agent@.service",
        "etc/systemd/system/" + mount_name: "systemd/" + mount_name,
        doc + "/schemas/contract.rs": "src/linux_install/contract.rs",
        doc + "/operator-guide.md": "packaging/ubuntu/README.md",
    }
    hook_destinations = {
        "usr/share/libalpm/hooks/00-sanctuary-castle-wall-upgrade-guard.hook": "00-sanctuary-castle-wall-upgrade-guard.hook",
        "usr/share/libalpm/hooks/00-sanctuary-castle-wall-remove-guard.hook": "00-sanctuary-castle-wall-remove-guard.hook",
    }
    payload_modes = {
        **{path: 0o755 for path in binaries.values()},
        **{path: 0o644 for path in sources},
        **{path: 0o644 for path in hook_destinations},
        identity: 0o644,
        guard: 0o755,
    }
    payload_hashes = {path: "a" * 64 for path in sorted(set(payload_modes) - {identity, guard})}
    identity_model = {
        "artifact_kind": "arch-install-pkg-v1",
        "install_ready": False,
        "package": package,
        "package_version": "0.1.0-1",
        "source_commit": "fc1bc892",
        "cargo_lock_sha256": "b" * 64,
        "rustc_version": "rustc 1.95.0",
        "target": "x86_64-unknown-linux-gnu",
        "features": [],
        "glibc_floor": "2.41",
        "payload_sha256": payload_hashes,
        "hook_sha256": {
            "00-sanctuary-castle-wall-upgrade-guard.hook": "c" * 64,
            "00-sanctuary-castle-wall-remove-guard.hook": "d" * 64,
        },
        "cli_path_deviation": {
            "ubuntu_path": "usr/sbin/sanctuary-linux",
            "arch_path": "usr/bin/sanctuary-linux",
            "reason": "Arch /usr/sbin is owned as a filesystem symlink; D4 Q9 chooses usr/bin.",
        },
    }
    identity_bytes = (json.dumps(identity_model, sort_keys=True, indent=2) + "\n").encode()
    return payload_modes, payload_hashes, identity_bytes


def generated_guard_bytes(identity: dict[str, object] | None = None) -> bytes:
    model = IDENTITY if identity is None else identity
    identity_bytes = (json.dumps(model, sort_keys=True, indent=2) + "\n").encode()
    return BUILD.guard_bytes("0.1.0-1", identity_bytes, HERE)


def module_from_bytes(source: bytes) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "guard.py"
        path.write_bytes(source)
        compile(source, str(path), "exec")
        return runpy.run_path(str(path))


def pre_p2b_guard() -> dict[str, object]:
    payload_modes, payload_hashes, identity_bytes = fc1bc892_header_constants()
    header = (
        "#!/usr/bin/python3 -I\n"
        + "PACKAGE_VERSION = '0.1.0-1'\n"
        + f"IDENTITY_SHA256 = {hashlib.sha256(identity_bytes).hexdigest()!r}\n"
        + f"PAYLOAD_MODES = {payload_modes!r}\n"
        + f"PAYLOAD_HASHES = {payload_hashes!r}\n"
    ).encode()
    return module_from_bytes(header + FC1BC892_FIXTURE.read_bytes())


def scratch_inert_missing_identity_guard() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "scratch-inert-missing-identity-guard.py"
        path.write_text(SCRATCH_INERT_MISSING_IDENTITY_GUARD_TEXT)
        return runpy.run_path(str(path))


GUARD = module_from_bytes(generated_guard_bytes())


class GuardTests(unittest.TestCase):
    def root(self):
        return type("Root", (), {"geteuid": staticmethod(lambda: 0)})

    def test_upgrade_refuses_without_host_observation(self):
        globals_ = GUARD["main"].__globals__
        with patch.dict(globals_, {"os": self.root(), "probe": lambda *_a, **_k: self.fail("upgrade read host state")}):
            with self.assertRaisesRegex(GUARD["Refusal"], "retire this host"):
                GUARD["main"](["upgrade"])

    def test_generated_guard_compiles_and_refuses_upgrade(self):
        identity = (json.dumps(IDENTITY, sort_keys=True, indent=2) + "\n").encode()
        guard = BUILD.guard_bytes("0.1.0-1", identity, HERE)
        self.assertEqual(guard.splitlines()[1].decode().split(" = ", 1)[0], "IDENTITY_SHA256")
        self.assertEqual(guard.splitlines()[2].decode().split(" = ", 1)[0], "PACKAGE_VERSION")
        self.assertEqual(guard.splitlines()[3].decode().split(" = ", 1)[0], "IDENTITY_PATH")
        self.assertEqual(guard.splitlines()[4].decode().split(" = ", 1)[0], "PAYLOAD_MODES")
        self.assertNotIn(b"PAYLOAD_HASHES", b"\n".join(guard.splitlines()[:8]))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guard.py"
            path.write_bytes(guard)
            compile(guard, str(path), "exec")
            result = subprocess.run([sys.executable, "-I", str(path), "upgrade"], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Castle Wall package guard refused:", result.stdout + result.stderr)

    def test_generated_static_hash_is_everything_after_identity_line(self):
        guard = generated_guard_bytes()
        lines = guard.splitlines(keepends=True)
        expected = hashlib.sha256(guard[len(lines[0]) + len(lines[1]) :]).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guard.py"
            path.write_bytes(guard)
            with patch.dict(GUARD["static_guard_source"].__globals__, {"GUARD_PATH": str(path)}):
                self.assertEqual(GUARD["static_guard_source"](), expected)

    def test_generated_guard_refuses_static_header_edits(self):
        guard = generated_guard_bytes()
        for old, new in (
            (b"PACKAGE_VERSION = '0.1.0-1'\n", b"PACKAGE_VERSION = '0.1.0-2'\n"),
            (
                b"IDENTITY_PATH = '/usr/lib/sanctuary-castle-wall/build-identity'\n",
                b"IDENTITY_PATH = '/missing/build-identity'\n",
            ),
        ):
            with self.subTest(old=old):
                altered = guard.replace(old, new, 1)
                self.assertNotEqual(altered, guard)
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "guard.py"
                    path.write_bytes(altered)
                    with patch.dict(GUARD["static_guard_source"].__globals__, {"GUARD_PATH": str(path)}):
                        with self.assertRaisesRegex(GUARD["Refusal"], "static header"):
                            GUARD["static_guard_source"]()

    def test_unknown_phase_and_non_root_refuse(self):
        with patch.dict(GUARD["main"].__globals__, {"os": self.root()}):
            with self.assertRaisesRegex(GUARD["Refusal"], "unsupported"):
                GUARD["main"]([])
        with patch.dict(GUARD["main"].__globals__, {"os": type("User", (), {"geteuid": staticmethod(lambda: 501)})}):
            with self.assertRaisesRegex(GUARD["Refusal"], "requires root"):
                GUARD["main"](["remove"])

    def test_remove_requires_exact_target_from_needs_targets(self):
        globals_ = GUARD["state_REMOVE"].__globals__
        with patch.dict(globals_, {"sys": SimpleNamespace(stdin=io.StringIO(""))}):
            with self.assertRaisesRegex(GUARD["Refusal"], "target"):
                GUARD["state_REMOVE"]()
        with patch.dict(globals_, {"sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\nother\n"))}):
            with self.assertRaisesRegex(GUARD["Refusal"], "target"):
                GUARD["state_REMOVE"]()

    def test_package_database_observations_fail_closed(self):
        for fn in ("package_query", "package_integrity", "package_owner"):
            with self.subTest(fn=fn):
                with patch.dict(GUARD[fn].__globals__, {"probe": lambda *_a, **_k: ""}):
                    with self.assertRaises(GUARD["Refusal"]):
                        if fn == "package_owner":
                            GUARD[fn]("usr/bin/sanctuary-linux")
                        elif fn == "package_integrity":
                            GUARD[fn](IDENTITY["file_count"])
                        else:
                            GUARD[fn]()

    def test_package_integrity_requires_exact_clean_summary_line(self):
        dirty_summary = "sanctuary-castle-wall: 42 total files, 10 altered files\n"
        with patch.dict(GUARD["package_integrity"].__globals__, {"probe": lambda *_a, **_k: dirty_summary}):
            with self.assertRaisesRegex(GUARD["Refusal"], "integrity"):
                GUARD["package_integrity"](42)
        clean_wrong_count = "sanctuary-castle-wall: 42 total files, 0 altered files\n"
        with patch.dict(GUARD["package_integrity"].__globals__, {"probe": lambda *_a, **_k: clean_wrong_count}):
            with self.assertRaisesRegex(GUARD["Refusal"], "integrity"):
                GUARD["package_integrity"](41)

    def test_identity_rejects_hash_mismatch_guard_hash_and_payload_mismatch(self):
        expected_payloads = set(GUARD["PAYLOAD_MODES"]) - {GUARD["IDENTITY_PATH"].lstrip("/"), GUARD["GUARD_PATH"].lstrip("/")}
        good = dict(IDENTITY, payload_sha256={path: "b" * 64 for path in expected_payloads})
        bad_guard = dict(good, guard_sha256="c" * 64)

        def read_identity(model):
            raw = (json.dumps(model, sort_keys=True, indent=2) + "\n").encode()
            return raw

        globals_ = GUARD["build_identity"].__globals__
        with patch.dict(globals_, {"lstat": lambda _p: object(), "checked_payload_path": lambda *_: None, "stable_read": lambda *_: read_identity(good), "IDENTITY_SHA256": "0" * 64}):
            with self.assertRaisesRegex(GUARD["Refusal"], "identity differs"):
                GUARD["build_identity"]()
        with patch.dict(globals_, {"lstat": lambda _p: object(), "checked_payload_path": lambda *_: None, "stable_read": lambda *_: read_identity(bad_guard), "IDENTITY_SHA256": hashlib.sha256(read_identity(bad_guard)).hexdigest()}):
            with self.assertRaisesRegex(GUARD["Refusal"], "wrong Arch"):
                GUARD["build_identity"]()
        list_identity = b'["not", "an", "object"]\n'
        with patch.dict(globals_, {"lstat": lambda _p: object(), "checked_payload_path": lambda *_: None, "stable_read": lambda *_: list_identity, "IDENTITY_SHA256": hashlib.sha256(list_identity).hexdigest()}):
            with self.assertRaisesRegex(GUARD["Refusal"], "wrong Arch"):
                GUARD["build_identity"]()
        with patch.dict(GUARD["installed_identity"].__globals__, {
            "build_identity": lambda: good,
            "static_guard_source": lambda: None,
            "checked_payload_path": lambda *_: None,
            "package_owner": lambda *_: None,
            "hash_file": lambda _p: "0" * 64,
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "payload differs"):
                GUARD["installed_identity"]()

    def test_runtime_footprints_refuse(self):
        class EmptyScandir:
            def __enter__(self):
                return iter(())

            def __exit__(self, *_):
                return False

        cases = (
            ("accounts", "accounts_absent"),
            ("mount", "mount_absent"),
            ("nft", "nft_absent"),
            ("jobs", "no_queued_jobs"),
            ("agent", "agent_instances_inactive"),
        )
        for label, fn in cases:
            with self.subTest(label=label):
                if fn == "no_queued_jobs":
                    with patch.dict(GUARD[fn].__globals__, {"probe": lambda *_a, **_k: "1 sanctuary-castle-wall.service start waiting\n"}):
                        with self.assertRaisesRegex(GUARD["Refusal"], "job queued"):
                            GUARD[fn]()
                    continue
                if fn == "agent_instances_inactive":
                    with patch.dict(GUARD[fn].__globals__, {"probe": lambda *_a, **_k: "sanctuary-agent@x.service loaded active running worker\n"}):
                        with self.assertRaisesRegex(GUARD["Refusal"], "agent instance"):
                            GUARD[fn]()
                    continue
                with patch.dict(GUARD["runtime_absent"].__globals__, {
                    "accounts_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "accounts_absent" else lambda: None,
                    "mount_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "mount_absent" else lambda: None,
                    "nft_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "nft_absent" else lambda: None,
                    "empty_runtime_root": lambda *_: None,
                    "os": SimpleNamespace(scandir=lambda _p: EmptyScandir()),
                }):
                    with self.assertRaisesRegex(GUARD["Refusal"], fn):
                        GUARD["runtime_absent"]()

    def test_systemd_inventory_refuses_walk_error(self):
        dir_info = SimpleNamespace(st_mode=0o040755, st_uid=0)

        def walk_with_error(_root, followlinks=False, onerror=None):
            if onerror is not None:
                onerror(OSError("permission denied"))
            return iter(())

        with patch.dict(GUARD["systemd_files"].__globals__, {
            "probe": lambda *_a, **_k: "/etc/systemd/system\n",
            "check_ancestors": lambda _p: True,
            "lstat": lambda _p: dir_info,
        }), patch.object(GUARD["os"], "walk", walk_with_error):
            with self.assertRaisesRegex(GUARD["Refusal"], "cannot inventory systemd directory"):
                GUARD["systemd_files"]()

    def test_systemd_active_or_alias_observations_refuse(self):
        properties = ("Id", "Names", "Following", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "Job", "NeedDaemonReload")
        clean = {
            "Id": "sanctuary-castle-wall.service",
            "Names": "sanctuary-castle-wall.service",
            "Following": "",
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "disabled",
            "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service",
            "DropInPaths": "",
            "Job": "",
            "NeedDaemonReload": "no",
        }

        def render(fields):
            return "\n".join(f"{key}={fields[key]}" for key in properties) + "\n"

        for mutation in ({"ActiveState": "active"}, {"DropInPaths": "/etc/systemd/system/x.d"}, {"FragmentPath": "/tmp/other"}):
            with self.subTest(mutation=mutation), patch.dict(GUARD["systemd_manager"].__globals__, {
                "systemd_pid1_comm": lambda: None,
                "probe": lambda *_a, **_k: render(dict(clean, **mutation)),
            }):
                with self.assertRaises(GUARD["Refusal"]):
                    GUARD["systemd_manager"]()
        contracted = (
            ({"NeedDaemonReload": "yes"}, "unit needs daemon reload"),
            ({"NeedDaemonReload": "maybe"}, "unit needs daemon reload"),
            ({"LoadState": "not-found", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service"}, "not-found unit reports a fragment path"),
        )
        for mutation, message in contracted:
            with self.subTest(mutation=mutation), patch.dict(GUARD["systemd_manager"].__globals__, {
                "systemd_pid1_comm": lambda: None,
                "probe": lambda *_a, **_k: render(dict(clean, **mutation)),
            }):
                with self.assertRaisesRegex(GUARD["Refusal"], message):
                    GUARD["systemd_manager"]()

    def test_pre_p2b_guard_admits_systemd_gap_witnesses(self):
        base = pre_p2b_guard()
        properties = ("Id", "Names", "Following", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "DropInPaths", "Job", "NeedDaemonReload")
        clean = {
            "Id": "sanctuary-castle-wall.service",
            "Names": "sanctuary-castle-wall.service",
            "Following": "",
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "disabled",
            "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service",
            "DropInPaths": "",
            "Job": "",
            "NeedDaemonReload": "no",
        }

        def render(fields):
            return "\n".join(f"{key}={fields[key]}" for key in properties) + "\n"

        class SystemdPath:
            def __init__(self, _path):
                pass

            def read_text(self):
                return "systemd\n"

        for mutation in (
            {"NeedDaemonReload": "yes"},
            {"LoadState": "not-found", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service"},
        ):
            with self.subTest(mutation=mutation), patch.dict(base["systemd_manager"].__globals__, {
                "Path": SystemdPath,
                "probe": lambda *_a, mutation=mutation, **_k: render(dict(clean, **mutation)),
            }):
                base["systemd_manager"]()

    def test_pre_p2b_guard_admits_mount_second_read_drift(self):
        base = pre_p2b_guard()
        first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service", "ActiveState": "inactive"}
        mount_first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/" + base["MOUNT_NAME"], "ActiveState": "inactive"}
        mount_second = dict(mount_first, LoadState="not-found", FragmentPath="")
        reads = iter((first, mount_first, first, mount_second))
        with patch.dict(base["state_REMOVE"].__globals__, {
            "sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\n")),
            "package_query": lambda: None,
            "package_integrity": lambda: None,
            "installed_identity": lambda: {"file_count": 3},
            "systemd_files": lambda: None,
            "systemd_manager": lambda *_a, **_k: next(reads),
            "agent_instances_inactive": lambda: None,
            "no_queued_jobs": lambda: None,
            "runtime_absent": lambda: None,
        }):
            base["state_REMOVE"]()

    def test_pre_p2b_guard_pid1_decode_error_crashes_uncontracted(self):
        base = pre_p2b_guard()

        class UndecodablePath:
            def __init__(self, _path):
                pass

            def read_text(self):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        with patch.dict(base["systemd_manager"].__globals__, {"Path": UndecodablePath}):
            with self.assertRaises(UnicodeDecodeError):
                base["systemd_manager"]()

    def test_pre_p2b_missing_identity_refuses_with_base_message(self):
        base = pre_p2b_guard()
        with patch.dict(base["build_identity"].__globals__, {
            "check_ancestors": lambda _p: True,
            "lstat": lambda _p: None,
        }):
            with self.assertRaisesRegex(base["Refusal"], "required package path absent"):
                base["build_identity"]()

    def test_remove_allows_only_systemd_load_state_transition(self):
        first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service", "ActiveState": "inactive"}
        second = dict(first, LoadState="not-found", FragmentPath="")
        mount = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/" + GUARD["MOUNT_NAME"], "ActiveState": "inactive"}
        reads = iter((first, mount, second, mount))
        globals_ = GUARD["state_REMOVE"].__globals__
        with patch.dict(globals_, {
            "sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\n")),
            "package_query": lambda: None,
            "package_integrity": lambda _count: None,
            "installed_identity": lambda: {"identity": "stable", "file_count": 3},
            "systemd_files": lambda: None,
            "systemd_manager": lambda *_a, **_k: next(reads),
            "agent_instances_inactive": lambda: None,
            "no_queued_jobs": lambda: None,
            "runtime_absent": lambda: None,
        }):
            GUARD["state_REMOVE"]()

    def test_remove_compares_mount_unit_whole(self):
        first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service", "ActiveState": "inactive"}
        mount_first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/" + GUARD["MOUNT_NAME"], "ActiveState": "inactive"}
        mount_second = dict(mount_first, LoadState="not-found", FragmentPath="")
        reads = iter((first, mount_first, first, mount_second))
        globals_ = GUARD["state_REMOVE"].__globals__
        with patch.dict(globals_, {
            "sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\n")),
            "package_query": lambda: None,
            "package_integrity": lambda _count: None,
            "installed_identity": lambda: {"file_count": 3},
            "systemd_files": lambda: None,
            "systemd_manager": lambda *_a, **_k: next(reads),
            "agent_instances_inactive": lambda: None,
            "no_queued_jobs": lambda: None,
            "runtime_absent": lambda: None,
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "systemd manager state changed"):
                GUARD["state_REMOVE"]()

    def test_decode_errors_are_refusals(self):
        with patch.dict(GUARD["probe"].__globals__, {
            "bounded_capture": lambda *_a, **_k: (0, b"\xff", b""),
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "decode|undecodable"):
                GUARD["probe"](["/usr/bin/example"])
        with patch.dict(GUARD["mount_absent"].__globals__, {
            "stable_read": lambda *_a, **_k: b"\xff",
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "decode|mount"):
                GUARD["mount_absent"]()
        with patch.dict(GUARD["systemd_pid1_comm"].__globals__, {
            "stable_read": lambda *_a, **_k: b"\xff",
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "decode|PID 1"):
                GUARD["systemd_pid1_comm"]()

    def test_missing_identity_refuses_before_runtime_footprint(self):
        globals_ = GUARD["state_REMOVE"].__globals__
        with patch.dict(globals_, {
            "sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\n")),
            "package_query": lambda: None,
            "installed_identity": lambda: (_ for _ in ()).throw(GUARD["Refusal"]("build identity absent")),
            "runtime_absent": lambda: self.fail("missing identity must not be treated as inert"),
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "identity absent"):
                GUARD["state_REMOVE"]()

    def test_build_identity_refuses_missing_identity_directly(self):
        with patch.dict(GUARD["build_identity"].__globals__, {"lstat": lambda _p: None}):
            with self.assertRaisesRegex(GUARD["Refusal"], "identity absent"):
                GUARD["build_identity"]()

    def test_pre_p2b_missing_identity_scratch_guard_treats_host_as_inert(self):
        base = scratch_inert_missing_identity_guard()
        reached = {"runtime": False}

        def runtime_absent():
            reached["runtime"] = True

        with patch.dict(base["state_REMOVE"].__globals__, {
            "lstat": lambda _p: None,
            "systemd_manager": lambda *_a, **_k: {"LoadState": "not-found"},
            "runtime_absent": runtime_absent,
        }):
            base["state_REMOVE"]()
        self.assertTrue(reached["runtime"])

    def test_bounded_capture_caps_output_and_deadline(self):
        with self.assertRaises(ValueError):
            GUARD["bounded_capture"](["/bin/sh", "-c", "printf 123456789"], timeout=5, limit=4)
        with self.assertRaises(ValueError):
            GUARD["bounded_capture"](["/bin/sh", "-c", "sleep 2"], timeout=0.01, limit=1024)

    def test_stable_read_rejects_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oversized = root / "big"
            oversized.write_bytes(b"abc")
            with self.assertRaisesRegex(GUARD["Refusal"], "oversized"):
                GUARD["stable_read"](str(oversized), 2)
            link = root / "link"
            link.symlink_to(oversized)
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["stable_read"](str(link), 10)

    def test_generated_identity_does_not_record_guard_hash(self):
        identity_block = Path(HERE / "build-arch-package.py").read_text().split("identity = ", 1)[1].split("identity_bytes", 1)[0]
        self.assertNotIn("guard_sha256", identity_block)
        self.assertIn('"hook_sha256"', identity_block)
        self.assertIn('"binary_features"', identity_block)
        self.assertIn('"rustflags"', identity_block)
        self.assertIn('"file_count"', identity_block)

    def test_optional_rust_constants_compare_absolute_cli_and_relative_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            crate = Path(tmp)
            src = crate / "src"
            src.mkdir()
            source = src / "lib.rs"
            source.write_text(
                'pub const ARCH_BUILD_IDENTITY: &str = "usr/lib/sanctuary-castle-wall/build-identity";\n'
                'pub const ARCH_CLI_PATH: &str = "/usr/bin/sanctuary-linux";\n'
            )
            BUILD.check_optional_rust_constants(crate)
            source.write_text(
                'pub const ARCH_BUILD_IDENTITY: &str = "usr/lib/sanctuary-castle-wall/build-identity";\n'
                'pub const ARCH_CLI_PATH: &str = "usr/bin/sanctuary-linux";\n'
            )
            with self.assertRaisesRegex(ValueError, "ARCH_CLI_PATH"):
                BUILD.check_optional_rust_constants(crate)

    def test_pkgbuild_scrubs_rust_environment_by_prefix(self):
        text = (HERE / "PKGBUILD").read_text()
        self.assertIn("CARGO_*|RUSTFLAGS*|RUSTC*|RUSTDOC*|RUSTUP_TOOLCHAIN*", text)
        self.assertIn("Rust build environment survived scrub", text)
        scrub_function = text.split("_scrub_rust_env() {", 1)[1].split("\n}\n\nbuild() {", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            script = f"""
set -euo pipefail
srcdir={tmp!r}
_scrub_rust_env() {{{scrub_function}
}}
export RUSTC_WRAPPER=wrapper RUSTC_WORKSPACE_WRAPPER=workspace RUSTDOCFLAGS=doc RUSTFLAGS=flags RUSTUP_TOOLCHAIN=toolchain CARGO_CACHE_RUSTC_INFO=cache
_scrub_rust_env
for name in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTDOCFLAGS RUSTFLAGS RUSTUP_TOOLCHAIN; do
  if printenv "$name" >/dev/null; then
    echo "$name survived scrub" >&2
    exit 1
  fi
  grep -Fx "$name" "$srcdir/rust-env-scrubbed.txt" >/dev/null
done
"""
            subprocess.run(["bash", "-c", script], check=True)


if __name__ == "__main__":
    unittest.main()
