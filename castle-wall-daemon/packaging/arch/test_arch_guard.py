#!/usr/bin/env python3
"""Arch guard unit tests: refusal and bounded-observation witnesses. ARCH-HOLD-01."""

from __future__ import annotations

import hashlib
import io
import importlib.util
import json
import os
import runpy
import sys
import subprocess
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
    "payload_sha256": {"usr/bin/sanctuary-linux": "b" * 64},
}
IDENTITY_BYTES = (str(IDENTITY).replace("'", '"') + "\n").encode()
GUARD = runpy.run_path(
    str(HERE / "sanctuary-castle-wall-guard.py"),
    init_globals={
        "PACKAGE_VERSION": "0.1.0-1",
        "IDENTITY_SHA256": hashlib.sha256(IDENTITY_BYTES).hexdigest(),
        "PAYLOAD_MODES": {
            "usr/bin/sanctuary-linux": 0o755,
            "usr/share/doc/sanctuary-castle-wall/build-identity": 0o644,
            "usr/share/libalpm/scripts/sanctuary-castle-wall-guard": 0o755,
        },
        "PAYLOAD_HASHES": IDENTITY["payload_sha256"],
    },
)


class GuardTests(unittest.TestCase):
    def root(self):
        return type("Root", (), {"geteuid": staticmethod(lambda: 0)})

    def test_upgrade_refuses_without_host_observation(self):
        globals_ = GUARD["main"].__globals__
        with patch.dict(globals_, {"os": self.root(), "probe": lambda *_a, **_k: self.fail("upgrade read host state")}):
            with self.assertRaisesRegex(GUARD["Refusal"], "retire this host"):
                GUARD["main"](["upgrade"])

    def test_generated_guard_compiles_and_refuses_upgrade(self):
        identity = json.dumps(IDENTITY, sort_keys=True, indent=2).encode()
        guard = BUILD.guard_bytes("0.1.0-1", identity, IDENTITY["payload_sha256"], HERE)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guard.py"
            path.write_bytes(guard)
            compile(guard, str(path), "exec")
            result = subprocess.run([sys.executable, "-I", str(path), "upgrade"], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Castle Wall package guard refused:", result.stdout + result.stderr)

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
                        else:
                            GUARD[fn]()

    def test_package_integrity_requires_exact_clean_summary_line(self):
        dirty_summary = "sanctuary-castle-wall: 42 total files, 10 altered files\n"
        with patch.dict(GUARD["package_integrity"].__globals__, {"probe": lambda *_a, **_k: dirty_summary}):
            with self.assertRaisesRegex(GUARD["Refusal"], "integrity"):
                GUARD["package_integrity"]()

    def test_identity_rejects_hash_mismatch_guard_hash_and_payload_mismatch(self):
        good = dict(IDENTITY)
        bad_guard = dict(good, guard_sha256="c" * 64)

        def read_identity(model):
            raw = (str(model).replace("'", '"') + "\n").encode()
            return raw

        globals_ = GUARD["build_identity"].__globals__
        with patch.dict(globals_, {"checked_payload_path": lambda *_: None, "stable_read": lambda *_: read_identity(good), "IDENTITY_SHA256": "0" * 64}):
            with self.assertRaisesRegex(GUARD["Refusal"], "identity differs"):
                GUARD["build_identity"]()
        with patch.dict(globals_, {"checked_payload_path": lambda *_: None, "stable_read": lambda *_: read_identity(bad_guard), "IDENTITY_SHA256": hashlib.sha256(read_identity(bad_guard)).hexdigest()}):
            with self.assertRaisesRegex(GUARD["Refusal"], "wrong Arch"):
                GUARD["build_identity"]()
        with patch.dict(GUARD["installed_identity"].__globals__, {
            "build_identity": lambda: good,
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

        class Proc:
            def read_text(self):
                return "systemd\n"

        for mutation in ({"ActiveState": "active"}, {"DropInPaths": "/etc/systemd/system/x.d"}, {"FragmentPath": "/tmp/other"}):
            with self.subTest(mutation=mutation), patch.dict(GUARD["systemd_manager"].__globals__, {
                "Path": lambda *_: Proc(),
                "probe": lambda *_a, **_k: render(dict(clean, **mutation)),
            }):
                with self.assertRaises(GUARD["Refusal"]):
                    GUARD["systemd_manager"]()

    def test_remove_allows_only_systemd_load_state_transition(self):
        first = {"LoadState": "loaded", "FragmentPath": "/etc/systemd/system/sanctuary-castle-wall.service", "ActiveState": "inactive"}
        second = dict(first, LoadState="not-found", FragmentPath="")
        reads = iter((first, first, second, second))
        globals_ = GUARD["state_REMOVE"].__globals__
        with patch.dict(globals_, {
            "sys": SimpleNamespace(stdin=io.StringIO("sanctuary-castle-wall\n")),
            "package_query": lambda: None,
            "package_integrity": lambda: None,
            "installed_identity": lambda: {"identity": "stable"},
            "systemd_files": lambda: None,
            "systemd_manager": lambda *_a, **_k: next(reads),
            "agent_instances_inactive": lambda: None,
            "no_queued_jobs": lambda: None,
            "runtime_absent": lambda: None,
        }):
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


if __name__ == "__main__":
    unittest.main()
