#!/usr/bin/env python3
"""Arch guard unit tests: refusal and bounded-observation witnesses. ARCH-HOLD-01."""

from __future__ import annotations

import hashlib
import io
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
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
                with patch.dict(GUARD["runtime_absent"].__globals__, {
                    "accounts_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "accounts_absent" else lambda: None,
                    "mount_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "mount_absent" else lambda: None,
                    "nft_absent": (lambda fn=fn: (_ for _ in ()).throw(GUARD["Refusal"](fn))) if fn == "nft_absent" else lambda: None,
                    "empty_runtime_root": lambda *_: None,
                    "os": SimpleNamespace(scandir=lambda _p: EmptyScandir()),
                }):
                    if fn in {"accounts_absent", "mount_absent", "nft_absent"}:
                        with self.assertRaisesRegex(GUARD["Refusal"], fn):
                            GUARD["runtime_absent"]()

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
