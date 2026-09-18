#!/usr/bin/env python3
"""Focused parser/decision tests; real dpkg/systemd acceptance runs in CI."""

import json
import io
import os
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


GUARD = runpy.run_path(str(Path(__file__).with_name("lifecycle-guard.py")), init_globals={
    "ROLE": "preinst", "PACKAGE_VERSION": "1.0-2",
    "DAEMON_SHA256": "a" * 64, "UNIT_SHA256": "b" * 64,
})
ARCHIVE = runpy.run_path(str(Path(__file__).with_name("assert-archive.py")))


class GuardTests(unittest.TestCase):
    def test_archive_root_requires_exact_directory_custody(self):
        def inspect(name, mode, uid=0, directory=True):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:") as tar:
                root = tarfile.TarInfo(name)
                root.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                root.mode, root.uid, root.gid = mode, uid, 0
                tar.addfile(root, io.BytesIO(b"") if not directory else None)
            with patch.object(ARCHIVE["archive"].__globals__["subprocess"], "run",
                              return_value=SimpleNamespace(stdout=stream.getvalue())):
                return ARCHIVE["archive"](Path("unused.deb"), "--fsys-tarfile")

        self.assertEqual(inspect(".", 0o755), {})
        self.assertEqual(inspect("./", 0o755), {})
        for name, mode, uid, directory in ((".", 0o777, 0, True),
                                           (".", 0o755, 1, True),
                                           (".", 0o755, 0, False)):
            with self.subTest(name=name, mode=mode, uid=uid, directory=directory):
                with self.assertRaises(ValueError):
                    inspect(name, mode, uid, directory)

    def test_runtime_depends_rejects_dev_relations_and_whitespace(self):
        script = Path(__file__).with_name("assert-structure.sh")
        for field in ("libc6, libfixture-dev", "libc6, libfixture-dev (>= 1)",
                      "libc6, libfixture-dev   , libmnl0"):
            with self.subTest(field=field):
                result = subprocess.run(["bash", str(script), "--check-depends", field],
                                        capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                with self.assertRaises(ValueError):
                    ARCHIVE["validate_runtime_depends"](field)
        self.assertEqual(ARCHIVE["validate_runtime_depends"]("libc6, libmnl0:amd64"),
                         ["libc6", "libmnl0:amd64"])
    def status(self, content):
        with patch.dict(GUARD["dpkg_status"].__globals__, {"checked_file": lambda *_: None, "stable_read": lambda *_: content}):
            return GUARD["dpkg_status"]()

    def test_status_requires_exact_installed_or_absent_triple(self):
        stanza = b"Package: sanctuary-castle-wall-internal\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n"
        fields, parts = self.status(stanza)
        self.assertEqual(parts, ["install", "ok", "installed"])
        self.assertEqual(fields["Version"], "1.0-1")
        for corrupt in (
            stanza.replace(b"install ok installed", b"install reinstreq installed"),
            stanza + b"\n" + stanza,
            stanza.replace(b"Status: install ok installed", b"Status: install ok installed\nStatus: install ok installed"),
            b"Package: sanctuary-castle-wall-internal\nStatus: hold ok installed\n",
        ):
            with self.subTest(corrupt=corrupt), self.assertRaises(GUARD["Refusal"]):
                self.status(corrupt)

    def test_status_missing_stanza_requires_complete_read(self):
        self.assertIsNone(self.status(b"Package: unrelated\nStatus: install ok installed\n"))
        with patch.dict(GUARD["dpkg_status"].__globals__, {"checked_file": lambda *_: None, "stable_read": lambda *_: (_ for _ in ()).throw(GUARD["Refusal"]("unreadable"))}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["dpkg_status"]()

    def test_unrelated_multiline_deb822_field_is_valid(self):
        status = (
            b"Package: base-files\nStatus: install ok installed\n"
            b"Architecture: amd64\nVersion: 13ubuntu10\nConffiles:\n"
            b" /etc/issue 0123456789abcdef\nDescription: base files\n"
            b" continuation text\nX_foo.bar+qux: valid\n\n"
            b"package: sanctuary-castle-wall-internal\n"
            b"Status: install ok not-installed\nArchitecture: amd64\n"
        )
        fields, parts = self.status(status)
        self.assertEqual(parts, ["install", "ok", "not-installed"])
        self.assertNotIn("Version", fields)
        for broken in (
            status.replace(b"Conffiles:\n", b"Conffiles:\nConffiles:\n"),
            status.replace(b"Conffiles:\n", b"Conffiles bad\n"),
            status.replace(b"Package: base-files\n", b" orphan\nPackage: base-files\n"),
            status.replace(b"X_foo.bar+qux: valid\n", b"X_foo.bar+qux: valid\nx_FOO.BAR+QUX: duplicate\n"),
        ):
            with self.subTest(broken=broken), self.assertRaises(GUARD["Refusal"]):
                self.status(broken)

    def test_nft_positive_absence_only(self):
        with patch.dict(GUARD["nft_absent"].__globals__, {"command": lambda *_: json.dumps({"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": "other"}}]})}):
            GUARD["nft_absent"]()
        with patch.dict(GUARD["nft_absent"].__globals__, {"command": lambda *_: json.dumps({"nftables": [{"table": {"family": "inet", "name": "sanctuary-castle"}}]})}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["nft_absent"]()
        with patch.dict(GUARD["nft_absent"].__globals__, {"command": lambda *_: "not-json"}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["nft_absent"]()
        with patch.dict(GUARD["nft_absent"].__globals__, {"command": lambda *_: (_ for _ in ()).throw(GUARD["Refusal"]("missing nft"))}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["nft_absent"]()

    def test_incomplete_manager_output_refuses(self):
        class Proc:
            def read_text(self):
                return "systemd\n"
        with patch.dict(GUARD["systemd_manager"].__globals__, {
            "Path": lambda *_: Proc(), "command": lambda *_: "LoadState=not-found\nActiveState=inactive\n",
        }):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["systemd_manager"](False)

    def test_empty_writable_enablement_directory_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wants = root / "multi-user.target.wants"
            wants.mkdir(mode=0o755)
            wants.chmod(0o777)
            real_lstat = os.lstat

            def root_custody_lstat(path):
                try:
                    info = real_lstat(path)
                except FileNotFoundError:
                    return None
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

            with patch.dict(GUARD["systemd_files"].__globals__, {
                "SYSTEMD_ROOTS": (str(root),), "check_ancestors": lambda *_: True,
                "lstat": root_custody_lstat, "command": lambda *_: str(root),
            }):
                with self.assertRaisesRegex(GUARD["Refusal"], "unsafe systemd directory"):
                    GUARD["systemd_files"](False)

    def test_unsupported_manager_unit_path_refuses(self):
        with patch.dict(GUARD["systemd_files"].__globals__, {
            "command": lambda *_: "/etc/systemd/system /opt/foreign/systemd/system",
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "unsupported systemd manager UnitPath"):
                GUARD["systemd_files"](False)

    def test_additional_search_root_dangling_enablement_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "usr-local-lib-systemd-system"
            wants = root / "codex-package-fixture.wants"
            wants.mkdir(parents=True)
            (wants / "sanctuary-castle-wall.service").symlink_to(
                "/etc/systemd/system/sanctuary-castle-wall.service")
            real_lstat = os.lstat

            def root_custody_lstat(path):
                try:
                    info = real_lstat(path)
                except FileNotFoundError:
                    return None
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

            with patch.dict(GUARD["systemd_files"].__globals__, {
                "SYSTEMD_ROOTS": (str(root),), "check_ancestors": lambda *_: True,
                "lstat": root_custody_lstat, "command": lambda *_: str(root),
            }):
                with self.assertRaisesRegex(GUARD["Refusal"], "systemd alias or enablement symlink"):
                    GUARD["systemd_files"](False)

    def test_direct_daemon_process_scan_uses_executable_and_fails_unknown(self):
        script = Path(__file__).with_name("ci-lifecycle.sh")
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp)
            pid = proc_root / "123"
            pid.mkdir()

            def scan():
                return subprocess.run(
                    ["bash", str(script), "--test-process-scan", str(proc_root)],
                    capture_output=True, text=True, check=False,
                )

            exe = pid / "exe"
            exe.symlink_to("/opt/sanctuary/castle-wall-daemon")
            result = scan()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("direct daemon executable exists at PID 123", result.stderr)

            exe.unlink()
            exe.symlink_to("/usr/bin/other-daemon")
            (pid / "cmdline").write_bytes(b"fixture castle-wall-daemon argument\0")
            self.assertEqual(scan().returncode, 0)  # Command text is not identity.

            exe.unlink()
            result = scan()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("live PID 123 has no readable executable", result.stderr)

            (pid / "cmdline").write_bytes(b"")
            self.assertEqual(scan().returncode, 0)  # No executable or command line.

    def test_unwind_and_failed_upgrade_do_not_inventory(self):
        globals_ = GUARD["main"].__globals__
        with patch.dict(globals_, {"ROLE": "preinst", "os": type("Root", (), {"geteuid": staticmethod(lambda: 0)}), "inspect": lambda *_: self.fail("unwind inventoried host")}):
            GUARD["main"](["abort-upgrade", "1.0-2"])
        with patch.dict(globals_, {"ROLE": "prerm", "os": type("Root", (), {"geteuid": staticmethod(lambda: 0)}), "inspect": lambda *_: self.fail("veto inventoried host")}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["main"](["failed-upgrade", "1.0-1", "1.0-2"])

    def test_unknown_actions_refuse(self):
        globals_ = GUARD["main"].__globals__
        with patch.dict(globals_, {"ROLE": "preinst", "os": type("Root", (), {"geteuid": staticmethod(lambda: 0)})}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["main"](["install", "old", "new"])


if __name__ == "__main__":
    unittest.main()
