#!/usr/bin/env python3
"""Focused parser/decision tests; real dpkg/systemd acceptance runs in CI."""

import json
import io
import hashlib
import os
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


GUARD = runpy.run_path(str(Path(__file__).with_name("lifecycle-guard.py")), init_globals={
    "ROLE": "preinst", "PACKAGE_VERSION": "1.0-2",
    "DAEMON_SHA256": "a" * 64, "UNIT_SHA256": "b" * 64, "AGENT_UNIT_SHA256": "c" * 64,
})
ARCHIVE = runpy.run_path(str(Path(__file__).with_name("assert-archive.py")))


class GuardTests(unittest.TestCase):
    def test_archive_root_requires_exact_directory_custody(self):
        def inspect(name, mode, uid=0, gid=0, directory=True, duplicate=False, with_payload=False):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:") as tar:
                root = tarfile.TarInfo(name)
                root.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                root.mode, root.uid, root.gid = mode, uid, gid
                tar.addfile(root, io.BytesIO(b"") if not directory else None)
                if duplicate:
                    tar.addfile(root, io.BytesIO(b"") if not directory else None)
                if with_payload:
                    child = tarfile.TarInfo("./etc/")
                    child.type = tarfile.DIRTYPE
                    child.mode, child.uid, child.gid = 0o755, 0, 0
                    tar.addfile(child)
            with patch.object(ARCHIVE["archive"].__globals__["subprocess"], "run",
                              return_value=SimpleNamespace(stdout=stream.getvalue())):
                return ARCHIVE["archive"](Path("unused.deb"), "--fsys-tarfile")

        self.assertEqual(inspect(".", 0o755), {})
        self.assertEqual(inspect("./", 0o755), {})
        self.assertEqual(set(inspect(".", 0o755, with_payload=True)), {"etc"})
        for name, mode, uid, gid, directory, duplicate in ((".", 0o777, 0, 0, True, False),
                                                           (".", 0o755, 1, 0, True, False),
                                                           (".", 0o755, 0, 1, True, False),
                                                           (".", 0o755, 0, 0, False, False),
                                                           (".", 0o755, 0, 0, True, True)):
            with self.subTest(name=name, mode=mode, uid=uid, gid=gid,
                              directory=directory, duplicate=duplicate):
                with self.assertRaises(ValueError):
                    inspect(name, mode, uid, gid, directory, duplicate)

    def test_runtime_depends_rejects_dev_relations_and_whitespace(self):
        script = Path(__file__).with_name("assert-structure.sh")
        for field in ("libc6, libfixture-dev", "libc6, libfixture-dev (>= 1)",
                      "libc6, libfixture-dev   , libmnl0", "libc6,\nlibmnl0",
                      "libc6,\rlibmnl0"):
            with self.subTest(field=field):
                result = subprocess.run(["bash", str(script), "--check-depends", field],
                                        capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                with self.assertRaises(ValueError):
                    ARCHIVE["validate_runtime_depends"](field)
        self.assertEqual(ARCHIVE["validate_runtime_depends"]("libc6, libmnl0:amd64"),
                         ["libc6", "libmnl0:amd64"])
        self.assertEqual(ARCHIVE["validate_runtime_depends"]("libc6,libmnl0"),
                         ARCHIVE["validate_runtime_depends"]("libc6, libmnl0"))
        self.assertNotEqual(ARCHIVE["validate_runtime_depends"]("libc6,libmnl0"),
                            ARCHIVE["validate_runtime_depends"]("libc6, libcap2"))
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

    # ---- TB11 (slice B): the agent template unit in the package guard ----
    # Capability: the guard refuses any agent drop-in, alternate fragment,
    # alias or instance enablement, and any package operation while an agent
    # instance runs. Register ids: LINUX-AGENT-BOOT-AUTOSTART-01,
    # defect.linux-no-agent-launcher-assigns-or-drops-to-the-agent-uid.

    def systemd_tree(self, build):
        """Run systemd_files(False) over one temporary unit root built by `build`."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "etc-systemd-system"
            root.mkdir()
            build(root)
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
                "AGENT_UNIT_PATH": str(root / "sanctuary-agent@.service"),
            }):
                GUARD["systemd_files"](False)

    def test_agent_unit_drop_ins_fragments_aliases_and_enablement_refuse(self):
        def template_drop_in(root):
            (root / "sanctuary-agent@.service.d").mkdir()

        def instance_drop_in(root):
            (root / "sanctuary-agent@60123.service.d").mkdir()

        def instance_enablement(root):
            wants = root / "multi-user.target.wants"
            wants.mkdir()
            (wants / "sanctuary-agent@60123.service").symlink_to("/etc/systemd/system/sanctuary-agent@.service")

        def alternate_fragment(root):
            (root / "sanctuary-agent@60123.service").write_text("[Service]\nExecStart=/bin/true\n")

        def alias(root):
            (root / "agent-alias.service").symlink_to("/etc/systemd/system/sanctuary-agent@.service")

        for name, build, message in (
            ("template drop-in dir", template_drop_in, "agent unit drop-in directory present"),
            ("instance drop-in dir", instance_drop_in, "agent unit drop-in directory present"),
            ("instance enablement symlink", instance_enablement, "alternate agent unit, alias or instance enablement"),
            ("alternate fragment", alternate_fragment, "alternate agent unit, alias or instance enablement"),
            ("alias symlink", alias, "agent unit alias or enablement symlink"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(GUARD["Refusal"], message):
                self.systemd_tree(build)
        # The package's own template is allowed while the package is installed
        # (installed=True does not refuse its presence).
        self.systemd_tree(lambda root: None)

    def instances(self, stdout, returncode=0):
        result = SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
        with patch.object(GUARD["command_allow_empty"].__globals__["subprocess"], "run", return_value=result):
            GUARD["agent_instances_inactive"]()

    def test_agent_instance_probe_passes_a_clean_host_and_refuses_a_live_instance(self):
        self.instances("")  # clean host: no loaded instance, return code 0
        self.instances("sanctuary-agent@60123.service loaded inactive dead Sanctuary confined agent (uid 60123)\n")
        self.instances("sanctuary-agent@60123.service loaded failed failed x\n")
        for state in ("active", "activating", "deactivating", "reloading", "refreshing"):
            with self.subTest(state=state), self.assertRaisesRegex(GUARD["Refusal"], "agent instance not inactive"):
                self.instances(f"sanctuary-agent@60123.service loaded {state} running x\n")
        for bad in ("garbage\n", "sanctuary-agent@60123.service loaded\n", "other.service loaded active running x\n"):
            with self.subTest(bad=bad), self.assertRaisesRegex(GUARD["Refusal"], "unparseable agent instance listing"):
                self.instances(bad)
        with self.assertRaisesRegex(GUARD["Refusal"], "probe failed or incomplete"):
            self.instances("", returncode=1)
        # Through command() a clean host would refuse (empty stdout): the
        # sibling runner is what makes "no instance" a pass.
        with patch.object(GUARD["command"].__globals__["subprocess"], "run",
                          return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["command"](["/usr/bin/systemctl"])

    def test_command_allow_empty_has_exactly_one_caller(self):
        source = Path(__file__).with_name("lifecycle-guard.py").read_text()
        calls = [m.start() for m in re.finditer(r"command_allow_empty\(", source)]
        definition = source.index("def command_allow_empty(")
        callers = [at for at in calls if at != definition + len("def ")]
        self.assertEqual(len(callers), 1, "command_allow_empty must have exactly one caller")
        caller_fn = re.findall(r"^def (\w+)\(", source[:callers[0]], re.M)[-1]
        self.assertEqual(caller_fn, "agent_instances_inactive")

    def test_installed_identity_binds_the_agent_unit(self):
        identity = {"package_version": "1.0-2", "daemon_sha256": "a" * 64, "unit_sha256": "b" * 64,
                    "agent_unit_sha256": "c" * 64}
        hashes = {GUARD["DAEMON_PATH"]: "a" * 64, GUARD["UNIT_PATH"]: "b" * 64, GUARD["AGENT_UNIT_PATH"]: "c" * 64}
        fields = {"Architecture": "amd64", "Version": "1.0-2"}
        globals_ = GUARD["installed_identity"].__globals__
        with patch.dict(globals_, {"build_identity": lambda: identity, "hash_file": lambda p: hashes[p]}):
            GUARD["installed_identity"](fields, "prerm")
        with patch.dict(globals_, {"build_identity": lambda: identity,
                                   "hash_file": lambda p: "d" * 64 if p == GUARD["AGENT_UNIT_PATH"] else hashes[p]}):
            with self.assertRaisesRegex(GUARD["Refusal"], "installed payload differs"):
                GUARD["installed_identity"](fields, "preinst")
        with patch.dict(globals_, {"build_identity": lambda: dict(identity, agent_unit_sha256="d" * 64),
                                   "hash_file": lambda p: "d" * 64 if p == GUARD["AGENT_UNIT_PATH"] else hashes[p]}):
            with self.assertRaisesRegex(GUARD["Refusal"], "old hook does not match"):
                GUARD["installed_identity"](fields, "prerm")

    def test_a_pre_b_install_is_refused_on_upgrade_for_the_absent_agent_unit(self):
        # PAYLOAD carries the agent unit, so an installed package without it
        # refuses as a required file absent, before any other check.
        self.assertIn(GUARD["AGENT_UNIT_PATH"], GUARD["PAYLOAD"])
        with patch.dict(GUARD["checked_file"].__globals__, {
            "check_ancestors": lambda *_: True,
            "lstat": lambda p: None if p == GUARD["AGENT_UNIT_PATH"] else SimpleNamespace(st_mode=0o100755, st_uid=0),
        }):
            with self.assertRaisesRegex(GUARD["Refusal"], "required package file absent"):
                for path in GUARD["PAYLOAD"]:
                    GUARD["checked_file"](path, True)

    # ---- TB11: the source-constants pin's declared partition ---------------

    def constants_copy(self, mutate=None):
        crate = Path(__file__).resolve().parent.parent.parent
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "castle-wall-daemon"
            for rel in ("packaging/ubuntu/assert-source-constants.py", "packaging/ubuntu/lifecycle-guard.py",
                        "systemd/sanctuary-castle-wall.service", "systemd/sanctuary-agent@.service",
                        "src/config.rs", "src/ownership_journal.rs", "src/runtime_lock.rs", "src/nftables.rs"):
                (copy / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(crate / rel, copy / rel)
            if mutate:
                mutate(copy)
            return subprocess.run(["python3", str(copy / "packaging/ubuntu/assert-source-constants.py")],
                                  capture_output=True, text=True, check=False)

    @staticmethod
    def replace_once(path, old, new):
        text = path.read_text()
        if text.count(old) != 1:
            raise AssertionError(f"mutation anchor {old!r} occurs {text.count(old)} times")
        path.write_text(text.replace(old, new))

    def test_source_constants_partition_and_agent_checks(self):
        result = self.constants_copy()
        self.assertEqual(result.returncode, 0, result.stderr)  # today's guard plus the agent unit passes
        agent = "systemd/sanctuary-agent@.service"
        gate = "ExecStartPre=+/usr/local/libexec/sanctuary/castle-wall-daemon --agent-start-gate"
        check = "ExecStartPre=/usr/local/libexec/sanctuary/castle-wall-daemon --agent-credential-check"
        cases = (
            ("BindsTo= names another unit", lambda c: self.replace_once(
                c / agent, "BindsTo=sanctuary-castle-wall.service", "BindsTo=other.service"), "BindsTo"),
            ("check path differs", lambda c: self.replace_once(
                c / agent, check, check.replace("castle-wall-daemon", "other-daemon")), "credential-check"),
            ("gate path differs", lambda c: self.replace_once(
                c / agent, gate, gate.replace("castle-wall-daemon", "other-daemon")), "start-gate"),
            ("gate '+' doubled", lambda c: self.replace_once(
                c / agent, gate, gate.replace("=+/", "=++/")), "start-gate"),
            ("gate '+' removed", lambda c: self.replace_once(
                c / agent, gate, gate.replace("=+/", "=/")), "start-gate"),
            ("guard path constant in neither set", lambda c: self.replace_once(
                c / "packaging/ubuntu/lifecycle-guard.py", 'INFO_PATH = "/var/lib/dpkg/info"\n',
                'INFO_PATH = "/var/lib/dpkg/info"\nEXTRA_PATH = "/etc/extra"\n'), "declared partition"),
            ("SOURCE_MIRRORED differs from expected", lambda c: self.replace_once(
                c / "packaging/ubuntu/assert-source-constants.py", '"NFT_TABLE", "AGENT_UNIT_PATH",',
                '"NFT_TABLE",'), "SOURCE_MIRRORED differs"),
        )
        for name, mutate, message in cases:
            with self.subTest(name=name):
                result = self.constants_copy(mutate)
                self.assertNotEqual(result.returncode, 0, f"{name} was accepted")
                self.assertIn(message, result.stderr)

    # ---- TB11: the archive assertion over a synthetic package --------------

    def synthetic_package(self):
        crate = Path(__file__).resolve().parent.parent.parent
        guard = Path(__file__).with_name("lifecycle-guard.py").read_bytes()
        daemon = b"\x7fELF fixture"
        unit = (crate / "systemd/sanctuary-castle-wall.service").read_bytes()
        agent = (crate / "systemd/sanctuary-agent@.service").read_bytes()
        sha = lambda data: hashlib.sha256(data).hexdigest()
        identity = {
            "artifact_kind": "internal-structural-deb", "install_ready": "false",
            "package": "sanctuary-castle-wall-internal", "package_version": "0.1.0-1",
            "source_commit": "0" * 40, "cargo_lock_sha256": "1" * 64, "rustc_version": "rustc 1.95.0",
            "daemon_sha256": sha(daemon), "unit_source": "castle-wall-daemon/systemd/sanctuary-castle-wall.service",
            "unit_sha256": sha(unit), "agent_unit_source": "castle-wall-daemon/systemd/sanctuary-agent@.service",
            "agent_unit_sha256": sha(agent), "runtime_depends": "libc6", "pre_depends": "systemd, nftables, python3",
        }
        header = lambda role, ident: (
            "#!/usr/bin/python3\n" f'ROLE = "{role}"\n' 'PACKAGE_VERSION = "0.1.0-1"\n'
            f'DAEMON_SHA256 = "{ident["daemon_sha256"]}"\n' f'UNIT_SHA256 = "{ident["unit_sha256"]}"\n'
            f'AGENT_UNIT_SHA256 = "{ident["agent_unit_sha256"]}"\n').encode() + guard
        payload = {
            "usr/local/libexec/sanctuary/castle-wall-daemon": (0o755, daemon),
            "etc/systemd/system/sanctuary-castle-wall.service": (0o644, unit),
            "etc/systemd/system/sanctuary-agent@.service": (0o644, agent),
        }
        return {"identity": identity, "payload": payload, "header": header}

    def run_archive(self, model):
        identity = model["identity"]
        payload = dict(model["payload"])
        payload["usr/share/doc/sanctuary-castle-wall-internal/build-identity"] = (
            0o644, "".join(f"{k}={v}\n" for k, v in identity.items()).encode())

        def entries(files, dirs):
            out = {}
            for name, (mode, data) in files.items():
                info = tarfile.TarInfo(name)
                info.mode, info.size = mode, len(data)
                out[name] = (info, data)
            for name in dirs:
                info = tarfile.TarInfo(name)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                out[name] = (info, b"")
            return out

        control = entries({"control": (0o644, b""), "preinst": (0o755, model["header"]("preinst", identity)),
                           "prerm": (0o755, model["header"]("prerm", identity))}, set())
        fsys = entries(payload, ARCHIVE["PAYLOAD_DIRS"])
        fields = {"Package": "sanctuary-castle-wall-internal", "Architecture": "amd64", "Version": "0.1.0-1",
                  "Pre-Depends": "systemd, nftables, python3", "Depends": "libc6"}
        with patch.dict(ARCHIVE["main"].__globals__, {
            "archive": lambda _deb, option: control if option == "--ctrl-tarfile" else fsys,
            "field": lambda _deb, name: fields[name],
        }):
            ARCHIVE["main"](Path("synthetic.deb"))

    def test_archive_assertion_requires_the_agent_unit_leaf_identity_and_header_order(self):
        self.run_archive(self.synthetic_package())  # the complete synthetic package passes

        def without_agent(model):
            del model["payload"]["etc/systemd/system/sanctuary-agent@.service"]

        def agent_bytes_differ(model):
            data = model["payload"]["etc/systemd/system/sanctuary-agent@.service"][1] + b"# drift\n"
            model["payload"]["etc/systemd/system/sanctuary-agent@.service"] = (0o644, data)
            model["identity"]["agent_unit_sha256"] = hashlib.sha256(data).hexdigest()

        def identity_without_agent_sha(model):
            del model["identity"]["agent_unit_sha256"]
            model["header"] = lambda role, ident: b""

        def header_out_of_order(model):
            original = model["header"]

            def swapped(role, ident):
                text = original(role, ident).decode()
                lines = text.split("\n")
                unit_at = next(i for i, l in enumerate(lines) if l.startswith("UNIT_SHA256"))
                lines[unit_at], lines[unit_at + 1] = lines[unit_at + 1], lines[unit_at]
                return "\n".join(lines).encode()
            model["header"] = swapped

        for name, mutate, message in (
            ("package without the agent unit", without_agent, "archive allowlist mismatch"),
            ("agent unit bytes differ from source", agent_bytes_differ, "agent unit differs from exact source bytes"),
            ("identity without agent_unit_sha256", identity_without_agent_sha, "build identity field allowlist mismatch"),
            ("AGENT_UNIT_SHA256 out of order", header_out_of_order, "preinst is not the exact source guard"),
        ):
            with self.subTest(name=name):
                model = self.synthetic_package()
                mutate(model)
                with self.assertRaisesRegex(ValueError, message):
                    self.run_archive(model)

    def test_unknown_actions_refuse(self):
        globals_ = GUARD["main"].__globals__
        with patch.dict(globals_, {"ROLE": "preinst", "os": type("Root", (), {"geteuid": staticmethod(lambda: 0)})}):
            with self.assertRaises(GUARD["Refusal"]):
                GUARD["main"](["install", "old", "new"])


if __name__ == "__main__":
    unittest.main()
