#!/usr/bin/env python3
"""Counterexamples against exact built package bytes. LINUX-INSTALL-P1."""
from pathlib import Path
import copy
import hashlib
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ARCHIVE = runpy.run_path(str(HERE / 'assert-install-archive.py'))
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
DEB = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else None
SOURCE = sys.argv.pop(1) if len(sys.argv) > 1 else None


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if DEB is None or SOURCE is None:
            raise ValueError('usage: test-install-archive.py <install-deb> <expected-source>')
        ARCHIVE['main'](DEB, SOURCE)
        cls.payload = ARCHIVE['archive'](DEB, '--fsys-tarfile')
        cls.control = ARCHIVE['archive'](DEB, '--ctrl-tarfile')
        cls.raw = cls.payload[LAYOUT['IDENTITY']][1]
        cls.identity = ARCHIVE['parse_identity'](cls.raw, SOURCE)

    def check_identity_refused(self, transform):
        obj = copy.deepcopy(self.identity)
        transform(obj)
        with self.assertRaises(ValueError):
            ARCHIVE['parse_identity'](json.dumps(obj).encode(), SOURCE)

    def test_variant_source_and_features_are_caller_bound(self):
        for key, value in (('install_ready', False), ('install_ready', 'true'), ('package', 'sanctuary-castle-wall-internal'),
                           ('artifact_kind', 'internal-structural-deb'), ('source_commit', '0' * 40),
                           ('features', ['test-isolation']), ('features', None), ('target', 'aarch64-unknown-linux-gnu'),
                           ('rustc_version', 'rustc 1.94.0 (fixture)')):
            with self.subTest(key=key, value=value):
                self.check_identity_refused(lambda o: o.update({key: value}))
        self.check_identity_refused(lambda o: o['payload_sha256'].pop('usr/sbin/sanctuary-linux'))
        self.check_identity_refused(lambda o: o.update({'extra': True}))
        with self.assertRaises(ValueError):
            ARCHIVE['parse_identity'](self.raw.replace(b'"install_ready": true', b'"install_ready": true, "install_ready": true'), SOURCE)

    def test_internal_parser_refuses_true_and_install_payload(self):
        internal = runpy.run_path(str(HERE / 'assert-archive.py'))
        with self.assertRaises(ValueError):
            internal['main'](DEB)
        original = b'\n'.join(f'{k}={v}'.encode() for k, v in {
            'artifact_kind': 'internal-structural-deb', 'install_ready': 'true',
            'package': 'sanctuary-castle-wall-internal', 'package_version': '0.1.0-1',
            'source_commit': SOURCE, 'daemon_sha256': 'a'*64, 'unit_sha256': 'a'*64,
            'agent_unit_sha256': 'a'*64, 'cargo_lock_sha256': 'a'*64,
            'runtime_depends': 'libc6', 'pre_depends': 'systemd, nftables, python3',
            'unit_source': 'x', 'agent_unit_source': 'x', 'rustc_version': 'x',
        }.items())
        with self.assertRaisesRegex(ValueError, 'kind/readiness'):
            internal['parse_identity'](original)
        guard = runpy.run_path(str(HERE / 'lifecycle-guard.py'))
        with patch.dict(guard['build_identity'].__globals__, {'checked_file': lambda *_: None, 'stable_read': lambda *_: original}):
            with self.assertRaisesRegex(guard['Refusal'], 'unbound'):
                guard['build_identity']()

    def test_payload_custody_control_and_hash_counterexamples(self):
        for kind in ('missing-binary', 'extra-config', 'hardlink', 'symlink', 'setuid', 'group-owner',
                     'wrong-unit', 'wrong-schema', 'guard-change', 'missing-dependency', 'wrong-architecture', 'wrong-conflict'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='install-negative-') as tmp:
                root = Path(tmp) / 'stage'
                subprocess.run(['dpkg-deb', '--raw-extract', str(DEB), str(root)], check=True, stdout=subprocess.DEVNULL)
                cli = root / 'usr/sbin/sanctuary-linux'
                control = root / 'DEBIAN/control'
                if kind == 'missing-binary':
                    cli.unlink()
                elif kind == 'extra-config':
                    (root / 'etc/sanctuary').mkdir()
                    (root / 'etc/sanctuary/configured').write_text('fixture')
                elif kind == 'hardlink':
                    cli.unlink()
                    os.link(root / 'usr/local/libexec/sanctuary/protected-agent-v1', cli)
                elif kind == 'symlink':
                    cli.unlink()
                    cli.symlink_to('/bin/false')
                elif kind == 'setuid':
                    cli.chmod(0o4755)
                elif kind == 'group-owner':
                    os.chown(cli, 0, 1)
                elif kind == 'wrong-unit':
                    (root / 'etc/systemd/system/sanctuary-agent@.service').write_text('fixture')
                elif kind == 'wrong-schema':
                    (root / LAYOUT['DOC'] / 'schemas/contract.rs').write_text('fixture')
                elif kind == 'guard-change':
                    with (root / 'DEBIAN/prerm').open('a') as stream:
                        stream.write('\n# fixture\n')
                elif kind == 'missing-dependency':
                    control.write_text('\n'.join('Depends: libc6' if line.startswith('Depends:') else line for line in control.read_text().splitlines()) + '\n')
                elif kind == 'wrong-architecture':
                    control.write_text(control.read_text().replace('Architecture: amd64', 'Architecture: arm64'))
                elif kind == 'wrong-conflict':
                    control.write_text(control.read_text().replace('Conflicts: sanctuary-castle-wall-internal', 'Conflicts: other'))
                mutated = Path(tmp) / 'mutated.deb'
                # Keep owner mutation; this test itself runs only on a disposable root runner.
                subprocess.run(['dpkg-deb', '--build', str(root), str(mutated)], check=True, stdout=subprocess.DEVNULL)
                with self.assertRaises(ValueError):
                    ARCHIVE['main'](mutated, SOURCE)


if __name__ == '__main__':
    unittest.main()
