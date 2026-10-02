#!/usr/bin/env python3
"""Closed install packaging, custody and lifecycle contracts. LINUX-INSTALL-P1."""
import hashlib
import io
import os
from pathlib import Path
import runpy
import stat
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
ARCHIVE = runpy.run_path(str(HERE / 'assert-install-archive.py'))
HEADER = {'ROLE': 'preinst', 'PACKAGE_VERSION': '0.1.0-1',
          'IDENTITY_SHA256': 'a' * 64, 'PAYLOAD_MODES': LAYOUT['PAYLOAD_FILES'],
          'PAYLOAD_HASHES': {p: 'b' * 64 for p in LAYOUT['PAYLOAD_FILES']}}
GUARD = runpy.run_path(str(HERE / 'install-lifecycle-guard.py'), init_globals=HEADER)


class InstallTests(unittest.TestCase):
    def test_internal_identity_remains_closed(self):
        internal = runpy.run_path(str(HERE / 'assert-archive.py'))
        for value in ('true', 'false'):
            with self.assertRaises(ValueError):
                internal['parse_identity'](f'install_ready={value}\npackage=sanctuary-castle-wall\n'.encode())

    def test_exact_payload_includes_three_binaries_mount_and_shared_schema(self):
        files = LAYOUT['PAYLOAD_FILES']
        for name in ('usr/sbin/sanctuary-linux', 'usr/local/libexec/sanctuary/protected-agent-v1',
                     'usr/local/libexec/sanctuary/network-agent-standin',
                     r'etc/systemd/system/var-lib-sanctuary\x2dagent\x2dworkspace.mount',
                     'usr/share/doc/sanctuary-castle-wall/schemas/contract.rs'):
            self.assertIn(name, files)
        self.assertFalse(any(p.startswith('etc/sanctuary/') for p in files))
        self.assertEqual(len(files), 10)

    def test_only_cold_install_remove_and_abort_are_admitted(self):
        fn = GUARD['main']
        for role, args in (('preinst', ['upgrade', '0.1.0-1', '0.1.0-2']),
                           ('prerm', ['upgrade', '0.1.0-2']), ('prerm', ['failed-upgrade', '0.1.0-2']),
                           ('preinst', ['install', '0.1.0-1']), ('prerm', ['deconfigure']),
                           ('preinst', ['abort-upgrade'])):
            with self.subTest(role=role, args=args), patch.dict(fn.__globals__, {'ROLE': role, 'inspect': lambda *_: None}), patch('os.geteuid', return_value=0):
                with self.assertRaises(GUARD['Refusal']):
                    fn(args)
        for role, args, calls in (('preinst', ['install'], 1), ('prerm', ['remove'], 1),
                                  ('preinst', ['abort-upgrade', '0.1.0-2'], 0)):
            with patch.dict(fn.__globals__, {'ROLE': role}), patch('os.geteuid', return_value=0), patch.dict(fn.__globals__, {'inspect': unittest.mock.Mock()}) as scope:
                fn(args)
                self.assertEqual(scope['inspect'].call_count, calls)

    def test_package_custody_requires_single_link_exact_mode_and_root_group(self):
        fn = GUARD['checked_file']
        path = '/usr/sbin/sanctuary-linux'
        good = dict(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0, st_nlink=1)
        for delta in ({'st_nlink': 2}, {'st_gid': 1}, {'st_mode': stat.S_IFREG | 0o4755},
                      {'st_mode': stat.S_IFREG | 0o644}, {'st_mode': stat.S_IFLNK | 0o755}):
            with self.subTest(delta=delta), patch.dict(fn.__globals__, {
                'check_ancestors': lambda _: True, 'lstat': lambda _: SimpleNamespace(**(good | delta))}):
                with self.assertRaises(GUARD['Refusal']):
                    fn(path, True)
        with patch.dict(fn.__globals__, {'check_ancestors': lambda _: True, 'lstat': lambda _: SimpleNamespace(**good)}):
            self.assertIsNotNone(fn(path, True))

    def test_install_identity_is_exact_and_hook_bound(self):
        fn = GUARD['build_identity']
        raw = b'install_ready=true\n'
        with patch.dict(fn.__globals__, {'checked_file': lambda *_: None, 'stable_read': lambda *_: raw}):
            with self.assertRaises(GUARD['Refusal']):
                fn()

    def test_product_config_and_workspace_refuse_even_when_stopped(self):
        fn = GUARD['runtime_absent']
        for retained in ('/etc/sanctuary', '/var/lib/sanctuary', '/run/sanctuary'):
            seen = []
            def empty(path):
                seen.append(path)
                if path == retained:
                    raise GUARD['Refusal']('retained fixture')
            with self.subTest(retained=retained), patch.dict(fn.__globals__, {
                'empty_runtime_root': empty, 'lstat': lambda _: None, 'mount_absent': lambda: None}):
                with self.assertRaises(GUARD['Refusal']):
                    fn()
        with patch.dict(fn.__globals__, {'empty_runtime_root': lambda _: None,
                                        'lstat': lambda _: SimpleNamespace(), 'mount_absent': lambda: None}):
            with self.assertRaises(GUARD['Refusal']):
                fn()

    def test_conflicting_internal_package_refuses(self):
        fn = GUARD['dpkg_status']
        raw = b'Package: sanctuary-castle-wall-internal\nStatus: install ok installed\nArchitecture: amd64\nVersion: 0.1.0-1\n'
        with patch.dict(fn.__globals__, {'checked_file': lambda *_: None, 'stable_read': lambda *_: raw}):
            with self.assertRaises(GUARD['Refusal']):
                fn()

    def test_archive_metadata_rejects_capabilities_and_path_aliases(self):
        fn = ARCHIVE['archive']
        for name, pax in (('./usr/../usr/file', {}), ('/usr/file', {}), ('./usr/file', {'SCHILY.xattr.security.capability': 'x'})):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as tar:
                entry = tarfile.TarInfo(name)
                entry.mode = 0o644
                entry.pax_headers = pax
                tar.addfile(entry, io.BytesIO())
            with self.subTest(name=name, pax=pax), patch.object(fn.__globals__['subprocess'], 'run', return_value=SimpleNamespace(stdout=stream.getvalue())):
                with self.assertRaises(ValueError):
                    fn(Path('fixture.deb'), '--fsys-tarfile')


if __name__ == '__main__':
    unittest.main()
