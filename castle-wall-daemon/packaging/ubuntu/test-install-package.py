#!/usr/bin/env python3
"""Closed install packaging, custody and lifecycle contracts. LINUX-INSTALL-P1."""
import hashlib
import io
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import time
import json
from contextlib import nullcontext
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
HEADER.update(runpy.run_path(str(HERE / 'bounded-process.py')))
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
        raw = json.dumps({'package': 'sanctuary-castle-wall', 'artifact_kind': 'ubuntu-install-deb-v1', 'install_ready': True, 'package_version': '0.1.0-1', 'payload_sha256': HEADER['PAYLOAD_HASHES']}).encode()
        with patch.dict(fn.__globals__, {'checked_file': lambda *_: None, 'stable_read': lambda *_: raw}):
            with self.assertRaises(GUARD['Refusal']):
                fn()

    def test_product_config_and_workspace_refuse_even_when_stopped(self):
        fn = GUARD['runtime_absent']
        for retained in ('/etc/sanctuary', '/var/lib/sanctuary', '/run/sanctuary', '/var/lib/sanctuary-agent-workspace'):
            seen = []
            def empty(path):
                seen.append(path)
                if path == retained:
                    raise GUARD['Refusal']('retained fixture')
            with self.subTest(retained=retained), patch.dict(fn.__globals__, {
                'empty_runtime_root': empty, 'lstat': lambda _: None, 'mount_absent': lambda: None, 'accounts_absent': lambda: None, 'legacy_agent_state_absent': lambda: None}):
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
            with self.subTest(name=name, pax=pax), patch.dict(fn.__globals__, {'bounded_capture': lambda *a, **k: (0, stream.getvalue(), b'')}):
                with self.assertRaises(ValueError):
                    fn(Path('fixture.deb'), '--fsys-tarfile')

    def test_probe_output_and_time_are_bounded(self):
        capture = HEADER['bounded_capture']
        self.assertEqual(capture([sys.executable, '-c', 'print("ok")'], timeout=2, limit=4096), (0, b'ok\n', b''))
        for script in ('print("x" * 4097)', 'import sys; sys.stderr.write("x" * 4097)'):
            with self.assertRaisesRegex(ValueError, 'output cap'):
                capture([sys.executable, '-c', script], timeout=2, limit=4096)
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'deadline'):
            capture([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.1, limit=4096)
        self.assertLess(time.monotonic() - start, 1)

    def test_stable_read_refuses_links_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'file'
            path.write_bytes(b'12345')
            self.assertEqual(GUARD['stable_read'](path, 5), b'12345')
            with self.assertRaises(GUARD['Refusal']):
                GUARD['stable_read'](path, 4)
            link = Path(temp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(GUARD['Refusal']):
                GUARD['stable_read'](link, 5)

    def test_jobs_and_mounts_require_positive_absence(self):
        fn = GUARD['no_queued_jobs']
        for text in ('1 sanctuary-agent@60123.service start waiting\n', '1 ' + GUARD['MOUNT_NAME'] + ' start running\n', 'incomplete'):
            with patch.dict(fn.__globals__, {'command_allow_empty': lambda _: text}):
                with self.assertRaises(GUARD['Refusal']):
                    fn()
        with patch.dict(fn.__globals__, {'command_allow_empty': lambda _: ''}):
            fn()
        fn = GUARD['mount_absent']
        for raw in (b'1 0 0:1 / /var/lib/sanctuary-agent-workspace rw - tmpfs tmpfs rw\n', b'bad'):
            with patch.dict(fn.__globals__, {'stable_read': lambda *_: raw}):
                with self.assertRaises(GUARD['Refusal']):
                    fn()


    def test_ci_inventory_rejects_missing_skipped_cancelled_and_wrong_head(self):
        module = runpy.run_path(str(HERE / 'record-install-ci.py'))
        head = 'a' * 40
        good = {job: {'result': 'success'} for job in module['PACKAGE_JOBS']}
        env = {'INSTALL_SOURCE_SHA': head, 'INSTALL_ARTIFACT_ID': '123', 'INSTALL_ARTIFACT_DIGEST': 'b' * 64,
               'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_WORKFLOW_SHA': 'd' * 40}
        workflow = (module['REPO'] / module['WORKFLOW']).read_bytes()
        # Model git's text SHA and binary workflow separately; never inherit the runner event.
        def git_output(argv, **kwargs):
            return head if argv[-2:] == ['rev-parse', 'HEAD'] else workflow
        with tempfile.TemporaryDirectory() as temp, patch.object(module['subprocess'], 'check_output', side_effect=git_output), patch.dict(os.environ, env, clear=True):
            output = Path(temp) / 'record.json'
            for bad in ('skipped', 'cancelled', 'failure', None):
                needs = {k: dict(v) for k, v in good.items()}
                if bad is None:
                    needs.pop('install-rust')
                else:
                    needs['install-rust']['result'] = bad
                with patch.dict(os.environ, {'INSTALL_NEEDS': __import__('json').dumps(needs)}):
                    with self.assertRaisesRegex(ValueError, 'required package job'):
                        module['record'](output, True)
            with patch.dict(os.environ, {'INSTALL_NEEDS': __import__('json').dumps(good)}):
                module['record'](output, True)
                with patch.object(module['subprocess'], 'check_output', side_effect=[head, workflow + b'\n']):
                    with self.assertRaisesRegex(ValueError, 'executed workflow differs'):
                        module['record'](output, True)
                with patch.dict(os.environ, {'INSTALL_ARTIFACT_DIGEST': ''}):
                    with self.assertRaisesRegex(ValueError, 'digest missing'):
                        module['record'](output, True)
                with patch.dict(os.environ, {'INSTALL_SOURCE_SHA': 'c' * 40}):
                    with self.assertRaisesRegex(ValueError, 'exact source head'):
                        module['record'](output, True)


    def test_existing_or_indeterminate_product_account_refuses(self):
        fn = GUARD['accounts_absent']
        for result in ((0, b'sanctuary:x:123:', b''), (1, b'', b''), (2, b'partial', b''), (2, b'', b'NSS failed')):
            with patch.dict(fn.__globals__, {'bounded_capture': lambda *a, **k: result}):
                with self.assertRaises(GUARD['Refusal']):
                    fn()
        with patch.dict(fn.__globals__, {'command_allow_empty': lambda _: '', 'bounded_capture': lambda *a, **k: (2, b'', b'')}):
            fn()

    def test_agent_unknown_or_failed_state_is_not_inactive(self):
        fn = GUARD['agent_instances_inactive']
        for state in ('active running', 'failed failed', 'mystery dead', 'inactive exited'):
            with patch.dict(fn.__globals__, {'command_allow_empty': lambda _: 'sanctuary-agent@60123.service loaded ' + state + ' description'}):
                with self.assertRaises(GUARD['Refusal']):
                    fn()
        with patch.dict(fn.__globals__, {'command_allow_empty': lambda _: 'sanctuary-agent@60123.service loaded inactive dead description'}):
            fn()


    def test_merged_usr_dependency_requires_same_unique_owner(self):
        deps = runpy.run_path(str(HERE / 'install-dependencies.py'))
        fn = deps['owner']
        canonical, alias = '/usr/bin/ip', '/bin/ip'
        def query(argv, **kw):
            if argv[-1] == canonical:
                return SimpleNamespace(returncode=1, stdout='', stderr='dpkg-query: no path found matching pattern /usr/bin/ip\n')
            return SimpleNamespace(returncode=0, stdout='iproute2: /bin/ip\n', stderr='')
        with patch.dict(fn.__globals__, {'Path': lambda _: SimpleNamespace(resolve=lambda **kw: canonical)}), patch.object(deps['subprocess'], 'run', side_effect=query):
            self.assertEqual(fn('/usr/sbin/ip'), 'iproute2')
        with patch.dict(fn.__globals__, {'Path': lambda _: SimpleNamespace(resolve=lambda **kw: canonical)}), patch.object(deps['subprocess'], 'run', return_value=SimpleNamespace(returncode=0, stdout='diversion by other\n', stderr='')):
            with self.assertRaises(ValueError):
                fn('/usr/sbin/ip')

    def test_indirect_agent_alias_is_refused_by_resolved_destination(self):
        fn = GUARD['systemd_files']
        root = '/etc/systemd/system'
        safe_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        with patch.dict(fn.__globals__, {
            'SYSTEMD_ROOTS': (root,), 'command': lambda _: root,
            'check_ancestors': lambda _: True,
            'lstat': lambda p: link if str(p).endswith('/unrelated.service') else safe_dir,
        }), patch.object(os, 'walk', return_value=[(root, [], ['unrelated.service'])]), patch.object(os, 'readlink', return_value='/outside/alias'), patch.object(os.path, 'realpath', return_value=GUARD['AGENT_UNIT_PATH']):
            with self.assertRaises(GUARD['Refusal']):
                fn(True)


    def test_legacy_agent_state_refuses(self):
        fn = GUARD['legacy_agent_state_absent']
        for parent in ('/var/lib', '/run'):
            def scan(path):
                entries = [SimpleNamespace(name='sanctuary-agent-60123', path=parent + '/sanctuary-agent-60123')] if path == parent else []
                return nullcontext(iter(entries))
            with patch.object(os, 'scandir', side_effect=scan):
                with self.assertRaises(GUARD['Refusal']):
                    fn()

    def test_inherited_dropins_refuse_before_manager_reload(self):
        fn = GUARD['systemd_files']
        root = '/etc/systemd/system'
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        for name in ('service.d', 'mount.d', 'sanctuary-.service.d', 'sanctuary-castle-.service.d', 'var-.mount.d', 'var-lib-.mount.d'):
            with self.subTest(name=name), patch.dict(fn.__globals__, {
                'SYSTEMD_ROOTS': (root,), 'command': lambda _: root,
                'check_ancestors': lambda _: True, 'lstat': lambda _: info,
            }), patch.object(os, 'walk', return_value=[(root, [name], [])]):
                with self.assertRaises(GUARD['Refusal']):
                    fn(True)

    def inspect_fixtures(self, installed):
        return {
            'ROLE': 'prerm' if installed else 'preinst',
            'dpkg_status': lambda: ({'Version': '0.1.0-1'}, ['install', 'ok', 'installed']) if installed else None,
            'package_owners': lambda: {}, 'checked_file': lambda *a: None, 'require_owners': lambda *a: None,
            'installed_identity': lambda *a: {'fixture': 'stable'}, 'systemd_files': lambda *a: None,
            'systemd_manager': lambda *a: {'NeedDaemonReload': 'no'}, 'agent_instances_inactive': lambda: None,
            'no_queued_jobs': lambda: None, 'runtime_absent': lambda: None, 'nft_absent': lambda: None,
            'lstat': lambda *a: None,
        }

    def test_second_observation_refuses_manager_or_payload_churn(self):
        fn = GUARD['inspect']
        with patch.dict(fn.__globals__, self.inspect_fixtures(True)):
            self.assertEqual(fn(True, 'remove', '0.1.0-1'), {'fixture': 'stable'})
        for site in ('mount', 'wall', 'identity'):
            fixture = self.inspect_fixtures(True)
            if site == 'identity':
                fixture['installed_identity'] = unittest.mock.Mock(side_effect=[{'fixture': 'stable'}, {'fixture': 'changed'}])
            else:
                rows = [{'NeedDaemonReload': 'no'} for _ in range(4)]
                rows[3 if site == 'mount' else 2] = {'NeedDaemonReload': 'yes'}
                fixture['systemd_manager'] = unittest.mock.Mock(side_effect=rows)
            with self.subTest(site=site), patch.dict(fn.__globals__, fixture):
                with self.assertRaises(GUARD['Refusal']):
                    fn(True, 'remove', '0.1.0-1')
        fixture = self.inspect_fixtures(False)
        fixture['lstat'] = unittest.mock.Mock(side_effect=[None] * len(GUARD['PAYLOAD']) + [SimpleNamespace()])
        with patch.dict(fn.__globals__, fixture):
            with self.assertRaises(GUARD['Refusal']):
                fn(False, 'install')


    def test_guard_path_set_matches_canonical_sources(self):
        LAYOUT['check_guard_paths'](HERE)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            for file in ('install-lifecycle-guard.py', 'lifecycle-guard.py'):
                (target / file).write_bytes((HERE / file).read_bytes())
            guard = target / 'install-lifecycle-guard.py'
            original = guard.read_text()
            for changed in (original.replace('NFT_TABLE = "sanctuary-castle"', 'NFT_TABLE = "other"'),
                            original + '\nEXTRA_PATH = "/unexpected"\n'):
                guard.write_text(changed)
                with self.assertRaises(ValueError):
                    LAYOUT['check_guard_paths'](target)


    def test_runtime_refusal_cannot_be_a_generic_startup_failure(self):
        runtime = runpy.run_path(str(HERE / 'assert-install-runtime.py'))
        fn = runtime['classify_refusal']
        flag = '--isolated-runtime-root'
        self.assertEqual(fn('castle-wall-daemon', flag, 2, 'unknown argument: ' + flag), 'unknown-argument')
        with self.assertRaises(ValueError):
            fn('sanctuary-linux', flag, 69, 'not built in this commit\n')
        self.assertEqual(fn('sanctuary-linux', flag, 1, 'sanctuary-linux: unknown command: ' + flag), 'unknown-argument')
        for name, status, stderr in (('castle-wall-daemon', 2, 'configuration missing'),
                                     ('sanctuary-linux', 78, 'configuration missing'),
                                     ('sanctuary-linux', 0, 'unknown argument: ' + flag),
                                     ('sanctuary-linux', 69, 'other error'),
                                     ('sanctuary-linux', -9, 'unknown argument: ' + flag)):
            with self.subTest(name=name, status=status), self.assertRaises(ValueError):
                fn(name, flag, status, stderr)


    def test_manager_names_use_systemd_255_escaped_array_rendering(self):
        fn = GUARD['systemd_manager']
        name = GUARD['MOUNT_NAME']
        fields = dict(Id=name, Names=json.dumps(name), Following='', LoadState='not-found',
                      ActiveState='inactive', SubState='dead', UnitFileState='', FragmentPath='',
                      DropInPaths='', Job='', NeedDaemonReload='no')
        def output(_):
            return ''.join(key + '=' + value + '\n' for key, value in fields.items())
        with patch.dict(fn.__globals__, {'Path': lambda _: SimpleNamespace(read_text=lambda: 'systemd\n'), 'command': output}):
            self.assertEqual(fn(False, name, GUARD['MOUNT_PATH']), fields)
            fields['Names'] += ' unrelated.mount'
            with self.assertRaises(GUARD['Refusal']):
                fn(False, name, GUARD['MOUNT_PATH'])



if __name__ == '__main__':
    unittest.main()
