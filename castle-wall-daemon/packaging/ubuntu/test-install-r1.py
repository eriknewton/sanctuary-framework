#!/usr/bin/env python3
"""Capability: complete cold-footprint and finite observation admission. LINUX-INSTALL-R1."""
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock, MagicMock
import re
import json
import stat
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / 'test-install-package.py'))
G = BASE['GUARD']
LAYOUT = BASE['LAYOUT']

class Repairs(unittest.TestCase):
    def test_dependency_directories_and_sibling_activation_units_refuse(self):
        fn = G['systemd_files']
        root = '/etc/systemd/system'
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        names = ['sanctuary-castle-wall.service.' + suffix for suffix in ['wants', 'requires', 'upholds']]
        names += [G['MOUNT_NAME'] + '.' + suffix for suffix in ['wants', 'requires', 'upholds']]
        names += ['sanctuary-castle-wall.socket', 'sanctuary-castle-wall.timer']
        for name in names:
            with self.subTest(name=name), patch.dict(fn.__globals__, {'SYSTEMD_ROOTS': (root,), 'command': lambda _: root,
                'check_ancestors': lambda _: True, 'lstat': lambda _: info}), patch.object(os, 'walk', return_value=[(root, [name], [])]):
                with self.assertRaises(G['Refusal']): fn(True)

    def test_orphan_product_account_or_group_refuses_without_shared_group(self):
        fn = G['accounts_absent']
        for database, row in [('passwd', 'sanctuary-agent-60123:x:60123:60123::/nonexistent:/usr/sbin/nologin\n'),
                              ('group', 'sanctuary-agent-60123:x:60123:\n')]:
            with self.subTest(database=database), patch.dict(fn.__globals__, {
                'command_allow_empty': lambda args: row if args[-1] == database else '',
                'bounded_capture': lambda *a, **k: (2, b'', b'')}):
                with self.assertRaises(G['Refusal']): fn()

    def test_reap_is_bounded_even_when_kill_does_not_complete(self):
        fn = BASE['HEADER']['bounded_capture']
        child = MagicMock()
        child.returncode = None
        child.pid = 12345
        child.__enter__.return_value = child
        def wait(*args, **kwargs):
            self.assertEqual(kwargs.get('timeout'), 1, 'reap must carry a deadline')
            raise subprocess.TimeoutExpired('fixture', 1)
        child.wait.side_effect = wait
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {1: 1}
        with patch('subprocess.Popen', return_value=child), patch('selectors.DefaultSelector', return_value=selector), patch('os.killpg'):
            with self.assertRaises(subprocess.TimeoutExpired): fn(['/fixture'], timeout=0, limit=1)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()

    def test_embedded_hook_imports_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); marker=d/'executed'
            (d/'json.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
            hook=d/'prerm';hook.write_bytes(LAYOUT['guard_bytes']('prerm','0.1.0-1',b'{}',{},HERE));hook.chmod(0o755)
            result=subprocess.run([str(hook),'unsupported'],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists(), 'adjacent Python module executed')

    def test_full_source_seam_set_and_exact_parser_refusal(self):
        runtime=runpy.run_path(str(HERE/'assert-install-runtime.py'))
        flags=set()
        for p in (HERE.parents[1]/'src').rglob('*.rs'):
            flags.update(re.findall(r'"(--(?:test|isolated)-[a-z0-9-]+)"',p.read_text()))
        with self.subTest(kind='whole-seam-set'):
            self.assertEqual(set(runtime['SEAMS']),flags)
        for binary in ['sanctuary-linux','network-agent-standin','protected-agent-v1']:
            with self.subTest(binary=binary),self.assertRaises(ValueError):
                runtime['classify_refusal'](binary,'--isolated-runtime-root',1,'invalid value for --isolated-runtime-root')

    def test_required_inventory_refuses_filters_conditions_and_pr_provenance(self):
        module=runpy.run_path(str(HERE/'record-install-ci.py'));fn=module['record'];head='a'*40
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)
            files={module['WORKFLOW']:[*module['PACKAGE_JOBS'],'install-package-evidence'],**module['EXTERNAL_JOBS']}
            for path,jobs in files.items():
                p=repo/path;p.parent.mkdir(parents=True,exist_ok=True)
                p.write_text('name: Test\non:\n  push: {}\njobs:\n'+''.join('  '+job+':\n    runs-on: ubuntu-24.04\n    steps: []\n' for job in jobs))
            env={'INSTALL_SOURCE_SHA':head,'INSTALL_NEEDS':json.dumps({j:{'result':'success'} for j in module['PACKAGE_JOBS']}),
                 'INSTALL_ARTIFACT_ID':'1','INSTALL_ARTIFACT_DIGEST':'b'*64,'GITHUB_EVENT_NAME':'push'}
            with patch.dict(fn.__globals__,{'REPO':repo}),patch('subprocess.check_output',return_value=head),patch.dict(os.environ,env):
                fn(repo/'record.json',True)
                p=repo/'.github/workflows/linux-package-structure.yml';original=p.read_text()
                for mutant in [original.replace('  push: {}','  push:\n    paths: [castle-wall-daemon/src/**]'),
                               original.replace('    runs-on:', '    if: false\n    runs-on:')]:
                    with self.subTest(workflow=mutant):
                        p.write_text(mutant)
                        with self.assertRaises(ValueError):fn(repo/'record.json',True)
                p.write_text(original)
                with patch.dict(os.environ,{'GITHUB_EVENT_NAME':'pull_request','GITHUB_WORKFLOW_SHA':'c'*40}):
                    with self.assertRaises(ValueError):fn(repo/'record.json',True)

    def test_environment_claim_cannot_authorize_a_disposable_host(self):
        module = runpy.run_path(str(HERE/'ci-install-lifecycle.py'))
        class FakePath:
            def __init__(self, path): self.path = path
            def is_file(self): return False
            def read_text(self):
                return {'/proc/1/comm':'systemd', '/etc/os-release':'ID=ubuntu\nVERSION_ID="24.04"\n'}[self.path]
        with patch.dict(module['preflight'].__globals__, {'Path':FakePath,'run':lambda *a:SimpleNamespace(stdout='systemd 255 fixture')}), patch.dict(os.environ, {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'}), patch('os.geteuid',return_value=0), patch('os.path.lexists',return_value=False):
            with self.assertRaisesRegex(ValueError,'disposable'): module['preflight']()

    def test_diversions_and_stat_overrides_are_not_fresh(self):
        base=BASE['InstallTests']();fn=G['inspect']
        for database in ['/var/lib/dpkg/diversions','/var/lib/dpkg/statoverride']:
            fixtures=base.inspect_fixtures(False)
            fixtures['lstat']=lambda path: object() if path==database else None
            fixtures['stable_read']=lambda *a: b'root root 4755 /usr/sbin/sanctuary-linux\n'
            with self.subTest(database=database),patch.dict(fn.__globals__,fixtures),self.assertRaises(G['Refusal']):fn(False,'install')

if __name__=='__main__':unittest.main()
