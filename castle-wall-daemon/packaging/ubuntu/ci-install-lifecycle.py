#!/usr/bin/env python3
"""Actual dpkg/manager cold-package witnesses on a positively disposable VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
PACKAGE = LAYOUT['PACKAGE']
UNIT = 'sanctuary-castle-wall.service'


def run(argv, success=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    print(json.dumps({'argv': argv, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}), flush=True)
    if success is not None and (result.returncode == 0) != success:
        raise ValueError('unexpected command outcome: ' + ' '.join(argv))
    return result


def preflight():
    hosted = (os.environ.get('GITHUB_ACTIONS'), os.environ.get('RUNNER_ENVIRONMENT'), os.environ.get('RUNNER_OS')) == ('true', 'github-hosted', 'Linux')
    marker = Path('/root/.sanctuary-host-role')
    marked = marker.is_file() and [s.strip() for s in marker.read_text().splitlines() if s.strip() and not s.lstrip().startswith('#')] == ['disposable']
    if os.geteuid() != 0 or not (hosted or marked):
        raise ValueError('requires root on a positively disposable VM')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise ValueError('real PID 1 systemd required')
    if not run(['systemctl', '--version']).stdout.startswith('systemd 255 '):
        raise ValueError('systemd 255 required')
    release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"\n' not in release:
        raise ValueError('Ubuntu 24.04 required')
    run(['nft', '-j', 'list', 'tables'])
    for path in ('/etc/sanctuary', '/var/lib/sanctuary', '/run/sanctuary', '/var/lib/sanctuary-agent-workspace'):
        if os.path.lexists(path):
            raise ValueError('pristine host required; no cleanup/adoption: ' + path)


def inert():
    for unit in (UNIT, LAYOUT['MOUNT_NAME']):
        result = run(['systemctl', 'show', unit, '--property=ActiveState,SubState,Job', '--no-pager'])
        values = dict(line.split('=', 1) for line in result.stdout.splitlines())
        if values != {'ActiveState': 'inactive', 'SubState': 'dead', 'Job': ''} and values != {'ActiveState': 'inactive', 'SubState': 'dead', 'Job': '0'}:
            raise ValueError('package is not inert: ' + unit)
    run(['systemctl', 'is-enabled', UNIT], False)
    agents = run(['systemctl', 'list-units', '--all', '--plain', '--no-legend', '--full', 'sanctuary-agent@*.service'])
    if agents.stdout.strip():
        raise ValueError('unexpected loaded agent instance')
    for path in ('/etc/sanctuary', '/var/lib/sanctuary', '/run/sanctuary'):
        if os.path.lexists(path):
            raise ValueError('install created operator state: ' + path)
    workspace = Path('/' + LAYOUT['WORKSPACE_DIRECTORY'])
    if not workspace.is_dir() or workspace.is_symlink() or any(workspace.iterdir()) or workspace.stat().st_mode & 0o7777 != 0o755:
        raise ValueError('packaged underlying workspace is not empty and root-only-writable')
    tables = json.loads(run(['nft', '-j', 'list', 'tables']).stdout)
    if any(row.get('table', {}).get('name') == 'sanctuary-castle' for row in tables['nftables']):
        raise ValueError('install created product table')


def main(args):
    if args.evidence.exists():
        raise ValueError('evidence output already exists')
    args.evidence.mkdir(parents=True)
    with (args.evidence / 'transcript.jsonl').open('w') as log:
        sys.stdout = log
        preflight()
        source = run(['git', '-C', str(HERE), 'rev-parse', 'HEAD']).stdout.strip()
        run([sys.executable, str(HERE / 'assert-install-archive.py'), str(args.deb), source])
        before_accounts = hashlib.sha256(Path('/etc/passwd').read_bytes() + Path('/etc/group').read_bytes()).hexdigest()
        deb_hash = hashlib.sha256(args.deb.read_bytes()).hexdigest()
        print(json.dumps({'source_commit': source, 'deb_sha256': deb_hash, 'scenario': args.scenario}), flush=True)
        run(['dpkg', '--install', str(args.deb)])
        inert()
        if before_accounts != hashlib.sha256(Path('/etc/passwd').read_bytes() + Path('/etc/group').read_bytes()).hexdigest():
            raise ValueError('package created or modified accounts')
        if args.scenario == 'inert':
            run(['dpkg', '--remove', PACKAGE])
            run(['dpkg', '--purge', PACKAGE])
            for path in LAYOUT['PAYLOAD_FILES']:
                if os.path.lexists('/' + path):
                    raise ValueError('payload survived inert purge: ' + path)
        elif args.scenario == 'upgrade':
            before = {path: hashlib.sha256(Path('/' + path).read_bytes()).hexdigest() for path in LAYOUT['PAYLOAD_FILES']}
            run(['dpkg', '--install', str(args.deb)], False)
            after = {path: hashlib.sha256(Path('/' + path).read_bytes()).hexdigest() for path in LAYOUT['PAYLOAD_FILES']}
            if before != after:
                raise ValueError('refused reinstall changed payload')
            # Refused upgrade can leave dpkg selection/state requiring operator
            # recovery. Do not force removal to turn unwind evidence into green.
        elif args.scenario == 'provisioned-refusal':
            # A retained provisioner marker is a package-lifecycle fixture, not
            # evidence that the stub CLI provisions successfully (P4 owns that).
            configured = Path('/etc/sanctuary/agent/configured-v1.json')
            configured.parent.mkdir(parents=True, mode=0o755)
            configured.write_text('{"version":1,"fixture":"retained-product-state"}\n')
            configured.chmod(0o600)
            before = configured.read_bytes()
            run(['dpkg', '--remove', PACKAGE], False)
            run(['dpkg', '--purge', PACKAGE], False)
            if configured.read_bytes() != before:
                raise ValueError('refusal changed retained product state')
            # Retain this fixture and package on the disposable proof VM. There
            # is intentionally no deprovision or force-removal escape hatch.
        print(json.dumps({'result': 'PASS', 'scenario': args.scenario, 'deb_sha256': deb_hash}), flush=True)
    sys.stdout = sys.__stdout__


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=('inert', 'upgrade', 'provisioned-refusal'), required=True)
    parser.add_argument('--deb', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    try:
        main(parser.parse_args())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('install lifecycle witness refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
