#!/usr/bin/env python3
"""Exercise exact extracted production binaries and rederive their dependencies."""
import json
import os
from pathlib import Path
import runpy
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
DEPENDENCIES = runpy.run_path(str(HERE / 'install-dependencies.py'))
# Must match the test-only flag families in src/main.rs and src/config.rs.
SEAMS = {'--isolated-runtime-root': '/nonexistent/package-seam', '--isolated-castle-table-tag': 'p1check',
         '--test-health-interval-ms': '1', '--test-shutdown-at': 'pre-recovery',
         '--test-stop-guard-deadline-secs': '1', '--test-nft-binary': '/bin/false',
         '--test-wedge-health-pass-after': '1', '--test-delay-before-ready-ms': '1',
         '--test-trigger-nfqueue-deadline-fail-stop': None,
         '--test-trigger-fatal-control-path': None, '--test-hang-teardown': None}


def classify_refusal(name, flag, status, stderr):
    # Exact parser diagnostics only: a value-validation failure after accepting
    # the seam is not evidence that the production parser rejects the flag.
    shapes = {
        'castle-wall-daemon': (2, ('unknown argument: ' + flag, 'castle-wall-daemon: unknown argument: ' + flag)),
        'sanctuary-linux': (1, ('sanctuary-linux: unknown command: ' + flag,)),
        'protected-agent-v1': (1, ('protected-agent-v1: refused: unknown argument: ' + flag,)),
        'network-agent-standin': (1, ('network-agent-standin: unknown or invalid argument: ' + flag,)),
    }
    expected_status, diagnostics = shapes[name]
    if status == expected_status and stderr.strip() in diagnostics:
        return 'unknown-argument'
    raise ValueError('binary did not demonstrate argument refusal: ' + name + ': ' + flag)


def check_seam_parity():
    # Full-set equality catches new source seams even if this caller forgets them.
    source = HERE.parents[1] / 'src'
    actual = set()
    for path in source.rglob('*.rs'):
        actual.update(re.findall(r'"(--(?:test|isolated)-[a-z0-9-]+)"', path.read_text()))
    if actual != set(SEAMS):
        raise ValueError('test seam registry differs from production source: ' + repr(actual ^ set(SEAMS)))


def main(deb, source):
    check_seam_parity()
    subprocess.run([sys.executable, str(HERE / 'assert-install-archive.py'), str(deb), source], check=True)
    with tempfile.TemporaryDirectory(prefix='sanctuary-install-runtime-') as scratch:
        root = Path(scratch)
        subprocess.run(['dpkg-deb', '--extract', str(deb), str(root)], check=True, timeout=30)
        binaries = [root / p for p in LAYOUT['BINARIES'].values()]
        identity = json.loads((root / LAYOUT['IDENTITY']).read_bytes())
        if DEPENDENCIES['runtime_dependencies'](binaries) != identity['runtime_depends']:
            raise ValueError('ELF/runtime command dependency closure mismatch')
        # A test-enabled daemon must be unable to affect the host while being
        # checked: isolate its network, mounts, users and PID namespace first.
        for binary in binaries:
            for flag, value in SEAMS.items():
                argv = [str(binary), flag] + ([] if value is None else [value])
                result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid', '--fork', *argv],
                                        capture_output=True, text=True, timeout=10,
                                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                classify_refusal(binary.name, flag, result.returncode, result.stderr)
    print('all four production binaries reject isolation seams; dependency closure matches')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('usage: assert-install-runtime.py <deb> <expected-source-sha>')
        main(Path(sys.argv[1]), sys.argv[2])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('install runtime assertion refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
