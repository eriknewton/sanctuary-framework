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
         '--test-trigger-nfqueue-deadline-fail-stop': None}


def classify_refusal(name, flag, status, stderr):
    if name == 'castle-wall-daemon':
        if status == 2 and ('unknown argument: ' + flag) in stderr:
            return 'unknown-argument'
    elif status in (1, 2, 64, 78) and flag in stderr and re.search(r'unknown|unexpected|unsupported|unrecognized|invalid', stderr, re.I):
        # A config/startup error alone would also occur after accepting a test
        # flag. Require the parser to identify that exact rejected argument.
        return 'unknown-argument'
    raise ValueError('binary did not demonstrate argument refusal: ' + name + ': ' + flag)


def main(deb, source):
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
