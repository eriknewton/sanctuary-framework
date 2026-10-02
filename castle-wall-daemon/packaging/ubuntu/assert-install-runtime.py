#!/usr/bin/env python3
"""Exercise exact extracted production binaries and rederive their dependencies."""
import json
import os
from pathlib import Path
import runpy
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
        for flag, value in SEAMS.items():
            argv = [str(binaries[0]), flag] + ([] if value is None else [value])
            result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid', '--fork', *argv],
                                    capture_output=True, text=True, timeout=10,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            if result.returncode != 2 or ('unknown argument: ' + flag) not in result.stderr:
                raise ValueError('production daemon did not reject isolation seam: ' + flag + ': ' + result.stderr[:512])
        # Other bins must refuse isolation flags too. The phase-0 stubs refuse
        # every invocation with 78; that is not proof of composed functionality.
        for binary in binaries[1:]:
            result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', '--mount', '--pid', '--fork',
                                     str(binary), '--isolated-runtime-root', '/nonexistent/package-seam'],
                                    capture_output=True, text=True, timeout=10,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            if result.returncode not in (2, 64, 78) or not result.stderr:
                raise ValueError('install binary did not refuse test-only input: ' + binary.name)
    print('exact package ELFs reject test isolation input; runtime dependencies match')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('usage: assert-install-runtime.py <deb> <expected-source-sha>')
        main(Path(sys.argv[1]), sys.argv[2])
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('install runtime assertion refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
