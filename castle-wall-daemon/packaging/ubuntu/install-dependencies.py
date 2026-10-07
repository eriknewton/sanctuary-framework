#!/usr/bin/env python3
"""Derive runtime closure from the four built ELFs and fixed runtime commands."""
from pathlib import Path
import re
import runpy
import subprocess

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def owner(path):
    canonical = str(Path(path).resolve(strict=True))
    candidates = [canonical]
    # Ubuntu's merged /usr may retain dpkg ownership under /bin or /lib.
    # Only a lexical alias resolving to the very same inode path is eligible.
    if canonical.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/")):
        alias = canonical.removeprefix("/usr")
        if str(Path(alias).resolve(strict=True)) == canonical:
            candidates.append(alias)
    owners = set()
    for candidate in candidates:
        result = subprocess.run(['dpkg-query', '-S', '--', candidate], capture_output=True, text=True,
                                timeout=15, env=ENV, check=False)
        absent = 'dpkg-query: no path found matching pattern ' + candidate + '\n'
        if result.returncode == 1 and not result.stdout and result.stderr == absent:
            continue
        pattern = re.compile(r'([a-z0-9][a-z0-9+.-]*(?::amd64)?): ' + re.escape(candidate))
        lines = result.stdout.splitlines()
        # A diversion, error or ambiguous owner cannot understate the closure.
        if result.returncode or result.stderr or len(lines) != 1 or not pattern.fullmatch(lines[0]):
            raise ValueError('runtime path has ambiguous package ownership: ' + candidate)
        owners.add(pattern.fullmatch(lines[0])[1])
    if len(owners) != 1:
        raise ValueError('runtime path has no unique package owner: ' + canonical)
    return owners.pop()


def runtime_dependencies(binaries):
    owners = {owner(path) for path in LAYOUT['RUNTIME_TOOLS']}
    for binary in binaries:
        result = subprocess.run(['ldd', str(binary)], capture_output=True, text=True, timeout=15, env=ENV, check=True)
        if result.stderr or 'not found' in result.stdout:
            raise ValueError('unresolved runtime library')
        libraries = []
        for line in result.stdout.splitlines():
            words = line.split()
            if not words:
                continue
            if words[0].startswith('linux-vdso.so.'):
                continue  # Kernel-provided virtual DSO, not a filesystem dependency.
            path = words[2] if len(words) >= 4 and words[1] == '=>' else words[0]
            if not path.startswith('/'):
                raise ValueError('unrecognized ldd dependency record: ' + line)
            libraries.append(path)
        if not libraries:
            raise ValueError('ELF dependency inventory empty')
        owners.update(owner(path) for path in libraries)
    if any(name.removesuffix(':amd64').endswith('-dev') for name in owners):
        raise ValueError('development package in runtime closure')
    if not LAYOUT['RUNTIME_PACKAGES'] <= {p.removesuffix(':amd64') for p in owners}:
        raise ValueError('fixed command owners differ from Ubuntu runtime closure')
    return ', '.join(sorted(owners - {'systemd', 'systemd:amd64', 'nftables', 'nftables:amd64', 'python3', 'libc-bin', 'libc-bin:amd64'}))
