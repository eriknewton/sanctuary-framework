#!/usr/bin/env python3
"""Explicit cold-install artifact builder; never installs or starts its output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent.parent
REPO = CRATE.parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
DEPENDENCIES = runpy.run_path(str(HERE / 'install-dependencies.py'))


def command(argv, **kwargs):
    return subprocess.check_output(argv, text=True, timeout=60, **kwargs).strip()


def clean_head():
    if command(['git', '-C', str(REPO), 'status', '--porcelain=v1', '--untracked-files=all']):
        raise ValueError('refusing dirty or untracked source inputs')
    return command(['git', '-C', str(REPO), 'rev-parse', 'HEAD'])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(revision, output):
    if not re.fullmatch(r'[1-9][0-9]*', revision):
        raise ValueError('revision must be a positive decimal without leading zeroes')
    if sys.platform != 'linux' or command(['dpkg', '--print-architecture']) != 'amd64':
        raise ValueError('Ubuntu amd64 required')
    release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"\n' not in release:
        raise ValueError('Ubuntu 24.04 required')
    head = clean_head()
    LAYOUT['check_contract'](CRATE)
    rustc = command(['rustc', '--version'], cwd=CRATE)
    if not rustc.startswith('rustc ' + LAYOUT['TOOLCHAIN'] + ' '):
        raise ValueError('pinned Rust toolchain required')
    version = tomllib.loads((CRATE / 'Cargo.toml').read_text())['package']['version'] + '-' + revision
    if not re.fullmatch(r'[0-9][0-9A-Za-z.+~-]*-[1-9][0-9]*', version):
        raise ValueError('invalid Debian version')
    output = output.resolve()
    if output.is_relative_to(REPO):
        raise ValueError('artifact output must be outside the source checkout')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('output directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    # A fresh target excludes cached feature-unified/test artifacts. Cargo's
    # emitted feature inventory is checked as well as invoking no feature flags.
    with tempfile.TemporaryDirectory(prefix='sanctuary-install-build-') as scratch:
        scratch = Path(scratch)
        target, stage = scratch / 'target', scratch / 'stage'
        cargo = ['cargo', 'build', '--locked', '--release', '--target', LAYOUT['TARGET'],
                 '--target-dir', str(target), '--message-format=json']
        for binary in LAYOUT['BINARIES']:
            cargo += ['--bin', binary]
        env = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTC', 'RUSTDOC', 'RUSTUP_TOOLCHAIN'))}
        env['CARGO_TERM_COLOR'] = 'never'
        with (scratch / 'cargo.jsonl').open('w') as log:
            subprocess.run(cargo, cwd=CRATE, env=env, stdout=log, check=True, timeout=45 * 60)
        seen = set()
        for line in (scratch / 'cargo.jsonl').read_text().splitlines():
            record = json.loads(line)
            if record.get('reason') == 'compiler-artifact' and record.get('target', {}).get('name') in LAYOUT['BINARIES'] and record.get('executable'):
                if record['features'] != [] or record['profile']['test']:
                    raise ValueError('non-default feature or test binary in package build')
                seen.add(record['target']['name'])
        if seen != set(LAYOUT['BINARIES']):
            raise ValueError('Cargo did not witness every required production binary')
        binaries = {name: target / LAYOUT['TARGET'] / 'release' / name for name in LAYOUT['BINARIES']}
        depends = DEPENDENCIES['runtime_dependencies'](binaries.values())
        for path in LAYOUT['PAYLOAD_DIRS'] | {'DEBIAN'}:
            (stage / path).mkdir(parents=True, exist_ok=True, mode=0o755)
        for name, destination in LAYOUT['BINARIES'].items():
            shutil.copyfile(binaries[name], stage / destination)
            (stage / destination).chmod(0o755)
        for destination, source in LAYOUT['SOURCES'].items():
            shutil.copyfile(CRATE / source, stage / destination)
            (stage / destination).chmod(0o644)
        hashes = {path: sha(stage / path) for path in sorted(set(LAYOUT['PAYLOAD_FILES']) - {LAYOUT['IDENTITY']})}
        identity = {
            'artifact_kind': LAYOUT['KIND'], 'install_ready': True, 'package': LAYOUT['PACKAGE'],
            'package_version': version, 'source_commit': head, 'cargo_lock_sha256': sha(CRATE / 'Cargo.lock'),
            'rustc_version': rustc, 'target': LAYOUT['TARGET'], 'features': [], 'payload_sha256': hashes,
            'guard_sha256': hashlib.sha256(LAYOUT['guard_source'](HERE)).hexdigest(), 'runtime_depends': depends,
            'pre_depends': LAYOUT['PRE_DEPENDS'],
        }
        identity_bytes = (json.dumps(identity, sort_keys=True, indent=2) + '\n').encode()
        (stage / LAYOUT['IDENTITY']).write_bytes(identity_bytes)
        (stage / LAYOUT['IDENTITY']).chmod(0o644)
        for role in ('preinst', 'prerm'):
            (stage / 'DEBIAN' / role).write_bytes(LAYOUT['guard_bytes'](role, version, identity_bytes, hashes, HERE))
            (stage / 'DEBIAN' / role).chmod(0o755)
        (stage / 'DEBIAN/control').write_text(
            f'Package: {LAYOUT["PACKAGE"]}\nVersion: {version}\nSection: admin\nPriority: optional\nArchitecture: amd64\n'
            f'Pre-Depends: {LAYOUT["PRE_DEPENDS"]}\nDepends: {depends}\nConflicts: sanctuary-castle-wall-internal\n'
            'Maintainer: Erik Newton <eriknewton@gmail.com>\n'
            'Description: Castle Wall cold-install package\n Installation is inert; provisioning and activation are explicit operator actions.\n')
        (stage / 'DEBIAN/control').chmod(0o644)
        if clean_head() != head:
            raise ValueError('source changed during package build')
        deb = output / f'{LAYOUT["PACKAGE"]}_{version}_amd64.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(stage), str(deb)], check=True, timeout=120)
        # Validate final archive bytes, then behavior and ELF dependency closure.
        subprocess.run([sys.executable, str(HERE / 'assert-install-archive.py'), str(deb), head], check=True)
        subprocess.run([sys.executable, str(HERE / 'assert-install-runtime.py'), str(deb), head], check=True)
        (output / (deb.name + '.sha256')).write_text(f'{sha(deb)}  {deb.name}\n')
        # This is build metadata, never a promotion record or external attestation.
        (output / (deb.name + '.build.json')).write_text(json.dumps({
            'source_commit': head, 'deb_sha256': sha(deb), 'deb_bytes': deb.stat().st_size,
            'artifact_file': deb.name, 'variant': 'install',
        }, sort_keys=True, indent=2) + '\n')
        print('install artifact: ' + str(deb))


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--revision', required=True)
        parser.add_argument('--output', type=Path, required=True)
        args = parser.parse_args()
        build(args.revision, args.output)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('install package build refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
