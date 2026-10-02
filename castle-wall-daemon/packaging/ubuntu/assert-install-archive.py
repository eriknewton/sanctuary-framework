#!/usr/bin/env python3
"""Read-only closed install archive assertion against a caller-pinned source head."""
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / 'install-layout.py'))
# Share low-level metadata parsers only; neither variant selects the other's policy.
COMMON = runpy.run_path(str(HERE / 'assert-archive.py'))
field = COMMON['field']
check_members = COMMON['check_members']
validate_runtime_depends = COMMON['validate_runtime_depends']
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024  # Four release binaries plus units and control scripts.
MAX_FILE_BYTES = 100 * 1024 * 1024  # Per-binary ceiling below the archive budget.


def fail(message):
    raise ValueError(message)


def archive(deb, option):
    result = subprocess.run(['dpkg-deb', option, str(deb)], capture_output=True, check=True, timeout=30)
    if len(result.stdout) > MAX_ARCHIVE_BYTES:
        fail('archive exceeds unpacked budget')
    answer = {}
    saw_root = False
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:') as tar:
        for entry in tar:
            # PAX metadata can override custody or confer capabilities outside
            # ordinary mode bits. The builder needs none, so admit none.
            if entry.pax_headers or entry.uid != 0 or entry.gid != 0:
                fail('archive extended metadata or non-root custody')
            if entry.name in ('.', './'):
                if saw_root or not entry.isdir() or entry.mode != 0o755:
                    fail('unsafe or duplicate archive root')
                saw_root = True
                continue
            name = entry.name.removeprefix('./').rstrip('/')
            if (not name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/'))
                    or name in answer or len(answer) >= 128):  # Well above the closed 10-leaf layout.
                fail('unsafe, duplicate or over-budget archive path')
            if not (entry.isfile() or entry.isdir()) or entry.mode & 0o7000 or entry.size > MAX_FILE_BYTES:
                fail('unsafe archive type, privilege bits or file size')
            answer[name] = (entry, tar.extractfile(entry).read() if entry.isfile() else b'')
    return answer


def no_duplicate_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('duplicate identity field')
        result[key] = value
    return result


def parse_identity(raw, expected_source):
    if len(raw) > 64 * 1024:
        fail('identity exceeds bound')
    value = json.loads(raw, object_pairs_hook=no_duplicate_fields)
    required = {'artifact_kind', 'install_ready', 'package', 'package_version', 'source_commit',
                'cargo_lock_sha256', 'rustc_version', 'target', 'features', 'payload_sha256',
                'guard_sha256', 'runtime_depends', 'pre_depends'}
    if not isinstance(value, dict) or set(value) != required:
        fail('install identity field allowlist mismatch')
    if (value['artifact_kind'] != LAYOUT['KIND'] or value['install_ready'] is not True
            or value['package'] != LAYOUT['PACKAGE']):
        fail('wrong install artifact kind/readiness/package')
    if not re.fullmatch(r'[0-9a-f]{40}', expected_source) or value['source_commit'] != expected_source:
        fail('install source is not the caller-pinned head')
    if value['target'] != LAYOUT['TARGET'] or value['features'] != [] or not value['rustc_version'].startswith('rustc ' + LAYOUT['TOOLCHAIN'] + ' '):
        fail('wrong production target/features/toolchain')
    hashes = value['payload_sha256']
    if not isinstance(hashes, dict) or set(hashes) != set(LAYOUT['PAYLOAD_FILES']) - {LAYOUT['IDENTITY']}:
        fail('payload hash inventory mismatch')
    for digest in [*hashes.values(), value['cargo_lock_sha256'], value['guard_sha256']]:
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            fail('malformed install hash')
    return value


def main(deb, expected_source):
    crate = HERE.parent.parent
    LAYOUT['check_contract'](crate)
    if subprocess.check_output(['git', '-C', str(crate), 'rev-parse', 'HEAD'], text=True).strip() != expected_source:
        fail('assertion checkout is not caller-pinned source')
    control, payload = archive(deb, '--ctrl-tarfile'), archive(deb, '--fsys-tarfile')
    check_members(control, LAYOUT['CONTROL_FILES'], set())
    check_members(payload, LAYOUT['PAYLOAD_FILES'], LAYOUT['PAYLOAD_DIRS'])
    raw = payload[LAYOUT['IDENTITY']][1]
    identity = parse_identity(raw, expected_source)
    version = field(deb, 'Version')
    if (field(deb, 'Package') != LAYOUT['PACKAGE'] or field(deb, 'Architecture') != 'amd64'
            or identity['package_version'] != version or not re.fullmatch(r'[0-9][0-9A-Za-z.+~-]*-[1-9][0-9]*', version)
            or field(deb, 'Conflicts') != 'sanctuary-castle-wall-internal'
            or field(deb, 'Replaces') or field(deb, 'Provides') or field(deb, 'Essential')):
        fail('install control identity mismatch')
    if identity['pre_depends'] != LAYOUT['PRE_DEPENDS'] or field(deb, 'Pre-Depends') != LAYOUT['PRE_DEPENDS']:
        fail('install pre-dependency mismatch')
    names = validate_runtime_depends(field(deb, 'Depends'))
    if names != validate_runtime_depends(identity['runtime_depends']) or not LAYOUT['RUNTIME_PACKAGES'] <= {n.removesuffix(':amd64') for n in names}:
        fail('runtime tool dependency closure mismatch')
    for path, digest in identity['payload_sha256'].items():
        if hashlib.sha256(payload[path][1]).hexdigest() != digest:
            fail('install payload hash mismatch: ' + path)
    for path, source in LAYOUT['SOURCES'].items():
        if payload[path][1] != (crate / source).read_bytes():
            fail('install payload differs from canonical source: ' + path)
    for path in LAYOUT['BINARIES'].values():
        data = payload[path][1]
        # ELF64 little-endian x86-64, not a fixture shell script or wrong target.
        if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\x3e\x00':
            fail('install executable is not an amd64 ELF: ' + path)
    for key, source in (('cargo_lock_sha256', crate / 'Cargo.lock'), ('guard_sha256', HERE / 'install-lifecycle-guard.py')):
        if identity[key] != hashlib.sha256(source.read_bytes()).hexdigest():
            fail('install source hash mismatch: ' + key)
    for role in ('preinst', 'prerm'):
        if control[role][1] != LAYOUT['guard_bytes'](role, version, raw, identity['payload_sha256'], HERE):
            fail('install control script differs from exact source: ' + role)
    print('install archive matches exact source and closed payload; composition is a separate gate')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            fail('usage: assert-install-archive.py <deb> <expected-source-sha>')
        main(Path(sys.argv[1]), sys.argv[2])
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print('install archive refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
