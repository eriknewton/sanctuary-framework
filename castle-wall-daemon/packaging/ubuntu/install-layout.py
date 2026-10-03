#!/usr/bin/env python3
"""Closed install archive inventory; shared by its builder and archive assertion."""
from pathlib import Path
import json
import re

PACKAGE = 'sanctuary-castle-wall'
KIND = 'ubuntu-install-deb-v1'
TARGET = 'x86_64-unknown-linux-gnu'
TOOLCHAIN = '1.95.0'
DOC = 'usr/share/doc/' + PACKAGE
# Must match the path constants in src/linux_install/contract.rs. That file is
# shipped verbatim as the shared command/endpoint schema, not a copied parser.
BINARIES = {
    'castle-wall-daemon': 'usr/local/libexec/sanctuary/castle-wall-daemon',
    'protected-agent-v1': 'usr/local/libexec/sanctuary/protected-agent-v1',
    'network-agent-standin': 'usr/local/libexec/sanctuary/network-agent-standin',
    'sanctuary-linux': 'usr/sbin/sanctuary-linux',
}
MOUNT_NAME = r'var-lib-sanctuary\x2dagent\x2dworkspace.mount'
SOURCES = {
    'etc/systemd/system/sanctuary-castle-wall.service': 'systemd/sanctuary-castle-wall.service',
    'etc/systemd/system/sanctuary-agent@.service': 'systemd/sanctuary-agent@.service',
    'etc/systemd/system/' + MOUNT_NAME: 'systemd/' + MOUNT_NAME,
    DOC + '/schemas/contract.rs': 'src/linux_install/contract.rs',
    DOC + '/operator-guide.md': 'packaging/ubuntu/README.md',
}
IDENTITY = DOC + '/build-identity'
PAYLOAD_FILES = {**{p: 0o755 for p in BINARIES.values()}, **{p: 0o644 for p in SOURCES}, IDENTITY: 0o644}
PAYLOAD_DIRS = {str(parent) for p in PAYLOAD_FILES for parent in Path(p).parents if str(parent) != '.'}
# The package owns an empty root-only-writable mountpoint; no unmounted U fallback.
WORKSPACE_DIRECTORY = 'var/lib/sanctuary-agent-workspace'
PAYLOAD_DIRS |= {'var', 'var/lib', WORKSPACE_DIRECTORY}
CONTROL_FILES = {'control': 0o644, 'preinst': 0o755, 'prerm': 0o755}
PRE_DEPENDS = 'systemd, nftables, python3, libc-bin'
# Runtime command closure for provisioning, accounts, manager and mount control.
# Must match runtime_dependencies in build-install-deb.py and the install check.
RUNTIME_TOOLS = ('/usr/sbin/useradd', '/usr/sbin/groupadd', '/usr/bin/getent',
                 '/usr/bin/mount', '/usr/bin/umount', '/usr/sbin/ip', '/usr/bin/timeout')
RUNTIME_PACKAGES = {'passwd', 'mount', 'iproute2', 'coreutils'}


def check_contract(crate):
    source = (crate / 'src/linux_install/contract.rs').read_text()
    expected = dict(zip(('DAEMON_PATH', 'LAUNCHER_PATH', 'STANDIN_PATH', 'CLI_PATH'),
                        ('/' + p for p in BINARIES.values())))
    expected['WORKSPACE_MOUNT_UNIT'] = MOUNT_NAME
    expected['WORKSPACE_PATH'] = '/' + WORKSPACE_DIRECTORY
    check_guard_paths(crate / 'packaging/ubuntu')
    for name, value in expected.items():
        matches = re.findall(r'^pub const ' + name + r': &str = (".*");$', source, re.M)
        if len(matches) != 1 or json.loads(matches[0]) != value:
            raise ValueError('install layout differs from shared contract: ' + name)
    for path in SOURCES.values():
        if not (crate / path).is_file() or (crate / path).is_symlink():
            raise ValueError('missing canonical install payload input: ' + path)


def guard_bytes(role, version, identity_bytes, hashes, here):
    import hashlib
    # Must match the constants consumed by install-lifecycle-guard.py.
    header = ('#!/usr/bin/python3 -I\n' + f'ROLE = {role!r}\nPACKAGE_VERSION = {version!r}\n'
              + f'IDENTITY_SHA256 = {hashlib.sha256(identity_bytes).hexdigest()!r}\n'
              + f'PAYLOAD_MODES = {PAYLOAD_FILES!r}\nPAYLOAD_HASHES = {hashes!r}\n')
    return header.encode() + guard_source(here)


def guard_source(here):
    # Both low-level process bounds and install policy are embedded verbatim;
    # no mutable helper is imported from the target host.
    return (here / 'bounded-process.py').read_bytes() + b'\n' + (here / 'install-lifecycle-guard.py').read_bytes()


def control_bytes(version, depends):
    # Exact metadata is shared by the builder and assertion; extra relationship
    # or lifecycle-affecting fields must not be accepted merely as unknown text.
    return (
        f'Package: {PACKAGE}\nVersion: {version}\nSection: admin\nPriority: optional\nArchitecture: amd64\n'
        f'Pre-Depends: {PRE_DEPENDS}\nDepends: {depends}\nConflicts: sanctuary-castle-wall-internal\n'
        'Maintainer: Erik Newton <eriknewton@gmail.com>\n'
        'Description: Castle Wall cold-install package\n Installation is inert; provisioning and activation are explicit operator actions.\n'
    ).encode()


def check_guard_paths(here):
    import runpy
    # The internal source assertion already binds the daemon's fixed paths.
    # Check the whole corresponding install set, including future additions,
    # instead of allowing a second hand-maintained runtime path inventory.
    internal = runpy.run_path(str(here / 'lifecycle-guard.py'))
    install = runpy.run_path(str(here / 'install-lifecycle-guard.py'), init_globals={'PAYLOAD_MODES': PAYLOAD_FILES})
    mirrored = {key: value for key, value in internal.items() if key.endswith(('_PATH', '_ROOT'))}
    mirrored.update({key: internal[key] for key in ('NFT_FAMILY', 'NFT_TABLE', 'UNIT_NAME', 'AGENT_UNIT_PREFIX', 'SYSTEMD_ROOTS')})
    mirrored.update({'IDENTITY_PATH': '/' + IDENTITY, 'MOUNT_PATH': '/etc/systemd/system/' + MOUNT_NAME,
                     'WORKSPACE_PATH': '/' + WORKSPACE_DIRECTORY, 'CONFIG_ROOT': '/etc/sanctuary'})
    actual = {key for key in install if key.endswith(('_PATH', '_ROOT'))}
    if actual != {key for key in mirrored if key.endswith(('_PATH', '_ROOT'))}:
        raise ValueError('install guard path inventory drifted')
    if any(install[key] != value for key, value in mirrored.items()):
        raise ValueError('install guard differs from shared source paths')
