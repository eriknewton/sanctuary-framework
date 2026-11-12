"""Render isolated user units, compare every directive, and observe activation/lifetime."""
import array
import hashlib
import json
import os
import re
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# One signer idle period gives the poll-driven wall-loss observer its required scheduling margin.
SIGNER_IDLE_DEADLINE_MS = int(re.search(r'pub const SIGNER_IDLE_DEADLINE_MS: usize = (\d+);', Path('src/business_profile/signer_contract.rs').read_text()).group(1))
WALL_LOSS_WINDOW_MS = SIGNER_IDLE_DEADLINE_MS
MILLISECONDS_PER_SECOND = 1000
helper, writer, mode = sys.argv[1:]
uid, gid = os.geteuid(), os.getegid()
runtime = Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{uid}'))
unit_dir = runtime / 'systemd/user'

def ctl(*args, check=True):
    return subprocess.run(['systemctl', '--user', *args], check=check, text=True, capture_output=True, timeout=10)

if not (runtime / 'bus').exists() or ctl('show-environment', check=False).returncode:
    raise RuntimeError('HARNESS_FAILURE: user manager or session bus absent')
root = Path(tempfile.mkdtemp(prefix='wunit-'))
prefix = f'k1c2-test-{os.getpid()}-{root.name}-'
roles = ['barrier.service', 'signer.service', 'writer.service', 'writer.socket', 'wall.service']
names = {role: prefix + role for role in roles}
mapping = { 'sanctuary-business-' + role: names[role] for role in roles if role != 'wall.service'}
mapping['sanctuary-castle-wall.service'] = names['wall.service']
assert len(set(mapping.values())) == len(mapping)
unit_paths = [unit_dir / name for name in names.values()]
manifest = dict(mapping=mapping, substitutions=[], omissions=[], scenario=mode)
manifest['external_dependencies'] = {'dbus.socket': 'retained' if ctl('show', 'dbus.socket', '--property=LoadState', '--value').stdout.strip() == 'loaded' else 'omitted: absent from user manager'}
manifest['paths'] = {'/usr/libexec/sanctuary-business-writer': str(root / 'writer'), '/usr/local/libexec/sanctuary/castle-wall-daemon': str(root / 'actor'), '/run/sanctuary-business-writer/record.sock': str(root / 'record.sock'), '/run/sanctuary-business-signer/sign.sock': str(root / 'sign.sock'), '/etc/sanctuary/business-writer.json': str(root / 'config.json'), '/proc/self/status': str(root / 'caps'), '/proc/self/maps': str(root / 'maps')}
manifest['standins'] = {'barrier': {'Type': 'oneshot', 'RemainAfterExit': 'yes', 'ExecStart': '/bin/true'}, 'signer': {'Type': 'notify', 'ExecStart': f'{root}/actor signer {root} main'}, 'wall': {'Type': 'simple', 'ExecStart': f'{root}/actor wall {root} ' + (mode if mode in ['child', 'outside', 'held'] else 'main')}}
manifest['test_arguments'] = ['--test-writer', str(root / 'seam.json')]
manifest['identities'] = {'artifact_owner': uid, 'library_owner': uid, 'listener_owner': uid, 'listener_group': gid, 'peer_uid': uid}

held = None
holder = None
outside = None

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
    os.chmod(path, 0o600)

def wait(predicate, label, seconds=4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(label + f': wall_bound={(root / "wall-bound").exists()}; ' + ctl('status', *names.values(), check=False).stdout)

def show(role, prop):
    return ctl('show', names[role], '--property=' + prop, '--value').stdout.strip()

def parse(text):
    result = {}
    section = ''
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            section = line
            continue
        key, value = line.split('=', 1)
        result.setdefault(section + '.' + key, []).append(value)
    return result

hardening = '''CapabilityBoundingSet AmbientCapabilities NoNewPrivileges UMask ProtectSystem ProtectHome PrivateDevices PrivateIPC PrivateTmp PrivateUsers ProtectProc ProcSubset ProtectKernelTunables ProtectKernelModules ProtectKernelLogs ProtectControlGroups RestrictAddressFamilies RestrictNamespaces RestrictRealtime RestrictSUIDSGID LockPersonality SystemCallArchitectures LimitCORE MemorySwapMax MemoryMax TasksMax StandardInput StandardOutput StandardError'''.split()
omit = set(hardening + ['User', 'Group', 'SupplementaryGroups', 'SocketUser', 'SocketGroup'])

def render(role):
    production = Path('systemd/sanctuary-business-' + role).read_text()
    original = parse(production)
    rendered = {}
    for key, values in original.items():
        directive = key.split('.', 1)[1]
        if directive in omit:
            manifest['omissions'].append(dict(unit=role, directive=key, values=values, reason='root enforcement remains in root drills'))
            continue
        changed = []
        for value in values:
            value = ' '.join(mapping.get(word, word) for word in value.split())
            if directive in ['BindsTo', 'PartOf'] and mode in ['death', 'held']:
                value = ' '.join(word for word in value.split() if word != names['wall.service'])
            if directive in ['Requires', 'After'] and 'dbus.socket' in value and ctl('show', 'dbus.socket', '--property=LoadState', '--value').stdout.strip() != 'loaded':
                value = ' '.join(word for word in value.split() if word != 'dbus.socket')
            if directive == 'Slice':
                value = 'app.slice'
            if directive == 'ExecStart':
                value = str(root / 'writer') + ' --test-writer ' + str(root / 'seam.json')
            if directive == 'ListenSequentialPacket':
                value = str(root / 'record.sock')
            changed.append(value)
        if values != changed:
            manifest['substitutions'].append(dict(unit=role, directive=key, before=list(values), after=list(changed)))
        rendered[key] = changed
    if mode == 'stream' and role == 'writer.socket':
        rendered['[Socket].ListenStream'] = rendered.pop('[Socket].ListenSequentialPacket')
        manifest['substitutions'].append(dict(unit=role, directive='socket type', before='ListenSequentialPacket', after='ListenStream'))
    if mode == 'two' and role == 'writer.socket':
        rendered['[Socket].ListenSequentialPacket'].append(str(root / 'second.sock'))
        manifest['substitutions'].append(dict(unit=role, directive='extra descriptor', before=[], after=[str(root / 'second.sock')]))
    if role == 'writer.service':
        gate = [f'{root}/actor before-writer {root} main']
        rendered['[Service].ExecStartPre'] = gate
        manifest['substitutions'].append(dict(unit=role, directive='[Service].ExecStartPre', before=[], after=gate, reason='hold before writer exec until socket ownership is observed'))
    output = ''
    previous = None
    for key, values in rendered.items():
        section, directive = key.split('.', 1)
        if previous != section:
            output += section + '\n'
            previous = section
        for value in values:
            output += directive + '=' + value + '\n'
    restored = parse(output)
    # Only exact named emitted substitutions may be inverted; a changed recorded value refuses parity.
    if mode == 'stream' and role == 'writer.socket':
        restored['[Socket].ListenSequentialPacket'] = restored.pop('[Socket].ListenStream')
    if mode == 'two' and role == 'writer.socket':
        assert restored['[Socket].ListenSequentialPacket'][-1] == str(root / 'second.sock')
        restored['[Socket].ListenSequentialPacket'].pop()
    for item in manifest['substitutions']:
        if item['unit'] == role and item['directive'].startswith('['):
            assert restored[item['directive']] == item['after'], 'emitted substitution equality: ' + item['directive']
            if item['directive'] in original:
                restored[item['directive']] = item['before']
            else:
                del restored[item['directive']]
    for item in manifest['omissions']:
        if item['unit'] == role:
            restored[item['directive']] = item['values']
    assert restored == original, 'complete reversed directive equality'
    return output

try:
    unit_dir.mkdir(parents=True, exist_ok=True)
    for src, dst in [(helper, root / 'actor'), (writer, root / 'writer')]:
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o700)
    # The default user-manager target root and the dedicated harness both preserve identical executable bytes.
    status_vectors = json.loads(Path('src/business_profile/signer_status_vectors.json').read_text())
    packet = bytes.fromhex(status_vectors['cases'][0]['packet_hex'])
    status = json.loads(packet[4:])
    status.update(state='LOCKED', started_boottime_ns='0', expires_boottime_ns='0', anchor_revision=None, anchor_digest=None)
    dump(root / 'signer-status.json', status)
    wall_mode = mode if mode in ['child', 'outside', 'held'] else 'main'
    argv = [str(root / 'actor'), 'wall', str(root), wall_mode]
    (unit_dir / names['barrier.service']).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    (unit_dir / names['signer.service']).write_text(f'[Service]\nType=notify\nExecStart={root}/actor signer {root} main\n')
    (unit_dir / names['wall.service']).write_text('[Service]\nType=simple\nExecStart=' + ' '.join(argv) + '\n')
    (unit_dir / names['writer.service']).write_text(render('writer.service'))
    (unit_dir / names['writer.socket']).write_text(render('writer.socket'))
    ctl('daemon-reload')
    ctl('start', names['barrier.service'], names['signer.service'])
    manager_pid = int((root / 'manager').read_text())
    config = dict(version=1, wall_unit=names['wall.service'], wall_exec=str(root / 'actor'),
                  wall_sha256=digest(root / 'actor'), wall_argv_sha256=hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest(),
                  wall_unit_sha256=digest(unit_dir / names['wall.service']), wall_dropins=[], wall_gid=gid, writer_socket_gid=gid,
                  writer_sha256=digest(root / 'writer'), fortress_id='fixture', enrollment_revision=1,
                  signer=dict(uid=uid, gid=gid, executable_sha256=digest(root / 'actor'), cgroup='0::' + show('signer.service', 'ControlGroup')))
    dump(root / 'config.json', config)
    (root / 'caps').write_text(''.join(k + ':\t0000000000000000\n' for k in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) + 'NoNewPrivs:\t1\n')
    image = (root / 'writer').stat()
    (root / 'maps').write_text(f'1000-2000 r-xp 00000000 {os.major(image.st_dev):02x}:{os.minor(image.st_dev):02x} {image.st_ino} {root}/writer\n')
    dump(root / 'seam.json', dict(config=str(root / 'config.json'), exec=str(root / 'writer'), status=str(root / 'caps'), maps=str(root / 'maps'),
         self_exe='/proc/self/exe', boot_id='/proc/sys/kernel/random/boot_id', artifact_owner=uid, library_owner=uid, signer_socket=str(root / 'sign.sock'),
         bus=dict(socket=str(runtime / 'bus'), socket_owner_uid=uid, expected_manager_uid=uid, expected_manager_pid=manager_pid, wall_unit=names['wall.service']),
         listener=dict(path=str(root / 'record.sock'), owner=uid, group=gid, peer_uid=uid)))
    if mode == 'held':
        holder = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        holder.bind(str(root / 'holder.sock'))
        holder.listen(1)
        holder.settimeout(4)
    ctl('start', names['writer.socket'], '--no-block')
    wait(lambda: (root / 'before-writer').exists(), 'writer pre-start hold')
    wait(lambda: (root / 'record.sock').exists() or (root / 'signer-closed').exists(), 'socket creation')
    before = (root / 'record.sock').stat() if (root / 'record.sock').exists() else None
    if before:
        assert (before.st_uid, before.st_gid, before.st_mode & 0o7777) == (uid, gid, 0o660)
    assert show('writer.service', 'SubState') == 'start-pre', 'socket observed before writer exec'
    assert not (root / 'signer-connected').exists(), 'pre-start hold precedes bootstrap'
    (root / 'start-writer').touch()
    if mode not in ['stream', 'two']:
        wait(lambda: show('writer.service', 'ActiveState') == 'active', 'writer READY')
        assert (root / 'signer-connected').exists(), 'ready writer has bootstrapped signer'
    if mode in ['death', 'held']:
        ctl('start', names['wall.service'])
    if mode == 'outside':
        outside = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        outside.connect(str(root / 'record.sock'))
    else:
        (root / 'go').touch()
    if mode in ['child', 'outside', 'stream', 'two']:
        if mode in ['stream', 'two']:
            wait(lambda: show('writer.service', 'ActiveState') in ['failed', 'inactive'], 'activation refused before bootstrap')
            assert not (root / 'signer-connected').exists(), 'activation precedes signer session'
        else:
            wait(lambda: (root / 'signer-closed').exists(), 'terminal refusal closes signer')
        assert not (root / 'wall-bound').exists()
        assert show('writer.service', 'ActiveState') in ['failed', 'inactive']
    else:
        wait(lambda: (root / 'wall-bound').exists(), 'authenticated HELLO ACK STATUS')
        assert show('writer.service', 'ActiveState') == 'active'
        assert show('writer.service', 'StatusText') == 'writer closed'
        after = (root / 'record.sock').stat()
        assert (before.st_uid, before.st_gid, before.st_mode) == (after.st_uid, after.st_gid, after.st_mode)
        if mode == 'held':
            connection, _ = holder.accept()
            data, ancillary, _, _ = connection.recvmsg(4, socket.CMSG_SPACE(array.array('i').itemsize))
            assert data == b'hold'
            fds = array.array('i')
            fds.frombytes(ancillary[0][2])
            assert len(fds) == 1
            held = socket.socket(fileno=fds[0])
            connection.close()
        if mode in ['held', 'death']:
            if held:
                poll = select.poll()
                poll.register(held, select.POLLHUP)
                assert not poll.poll(0), 'holder preserves peer fd before writer loss dispatch'
            os.kill(int(show('wall.service', 'MainPID')), 9)
            wait(lambda: show('writer.service', 'ActiveState') in ['failed', 'inactive'], 'pidfd death closes writer', WALL_LOSS_WINDOW_MS / MILLISECONDS_PER_SECOND)
            assert (root / 'signer-closed').exists()
        elif mode == 'edges':
            ctl('stop', names['wall.service'])
            assert show('writer.service', 'ActiveState') in ['failed', 'inactive']
        else:
            ctl('stop', names['writer.socket'])
        assert show('writer.service', 'Restart') == 'no'
    output_dir = os.environ.get('WRITER_RENDER_MANIFEST_DIR')
    if output_dir:
        Path(output_dir, f'rendering-{mode}.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(scenario=mode, result='PASS', manifest=manifest)))
finally:
    if held:
        held.close()
    if holder:
        holder.close()
    if outside:
        outside.close()
    ctl('stop', *names.values(), check=False)
    ctl('reset-failed', *names.values(), check=False)
    for path in unit_paths:
        path.unlink(missing_ok=True)
    ctl('daemon-reload', check=False)
    for path in root.iterdir():
        path.unlink()
    root.rmdir()
