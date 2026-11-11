"""Isolated fd-3 writer launcher and datagram observer; owns and reaps its child."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import time

root, executable, signer_socket, policy_json = sys.argv[1:5]
fault = sys.argv[5] if len(sys.argv) == 6 else "none"
root = Path(root)
shutil.copyfile(executable, root / "writer.exec")
os.chmod(root / "writer.exec", 0o700)
executable = str(root / "writer.exec")
record = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
record.bind(str(root / 'writer.record'))
os.chmod(root / 'writer.record', 0o660)
record.listen(1)
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
notify.bind(str(root / 'writer.notify'))
notify.settimeout(0.05)
image = os.stat(executable)
digest = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
(root / 'writer.status').write_text(''.join(k + ':\t0000000000000000\n' for k in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) + 'NoNewPrivs:\t1\n')
def mapping(path, permissions):
    meta = path.stat()
    return f'1000-2000 {permissions} 00000000 {os.major(meta.st_dev):02x}:{os.minor(meta.st_dev):02x} {meta.st_ino} {path}\n'

library = root / 'writer.library'
library.write_bytes(b'isolated library inventory fixture')
os.chmod(library, 0o600)
maps = mapping(Path(executable), 'r-xp') + mapping(library, 'r--p')
if fault == 'mapping-count':
    for index in range(63):
        extra = root / f'writer.lib-{index}'
        extra.write_bytes(b'isolated inventory entry')
        os.chmod(extra, 0o600)
        maps += mapping(extra, 'r--p')
(root / 'writer.maps').write_text(maps)
config = dict(version=1, wall_unit='fixture.service', wall_exec=executable, wall_sha256=digest,
              wall_argv_sha256=digest, wall_unit_sha256=digest, wall_dropins=[], wall_gid=os.getegid(),
              writer_socket_gid=os.getegid(), writer_sha256=digest, fortress_id='fixture', enrollment_revision=1,
              signer=json.loads(policy_json))
seam = dict(config=str(root / 'writer.json'), exec=executable, status=str(root / 'writer.status'),
            maps=str(root / 'writer.maps'), self_exe='/proc/self/exe', boot_id='/proc/sys/kernel/random/boot_id',
            bus=dict(socket=str(root / 'unused.bus'), socket_owner_uid=os.geteuid(), expected_manager_uid=os.geteuid(),
                     expected_manager_pid=os.getpid(), wall_unit='fixture.service'),
            listener=dict(path=str(root / 'writer.record'), owner=os.geteuid(), group=os.getegid(), peer_uid=os.geteuid()),
            artifact_owner=os.geteuid(), library_owner=os.geteuid(), signer_socket=signer_socket)
if fault in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
    path = root / 'writer.status'
    path.write_text(path.read_text().replace(fault + ':\t0000000000000000', fault + ':\t0000000000000001'))
if fault == 'NoNewPrivs':
    path = root / 'writer.status'
    path.write_text(path.read_text().replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'))
if fault == 'digest':
    config['writer_sha256'] = '0' * 64
if fault == 'owner':
    seam['artifact_owner'] = os.geteuid() + 1
if fault == 'library-owner':
    seam['library_owner'] = os.geteuid() + 1
if fault == 'library-mode':
    os.chmod(library, 0o622)
if fault == 'config-replace':
    (root / 'replace-config').write_bytes(b'fixture')
if fault == 'mode':
    os.chmod(executable, 0o722)
if fault == 'links':
    os.link(executable, root / 'writer.link')
if fault == 'identity':
    seam['self_exe'] = '/proc/self/status'
if fault in ['wx', 'deleted', 'map-size']:
    path = root / 'writer.maps'
    text = path.read_text()
    if fault == 'wx': text = text.replace('r-xp', 'rwxp')
    if fault == 'deleted': text = text.rstrip() + ' (deleted)\n'
    if fault == 'map-size': text = 'x' * 65537
    path.write_text(text)
if fault == 'unknown':
    seam['unknown'] = True
for name, value in [('writer.json', config), ('writer.seam', seam)]:
    (root / name).write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
    os.chmod(root / name, 0o600)
pid = os.fork()
if pid == 0:
    os.dup2(record.fileno(), 3, inheritable=True)
    os.set_inheritable(3, True)
    if fault == "two-fds":
        os.dup2(3, 4, inheritable=True)
    os.execve(executable, [executable, '--test-writer', str(root / 'writer.seam')],
              dict(VITEST='true', LISTEN_PID=str(os.getpid()), LISTEN_FDS='2' if fault == 'two-fds' else '1', LISTEN_FDNAMES='records',
                   NOTIFY_SOCKET=str(root / 'writer.notify'), **({'LD_SANCTUARY_PROBE': '1'} if fault == 'environment' else {})))
record.close()
print(json.dumps(dict(pid=pid)), flush=True)
stopping = False

def stop(_signum, _frame):
    global stopping
    stopping = True

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
reaped = False
deadline = time.monotonic() + 60  # Bounds even a writer that never exits or notifies.
try:
    while not stopping:
        if time.monotonic() >= deadline:
            raise TimeoutError("writer child did not settle")
        try:
            packet = notify.recv(4096).decode()
            print(json.dumps(dict(notify=packet)), flush=True)
        except socket.timeout:
            pass
        child, status = os.waitpid(pid, os.WNOHANG)
        if child:
            reaped = True
            notify.setblocking(False)
            while True:
                try:
                    packet = notify.recv(4096).decode()
                    print(json.dumps(dict(notify=packet)), flush=True)
                except BlockingIOError:
                    break
            print(json.dumps(dict(exit=os.waitstatus_to_exitcode(status))), flush=True)
            break
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    notify.close()
