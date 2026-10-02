#!/usr/bin/env python3
"""Cold package composition with real PID 1, finite sentinels and public evidence.

This is a CI witness using test-owned policy and local IPv4/IPv6 receivers,
not the separately authorized owner-custody or multi-host reboot acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import runpy
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
LIFECYCLE = runpy.run_path(str(HERE / 'ci-install-lifecycle.py'))
REGRESSIONS = runpy.run_path(str(HERE / 'install-cli-regressions.py'))
CLI = '/usr/sbin/sanctuary-linux'
STANDIN = '/usr/local/libexec/sanctuary/network-agent-standin'
WALL = 'sanctuary-castle-wall.service'
AGENT = 'sanctuary-agent@60123.service'
MOUNT = r'var-lib-sanctuary\x2dagent\x2dworkspace.mount'
WORKSPACE = Path('/var/lib/sanctuary-agent-workspace')
FORTRESS = '0123456789abcdef'
# Must match contract.rs: one normal activation plus one separate fault attempt.
U_ATTEMPTS = 18 + 1
# Three ordinary controls (before/during/after), exactly six attempts each.
CONTROL_ATTEMPTS = 3 * 6
# Capture allowance: 60 s quiet + 18 * 3 s slots + 30 s collection/manager slack.
ACTIVATION_SECONDS = 60 + 18 * 3 + 30
BACKSTOP = 'p4-composition-backstop'


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Witness:
    def __init__(self, path):
        self.path = path
        self.log = (path / 'transcript.jsonl').open('x')

    def run(self, argv, expected=0, timeout=120, **kwargs):
        start = time.monotonic_ns()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kwargs)
        self.log.write(json.dumps(dict(argv=[str(a) for a in argv], start_ns=start,
            end_ns=time.monotonic_ns(), exit=result.returncode, stdout=result.stdout, stderr=result.stderr)) + '\n')
        self.log.flush()
        if expected is not None:
            require(result.returncode == expected, f'command failed: {argv}: {result.stderr}')
        return result

    def save(self, name, value):
        (self.path / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class Sentinels:
    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.stop = threading.Event()
        self.receipts = []
        self.errors = []
        # Must match prepare-install-composition.py. This is test authority only.
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([22]) * 32)
        for family, ip in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            for kind, port in [(socket.SOCK_STREAM, 41001), (socket.SOCK_DGRAM, 41002), (socket.SOCK_STREAM, 41003)]:
                s = socket.socket(family, kind)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((ip, port))
                if kind == socket.SOCK_STREAM:
                    s.listen(8)  # Six declared endpoints; no unbounded accept queue.
                self.selector.register(s, selectors.EVENT_READ, (kind, port))
        self.thread = threading.Thread(target=self.loop)
        self.thread.start()

    def loop(self):
        try:
            while not self.stop.is_set():
                for selected, _ in self.selector.select(.1):
                    s = selected.fileobj
                    kind, port = selected.data
                    if kind == socket.SOCK_DGRAM:
                        data, peer = s.recvfrom(257)
                    else:
                        conn, peer = s.accept()
                        with conn:
                            conn.settimeout(3)
                            data = b''
                            while len(data) < 32:
                                part = conn.recv(32 - len(data))
                                if not part:
                                    break
                                data += part
                            if port == 41003 and len(data) == 32:
                                # One finite 96-byte nonce/signature response, no streaming.
                                conn.sendall(data + self.key.sign(data))
                    if len(self.receipts) >= 128:  # 37 planned attempts, >3x observation headroom.
                        raise ValueError('sentinel receipt quota')
                    self.receipts.append(dict(time_ns=time.monotonic_ns(), port=port, peer=peer, nonce_hex=data.hex()))
        except Exception as exc:
            self.errors.append(str(exc))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=4)
        require(not self.thread.is_alive(), 'sentinel did not stop')
        for item in list(self.selector.get_map().values()):
            item.fileobj.close()
        self.selector.close()


def pids_for_uid(uid):
    found = []
    for status in Path('/proc').glob('[0-9]*/status'):
        try:
            uid_line = next(line for line in status.read_text().splitlines() if line.startswith('Uid:'))
            if uid in map(int, uid_line.split()[1:]):
                found.append(int(status.parent.name))
        except FileNotFoundError:
            continue
    return found


def main(args):
    args.evidence.mkdir(parents=True, mode=0o700)
    w = Witness(args.evidence)
    # Inherit the same positive disposable/real-manager gate as inert lifecycle.
    LIFECYCLE['preflight']()
    artifacts = list(args.artifact_dir.glob('*.deb'))
    require(len(artifacts) == 1, 'one final artifact required')
    deb = artifacts[0].resolve()
    sha = hashlib.sha256(deb.read_bytes()).hexdigest()
    metadata = json.loads(Path(str(deb) + '.build.json').read_text())
    require(metadata['deb_sha256'] == sha and metadata['deb_bytes'] == deb.stat().st_size, 'composition invariant failed')
    source = metadata['source_commit']
    w.run([sys.executable, str(HERE / 'assert-install-archive.py'), str(deb), source])
    with tempfile.TemporaryDirectory(prefix='p4-preinst-') as control:
        w.run(['dpkg-deb', '--control', str(deb), control])
        # The same lifecycle guard verifies the cleaned host before any unpack.
        w.run([str(Path(control) / 'preinst'), 'install'])
    operator_uid = args.operator_uid
    operator = pwd.getpwuid(operator_uid)
    require(1000 <= operator_uid < 60123 and operator_uid != 60124, 'composition invariant failed')
    # CI has no SSH/PAM login ceremony. Establish this disposable driver's audit
    # session explicitly; the product still reads the kernel loginuid, never an
    # environment claim. Real operators obtain the same identity from PAM/sudo.
    Path('/proc/self/loginuid').write_text(str(operator_uid))
    require(Path('/proc/self/loginuid').read_text().strip() == str(operator_uid), 'composition invariant failed')
    w.save('operator-session.json', dict(uid=operator_uid, loginuid=operator_uid,
        setup='explicit disposable CI audit session; normal operator uses PAM'))
    w.save('freeze.json', dict(source_commit=source, deb_sha256=sha, deb_bytes=deb.stat().st_size,
        u_attempts=U_ATTEMPTS, operator_attempts=CONTROL_ATTEMPTS, reboot_claim=False,
        authority='ephemeral CI test authority; not owner-custody A3',
        network='independent local loopback receivers, IPv4 and IPv6',
        identity=dict(machine=Path('/etc/machine-id').read_text().strip(), boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())))
    w.run(['uname', '-a'])
    w.run(['systemctl', '--version'])
    w.run(['nft', '--version'])
    w.run(['ip', '-j', 'address'])
    w.run(['ip', '-j', 'route'])
    w.run(['ip', '-6', '-j', 'route'])
    w.run(['getent', 'passwd'])
    w.run(['getent', 'group'])
    # Inputs are public and operator-readable; no policy seed exists on this host.
    inputs = args.inputs.resolve()
    for name in ['endpoints.json', 'rules.json', 'policy.bundle.json', 'policy-key-sha256']:
        require((inputs / name).is_file(), 'composition invariant failed')
    sentinels = Sentinels()
    capture = None
    started = False
    backstop = False
    try:
        w.run(['systemd-run', '--unit=' + BACKSTOP, '--on-active=8m', '/usr/bin/systemctl', 'stop', AGENT, WALL])
        backstop = True
        capture = subprocess.Popen(['tcpdump', '-U', '-n', '-i', 'lo', '-w', str(args.evidence / 'network.pcap'),
            'portrange', '41001-41003'], stdout=subprocess.DEVNULL, stderr=(args.evidence / 'tcpdump.log').open('w'))
        w.run(['apt-get', 'install', '-y', str(deb)])
        LIFECYCLE['inert']()
        control_cmd = ['runuser', '-u', operator.pw_name, '--', STANDIN, '--control', '--endpoints', str(inputs / 'endpoints.json')]
        def control(name):
            record = json.loads(w.run(control_cmd, timeout=25).stdout)
            require(record['attempt_count'] == 6, 'composition invariant failed')
            require(all(row['sent_bytes'] == 32 for row in record['attempts']), 'composition invariant failed')
            require(all(row['authenticated'] for row in record['attempts'] if row['endpoint']['role'] == 'allow'), 'composition invariant failed')
            w.save(name, record)
            return record
        control('control-before.json')
        REGRESSIONS['provision'](w, [CLI, 'provision', '--agent-uid', '60123', '--service-uid', '60124', '--fortress-id', FORTRESS,
            '--stage-file', str(inputs / 'endpoints.json'), '--', STANDIN, '--endpoints', '/etc/sanctuary/agent/endpoints.json'])
        require(not Path('/etc/sanctuary/agent/configured-v1.json').exists(), 'composition invariant failed')
        pin = (inputs / 'policy-key-sha256').read_text().strip()
        policy_argv = [CLI, 'policy-install', '--bundle', str(inputs / 'policy.bundle.json'), '--expected-key-sha256', pin]
        w.run(policy_argv)
        REGRESSIONS['policy'](w, policy_argv)
        w.run([CLI, 'status', '--json'])
        w.run([CLI, 'start'])
        started = True
        w.run([CLI, 'enable'])
        during = control('control-during.json')
        deadline = time.monotonic() + ACTIVATION_SECONDS
        while not (WORKSPACE / 'observations.json').exists():
            require(time.monotonic() < deadline, 'finite activation did not complete')
            require(capture.poll() is None and not sentinels.errors, 'capture lost')
            time.sleep(.2)
        record = json.loads((WORKSPACE / 'observations.json').read_text())
        require(record['attempt_count'] == 18 and len(record['attempts']) == 18, 'composition invariant failed')
        require(during['end_monotonic_ns'] < min(row['start_ns'] for row in record['attempts']), 'composition invariant failed')
        w.run([CLI, 'status', '--json'])
        nft = json.loads(w.run(['nft', '-a', '-j', 'list', 'table', 'inet', 'sanctuary-castle']).stdout)
        w.save('nft-running.json', nft)
        # Kernel uid and mark observations accompany WAL decisions; testimony alone cannot pass.
        rules = [row['rule'] for row in nft['nftables'] if 'rule' in row]
        uid_match = {'match': {'left': {'meta': {'key': 'skuid'}}, 'op': '==', 'right': 60123}}
        jumps = [r for r in rules if r['chain'] == 'output' and uid_match in r['expr']]
        require(len(jumps) == 1 and isinstance(jumps[0]['handle'], int), 'composition invariant failed')
        targets = [e['goto']['target'] for e in jumps[0]['expr'] if 'goto' in e]
        require(len(targets) == 1, 'composition invariant failed')
        bodies = [r for r in rules if r['chain'] == targets[0] and uid_match in r['expr']]
        require(len(bodies) == 1 and isinstance(bodies[0]['handle'], int), 'composition invariant failed')
        require({'queue': {'num': 0}} in bodies[0]['expr'], 'composition invariant failed')
        marks = [e['mangle']['value'] for e in bodies[0]['expr']
                 if e.get('mangle', {}).get('key') == {'meta': {'key': 'mark'}}]
        require(len(marks) == 1 and isinstance(marks[0], int) and marks[0] > 0, 'composition invariant failed')
        w.save('binding.json', dict(uid=60123, jump_handle=jumps[0]['handle'],
            chain=targets[0], queue_handle=bodies[0]['handle'], mark=marks[0]))
        result = json.loads(w.run([CLI, 'evidence', '--output', str(args.evidence / 'boot-0')]).stdout)
        require(result['complete'] is True, 'composition invariant failed')
        # Tail exceeds the sender's deadline, and listener health remains positive.
        time.sleep(4)
        require(sentinels.thread.is_alive() and not sentinels.errors, 'composition invariant failed')
        receipts = {row['nonce_hex'] for row in sentinels.receipts}
        for row in record['attempts']:
            if row['endpoint']['role'] == 'allow':
                require(row['authenticated'] and row['nonce_hex'] in receipts, 'composition invariant failed')
            else:
                require(row['nonce_hex'] not in receipts, 'composition invariant failed')
        wal = (args.evidence / 'boot-0/filter-events.wal').read_bytes()
        rows = [json.loads(line) for line in wal.splitlines()]
        events = [json.loads(row['event_canonical_json']) for row in rows]
        for endpoint in json.loads((inputs / 'endpoints.json').read_text())['endpoints']:
            operation = 'egress_approved' if endpoint['role'] == 'allow' else 'egress_blocked'
            require(any(event.get('operation') == operation and event.get('details', {}).get('dest_ip') == endpoint['ip']
                and event['details'].get('dest_port') == endpoint['port'] and event['details'].get('dest_protocol') == endpoint['protocol']
                and event['details'].get('agent_id') == 'uid-60123' for event in events), 'missing endpoint WAL join')
        observation = WORKSPACE / 'observations.json'
        saved_observation = observation.read_bytes()
        def replace_testimony(raw):
            # Open the existing U-owned fixture without O_CREAT: Linux's
            # protected_regular correctly rejects root's create-open in 1777.
            fd = os.open(observation, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(fd, 'wb') as target:
                target.write(raw)
        try:
            replace_testimony(b'not-json')
            malformed = json.loads(w.run([CLI, 'evidence', '--output', str(args.evidence / 'malformed-testimony')], expected=1).stdout)
            require(malformed['complete'] is False and 'stand-in observation' in malformed['missing'], 'malformed testimony did not produce incomplete evidence')
        finally:
            replace_testimony(saved_observation)
        # A refused remove changes dpkg selection; safety retirement must remain available.
        refused = w.run(['dpkg', '--remove', 'sanctuary-castle-wall'], expected=None)
        require(refused.returncode != 0, 'provisioned removal admitted')
        require(w.run(['dpkg-query', '-W', '-f=${Status}', 'sanctuary-castle-wall']).stdout == 'deinstall ok installed', 'refusal state differs')
        w.run([CLI, 'disable'])
        require(w.run(['systemctl', 'is-active', AGENT]).stdout.strip() == 'active', 'composition invariant failed')
        require(w.run(['systemctl', 'is-enabled', WALL]).stdout.strip() == 'enabled', 'composition invariant failed')
        w.run([CLI, 'stop'])
        require(not pids_for_uid(60123), 'uid workload survived stop')
        require(w.run(['systemctl', 'is-active', WALL]).stdout.strip() == 'active', 'composition invariant failed')
        fault = json.loads((inputs / 'endpoints.json').read_text())
        for index, endpoint in enumerate(fault['endpoints']):
            endpoint['attempts'] = int(index == 0)
        fault_path = inputs / 'fault-endpoints.json'
        fault_path.write_text(json.dumps(fault))
        fault_path.chmod(0o644)
        probe = json.loads(w.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=p4-fault-probe',
            '--uid=60123', STANDIN, '--fault-probe', '--endpoints', str(fault_path)], timeout=15).stdout)
        require(probe['attempt_count'] == 1 and probe['uid'] == 60123, 'composition invariant failed')
        w.save('fault-probe.json', probe)
        require(not pids_for_uid(60123), 'composition invariant failed')
        w.run(['systemctl', 'stop', WALL])
        # Workload identity is honestly unavailable after stop; preserve that result.
        w.run([CLI, 'evidence', '--output', str(args.evidence / 'final')], expected=1)
        w.run(['/usr/local/libexec/sanctuary/castle-wall-daemon', '--disarm'])
        w.run(['systemctl', 'disable', WALL])
        w.run(['systemctl', 'stop', MOUNT])
        control('control-after.json')
        time.sleep(4)
        require(not sentinels.errors and probe['attempts'][0]['nonce_hex'] not in {r['nonce_hex'] for r in sentinels.receipts}, 'composition invariant failed')
        require(len(sentinels.receipts) == CONTROL_ATTEMPTS + 6, 'receiver count differs from declared phase ledger')
        for verb in ['--remove', '--purge']:
            refused = w.run(['dpkg', verb, 'sanctuary-castle-wall'], expected=None)
            require(refused.returncode != 0 and 'refus' in refused.stderr.lower(), 'composition invariant failed')
        require(Path('/etc/sanctuary/agent/configured-v1.json').exists(), 'composition invariant failed')
        final_wal = (args.evidence / 'final/filter-events.wal').read_bytes()
        # Must match contract.rs EMAX=4 KiB and PLANNED_WAL_MAX_BYTES=
        # AMAX(1024) * PMAX(16) * EMAX(4096) + CMAX(4 MiB) = 68 MiB;
        # lib.rs::constants::DEFAULT_WAL_SIZE_CAP_BYTES is 100 MiB.
        max_row = max(map(len, final_wal.splitlines(keepends=True)))
        require(max_row <= 4 * 1024 and len(final_wal) < 68 * 1024 * 1024, 'composition invariant failed')
        w.save('result.json', dict(result='PASS', source_commit=source, deb_sha256=sha,
            normal_attempts=18, fault_attempts=1, operator_attempts=CONTROL_ATTEMPTS,
            receipts=len(sentinels.receipts), wal_bytes=len(final_wal), maximum_encoded_row=max_row,
            wal_remaining_bytes=100 * 1024 * 1024 - len(final_wal), reboot_claim=False,
            budget_scope='observed finite composition only; A3 refusal-wave and packet ceiling remain separately substantiated'))
    finally:
        # Finite backstop never clears firewall state. Always stop workloads first.
        if started:
            w.run(['systemctl', 'stop', AGENT, WALL], expected=None)
            require(not pids_for_uid(60123), 'cleanup left uid processes')
        if capture:
            capture.send_signal(signal.SIGINT)
            try:
                capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait(timeout=5)
        sentinels.close()
        w.save('sentinel-receipts.json', dict(receipts=sentinels.receipts, errors=sentinels.errors))
        if backstop:
            w.run(['systemctl', 'stop', BACKSTOP + '.timer', BACKSTOP + '.service'], expected=None)
        w.log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--operator-uid', type=int, default=1000)
    main(parser.parse_args())
