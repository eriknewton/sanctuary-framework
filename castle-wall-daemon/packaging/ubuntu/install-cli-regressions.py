"""Capability: real installed CLI crash recovery and generation refusal. LINUX-INSTALL-R1."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CLI = '/usr/sbin/sanctuary-linux'
TRANSACTION = Path('/etc/sanctuary/install-transaction.json')
MARKER = Path('/etc/sanctuary/agent/configured-v1.json')
STEPS = ('Fresh', 'SanctuaryIntent', 'SanctuaryCreated', 'AgentGroupIntent', 'AgentGroupCreated', 'AgentUserIntent', 'Complete')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def wait_for_helpers():
    # The real CLI's lock is inherited by every helper. An obtainable flock
    # proves a killed transaction no longer has a detached account helper.
    with open('/run/sanctuary-linux/mutation.lock', 'r') as lock:
        deadline = time.monotonic() + 10  # Twice the product helper deadline.
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                require(time.monotonic() < deadline, 'helper retained transaction lock')
                time.sleep(.01)


def provision(witness, argv):
    require(os.geteuid() == 0, 'root CLI witness required')
    require(not TRANSACTION.exists(), 'fresh transaction required')
    for step in STEPS:
        with (witness.path / ('crash-' + step + '.log')).open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30  # Bounded saved-state observation window.
                observed = False
                while child.poll() is None and time.monotonic() < deadline:
                    try:
                        state = json.loads(TRANSACTION.read_bytes())
                    except (FileNotFoundError, ValueError):
                        state = {}
                    if state.get('account_step') == step:
                        child.kill()
                        child.wait(timeout=10)
                        observed = True
                        break
                    time.sleep(.0001)  # Observe durable rename between finite NSS probes.
                require(observed, 'did not capture saved AccountStep ' + step)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=10)
        wait_for_helpers()
        require(not MARKER.exists(), 'partial provision published Configured')
        captured = json.loads(TRANSACTION.read_bytes())
        require(captured['account_step'] == step, 'saved AccountStep advanced before kill: ' + step)
        witness.save('crash-' + step + '.json', captured)
    witness.run(argv)
    require(json.loads(TRANSACTION.read_bytes())['state'] == 'CommandStaged', 'resume not completed')
    witness.run(argv)
    changed = [a if a != '60124' else '60125' for a in argv]
    refused = witness.run(changed, expected=None)
    require(refused.returncode != 0 and 'identical provision request' in refused.stderr, 'changed request admitted')
    # The operator may change across a resume; the current audit principal must
    # remain excluded even when that uid has no passwd entry.
    # Root-owned input ancestry lets the second principal reach that guard;
    # the original operator's home would instead refuse at input custody.
    operator_argv = list(argv)
    stage_index = operator_argv.index('--stage-file') + 1
    shared_input = Path('/etc/sanctuary/resume-endpoints-ci.json')
    require(shared_input.parent.is_dir() and not shared_input.parent.is_symlink()
            and shared_input.parent.stat().st_uid == 0
            and shared_input.parent.stat().st_mode & 0o022 == 0,
            'root-owned resume input parent required')
    with shared_input.open('xb') as stream:
        stream.write(Path(operator_argv[stage_index]).read_bytes())
    shared_input.chmod(0o644)
    operator_argv[stage_index] = str(shared_input)
    try:
        refused = witness.run(['/bin/sh', '-c', 'printf 60124 > /proc/self/loginuid; exec "$@"', 'resume-test', *operator_argv], expected=None)
    finally:
        shared_input.unlink()
    require(refused.returncode != 0 and 'current operator' in refused.stderr, 'current operator collision admitted')
    invalid = subprocess.run([os.fsencode(CLI), b'\xff'], capture_output=True, timeout=10)
    require(invalid.returncode == 1 and b'non-UTF-8 argument refused' in invalid.stderr, 'argv refusal not bounded')
    require(not MARKER.exists(), 'provision alone published Configured')


def policy(witness, argv):
    before = MARKER.read_bytes()
    t = json.loads(TRANSACTION.read_bytes())
    directory = Path('/var/lib/sanctuary') / t['fortress_id'] / 'policy/egress'
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    refused = witness.run(argv, expected=None)
    require(refused.returncode != 0 and 'generation must advance' in refused.stderr, 'completed equality admitted')
    require(MARKER.read_bytes() == before, 'equality refusal changed Configured')
    high = directory / '.manifest-high-water.json'
    require(not high.exists(), 'fresh policy high-water required')
    high_bytes = json.dumps(dict(fortress_id=t['fortress_id'], generation=t['policy_generation'] + 1,
        manifest_signature_b64url=manifest['signature']['signature_b64url'])).encode()
    high.write_bytes(high_bytes)
    high.chmod(0o600)
    try:
        refused = witness.run(argv, expected=None)
        require(refused.returncode != 0 and 'generation must advance' in refused.stderr, 'committed lower bound admitted')
        require(high.read_bytes() == high_bytes and MARKER.read_bytes() == before, 'generation refusal mutated authority')
    finally:
        # This test-owned simulated daemon record precedes any daemon start.
        high.unlink()
    # A valid policy cannot mutate state before provision is fully staged.
    transaction = TRANSACTION.read_bytes()
    # Keep the transaction shape valid so this reaches policy's account-stage
    # guard rather than the earlier completed-transaction consistency check.
    incomplete = dict(t, state='Absent', account_step='AgentUserIntent', policy_complete=False)
    TRANSACTION.write_text(json.dumps(incomplete))
    digests = {p:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob('*') if p.is_file()}
    try:
        refused = witness.run(argv, expected=None)
        require(refused.returncode != 0 and 'provision accounts incomplete' in refused.stderr, 'partial account step admitted')
        require(MARKER.read_bytes() == before, 'misordered policy changed marker')
        require(digests == {p:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob('*') if p.is_file()}, 'misordered policy mutated files')
    finally:
        TRANSACTION.write_bytes(transaction)
    witness.save('cli-regressions.json', dict(saved_account_steps=list(STEPS), changed_request_refused=True,
        current_operator_refused=True, completed_equality_refused=True, high_water_refused=True,
        incomplete_provision_refused=True, marker_preserved=True))
