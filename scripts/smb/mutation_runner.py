"""Run each mutation with a passing control and an exact named witness."""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

BUILD_MARKERS = ('SMB_BUILD_FAILURE', 'TransformError', 'failed to load config', 'error TS')
# Per-witness budget includes the release build; resource parallelism remains two jobs.
WITNESS_TIMEOUT_SECONDS = 15 * 60


def run(command, cwd, env):
    # Kill the complete child process group on timeout, including compilers and test workers.
    with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate(timeout=WITNESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)


def witness_status(result, report, witness):
    """Only a collected assertion failure can kill a plant; setup/build failures cannot."""
    output = result.stdout + result.stderr
    if not report.exists():
        return 'broken'
    data = json.loads(report.read_text())
    tests = [t for file in data['testResults'] for t in file['assertionResults']
             if t['fullName'].strip() == witness]
    messages = '\n'.join(m for t in tests for m in t.get('failureMessages', []))
    print(output + messages, flush=True)
    # A build/collection failure is not evidence that the named assertion ran.
    if (len(tests) != 1 or data.get('numRuntimeErrorTestSuites', 0)
            or any(marker in output + messages for marker in BUILD_MARKERS)):
        return 'broken'
    if result.returncode == 0 and tests[0]['status'] == 'passed':
        return 'passed'
    if result.returncode != 0 and tests[0]['status'] == 'failed':
        return 'failed'
    return 'broken'


def execute_plant(copy, patch, witness, build_command, test_command, env, report):
    """Continue to planting only after both the clean build and named control pass."""
    def build():
        result = run(build_command, copy / 'castle-wall-daemon', env)
        print(result.stdout + result.stderr, flush=True)
        return result.returncode == 0

    def test():
        report.unlink(missing_ok=True)
        return witness_status(run(test_command, copy / 'server', env), report, witness)

    # The unchanged control is measured separately for EVERY plant, never inferred from another test.
    if not build() or test() != 'passed':
        print('BROKEN: clean named witness is not green; plant not applied', flush=True)
        return 'broken'
    applied = run(['git', 'apply', '--unidiff-zero', str(patch)], copy, env)
    if applied.returncode:
        print('BROKEN PATCH: ' + applied.stderr, flush=True)
        return 'broken'
    try:
        if not build():
            return 'broken'
        verdict = test()
        return {'failed': 'killed', 'passed': 'survived', 'broken': 'broken'}[verdict]
    finally:
        subprocess.run(['git', 'apply', '--unidiff-zero', '--reverse', str(patch)], cwd=copy, check=True)


def main(root, scratch, slice_name):
    copy = scratch / 'source'
    copy.mkdir()
    # Only versioned and nonignored source enters the fixture; no operator state or private inputs.
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).split(b'\0')
    for raw in set(names):
        if not raw:
            continue
        src = root / os.fsdecode(raw)
        dst = copy / os.fsdecode(raw)
        if src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    (copy / 'server/node_modules').symlink_to(root / 'server/node_modules', target_is_directory=True)
    env = dict(os.environ, CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(scratch / 'target'), CARGO_TERM_COLOR='never')
    patches = sorted((copy / 'scripts/smb/mutations' / slice_name).glob('*.patch'))
    if not patches:
        raise SystemExit('BROKEN: no mutation patches')
    counts = dict(killed=0, broken=0, survived=0)
    for patch in patches:
        lines = patch.read_text().splitlines()
        if not lines[0].startswith('# witness: '):
            raise SystemExit('BROKEN: missing witness header')
        witness = lines[0].removeprefix('# witness: ')
        feature = ['--features', 'smb-test-hooks'] if '# features: smb-test-hooks' in lines else []
        witness_env = dict(env, SMB_WITNESS_FEATURES='smb-test-hooks' if feature else '')
        # The real container witness cannot count as a kill while skipped or without its fixture image.
        if witness == 'container_peer' and not witness_env.get('SMB_CONTAINER_PEER_IMAGE'):
            print('BROKEN: container_peer requires SMB_CONTAINER_PEER_IMAGE', flush=True)
            counts['broken'] += 1
            continue
        # A skipped release scan supplies no assertion evidence, so its plants are BROKEN.
        if witness == 'release_hook_scan' and witness_env.get('SMB_RELEASE_HOOK_SCAN') != '1':
            print('BROKEN: ' + patch.name + ' requires SMB_RELEASE_HOOK_SCAN=1', flush=True)
            counts['broken'] += 1
            continue
        report = scratch / 'report.json'
        build = ['cargo', 'test', '--locked', '--lib', 'smb', '--no-run'] + feature
        test = [str(root / 'server/node_modules/.bin/vitest'), 'run', 'test/smb/contracts.test.ts',
                '--maxWorkers=2', '--testNamePattern', '^' + re.escape(witness) + '$',
                '--reporter=json', '--outputFile=' + str(report)]
        print('\nPLANT ' + patch.name + ' WITNESS ' + witness, flush=True)
        try:
            verdict = execute_plant(copy, patch, witness, build, test, witness_env, report)
        except (subprocess.TimeoutExpired, ValueError, KeyError) as error:
            print('BROKEN: ' + str(error), flush=True)
            verdict = 'broken'
        counts[verdict] += 1
        print(verdict.upper() + ' ' + patch.name + ' by ' + witness, flush=True)
    print(f"RESULT: {counts['killed']}/{len(patches)} killed; {counts['broken']} broken; {counts['survived']} survived", flush=True)
    return 0 if counts['killed'] == len(patches) else 1


if __name__ == '__main__':
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
