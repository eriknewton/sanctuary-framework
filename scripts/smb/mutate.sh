#!/usr/bin/env bash
# Each plant runs alone in a disposable copy and must fail its exact named witness.
# Failure mode: a compile/collection error is a broken patch, never a killed plant.
set -euo pipefail
slice="${1:?usage: mutate.sh SLICE}"
[[ "$slice" =~ ^[a-z0-9-]+$ ]] || exit 2
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
mutation_scratch="$(mktemp -d "${TMPDIR:-/tmp}/smb-mutation.XXXXXX")"
cleanup() {
  case "$mutation_scratch" in "${TMPDIR:-/tmp}"/smb-mutation.*) find "$mutation_scratch" -delete ;; *) exit 2 ;; esac
}
trap cleanup EXIT
python3 - "$repo_root" "$mutation_scratch" "$slice" <<'PY'
import json, os, pathlib, shutil, subprocess, sys
root, scratch = map(pathlib.Path, sys.argv[1:3]); slice=sys.argv[3]
copy=scratch/'source';copy.mkdir()
# Copy only versioned and nonignored source, never credentials or .build-inputs.
names=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=root).split(b'\0')
for raw in set(names):
    if not raw:continue
    name=os.fsdecode(raw);src=root/name;dst=copy/name
    if not src.is_file():continue
    dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
(copy/'server/node_modules').symlink_to(root/'server/node_modules',target_is_directory=True)
env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(scratch/'target'),CARGO_TERM_COLOR='never')
patches=sorted((copy/'tests/smb-mutations'/slice).glob('*.patch'))
if not patches:raise SystemExit('BROKEN: no mutation patches')
killed=0;broken=0;survived=0
for patch in patches:
    header=patch.read_text().splitlines()[0]
    if not header.startswith('# witness: '):raise SystemExit('BROKEN: missing witness header')
    witness=header.removeprefix('# witness: ')
    hooks='# features: smb-test-hooks' in patch.read_text().splitlines()
    feature=['--features','smb-test-hooks'] if hooks else []
    witness_env=dict(env,SMB_WITNESS_FEATURES='smb-test-hooks' if hooks else '')
    print('\nPLANT '+patch.name+' WITNESS '+witness,flush=True)
    apply=subprocess.run(['git','apply','--unidiff-zero',str(patch)],cwd=copy,capture_output=True,text=True)
    if apply.returncode:print('BROKEN PATCH: '+apply.stderr,flush=True);broken+=1;continue
    try:
        build=subprocess.run(['cargo','test','--locked','--lib','smb','--no-run']+feature,cwd=copy/'castle-wall-daemon',env=witness_env,capture_output=True,text=True,timeout=300)
        print(build.stdout+build.stderr,flush=True)
        if build.returncode:print('BROKEN PATCH: build failed',flush=True);broken+=1;continue
        report=scratch/'report.json'
        if report.exists():report.unlink()
        run=subprocess.run([str(root/'server/node_modules/.bin/vitest'),'run','test/smb/contracts.test.ts','--maxWorkers=2','--testNamePattern','^'+witness+'$','--reporter=json','--outputFile='+str(report)],cwd=copy/'server',env=witness_env,capture_output=True,text=True,timeout=300)
        print(run.stdout+run.stderr,flush=True)
        if not report.exists():print('BROKEN PATCH: no test report',flush=True);broken+=1;continue
        data=json.loads(report.read_text());tests=[t for file in data['testResults'] for t in file['assertionResults'] if t['fullName'].strip()==witness]
        messages='\n'.join(m for t in tests for m in t.get('failureMessages',[]))
        if len(tests)!=1 or data.get('numRuntimeErrorTestSuites',0) or 'SMB_BUILD_FAILURE' in messages:
            print('BROKEN PATCH: collection or setup failed',flush=True);broken+=1
        elif run.returncode and tests[0]['status']=='failed':
            print(messages,flush=True);print('KILLED '+patch.name+' by '+witness,flush=True);killed+=1
        else:print('SURVIVED '+patch.name,flush=True);survived+=1
    finally:
        subprocess.run(['git','apply','--unidiff-zero','--reverse',str(patch)],cwd=copy,check=True)
print(f'RESULT: {killed}/{len(patches)} killed; {broken} broken; {survived} survived',flush=True)
if killed!=len(patches):raise SystemExit(1)
PY
