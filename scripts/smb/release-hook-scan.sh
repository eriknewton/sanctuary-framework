#!/usr/bin/env bash
# Build the Ubuntu install payload with its production cargo invocation, then scan bytes.
# Failure mode: checking source or an old target can report green while a different binary ships.
# --feature-fixture deliberately builds the forbidden feature and must finish red.
# --artifact PATH additionally scans a B bundle, staging tree, or extracted Debian payload.
set -euo pipefail
# Packaging builds require explicit intent on hosts that may lack the Linux linker.
if [[ "${SMB_RELEASE_HOOK_SCAN:-}" != 1 ]]; then
  echo 'release_hook_scan requires SMB_RELEASE_HOOK_SCAN=1' >&2
  exit 2
fi
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
scan_scratch="$(mktemp -d "${TMPDIR:-/tmp}/smb-release.XXXXXX")"
cleanup() {
  case "$scan_scratch" in "${TMPDIR:-/tmp}"/smb-release.*) find "$scan_scratch" -delete ;; *) exit 2 ;; esac
}
trap cleanup EXIT
export CARGO_BUILD_JOBS=2
python3 - "$repo_root" "$scan_scratch" "$@" <<'PY'
import argparse, json, os, pathlib, runpy, subprocess, sys
root, scratch = map(pathlib.Path, sys.argv[1:3])
p = argparse.ArgumentParser()
p.add_argument('--feature-fixture', action='store_true')
p.add_argument('--artifact', type=pathlib.Path)
args = p.parse_args(sys.argv[3:])
crate = root / 'castle-wall-daemon'
# Must match build-install-deb.py: the shared layout supplies target and every packaged binary.
layout = runpy.run_path(str(crate / 'packaging/ubuntu/install-layout.py'))
env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO_', 'RUSTFLAGS', 'RUSTC', 'RUSTDOC', 'RUSTUP_TOOLCHAIN'))}
env.update(CARGO_TERM_COLOR='never', CARGO_BUILD_JOBS='2')
feature = ['--features', 'smb-test-hooks'] if args.feature_fixture else []
command = ['cargo', 'build', '--locked', '--release', '--target', layout['TARGET'], '--target-dir', str(pathlib.Path(os.environ.get('CARGO_TARGET_DIR', str(crate/'target'))) / 'smb-release-scan'), '--message-format=json']
for binary in layout['BINARIES']: command += ['--bin', binary]
command += feature
print('BUILD ' + ' '.join(command), flush=True)
with (scratch/'cargo.jsonl').open('w') as log:
    build = subprocess.run(command, cwd=crate, env=env, stdout=log, timeout=45*60)
    if build.returncode: raise SystemExit('SMB_BUILD_FAILURE: release compilation failed')
# Cached targets are only acceleration: Cargo must produce the complete current artifact inventory.
artifacts = [json.loads(line) for line in (scratch/'cargo.jsonl').read_text().splitlines()]
artifacts = [a for a in artifacts if a.get('reason')=='compiler-artifact' and a.get('executable')]
if {a['target']['name'] for a in artifacts} != set(layout['BINARIES']): raise SystemExit('SCAN FAILURE: incomplete artifact inventory')
violations=[]
tree = subprocess.check_output(['cargo','tree','--locked','-e','features','-i','castle-wall-daemon','--target',layout['TARGET']]+feature,cwd=crate,env=env,text=True,timeout=60)
print(tree, flush=True)
if 'smb-test-hooks' in tree or any('smb-test-hooks' in a['features'] for a in artifacts): violations.append('smb-test-hooks enabled')
# The SMB B service does not exist in S0; bundle the owned TS surface as its release fixture.
bundle = scratch/'smb-b-fixture.js'
subprocess.run([str(root/'server/node_modules/.bin/esbuild'),str(root/'server/src/smb/index.ts'),'--bundle','--platform=node','--format=esm',f'--outfile={bundle}'],cwd=root,check=True,timeout=60)
paths = [pathlib.Path(a['executable']) for a in artifacts] + [bundle]
if args.artifact:
    artifact=args.artifact.resolve(strict=True)
    if artifact.suffix=='.deb':
        stage=scratch/'deb'; stage.mkdir()
        subprocess.run(['dpkg-deb','--extract',str(artifact),str(stage)],check=True,timeout=60)
        paths += list(stage.rglob('*'))
    else: paths += list(artifact.rglob('*')) if artifact.is_dir() else [artifact]
for path in paths:
    if path.is_symlink(): raise SystemExit('SCAN FAILURE: unresolved artifact symlink '+str(path))
    if not path.is_file(): continue
    if 'testing' in path.parts: violations.append('testing file shipped: '+str(path))
    data=path.read_bytes()
    if b'SMB_TEST_HOOK_MARKER_7f3c' in data or b'smb_test_hook' in data: violations.append('hook bytes: '+str(path))
    if data.startswith(b'\x7fELF'):
        for options in [[], ['-D']]:
            scan=subprocess.run(['nm',*options,'-a',str(path)],capture_output=True,text=True,timeout=60)
            # Packaging strips symbols; an explicit "no symbols" is acceptable only with the byte scan above.
            if scan.returncode and 'no symbols' not in scan.stderr: raise SystemExit('SCAN FAILURE: nm failed '+scan.stderr)
            if 'smb_test_hook' in scan.stdout: violations.append('hook symbol: '+str(path))
    print('SCANNED '+path.name, flush=True)
if violations:
    print('RELEASE_HOOK_SCAN: REFUSED: '+'; '.join(violations),flush=True); raise SystemExit(1)
print('RELEASE_HOOK_SCAN: PASS',flush=True)
PY
