# Second-Mac evidence snapshot procedure

This is a future synthetic-data procedure. No second-Mac results have been recorded. The operator prepares Mac A with a reviewed build and approved candidate tarball. A witness operates a different physical Mac B. Both record UTC times, OS and Node versions, machine distinction, exact command bytes, stdout, stderr, exits and observations. Publication requires a separate owner action.

Use only an explicit disposable root directly below `/tmp/v70`. Never use a live fortress. The fixture creates fresh keys and synthetic audit and transparency checkpoints. Its private fixture state stays on Mac A. Transfer only public pins, receipts and pack directories. Authenticate pins and the expected digest through a channel independent of the transferred pack. A fixture drill describes copy integrity, not live wall records.

Mac A first builds the reviewed source tree using an independently authenticated full revision and source archive. From the repository root, set `APPROVED_REVISION`, `SOURCE_METADATA` and `SOURCE_ARCHIVE` to those approved inputs. The metadata has the exact fields `format`, `source_revision` and `source_archive_sha256`, with format `SANCTUARY_RELEASE_SOURCE_V1`. A missing or mismatched input stops the build.

```sh
cd server
npm ci --no-audit --no-fund
SANCTUARY_SOURCE_SHA="$APPROVED_REVISION" npm run build
SANCTUARY_SOURCE_SHA="$APPROVED_REVISION" npm run build:evidence-pack -- --source-metadata "$SOURCE_METADATA" --source-archive "$SOURCE_ARCHIVE"
```

Mac A, from the reviewed build's server directory:

```sh
test ! -L /tmp/v70 || exit 1
# Private ownership and mode keep all synthetic state within the operator's disposable root.
# Must match the parent prerequisite witness in snapshot-packed.test.ts.
if [ ! -e /tmp/v70 ]; then mkdir -m 700 /tmp/v70 || exit 1; fi
test -d /tmp/v70 || exit 1
test "$(stat -f %u /tmp/v70)" = "$(id -u)" || exit 1
test "$(stat -f %Lp /tmp/v70)" = 700 || exit 1
mkdir -m 700 /tmp/v70/mac-a
export NODE_OPTIONS=--max-old-space-size=3072
FIXTURE=evidence-pack-dist/evidence-pack-drill-fixture.js
mkdir -p /tmp/v70/mac-a-records
run_a() {
  label=$1; shift
  printf '%q ' "$@" > "/tmp/v70/mac-a-records/$label.command"
  printf '\n' >> "/tmp/v70/mac-a-records/$label.command"
  "$@" > "/tmp/v70/mac-a-records/$label.stdout" 2> "/tmp/v70/mac-a-records/$label.stderr"
  rc=$?
  printf '%s\n' "$rc" > "/tmp/v70/mac-a-records/$label.exit"
  test "$rc" -eq 0 || exit 1
}
run_a create node "$FIXTURE" create --root /tmp/v70/mac-a
run_a stale node "$FIXTURE" export --root /tmp/v70/mac-a --name pack-stale
run_a advance node "$FIXTURE" advance --root /tmp/v70/mac-a
run_a current node "$FIXTURE" export --root /tmp/v70/mac-a --name pack
run_a other node "$FIXTURE" export --root /tmp/v70/mac-a --name pack-other
```

The fixture requires both directories to be owned by the operator with mode 0700; an unsuitable directory stops the procedure before fixture state is written.

Wrap each command to retain its command text, stdout, stderr and exit in a new records directory. Stop on a nonzero exit and retain every result. Never translate exit 10 into success. The compiled fixture installs the in-memory credential store in the same module instance as its signing helpers. It appends and flushes records through the production audit log and transparency emitter and labels its records synthetic. All fixture state remains beneath the explicit root.

Extract the current, other and stale digests and export ids from their respective receipts. Copy `pack-trust.json` to the separately authenticated `pins/public-trust.json`. Confirm every role and full key fingerprint, and authenticate the package hash and full source revision. Do not derive the expected digest by hashing the delivery on Mac B.

```sh
python3 - <<'PY'
import json, shutil
from pathlib import Path
root = Path('/tmp/v70/mac-a')
pins = root / 'pins'
pins.mkdir(mode=0o700)
for name in ['pack-key.txt', 'wrong-key.txt']:
    shutil.copyfile(root / name, pins / name)
shutil.copyfile(root / 'pack-trust.json', pins / 'public-trust.json')
shutil.copyfile(root / 'pack-wrong-trust.json', pins / 'wrong-trust.json')
for name, target in [('pack', 'expected'), ('pack-other', 'other'), ('pack-stale', 'stale')]:
    receipt = json.loads((root / (name + '-receipt.json')).read_text())
    assert receipt['status'] == 'PASS'
    (pins / (target + '-digest.txt')).write_text(receipt['manifest_digest'] + '\n')
    (pins / (target + '-export-id.txt')).write_text(receipt['export_id'] + '\n')
PY
COPYFILE_DISABLE=1 tar --no-xattrs -cf /tmp/v70/transfer.tar -C /tmp/v70/mac-a pack pack-stale pack-other
```

Transfer the archive using removable media or an approved method. Transfer no private fixture state. Deliver the reviewed tamper script separately from the pack. On Mac B, follow [recipient verification](../evidence-pack-recipient-v0.md), including tarball authentication, installation with scripts disabled and a clean-pack result. Verify the other and stale packs with their own independently supplied digests as positive controls. Retain PASS and the expected export id for all three.

The witness then runs the reviewed tamper harness against a fresh copy and records each result. The harness writes fresh directories only and records original and changed sizes and SHA-256 values. It covers report bytes, PDF bytes, manifest formatting, a missing report and a shortened audit file. The audit prefix has a genuine checkpoint and is also checked independently with its audit pin. Full-pack checks use the current independent digest.

```sh
python3 /tmp/v70/drill/evidence-pack-drill-tamper.py --source ./pack --output ./tamper
```

Use the installed command with the independent key, descriptor and digest for every row. Record the exact exit, `status`, `accepted` and finding code together.

| Input | Expected exit | Status | Accepted | Required finding |
|---|---|---|---|---|
| Clean current pack | 0 | PASS | true | None |
| Other pack with its own digest | 0 | PASS | true | None |
| Stale pack with its own digest | 0 | PASS | true | None |
| Report byte copy | 1 | FAIL | false | file_digest_mismatch |
| PDF byte copy | 1 | FAIL | false | file_digest_mismatch |
| Manifest formatting copy | 1 | FAIL | false | manifest_digest_mismatch |
| Missing report copy | 1 | FAIL | false | file_set_mismatch |
| Shortened audit copy | 1 | FAIL | false | file_digest_mismatch |
| Other pack with current digest | 1 | FAIL | false | manifest_digest_mismatch |
| Stale pack with current digest | 1 | FAIL | false | manifest_digest_mismatch |
| Unrelated key and current descriptor | 1 | FAIL | false | pin_invalid |
| Matching unrelated key and descriptor | 1 | FAIL | false | manifest_signature_invalid |

The following wrapper keeps each verdict together with its expected exit and finding. Use a new records directory. Supply the independently authenticated digest file for each positive control.

```sh
VERIFY=./verifier/node_modules/.bin/verify-evidence-pack
mkdir records
check_pack() {
  label=$1; directory=$2; key=$3; descriptor=$4; digest=$5; expected=$6; code=$7
  printf '%q ' "$VERIFY" --pack "$directory" --public-key-file "$key" --trust-descriptor-file "$descriptor" --expect-manifest-digest "$(cat "$digest")" --json > "records/$label.command"
  "$VERIFY" --pack "$directory" --public-key-file "$key" --trust-descriptor-file "$descriptor" --expect-manifest-digest "$(cat "$digest")" --json > "records/$label.json" 2> "records/$label.stderr"
  actual=$?
  printf '%s\n' "$actual" > "records/$label.exit"
  python3 - "records/$label.json" "$actual" "$expected" "$code" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
actual, expected = map(int, sys.argv[2:4])
assert actual == expected == result['exit_code']
assert result['status'] == ('PASS' if expected == 0 else 'FAIL')
assert result['accepted'] is (expected == 0)
assert result['partial_reasons'] == []
if expected:
    assert sys.argv[4] in [finding['code'] for finding in result['findings']]
PY
}
check_pack clean ./pack ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 0 none || exit 1
check_pack other-control ./pack-other ./pins/pack-key.txt ./pins/public-trust.json ./pins/other-digest.txt 0 none || exit 1
check_pack stale-control ./pack-stale ./pins/pack-key.txt ./pins/public-trust.json ./pins/stale-digest.txt 0 none || exit 1
for label in byte-edit pdf-edit shortened-file; do
  check_pack "$label" "./tamper/$label" ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 file_digest_mismatch || exit 1
done
check_pack manifest-whitespace ./tamper/manifest-whitespace ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 manifest_digest_mismatch || exit 1
check_pack removed-file ./tamper/removed-file ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 file_set_mismatch || exit 1
check_pack other-valid ./pack-other ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 manifest_digest_mismatch || exit 1
check_pack stale ./pack-stale ./pins/pack-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 manifest_digest_mismatch || exit 1
check_pack wrong-key ./pack ./pins/wrong-key.txt ./pins/public-trust.json ./pins/expected-digest.txt 1 pin_invalid || exit 1
check_pack wrong-consistent ./pack ./pins/wrong-key.txt ./pins/wrong-trust.json ./pins/expected-digest.txt 1 manifest_signature_invalid || exit 1
```

Before the last row, use the fixture-generated `pins/wrong-trust.json` supplied with the other authenticated test pins. It names the unrelated public key for the pack role and retains the other role pins. This is a signature-gate exercise. Do not use it for acceptance.

OS-attached file metadata (provenance, quarantine, security label) is outside the signed set. Darwin's OS enumerator can read values internally; only names enter the verifier and value output is discarded. No label value is evidence. Verify before browsing the fresh extraction in Finder and keep the delivery unchanged during use.

Retain tarball SHA-256 and npm integrity, package provenance, tree hashes, authenticated pins and their authentication method, receipts, command records, every exact verdict, tamper hashes, prefix positive control and the independent recipient observation. Place these in a dated audit directory with separate Mac A, Mac B and tamper records and an acceptance note. An incomplete prerequisite, unexplained exit, PARTIAL result or missing observation leaves the procedure incomplete. PASS does not establish freshness, continuous history, legal compliance, wall enforcement, external approval or a globally atomic cut.

## Results

No second-Mac results have been recorded.

<!-- Fixture root and checkpoint prefix contract: server/scripts/evidence-pack-drill-fixture.ts and evidence-pack-drill-tamper.py. -->

## Artifact handoff

Supply explicit `--artifact-dir` and `--artifact-mode` arguments to the candidate builder. The destination must be a new absolute directory beneath a trusted resolved parent. The receipt is written last. On refusal, leave partial outputs for inspection and rebuild in a clean destination; a complete-looking convenience copy is not a release authority.

Before installation or upload, run `node server/scripts/build-evidence-pack.mjs --check-descriptor <artifact-directory>`. Install only its fixed `candidate.tgz`, offline with scripts disabled. The shipped `check-evidence-pack-artifact` checks the same pair against independently supplied digest and revision pins. Fixture-policy success is non-release evidence. Neither the process nor its receipt authenticates a publisher.

The artifact path still needs native Darwin and Node 24 drills. No native Darwin result is asserted here; existing snapshot and isolation bounds remain unchanged.
