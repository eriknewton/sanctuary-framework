# Verify a selected evidence snapshot

Use the approved candidate tarball with Node 22 or later. The candidate is private and has not been published. Obtain the exact tarball SHA-256, package version, full source revision, export id, expected manifest digest, pack public key and public trust descriptor through an independently authenticated channel. Confirm every signing role and complete key fingerprint with the sender. A key or descriptor copied from the pack is not independently authenticated.

Save pins outside the received directory. The key file contains canonical unpadded base64url for 32 bytes and at most one final LF. The expected digest uses `sha256:` followed by 64 lowercase hexadecimal digits. Verify a fresh extraction before browsing it in Finder. Keep the directory unchanged during verification and use.

```sh
# Enter the hash and version supplied through the authenticated channel.
APPROVED_SHA256='<64 lowercase hex digits>'
APPROVED_VERSION='0.1.0'
TGZ='./approved-candidate.tgz'
test "$(shasum -a 256 "$TGZ" | cut -d ' ' -f 1)" = "$APPROVED_SHA256" || exit 1
npm install --prefix ./verifier --ignore-scripts --no-audit --no-fund --offline "$TGZ"
VERIFY=./verifier/node_modules/.bin/verify-evidence-pack
"$VERIFY" --version
"$VERIFY" --pack ./pack --public-key-file ./pins/pack-key.txt \
  --trust-descriptor-file ./pins/public-trust.json \
  --expect-manifest-digest "$(cat ./pins/expected-digest.txt)" --json > result.json
rc=$?
printf 'VERIFIER_EXIT=%s\n' "$rc"
cat result.json
```

Compare the reported version and full revision with the authenticated notice. Accept only exit 0, `status:"PASS"`, `accepted:true` and the expected export id together. Exit 10, `status:"PARTIAL"` and `accepted:false` mean checks are incomplete; retain the explicit reasons and ask the sender to resolve them. Exit 1 and FAIL reject the delivery. Exit 2 requests corrected arguments and a fresh run. On admitted installations, only lone `--help` or `--version` exits 0 without a verdict.

The command checks the exact signed manifest digest, the manifest signature, the complete file set, every file's bytes, independent descriptor equality and the included supported audit and transparency records. It requires all four value flags once each. There are no environment pins, embedded trust options or downgrade flags. Output failure is a failed command.

OS-attached file metadata (provenance, quarantine, security label) is outside the signed set. No label value is evidence. Darwin uses the OS enumerator, which can read values internally; the verifier consumes names only and discards value output. A native name-only call is outside this candidate's capability. File modes, owners and timestamps are not exported evidence. The verifier observes file stability during its run and gives no guarantee about later changes.

PASS does not establish continuous history, legal compliance, wall enforcement, external approval, freshness or a globally atomic cut. An old snapshot rejects only relative to a different independently supplied digest. Reusing its old digest does not establish freshness. The package's provenance records require an authenticated distribution channel and do not by themselves prove reproducibility.

The command invokes both nested verifiers. A separately installed legacy server command can diagnose a single audit key with `sanctuary audit-chain verify --input audit-chain.jsonl --public-key "$(cat pins/audit-key.txt)"`. That diagnostic is not full-pack acceptance and does not handle multiple audit keys.

<!-- Command and exit contract: server/src/evidence-pack/snapshot-offline-cli.ts and snapshot-contract.ts. -->

Supported hosts are macOS with `/usr/bin/xattr` and Linux with `/usr/bin/python3` and filesystem attribute enumeration support. Use `--json` to retain named capture findings. `enumerator_unavailable` means the platform or enumerator prerequisite is absent; `unexpected_metadata` or `io_error` can also reflect a local capture failure. Retain the result and repeat verification from a fresh extraction on a supported host before making an acceptance decision.

Metadata enumeration uses paths and checks the held inode after each subprocess. A path changed and restored during the subprocess cannot be excluded by those observations. This bounds observation of names only; metadata values are never evidence.

Build provenance includes the SHA-256 of the dependency lockfile used by the build tree. Installed dependency bytes still require a trusted build environment; the lockfile record alone does not establish reproducibility.

## Check the delivered artifact

Evidence-pack verifier artifacts remain private candidates. The builder checks the packed tarball's exact contents and emits `candidate.tgz`, `artifact-manifest.json` and the final `candidate.json` receipt. Checkout copies are convenience outputs: verification is a sequence of observations, not an atomic snapshot, and does not authenticate later contents. A refused build can leave a tarball without a receipt; do not use it.

Obtain a trusted checker independently, or authenticate both delivered files with an independent trusted SHA-256 tool before installing that exact tarball with scripts disabled. Obtain both hashes and the full source revision through a separately authenticated channel. Installing an unauthenticated checker and trusting its own result does not authenticate it.

```sh
check-evidence-pack-artifact --tarball candidate.tgz --manifest artifact-manifest.json --expect-tarball-sha256 "$TRUSTED_TARBALL_SHA256" --expect-manifest-sha256 "$TRUSTED_MANIFEST_SHA256" --expect-source-revision "$TRUSTED_SOURCE_REVISION" --expect-mode release
```

Success establishes byte equality, member policy and internal provenance consistency. It does not authenticate the publisher, prove source correctness or establish dependency reproducibility. A fixture-built checker only permits fixture-policy success; use `--expect-mode fixture` for synthetic artifacts. Snapshot signature verification is separate.

The build creates no signature, attestation or distribution notice. Authenticated digest publication remains an owner-controlled process outside this workflow. PR artifacts are non-release test material even if PR-controlled source or YAML labels them otherwise. Only dispatches from the workflow's permitted main or version-tag refs are eligible for subsequent external authentication. Rechecking before upload and installation is a point-in-time observation, not protection against concurrent writers.

## Installed package classification

The installed verifier classifies its own package before help, version, argument parsing or evidence reads. There is no environment or flag override. A regular `dist/NON_RELEASE` entry refuses with exit 1, empty stdout and exactly:

```text
NON_RELEASE: this verifier package is not a release artifact.
```

An unexpected package layout, a non-regular marker entry or an observation failure refuses with exit 1, empty stdout and exactly:

```text
PACKAGE_MARKER_UNAVAILABLE: verifier package classification could not be established.
```

`PACKAGE_MARKER_UNAVAILABLE` refuses use when absence is unproved, including a symlink at the package root or an unexpected parent. This refusal is not a finding that the package is a release. Treat a nonzero exit or missing result as refusal, even when no snapshot JSON is produced. Restore a trusted, intact installation before retrying; do not remove a marker to make a candidate usable.

The observation is in-process and adds no host prerequisite. Marker contents and link targets are never opened. Ancestors above the package root are not inspected. Classification is a point-in-time observation that requires a trusted installation with no concurrent package writers. Marker absence does not authenticate a release; authenticate the exact tarball independently.

The companion artifact checker applies the same classification before release-policy checks. Fixture-policy checks and standalone checker help remain available. A fixture-built checker still cannot report release-policy success. Marker-free verifier help, version and snapshot result bytes retain their existing meanings.
