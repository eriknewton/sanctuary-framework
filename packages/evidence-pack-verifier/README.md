# Evidence snapshot verifier candidate

Copyright 2026 Erik Newton. Apache-2.0.

This private candidate verifies a selected snapshot with independently authenticated pins. It is not published. Use Node 22 or later. Authenticate the exact tarball hash and source revision before installing with scripts disabled.

```sh
npm install --prefix ./verifier --ignore-scripts --no-audit --no-fund --offline ./approved-candidate.tgz
./verifier/node_modules/.bin/verify-evidence-pack --version
./verifier/node_modules/.bin/verify-evidence-pack --pack ./pack \
  --public-key-file ./pins/pack-key.txt --trust-descriptor-file ./pins/public-trust.json \
  --expect-manifest-digest "$(cat ./pins/expected-digest.txt)" --json
```

Only exit 0, status PASS and accepted true accept a snapshot. Compare its export id with the authenticated notice. Exit 10 and PARTIAL require resolution by the sender. Exit 1 and FAIL reject the delivery. Exit 2 requests corrected arguments. On admitted installations, help and version alone exit 0 without a verdict.

All four value flags are mandatory and may occur only once. The key file contains canonical unpadded base64url for 32 bytes with at most one final LF. The expected digest is `sha256:` followed by 64 lowercase hexadecimal digits. Keep pins outside the received pack and authenticate every role and complete key fingerprint separately.

Verify a fresh extraction before browsing it in Finder. Keep the directory unchanged during verification and use. File bytes and names are checked. OS-attached file metadata (provenance, quarantine, security label) is outside the signed set. On Darwin the OS enumerator may read values internally; the verifier consumes only names and discards value output. No label value is evidence.

PASS does not establish freshness, continuous history, legal compliance, wall enforcement, external approval or a globally atomic cut. An older snapshot fails against a different independently supplied expected digest. Reusing the older digest does not establish freshness.

The package has no runtime dependencies or install scripts. Its bundle contains the offline verifier and public verification primitives. Build provenance records the exact bundle hash, source revision and source archive hash; these records require an authenticated distribution channel. Drill programs are not shipped in this package.

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

`PACKAGE_MARKER_UNAVAILABLE` refuses use when absence is unproved, including a loader path that does not end in `dist/verify-evidence-pack.js` (such as an unresolved bin link) or a package root that is not a real directory. This refusal is not a finding that the package is a release. Treat a nonzero exit or missing result as refusal, even when no snapshot JSON is produced. Restore a trusted, intact installation before retrying; do not remove a marker to make a candidate usable.

The observation is in-process and adds no host prerequisite. Marker contents and link targets are never opened. Ancestors above the package root are not inspected. Classification is a point-in-time observation that requires a trusted installation with no concurrent package writers. Marker absence does not authenticate a release; authenticate the exact tarball independently.

The companion artifact checker applies the same classification before release-policy checks. Fixture-policy checks and standalone checker help remain available. A fixture-built checker still cannot report release-policy success. Marker-free verifier help, version and snapshot result bytes retain their existing meanings.
