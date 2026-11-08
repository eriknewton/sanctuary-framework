# Evidence snapshot verifier candidate

Copyright 2026 Erik Newton. Apache-2.0.

This private candidate verifies a selected snapshot with independently authenticated pins. It is not published. Use Node 22 or later. Authenticate the exact tarball hash and source revision before installing with scripts disabled.

```sh
npm install --prefix ./verifier --ignore-scripts --no-audit --no-fund ./approved-candidate.tgz
./verifier/node_modules/.bin/verify-evidence-pack --version
./verifier/node_modules/.bin/verify-evidence-pack --pack ./pack \
  --public-key-file ./pins/pack-key.txt --trust-descriptor-file ./pins/public-trust.json \
  --expect-manifest-digest "$(cat ./pins/expected-digest.txt)" --json
```

Only exit 0, status PASS and accepted true accept a snapshot. Compare its export id with the authenticated notice. Exit 10 and PARTIAL require resolution by the sender. Exit 1 and FAIL reject the delivery. Exit 2 requests corrected arguments. Help and version alone exit 0 without a verdict.

All four value flags are mandatory and may occur only once. The key file contains canonical unpadded base64url for 32 bytes with at most one final LF. The expected digest is `sha256:` followed by 64 lowercase hexadecimal digits. Keep pins outside the received pack and authenticate every role and complete key fingerprint separately.

Verify a fresh extraction before browsing it in Finder. Keep the directory unchanged during verification and use. File bytes and names are checked. OS-attached file metadata (provenance, quarantine, security label) is outside the signed set. On Darwin the OS enumerator may read values internally; the verifier consumes only names and discards value output. No label value is evidence.

PASS does not establish freshness, continuous history, legal compliance, wall enforcement, external approval or a globally atomic cut. An older snapshot fails against a different independently supplied expected digest. Reusing the older digest does not establish freshness.

The package has no runtime dependencies or install scripts. Its bundle contains the offline verifier and public verification primitives. Build provenance records the exact bundle hash, source revision and source archive hash; these records require an authenticated distribution channel. Drill programs are not shipped in this package.

<!-- Command and exit contract: server/src/evidence-pack/snapshot-offline-cli.ts and snapshot-contract.ts. -->
