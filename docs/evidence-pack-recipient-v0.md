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

Compare the reported version and full revision with the authenticated notice. Accept only exit 0, `status:"PASS"`, `accepted:true` and the expected export id together. Exit 10, `status:"PARTIAL"` and `accepted:false` mean checks are incomplete; retain the explicit reasons and ask the sender to resolve them. Exit 1 and FAIL reject the delivery. Exit 2 requests corrected arguments and a fresh run. Only lone `--help` or `--version` exits 0 without a verdict.

The command checks the exact signed manifest digest, the manifest signature, the complete file set, every file's bytes, independent descriptor equality and the included supported audit and transparency records. It requires all four value flags once each. There are no environment pins, embedded trust options or downgrade flags. Output failure is a failed command.

OS-attached file metadata (provenance, quarantine, security label) is outside the signed set. No label value is evidence. Darwin uses the OS enumerator, which can read values internally; the verifier consumes names only and discards value output. A native name-only call is outside this candidate's capability. File modes, owners and timestamps are not exported evidence. The verifier observes file stability during its run and gives no guarantee about later changes.

PASS does not establish continuous history, legal compliance, wall enforcement, external approval, freshness or a globally atomic cut. An old snapshot rejects only relative to a different independently supplied digest. Reusing its old digest does not establish freshness. The package's provenance records require an authenticated distribution channel and do not by themselves prove reproducibility.

The command invokes both nested verifiers. A separately installed legacy server command can diagnose a single audit key with `sanctuary audit-chain verify --input audit-chain.jsonl --public-key "$(cat pins/audit-key.txt)"`. That diagnostic is not full-pack acceptance and does not handle multiple audit keys.

<!-- Command and exit contract: server/src/evidence-pack/snapshot-offline-cli.ts and snapshot-contract.ts. -->
