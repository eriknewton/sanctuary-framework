# SDW Secret Persistence Boundary

The enforced SDW secret boundary is **structural provenance**, not text scanning.
Read the claim carefully: it is precise about what is and is not guaranteed.

## What provenance guarantees (and its precondition)

When Principal Policy material, identity private-key material, or recovery-key
material is **routed through the SDW provenance minters** (`taintFromPolicy`,
`taintFromIdentityKey`, `taintFromSecret`) and assembled with
`taintRecordFromFields`, its forbidding taint is carried with the value. The
join uses the monotone SDW lattice (most-restrictive wins; no rank descends from
a forbidden taint to a persistable one), and `mintPersistableFromProvenance`
admits only the three persistable taints, so a record carrying any forbidding
field taint is rejected before encryption.

**Precondition (honest boundary).** This guarantee holds for values that *enter
the SDW through the provenance path*. It is NOT retroactive: a caller that
unwraps `carrier.value` and re-mints it as clean, via `taintClean(value,
"user_content")` or via the legacy caller-asserted `mintPersistable` path that
stores still use for their own already-clean typed records, can launder it past
the structural gate (the classifier is then the only backstop). The provenance
minters therefore assume callers do not deliberately re-mint source-derived
values as clean. **Forcing every crown-jewel source through the provenance path
and retiring/guarding the caller-asserted taint is the consumer-integration
follow-on; it is not yet built because SDW has no live consumers outside
`server/src/sdw/` today.** Until then, "provenance is the enforced boundary"
means "for material the consumer routes through it," not "for all bytes that
reach the store."

## What the classifier is (defense in depth, with known gaps)

The classifier in `write-gate.ts` is a heuristic backstop, **not** the guarantee.
It canonicalizes the whole record (fields + nested values + metadata) before
scanning and *flags* several common high-signal shapes: PEM/private-key markers
(including split across non-adjacent fields), encoded or explicitly labeled
Ed25519 key material, explicitly labeled Sanctuary recovery-key material,
checksum-valid GitHub tokens, common provider token prefixes, JWTs, URL-embedded
credentials, and keyword-gated high-entropy blobs. A classifier hit fails closed;
a classifier **pass is never a guarantee** that arbitrary free text contains no
secret. Known, deliberate false negatives (documented, not bugs):

- GitHub tokens are rejected only when the trailing CRC32-base62 **checksum
  validates** (a deliberate false-positive control per the secret-detection prior
  art). Malformed or legacy-format `gh*_`/`github_pat_` values may pass.
- Keyword-gated entropy detection **skips canonical hash lengths** (32/40/64-char
  hex) to avoid flagging content hashes/ids; a secret that happens to be exactly
  a hash length may pass even when a secret-ish keyword is nearby.
- The split-marker reassembly covers PEM private-key markers; it does not attempt
  to reassemble arbitrary secrets fragmented across fields.
- Keyword-gated entropy requires the keyword and a high-entropy candidate to
  be near each other (the same line, or a bounded proximity window), not
  anywhere in the whole scanned text. A keyword and a genuine secret farther
  apart, or split across unrelated fields, may pass unless provenance,
  another detector, or the bare-credential fallback below rejects it.
- A bare high-entropy value with no keyword nearby is additionally checked
  against a narrow, opt-in fallback. The classifier recognizes a small set
  of concrete shapes as not themselves the secret (for example, a value
  written inside a markdown code span); a value in one of those shapes is a
  stated residual, and a value that is neither near a keyword nor in one of
  those shapes still passes this fallback, with provenance and the other
  detectors as the remaining backstops. This fallback runs only for
  harness-mirrored memory-file text, where the classifier is the sole
  backstop; every other SDW record kind and memory-passage caller
  legitimately carries system-generated content this fallback would
  otherwise misclassify, so it stays off there by default.
- Names such as `principal_policy`, `recovery key`, `SANCTUARY_RECOVERY_KEY`,
  and `Ed25519 private key` are allowed in ordinary prose. Policy and key
  provenance remains fail-closed, while the classifier rejects labeled key
  values only when they have a concrete 32-byte base64url or hex shape.
  Arbitrary copied policy text or malformed/legacy key encodings may therefore
  pass when a caller bypasses the provenance minters.

Free text that never passes through a source minter is covered **only** by this
heuristic backstop. Closing these gaps fully is the consumer-integration
follow-on (route real sources through provenance), not a stronger classifier.

**Known, deliberate false positive (documented, not a bug):** the
keyword-gated entropy check's keyword boundary treats punctuation
(including `_` and `=`) as a delimiter. This correctly catches an
assignment-shaped secret line, but a keyword that is itself the prefix of a
longer identifier named in ordinary prose can also gate, with no secret
present, when a high-entropy value sits nearby. This is the deliberately
chosen behavior: correctness on the assignment shape outweighs the prose
false positive, which the operator resolves the same way as any other
classifier refusal: edit the file, or keep it outside the mirrored
directory.

## Out of scope by design

Verification-based secret detection (calling a provider API to confirm a
candidate credential is live) is deliberately NOT part of the SDW write gate:
Sanctuary must never transmit candidate secrets to third parties. The
false-positive budget is spent on offline structure checks (checksums, structural
JWT decode, keyword-gated entropy) instead.
