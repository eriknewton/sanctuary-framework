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
admits only the three persistable taints — so a record carrying any forbidding
field taint is rejected before encryption.

**Precondition (honest boundary).** This guarantee holds for values that *enter
the SDW through the provenance path*. It is NOT retroactive: a caller that
unwraps `carrier.value` and re-mints it as clean — via `taintClean(value,
"user_content")` or via the legacy caller-asserted `mintPersistable` path that
stores still use for their own already-clean typed records — can launder it past
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
scanning and *flags* several common high-signal shapes — PEM/private-key markers
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
- Keyword-gated entropy requires the keyword and the high-entropy candidate to
  co-occur on the SAME LINE, or within a bounded proximity window (measured in
  Unicode code points, not raw UTF-16 offsets), not anywhere in the whole
  scanned text (Rung-1 F1, 2026-08-22). Pre-fix, a keyword anywhere in a large
  file and an unrelated high-entropy identifier anywhere else in the same file
  were treated as one secret; the round-trip drill measured this refusing a
  real memory-file index that mentioned "token" once and held one unrelated
  identifier hundreds of lines away. This also prevents a prose word such as
  `secret` from turning an unrelated generated record ID elsewhere in the same
  field into a false positive. A keyword and a genuine secret split across
  unrelated fields, or farther apart than the window within one field, may
  pass unless provenance, another high-signal detector, or the bare-credential
  fallback below rejects it.
- A bare high-entropy value with no keyword nearby is additionally checked
  against a narrow fallback (`bare_high_entropy_credential`): a base64url- or
  hex-shaped run of 32+ characters at or above the entropy threshold is
  refused unless it sits in one of four exempted contexts — a canonical hash
  length (32/40/64 hex chars, already covered above), a markdown link target
  or a URL path/query segment written contiguously against it (no
  whitespace break — an unrelated URL earlier on the same line does not
  exempt a later, separate value), an explicit `sha256:`/`sha1:`/`md5:`/
  `commit` label immediately before it, or a value written between
  backticks (an inline code span, e.g. a key pasted as `` `<value>` ``,
  which markdown authoring commonly does for file paths and identifiers).
  Those four are the capability's bound, not an exhaustive defense: a value
  in one of those four shapes passes even when it is a genuine secret. This
  fallback is opt-in (`applyBareCredentialFallback`), not the classifier's
  default — `claude-code-file-adapter.ts`/`codex-memory-file-adapter.ts` turn
  it on for harness memory-file text specifically, because the classifier is
  the ONLY backstop there (both tag mirrored files `user_content`, so no
  provenance/taint check catches it either). It is deliberately OFF for
  every other SDW record kind and for every other memory-passage caller
  (archive import/restore, memory-transcode's own archive bookkeeping, the
  general-purpose agent-memory MCP tool), which legitimately carry
  system-generated ids, signatures, and content hashes that are high-entropy
  by construction and are not the false-positive class this fallback exists
  to catch.
- Names such as `principal_policy`, `recovery key`, `SANCTUARY_RECOVERY_KEY`,
  and `Ed25519 private key` are allowed in ordinary prose. Policy and key
  provenance remains fail-closed, while the classifier rejects labeled key
  values only when they have a concrete 32-byte base64url or hex shape.
  Arbitrary copied policy text or malformed/legacy key encodings may therefore
  pass when a caller bypasses the provenance minters.

Free text that never passes through a source minter is covered **only** by this
heuristic backstop. Closing these gaps fully is the consumer-integration
follow-on (route real sources through provenance), not a stronger classifier.

## Out of scope by design

Verification-based secret detection (calling a provider API to confirm a
candidate credential is live) is deliberately NOT part of the SDW write gate:
Sanctuary must never transmit candidate secrets to third parties. The
false-positive budget is spent on offline structure checks (checksums, structural
JWT decode, keyword-gated entropy) instead.
