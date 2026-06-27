# Signed Self-Update Design, 2026-06-27

## Current Surface

Sanctuary does not currently apply its own updates. The server package is installed through npm or npx as `@sanctuary-framework/mcp-server`, and `server/src/update-check.ts` performs only a best-effort npm registry lookup that prints an update notice. It does not download, install, replace, or execute a new artifact. Castle Wall native delivery is also outside this server-side update check path.

Because there is no in-tree self-applying updater, this hardening wave does not add an update applicator. The safe change is to specify the verifier that must front any future updater and to keep the current notice-only path from being mistaken for an integrity guarantee.

## Threat

A self-update path must assume an attacker may control or tamper with the package source, a transit path, a cached artifact, or an older signed artifact. The update check must reject:

- unsigned release metadata
- metadata signed by the wrong key
- artifact bytes whose digest does not match the signed metadata
- a version lower than or equal to the locally applied version
- expired metadata
- metadata for the wrong package, platform, architecture, or release channel

The failure mode is refusal with audit, never fallback to an unsigned or lower-version update.

## Proposed Verifier

Add a small reusable verifier before any update is applied:

1. Pin an Ed25519 release-signing public key in source.
2. Fetch a release manifest whose signed body contains:
   - package name
   - release channel
   - semantic version
   - created_at and expires_at
   - npm package tarball sha256
   - native artifact hashes when Castle Wall artifacts are included
   - minimum supported current version, if a migration requires it
3. Verify the manifest signature over canonical JSON.
4. Verify `manifest.version > currently_applied_version`.
5. Verify `created_at <= now < expires_at`.
6. Download the artifact only after manifest verification.
7. Hash the artifact and compare it to the signed digest.
8. Apply the update only after all checks pass.
9. Emit an audit event for every rejection and for every accepted update.

The verifier should return structured refusal reasons such as `update_manifest_unsigned`, `update_manifest_bad_signature`, `update_version_replay`, `update_manifest_expired`, and `update_artifact_digest_mismatch`.

## Integration Rule

`server/src/update-check.ts` may continue to be a notice-only registry check, but its output must not claim the update is verified. If a future PR adds any code path that downloads or applies an update, that path must call the signed manifest verifier before touching the artifact, and must fail closed on every verifier error.

