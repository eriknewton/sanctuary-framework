/**
 * state_SUBJECT and state_MANIFEST: bind the fetched tarball bytes to the
 * signed provenance subject, to the registry's integrity string, and to the
 * release manifest signed with Sanctuary's pinned key.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { manifestArtifactName, subjectName } from "./constants.js";
import { passed, type ManifestEvidence, type StatementEvidence, type SubjectEvidence } from "./evidence.js";
import { refuse, type StepOutcome } from "./reasons.js";
import type { ManifestVerificationResult } from "../release-manifest.js";

const SHA512_BYTES = 64;
const SHA512_HEX_PATTERN = /^[0-9a-f]{128}$/; // 128 = 2 hex characters x 64 bytes
const SRI_SHA512_PREFIX = "sha512-";
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/; // 64 = 2 hex characters x 32 bytes

/** Decode SRI `sha512-<base64>`: exactly one token, canonical base64, 64 bytes. */
export function decodeSriSha512(integrity: unknown): Buffer | null {
  if (typeof integrity !== "string" || !integrity.startsWith(SRI_SHA512_PREFIX)) return null;
  const body = integrity.slice(SRI_SHA512_PREFIX.length);
  // Node's decoder is lenient, so the bytes must re-encode to exactly the input: a second token, whitespace,
  // missing padding or non-zero padding bits would make the string ambiguous about which digest counts.
  const bytes = Buffer.from(body, "base64");
  return bytes.length === SHA512_BYTES && bytes.toString("base64") === body ? bytes : null;
}

/**
 * state_SUBJECT. The provenance signs a digest, not a file: only when that
 * digest equals the sha512 of the bytes actually fetched does the signature
 * speak for this tarball. The registry's own `dist.integrity` must agree too,
 * so the version document and the provenance cannot describe different files.
 */
export function state_SUBJECT(
  statement: StatementEvidence,
  versionDocument: unknown,
  tarball: Buffer,
  version: string,
): StepOutcome<SubjectEvidence> {
  if (statement.subjects.length !== 1) return refuse("subject-invalid");
  const subject = statement.subjects[0]!;
  if (subject.name !== subjectName(version)) return refuse("subject-invalid");
  if (subject.sha512 === undefined || !SHA512_HEX_PATTERN.test(subject.sha512)) return refuse("digest-malformed");
  const dist = (versionDocument as { dist?: unknown } | null)?.dist;
  const integrity = decodeSriSha512((dist as { integrity?: unknown } | null)?.integrity);
  if (integrity === null) return refuse("digest-malformed");
  const actual = createHash("sha512").update(tarball).digest();
  if (!timingSafeEqual(Buffer.from(subject.sha512, "hex"), actual)) return refuse("subject-digest-mismatch");
  if (!timingSafeEqual(integrity, actual)) return refuse("packument-integrity-mismatch");
  return passed({ state: "state_SUBJECT", sha512: actual });
}

/**
 * state_MANIFEST. `verify` is `verifyReleaseManifest` (pinned key) in
 * production; tests pass `verifyReleaseManifestWithKey` bound to a test key.
 * The manifest must list exactly the one tarball artifact, so a manifest cannot
 * vouch for this version by naming some other file.
 */
export function state_MANIFEST(
  manifest: unknown,
  tarball: Buffer,
  version: string,
  verify: (value: unknown) => ManifestVerificationResult,
): StepOutcome<ManifestEvidence> {
  const result = verify(manifest);
  if (!result.ok) return refuse("manifest-invalid");
  if (result.body.version !== version) return refuse("manifest-version-mismatch");
  const hashes = result.body.artifact_hashes;
  if (Object.keys(hashes).length !== 1) return refuse("manifest-invalid");
  // The one listed artifact must be this tarball; a lookup under any other name finds nothing.
  const signed = hashes[manifestArtifactName(version)];
  if (signed === undefined || !SHA256_HEX_PATTERN.test(signed)) return refuse("manifest-invalid");
  const actual = createHash("sha256").update(tarball).digest("hex");
  if (signed !== actual) return refuse("manifest-digest-mismatch");
  return passed({ state: "state_MANIFEST", sha256: actual });
}
