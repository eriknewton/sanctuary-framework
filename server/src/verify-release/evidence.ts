/**
 * Named states, their typed evidence, and the ONE verdict constructor.
 *
 * Each step returns evidence or a refusal. `constructVerifiedVerdict` is the only
 * function that produces `verified`; it takes one evidence object per state as
 * required parameters, so the type system rejects a call that skips a step, and
 * it re-checks at run time that every object was minted for its own state and
 * that the run deadline has not passed.
 */

import type { Deadline } from "./deadline.js";
import type { StepOutcome } from "./reasons.js";

/** The reported steps, in their fixed order. */
export const STEP_NAMES = [
  "runtime", "target", "fetch", "bundle-select", "sigstore", "identity",
  "statement", "subject", "manifest", "archive", "installed",
] as const;
export type StepName = typeof STEP_NAMES[number];

export interface RuntimeEvidence { readonly state: "state_RUNTIME"; readonly nodeVersion: string }
export interface TargetEvidence {
  readonly state: "state_TARGET";
  /** realpath of the target; printed so the user sees exactly what was checked. */
  readonly root: string;
  readonly version: string;
  readonly mode: "target" | "self";
}
export interface FetchEvidence {
  readonly state: "state_FETCH";
  readonly versionDocument: unknown;
  readonly attestations: unknown;
  readonly tarball: Buffer;
  readonly manifest: unknown;
}
export interface BundleSelectEvidence { readonly state: "state_BUNDLE_SELECT"; readonly bundle: unknown }
export interface CertificateExtensionView {
  /** Extension OID, dotted. */
  readonly oid: string;
  /** Contents of the extnValue OCTET STRING. */
  readonly value: Buffer;
}
/** The parts of the verified leaf certificate the identity adapter reads. */
export interface CertificateView {
  readonly sanUri: string | undefined;
  readonly extensions: readonly CertificateExtensionView[];
}
export interface SigstoreEvidence {
  readonly state: "state_SIGSTORE";
  /** The DSSE payload the library verified the signature over. */
  readonly payload: Buffer;
  readonly payloadType: string;
  /** The leaf certificate the library verified, read from the same object. */
  readonly certificate: CertificateView;
  /** Seconds since the epoch, authenticated by the verified SET. */
  readonly integratedTime: number;
}
export interface IdentityEvidence {
  readonly state: "state_IDENTITY";
  readonly repositoryUri: string;
  readonly repositoryId: string;
  readonly repositoryOwnerId: string;
  readonly ref: string;
  readonly trigger: string;
}
export interface StatementSubject { readonly name: string; readonly sha512: string | undefined }
export interface StatementEvidence { readonly state: "state_STATEMENT"; readonly subjects: readonly StatementSubject[] }
export interface SubjectEvidence { readonly state: "state_SUBJECT"; readonly sha512: Buffer }
export interface ManifestEvidence { readonly state: "state_MANIFEST"; readonly sha256: string }
export interface ArchiveFile { readonly sha256: string; readonly size: number }
export interface ArchiveEvidence {
  readonly state: "state_ARCHIVE";
  /** Key: archive path with one `package/` removed, NFC. */
  readonly files: ReadonlyMap<string, ArchiveFile>;
  /** Explicit and implicit directories, same key form. */
  readonly directories: ReadonlySet<string>;
}
export interface InstalledEvidence { readonly state: "state_INSTALLED"; readonly fileCount: number }

type AnyEvidence = RuntimeEvidence | TargetEvidence | FetchEvidence | BundleSelectEvidence | SigstoreEvidence
  | IdentityEvidence | StatementEvidence | SubjectEvidence | ManifestEvidence | ArchiveEvidence | InstalledEvidence;

const minted = new WeakSet<object>();

/** Freeze and register one evidence object. */
export function mint<E extends AnyEvidence>(evidence: E): E {
  const frozen = Object.freeze(evidence);
  minted.add(frozen);
  return frozen;
}

export function passed<E extends AnyEvidence>(evidence: E): StepOutcome<E> {
  return { ok: true, evidence: mint(evidence) };
}

export interface VerdictEvidence {
  runtime: RuntimeEvidence;
  target: TargetEvidence;
  fetch: FetchEvidence;
  bundle: BundleSelectEvidence;
  sigstore: SigstoreEvidence;
  identity: IdentityEvidence;
  statement: StatementEvidence;
  subject: SubjectEvidence;
  manifest: ManifestEvidence;
  archive: ArchiveEvidence;
  installed: InstalledEvidence;
}

const REQUIRED_STATES: { [K in keyof VerdictEvidence]: VerdictEvidence[K]["state"] } = {
  runtime: "state_RUNTIME", target: "state_TARGET", fetch: "state_FETCH", bundle: "state_BUNDLE_SELECT",
  sigstore: "state_SIGSTORE", identity: "state_IDENTITY", statement: "state_STATEMENT",
  subject: "state_SUBJECT", manifest: "state_MANIFEST", archive: "state_ARCHIVE", installed: "state_INSTALLED",
};

export interface VerifiedVerdict { readonly verdict: "verified"; readonly root: string; readonly version: string }

/** Thrown when the constructor is called without full evidence: a programming error, never a verdict. */
export class IncompleteEvidenceError extends Error {
  constructor(field: string) {
    super(`verdict constructor called without ${field} evidence`);
    this.name = "IncompleteEvidenceError";
  }
}

/**
 * state_VERDICT. The single constructor of `verified`. A missing or forged
 * evidence object throws (internal error, exit 1, never `verified`); a passed
 * deadline returns the `deadline-exceeded` refusal.
 */
export function constructVerifiedVerdict(
  evidence: VerdictEvidence,
  deadline: Deadline,
): { ok: true; verdict: VerifiedVerdict } | { ok: false; reason: "deadline-exceeded" } {
  for (const [field, state] of Object.entries(REQUIRED_STATES)) {
    const item = (evidence as unknown as Record<string, AnyEvidence | undefined>)[field];
    // Evidence must be minted by a step for its own state; a look-alike object is refused.
    if (item === undefined || item === null || !minted.has(item) || item.state !== state) {
      throw new IncompleteEvidenceError(field);
    }
  }
  // A step that completed after expiry contributes nothing, so expiry is checked last, here.
  if (deadline.expired()) return { ok: false, reason: "deadline-exceeded" };
  return { ok: true, verdict: Object.freeze({ verdict: "verified", root: evidence.target.root, version: evidence.target.version }) };
}
