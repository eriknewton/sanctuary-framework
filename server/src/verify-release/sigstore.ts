/**
 * state_BUNDLE_SELECT and state_SIGSTORE.
 *
 * The Sigstore packages are imported here with `await import()` only, inside
 * the step, so no other command and no earlier step ever loads them, and a
 * runtime outside their engine range refuses before they load.
 */

import { SLSA_PROVENANCE_V1 } from "./constants.js";
import { passed, type BundleSelectEvidence, type CertificateView, type SigstoreEvidence } from "./evidence.js";
import { refuse, type StepOutcome } from "./reasons.js";

/** Read the predicateType from a bundle's SIGNED payload, or undefined when it does not decode. */
function signedPredicateType(bundle: unknown): string | undefined {
  if (typeof bundle !== "object" || bundle === null) return undefined;
  const envelope = (bundle as { dsseEnvelope?: unknown }).dsseEnvelope;
  if (typeof envelope !== "object" || envelope === null) return undefined;
  const payload = (envelope as { payload?: unknown }).payload;
  if (typeof payload !== "string") return undefined;
  try {
    const statement: unknown = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    const type = (statement as { predicateType?: unknown } | null)?.predicateType;
    return typeof type === "string" ? type : undefined;
  } catch {
    return undefined;
  }
}

/**
 * state_BUNDLE_SELECT. The attestations document's outer `predicateType` label
 * is unsigned, so selection reads the predicateType inside each DSSE payload.
 * Exactly one SLSA provenance v1 bundle must exist: none is absent provenance,
 * and two would let the document choose which one is checked.
 */
export function state_BUNDLE_SELECT(document: unknown): StepOutcome<BundleSelectEvidence> {
  const list = (document as { attestations?: unknown } | null)?.attestations;
  if (!Array.isArray(list)) return refuse("provenance-absent");
  const selected = list
    .map(item => (item as { bundle?: unknown } | null)?.bundle)
    .filter(bundle => signedPredicateType(bundle) === SLSA_PROVENANCE_V1);
  if (selected.length === 0) return refuse("provenance-absent");
  if (selected.length > 1) return refuse("provenance-ambiguous");
  return passed({ state: "state_BUNDLE_SELECT", bundle: selected[0] });
}

const nonEmptyString = (value: unknown): boolean => typeof value === "string" && value.length > 0;

/**
 * The local transparency-log guard. The library's threshold counts entries; it
 * does not demand a proof. Both are required here, and the library verifies
 * each one that is present, so presence plus a passing verify means both were
 * checked. Exactly one entry, so which entry authenticated the time is never
 * ambiguous.
 */
export function requireProofAndSet(bundle: unknown): `sigstore-invalid:${string}` | null {
  const entries = (bundle as { verificationMaterial?: { tlogEntries?: unknown } } | null)?.verificationMaterial?.tlogEntries;
  if (!Array.isArray(entries) || entries.length !== 1) return "sigstore-invalid:TLOG_ENTRY_COUNT";
  const entry = entries[0] as { inclusionProof?: { checkpoint?: { envelope?: unknown } }; inclusionPromise?: { signedEntryTimestamp?: unknown } } | null;
  // A promise alone is a log's signed intent to include, not evidence of inclusion in its tree.
  if (!nonEmptyString(entry?.inclusionProof?.checkpoint?.envelope)) return "sigstore-invalid:proof-required";
  // The SET is what authenticates integratedTime in Rekor v1; a Merkle proof does not cover it.
  if (!nonEmptyString(entry?.inclusionPromise?.signedEntryTimestamp)) return "sigstore-invalid:set-required";
  return null;
}

/** Library thresholds: one tlog entry, one SCT, one timestamp (the SET-authenticated log time). */
export const VERIFIER_THRESHOLDS = { tlogThreshold: 1, ctlogThreshold: 1, timestampThreshold: 1 } as const;

function libraryCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]{1,64}$/.test(code) ? code : "VERIFY_ERROR";
}

/**
 * state_SIGSTORE. The ONLY trust material is
 * `toTrustMaterial(TrustedRoot.fromJSON(<committed root bytes>))`.
 */
export async function state_SIGSTORE(
  selection: BundleSelectEvidence,
  trustedRootBytes: Buffer | null,
): Promise<StepOutcome<SigstoreEvidence>> {
  const [{ bundleFromJSON }, { Verifier, toSignedEntity, toTrustMaterial }, { TrustedRoot }] = await Promise.all([
    import("@sigstore/bundle"),
    import("@sigstore/verify"),
    import("@sigstore/protobuf-specs"),
  ]);

  if (trustedRootBytes === null) return refuse("sigstore-invalid:TRUSTED_ROOT_UNAVAILABLE");
  let trustMaterial: ReturnType<typeof toTrustMaterial>;
  try {
    trustMaterial = toTrustMaterial(TrustedRoot.fromJSON(JSON.parse(trustedRootBytes.toString("utf8"))));
  } catch {
    return refuse("sigstore-invalid:TRUSTED_ROOT_INVALID");
  }

  // The proof-and-SET guard reads the same JSON object the library parses next. It runs first because the
  // library's own bundle validation also rejects some of these shapes, which would hide which one failed.
  const guard = requireProofAndSet(selection.bundle);
  if (guard !== null) return refuse(guard);

  let bundle: ReturnType<typeof bundleFromJSON>;
  let entity: ReturnType<typeof toSignedEntity>;
  try {
    bundle = bundleFromJSON(selection.bundle);
    // Entity conversion parses the leaf certificate's DER, so it is parsing too: malformed bytes refuse here.
    entity = toSignedEntity(bundle);
  } catch {
    return refuse("sigstore-invalid:BUNDLE_INVALID");
  }
  if (bundle.content.$case !== "dsseEnvelope") return refuse("sigstore-invalid:DSSE_REQUIRED");
  const entry = bundle.verificationMaterial.tlogEntries[0]!;
  const integratedTime = Number(entry.integratedTime);
  if (!Number.isSafeInteger(integratedTime) || integratedTime <= 0) return refuse("sigstore-invalid:INTEGRATED_TIME");

  // Only a Fulcio certificate carries the workflow identity; a bare public key names no build.
  if (entity.key.$case !== "certificate") return refuse("sigstore-invalid:CERTIFICATE_REQUIRED");
  try {
    new Verifier(trustMaterial, VERIFIER_THRESHOLDS).verify(entity);
  } catch (error) {
    // Every library failure reports the library's code: the log time is unauthenticated once verification has
    // failed, so it can never select a different refusal, such as a claim that the committed root is stale.
    return refuse(`sigstore-invalid:${libraryCode(error)}`);
  }

  // The identity adapter reads the SAME certificate object the verifier accepted.
  const certificate = certificateViewOf(entity.key.certificate);
  return passed({
    state: "state_SIGSTORE",
    payload: Buffer.from(bundle.content.dsseEnvelope.payload),
    payloadType: bundle.content.dsseEnvelope.payloadType,
    certificate,
    integratedTime,
  });
}

/**
 * The view of a parsed `@sigstore/core` X509Certificate that the identity
 * adapter reads: the SAN URI and each extension's OID and extnValue contents.
 */
export function certificateViewOf(leaf: {
  extSubjectAltName?: { uri?: string } | undefined;
  extensions: Array<{ subs: Array<{ toOID(): string; value: Buffer }> }>;
}): CertificateView {
  return {
    sanUri: leaf.extSubjectAltName?.uri,
    extensions: leaf.extensions.map(extension => ({
      oid: extension.subs[0]!.toOID(),
      value: extension.subs[extension.subs.length - 1]!.value,
    })),
  };
}
