/**
 * state_IDENTITY: the Sanctuary identity adapter over the verified leaf
 * certificate.
 *
 * The library's own policy matching is not used: its SAN check accepts a
 * pattern and its extension check reads the deprecated V1 issuer. This adapter
 * compares exact strings, reads only the V2 Fulcio extensions (OIDs listed in
 * constants.ts), and decodes each as a DER UTF8String, refusing any other
 * encoding. It is a pure function over the certificate view, so tests feed it
 * generated certificates directly.
 */

import {
  FULCIO_OID,
  PINNED_ISSUER,
  PINNED_REF,
  PINNED_REPOSITORY_ID,
  PINNED_REPOSITORY_OWNER_ID,
  PINNED_REPOSITORY_URI,
  PINNED_RUNNER_ENVIRONMENT,
  PINNED_TRIGGER,
  PINNED_WORKFLOW_IDENTITY,
} from "./constants.js";
import { passed, type CertificateView, type IdentityEvidence } from "./evidence.js";
import { refuse, type StepOutcome } from "./reasons.js";

const OID_SUBJECT_ALT_NAME = "2.5.29.17";

/** Each pinned extension: its reason name, OID, and the one accepted value. */
export const IDENTITY_PINS: ReadonlyArray<{ name: string; oid: string; value: string }> = [
  // The token came from GitHub Actions, not another OIDC provider.
  { name: "issuer", oid: FULCIO_OID.issuer, value: PINNED_ISSUER },
  // The workflow file that held the signing token is the release workflow.
  { name: "build-signer-uri", oid: FULCIO_OID.buildSignerUri, value: PINNED_WORKFLOW_IDENTITY },
  // A self-hosted runner is outside GitHub's isolation.
  { name: "runner-environment", oid: FULCIO_OID.runnerEnvironment, value: PINNED_RUNNER_ENVIRONMENT },
  { name: "source-repository-uri", oid: FULCIO_OID.sourceRepositoryUri, value: PINNED_REPOSITORY_URI },
  { name: "source-repository-ref", oid: FULCIO_OID.sourceRepositoryRef, value: PINNED_REF },
  // Numeric ids survive renames, so a new repository or owner under the old name differs here.
  { name: "source-repository-identifier", oid: FULCIO_OID.sourceRepositoryId, value: PINNED_REPOSITORY_ID },
  { name: "source-repository-owner-identifier", oid: FULCIO_OID.sourceRepositoryOwnerId, value: PINNED_REPOSITORY_OWNER_ID },
  // The top-level workflow is the release workflow, not a caller of a reusable one.
  { name: "build-config-uri", oid: FULCIO_OID.buildConfigUri, value: PINNED_WORKFLOW_IDENTITY },
  { name: "build-trigger", oid: FULCIO_OID.buildTrigger, value: PINNED_TRIGGER },
];

const UTF8_STRING_TAG = 0x0c;
const LONG_FORM_BIT = 0x80;
const SHORT_FORM_MAX = 0x7f;
const MAX_LENGTH_OCTETS = 2;
const BITS_PER_BYTE = 8;

/**
 * Decode a DER UTF8String that fills the whole buffer, or return null. DER
 * means the minimal length form: short form below 128, and long form with no
 * leading zero octet and a value that needs it.
 */
export function decodeDerUtf8String(bytes: Buffer): string | null {
  if (bytes.length < 2 || bytes[0] !== UTF8_STRING_TAG) return null;
  const first = bytes[1]!;
  let length: number;
  let offset: number;
  if ((first & LONG_FORM_BIT) === 0) {
    length = first;
    offset = 2;
  } else {
    const octets = first & ~LONG_FORM_BIT;
    if (octets === 0 || octets > MAX_LENGTH_OCTETS || bytes.length < 2 + octets || bytes[2] === 0) return null;
    length = 0;
    for (let i = 0; i < octets; i++) length = (length << BITS_PER_BYTE) | bytes[2 + i]!;
    if (length <= SHORT_FORM_MAX) return null;
    offset = 2 + octets;
  }
  if (offset + length !== bytes.length) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(offset));
  } catch {
    return null;
  }
}

export function state_IDENTITY(certificate: CertificateView): StepOutcome<IdentityEvidence> {
  const sanExtensions = certificate.extensions.filter(extension => extension.oid === OID_SUBJECT_ALT_NAME);
  if (sanExtensions.length === 0 || certificate.sanUri === undefined) return refuse("identity-extension-absent:san");
  // The SAN is the workflow identity Fulcio bound the key to; exact equality, never a pattern.
  if (sanExtensions.length > 1 || certificate.sanUri !== PINNED_WORKFLOW_IDENTITY) return refuse("identity-mismatch:san");

  const values = new Map<string, string>();
  for (const pin of IDENTITY_PINS) {
    const found = certificate.extensions.filter(extension => extension.oid === pin.oid);
    if (found.length === 0) return refuse(`identity-extension-absent:${pin.name}`);
    // A repeated extension is malformed X.509, and which copy counts would be the certificate's choice.
    if (found.length > 1) return refuse(`identity-mismatch:${pin.name}`);
    const value = decodeDerUtf8String(found[0]!.value);
    if (value === null || value !== pin.value) return refuse(`identity-mismatch:${pin.name}`);
    values.set(pin.name, value);
  }
  return passed({
    state: "state_IDENTITY",
    repositoryUri: values.get("source-repository-uri")!,
    repositoryId: values.get("source-repository-identifier")!,
    repositoryOwnerId: values.get("source-repository-owner-identifier")!,
    ref: values.get("source-repository-ref")!,
    trigger: values.get("build-trigger")!,
  });
}
