import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import type {
  EnforcementAvailabilityReportNotification,
  EnforcementAvailabilitySnapshot,
} from "../../../src/castle-wall/ipc/messages.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import {
  ENFORCEMENT_AVAILABILITY_REPORT_OPERATION,
} from "../../../src/castle-wall/runtime/enforcement-availability.js";
import {
  producerSigningBytes,
  toBase64url,
} from "../../../src/castle-wall/runtime/producer-signature.js";

export const DEFAULT_AVAILABILITY_FORTRESS_ID = "fortress-test";
export const DEFAULT_AVAILABILITY_CAPTURED_AT_UNIX_MS = 1_780_000_000_000;

export interface AvailabilityProducerKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyB64url: string;
}

export function makeAvailabilityProducerKey(): AvailabilityProducerKey {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    publicKeyB64url: toBase64url(publicKey),
  };
}

export function availabilitySnapshot(
  overrides: Partial<EnforcementAvailabilitySnapshot> = {},
): EnforcementAvailabilitySnapshot {
  return {
    protocol_version: 1,
    source: "macos_extension",
    lease_state: "live",
    lease_reason: "ok",
    manifest_state: "applied",
    manifest_signature_b64url: "manifest-sig",
    provider_bound: true,
    producer_claimed_at: "1970-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function availabilityIsGreen(snapshot: EnforcementAvailabilitySnapshot): boolean {
  return (
    snapshot.protocol_version === 1 &&
    snapshot.source === "macos_extension" &&
    snapshot.lease_state === "live" &&
    snapshot.lease_reason === "ok" &&
    snapshot.manifest_state === "applied" &&
    typeof snapshot.manifest_signature_b64url === "string" &&
    snapshot.manifest_signature_b64url.length > 0 &&
    snapshot.provider_bound === true
  );
}

export function availabilityCanonicalJson(input: {
  report: EnforcementAvailabilitySnapshot;
  seq: number;
  priorSha256Hex?: string | null;
  capturedAtUnixMs?: number;
  fortressId?: string;
}): string {
  const capturedAtUnixMs =
    input.capturedAtUnixMs ?? DEFAULT_AVAILABILITY_CAPTURED_AT_UNIX_MS;
  return canonicalize({
    timestamp:
      input.report.producer_claimed_at ??
      new Date(capturedAtUnixMs).toISOString(),
    layer: "l1",
    operation: ENFORCEMENT_AVAILABILITY_REPORT_OPERATION,
    identity_id: input.fortressId ?? DEFAULT_AVAILABILITY_FORTRESS_ID,
    result: availabilityIsGreen(input.report) ? "success" : "failure",
    details: {
      seq: input.seq,
      prior_sha256_hex: input.priorSha256Hex ?? null,
      enforcement: input.report,
    },
  });
}

export function signAvailabilityReport(input: {
  visibleReport: EnforcementAvailabilitySnapshot;
  signedReport?: EnforcementAvailabilitySnapshot;
  privateKey: Uint8Array;
  seq?: number;
  priorSha256Hex?: string | null;
  capturedAtUnixMs?: number;
  fortressId?: string;
}): EnforcementAvailabilityReportNotification {
  const seq = input.seq ?? 0;
  const capturedAtUnixMs =
    input.capturedAtUnixMs ?? DEFAULT_AVAILABILITY_CAPTURED_AT_UNIX_MS;
  const priorSha256Hex = input.priorSha256Hex ?? null;
  const eventCanonicalJson = availabilityCanonicalJson({
    report: input.signedReport ?? input.visibleReport,
    seq,
    priorSha256Hex,
    capturedAtUnixMs,
    fortressId: input.fortressId,
  });
  const signature = ed25519.sign(
    producerSigningBytes(eventCanonicalJson, capturedAtUnixMs, seq),
    input.privateKey,
  );
  return {
    type: "enforcement_availability_report",
    enforcement: input.visibleReport,
    producer: {
      event_canonical_json: eventCanonicalJson,
      captured_at_unix_ms: capturedAtUnixMs,
      seq,
      prior_sha256_hex: priorSha256Hex,
      signature_b64url: toBase64url(signature),
      key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
  };
}
