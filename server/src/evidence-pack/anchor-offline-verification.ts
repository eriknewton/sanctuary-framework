/**
 * Evidence-pack wording gate for public-anchor evidence.
 *
 * This does not fetch from Rekor and does not weaken the standalone verifier.
 * It parses the already-bundled files and runs the existing offline anchor
 * verifier to decide whether the report may claim offline public-anchor
 * confirmation, or must print a caveat.
 */

import { TRANSPARENCY_BUNDLE_FORMAT } from "../transparency/checkpoint.js";
import { verifyAnchorEvidence } from "../transparency/anchor-verify.js";
import {
  isVerifierCheckpointRecord,
  type VerifierCheckpointRecord,
} from "../transparency/verify.js";
import type { ReadOutcome } from "./read-outcome.js";

export interface AnchorOfflineVerificationView {
  status: "confirmable" | "not_confirmable";
  confirmable_receipts: number;
  verified_receipts: number;
  consistent_receipts: number;
  unverified_receipts: number;
  invalid_receipts: number;
  anchor_failed_receipts: number;
  unanchored_checkpoints: number;
  findings: number;
  log_signature_basis: "pinned-rekor-key" | "none";
  detail: string;
}

const NOT_RUN_BASIS: AnchorOfflineVerificationView = {
  status: "not_confirmable",
  confirmable_receipts: 0,
  verified_receipts: 0,
  consistent_receipts: 0,
  unverified_receipts: 0,
  invalid_receipts: 0,
  anchor_failed_receipts: 0,
  unanchored_checkpoints: 0,
  findings: 0,
  log_signature_basis: "none",
  detail:
    "the bundled files were not both present as populated evidence, so the offline anchor verifier was not run",
};

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseJson(text: string): unknown | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseCheckpointRecords(text: string): VerifierCheckpointRecord[] | null {
  const parsed = parseJson(text);
  if (
    !isObject(parsed) ||
    parsed.format !== TRANSPARENCY_BUNDLE_FORMAT ||
    !Array.isArray(parsed.checkpoints)
  ) {
    return null;
  }
  const records: VerifierCheckpointRecord[] = [];
  for (const checkpoint of parsed.checkpoints) {
    if (!isVerifierCheckpointRecord(checkpoint)) return null;
    records.push(checkpoint);
  }
  return records;
}

function caveatDetail(view: Omit<AnchorOfflineVerificationView, "detail" | "status">): string {
  return (
    `the offline verifier reported ${view.verified_receipts} log-key verified ` +
    `receipt(s), ${view.consistent_receipts} internally consistent receipt(s), ` +
    `${view.unverified_receipts} unverified receipt(s), ` +
    `${view.invalid_receipts} invalid receipt(s), ` +
    `${view.anchor_failed_receipts} failed anchor attempt receipt(s), ` +
    `${view.unanchored_checkpoints} checkpoint(s) without an anchor receipt, ` +
    `and ${view.findings} anchor finding(s). The files support only the listed ` +
    "receipt counters and any internally consistent receipt bodies/proofs; " +
    "they do not support an offline public-anchoring confirmation for every " +
    "bundled receipt."
  );
}

export function evaluateAnchorOfflineConfirmation(input: {
  transparency: ReadOutcome<string>;
  anchor: ReadOutcome<string>;
}): AnchorOfflineVerificationView {
  if (
    input.transparency.status !== "populated" ||
    input.anchor.status !== "populated"
  ) {
    return NOT_RUN_BASIS;
  }

  const records = parseCheckpointRecords(input.transparency.value);
  if (!records) {
    return {
      ...NOT_RUN_BASIS,
      detail:
        "the included transparency bundle could not be parsed into valid checkpoint records, so anchor receipts were not confirmable against it",
    };
  }
  const anchorsDoc = parseJson(input.anchor.value);
  if (!anchorsDoc) {
    return {
      ...NOT_RUN_BASIS,
      detail:
        "the included anchor evidence could not be parsed as JSON, so it was not confirmable against the transparency bundle",
    };
  }

  const result = verifyAnchorEvidence(records, anchorsDoc, {});
  const view = {
    confirmable_receipts: result.coverage.verified + result.coverage.consistent,
    verified_receipts: result.coverage.verified,
    consistent_receipts: result.coverage.consistent,
    unverified_receipts: result.coverage.unverified,
    invalid_receipts: result.coverage.invalid,
    anchor_failed_receipts: result.coverage.anchor_failed,
    unanchored_checkpoints: result.coverage.unanchored,
    findings: result.findings.length,
    log_signature_basis: result.coverage.log_signature_basis,
  };
  const confirmable =
    view.confirmable_receipts > 0 &&
    view.unverified_receipts === 0 &&
    view.invalid_receipts === 0 &&
    view.findings === 0;
  if (confirmable) {
    return {
      status: "confirmable",
      ...view,
      detail:
        "the offline anchor verifier found no unverified or invalid anchored receipt in the bundled evidence",
    };
  }
  return {
    status: "not_confirmable",
    ...view,
    detail: caveatDetail(view),
  };
}
