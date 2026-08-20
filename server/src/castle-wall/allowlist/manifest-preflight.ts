/**
 * Read-only compatibility inventory for a persisted Castle Wall manifest.
 *
 * MANIFEST-RULEID-PATH-01: relation checks complete before this module asks
 * its reader for any path named by a manifest entry.
 */

import { sha256 } from "@noble/hashes/sha256";

import { verifyManifestSignature } from "./parse.js";
import { parseRuleId, preflightManifestRuleEntries } from "./rule-identity.js";
import type { SignedManifest } from "./manifest.js";

export const MAX_MANIFEST_PREFLIGHT_ISSUES = 100;

export type ManifestPreflightIssueKind =
  | "manifest_envelope"
  | "manifest_signature"
  | "manifest_relation"
  | "rule_body_read"
  | "rule_body_digest"
  | "rule_body_json"
  | "rule_body_id";

export interface ManifestPreflightIssue {
  kind: ManifestPreflightIssueKind;
  entry_index?: number;
  rule_id?: string;
  message: string;
}

export interface ManifestPreflightReport {
  signature: "verified" | "not_verified" | "not_checked";
  relation_preflight: "passed" | "failed" | "not_checked";
  rule_bodies_scanned: number;
  issue_count: number;
  omitted_issue_count: number;
  issues: ReadonlyArray<ManifestPreflightIssue>;
}

export interface ManifestRuleBodyReader {
  readRuleBody(filename: string): Promise<Uint8Array>;
}

interface UnknownManifestRuleEntry {
  rule_id?: unknown;
  file?: unknown;
  sha256?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function sha256Hex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of sha256(bytes)) output += byte.toString(16).padStart(2, "0");
  return output;
}

function validatedEntryRuleId(entry: unknown): string | undefined {
  try {
    if (!isRecord(entry)) return undefined;
    const parsed = parseRuleId(entry.rule_id);
    return parsed.ok ? parsed.value : undefined;
  } catch {
    return undefined;
  }
}

class IssueCollector {
  readonly issues: ManifestPreflightIssue[] = [];
  issueCount = 0;

  add(issue: ManifestPreflightIssue): void {
    this.issueCount += 1;
    if (this.issues.length < MAX_MANIFEST_PREFLIGHT_ISSUES) this.issues.push(issue);
  }

  get omittedIssueCount(): number {
    return this.issueCount - this.issues.length;
  }
}

function report(
  signature: ManifestPreflightReport["signature"],
  relationPreflight: ManifestPreflightReport["relation_preflight"],
  ruleBodiesScanned: number,
  collector: IssueCollector,
): ManifestPreflightReport {
  return {
    signature,
    relation_preflight: relationPreflight,
    rule_bodies_scanned: ruleBodiesScanned,
    issue_count: collector.issueCount,
    omitted_issue_count: collector.omittedIssueCount,
    issues: collector.issues,
  };
}

/**
 * Scan a persisted envelope, its full manifest relation set, and each validly
 * referenced rule body's identity. Signature/envelope failures are reported
 * separately; neither failure nor an invalid relation authorizes a body read.
 */
export async function preflightPersistedManifestRuleIdentities(
  envelope: unknown,
  pinnedPublicKey: Uint8Array,
  reader: ManifestRuleBodyReader,
): Promise<ManifestPreflightReport> {
  const collector = new IssueCollector();
  if (!isRecord(envelope) || !isRecord(envelope.manifest) || !isRecord(envelope.signature)) {
    collector.add({
      kind: "manifest_envelope",
      message: "manifest is missing its manifest/signature envelope",
    });
    return report("not_checked", "not_checked", 0, collector);
  }

  const signed = envelope as unknown as SignedManifest;
  let signatureStatus: ManifestPreflightReport["signature"] = "not_verified";
  try {
    const signature = verifyManifestSignature(signed, pinnedPublicKey);
    signatureStatus = signature.ok ? "verified" : "not_verified";
    if (!signature.ok) {
      collector.add({
        kind: "manifest_signature",
        message: "manifest signature verification did not succeed",
      });
    }
  } catch {
    collector.add({
      kind: "manifest_signature",
      message: "manifest signature verification could not be completed",
    });
  }

  let relationIssues: string[];
  let entriesValue: unknown;
  try {
    entriesValue = signed.manifest.rules;
    relationIssues = preflightManifestRuleEntries(entriesValue);
  } catch {
    collector.add({
      kind: "manifest_envelope",
      message: "manifest rule entries could not be inspected",
    });
    return report(signatureStatus, "not_checked", 0, collector);
  }
  for (const message of relationIssues) {
    const match = /^manifest rule (\d+): /.exec(message);
    const entryIndex = match === null ? undefined : Number(match[1]);
    const ruleId =
      entryIndex === undefined || !Array.isArray(entriesValue)
        ? undefined
        : validatedEntryRuleId(entriesValue[entryIndex]);
    collector.add({
      kind: "manifest_relation",
      ...(entryIndex === undefined ? {} : { entry_index: entryIndex }),
      ...(ruleId === undefined ? {} : { rule_id: ruleId }),
      message,
    });
  }
  if (relationIssues.length > 0) return report(signatureStatus, "failed", 0, collector);

  // This cast is justified by the complete relation preflight above. The
  // reader sees only filenames that passed the shared relation contract.
  const entries = entriesValue as UnknownManifestRuleEntry[];
  let ruleBodiesScanned = 0;
  if (signatureStatus !== "verified") {
    return report(signatureStatus, "passed", ruleBodiesScanned, collector);
  }

  for (const [index, entry] of entries.entries()) {
    const filename = entry.file as string;
    const ruleId = validatedEntryRuleId(entry);
    let bytes: Uint8Array;
    try {
      bytes = await reader.readRuleBody(filename);
      ruleBodiesScanned += 1;
    } catch {
      collector.add({
        kind: "rule_body_read",
        entry_index: index,
        ...(ruleId === undefined ? {} : { rule_id: ruleId }),
        message: `manifest rule ${index}: referenced rule body could not be read`,
      });
      continue;
    }

    if (typeof entry.sha256 !== "string" || sha256Hex(bytes) !== entry.sha256.toLowerCase()) {
      collector.add({
        kind: "rule_body_digest",
        entry_index: index,
        ...(ruleId === undefined ? {} : { rule_id: ruleId }),
        message: `manifest rule ${index}: referenced rule body digest does not match manifest`,
      });
      continue;
    }

    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      collector.add({
        kind: "rule_body_json",
        entry_index: index,
        ...(ruleId === undefined ? {} : { rule_id: ruleId }),
        message: `manifest rule ${index}: referenced rule body is not valid JSON`,
      });
      continue;
    }
    const bodyId = isRecord(body) ? body.id : undefined;
    const bodyIdValidation = parseRuleId(bodyId);
    if (!bodyIdValidation.ok) {
      collector.add({
        kind: "rule_body_id",
        entry_index: index,
        ...(ruleId === undefined ? {} : { rule_id: ruleId }),
        message: `manifest rule ${index}: referenced rule body has an invalid rule id`,
      });
    }
    if (bodyId !== entry.rule_id) {
      collector.add({
        kind: "rule_body_id",
        entry_index: index,
        ...(ruleId === undefined ? {} : { rule_id: ruleId }),
        message: `manifest rule ${index}: referenced rule body id does not match manifest rule id`,
      });
    }
  }

  return report(signatureStatus, "passed", ruleBodiesScanned, collector);
}
