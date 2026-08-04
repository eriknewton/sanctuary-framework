/**
 * Pure operator-side builder for neutral enforcement-evidence bundle bodies.
 *
 * This module projects already-recorded, producer-signed Castle Wall egress
 * audit rows into an offline-verifiable, producer-agnostic bundle body. It is
 * PURE, operator-only, fail-closed, and agent-unreachable: do not call it from
 * an agent-facing tool, and do not pass it agent-redacted audit entries. It
 * performs no I/O, network access, signing, or independent cryptography; the
 * only authenticity check is the existing read-side producer-signature
 * verification path reused by `mapAuditEntryToEnforcementEvent`.
 *
 * The bundle is evidence, not a capability claim. It does not produce or imply
 * the `enforcement-verified` Verascore tier; that tier remains unproduced until
 * the later drill proves the full enforcement path.
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
  CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
} from "../constants.js";
import {
  mapAuditEntryToEnforcementEvent,
  type EnforcementEventMapOptions,
} from "./map.js";
import type { ExportedEgressDecision, EnforcementPoint } from "./schema.js";

export const ENFORCEMENT_BUNDLE_TYP =
  "verascore.enforcement-evidence.bundle.v1" as const;
export const ENFORCEMENT_BUNDLE_SCHEMA =
  "verascore.enforcement-evidence.bundle.body.v1" as const;
export const ENFORCEMENT_BUNDLE_CLAIMS_SCOPE =
  "Operator-produced, offline-verifiable per-flow rule-attributed enforcement evidence. Each record carries the producer signature emitted by the wall. This is not a third-party audit or certification." as const;

// RECONCILE: Verascore D2/D3 handoff finalizes the neutral envelope wire names.
export const NEUTRAL_WIRE_FIELDS = {
  typ: "typ",
  schema: "schema",
  producer: "producer",
  kid: "kid",
  keyDistribution: "key_distribution",
  generatedAt: "generated_at",
  claimsScope: "claims_scope",
  records: "records",
  summary: "summary",
} as const;

export interface ProducerEvidence {
  signed_canonical: string;
  signature: string;
  kid: string;
  seq: number;
  captured_at_ms: number;
}

export interface EnforcementBundleRecord {
  timestamp: string;
  decision: ExportedEgressDecision;
  destination_host: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  destination_protocol: "tcp" | "udp" | null;
  rule_id: string | null;
  agent_id: string | null;
  agent_template: string | null;
  enforcement_point: EnforcementPoint;
  producer_evidence: ProducerEvidence;
}

export interface EnforcementBundleSummary {
  total: number;
  allow: number;
  deny: number;
}

interface InternalEnforcementBundleEnvelope {
  type: typeof ENFORCEMENT_BUNDLE_TYP;
  schema: typeof ENFORCEMENT_BUNDLE_SCHEMA;
  producer: string;
  producerKeyId: string;
  keyDistribution: string | null;
  generatedAt: string;
  claimsScope: typeof ENFORCEMENT_BUNDLE_CLAIMS_SCOPE;
  records: EnforcementBundleRecord[];
  summary: EnforcementBundleSummary;
}

export interface EnforcementBundleBody {
  typ: typeof ENFORCEMENT_BUNDLE_TYP;
  schema: typeof ENFORCEMENT_BUNDLE_SCHEMA;
  producer: string;
  kid: string;
  key_distribution: string | null;
  generated_at: string;
  claims_scope: typeof ENFORCEMENT_BUNDLE_CLAIMS_SCOPE;
  records: EnforcementBundleRecord[];
  summary: EnforcementBundleSummary;
}

export interface BuildEnforcementBundleOptions {
  /** Producer identifier for this bundle. This is not the vendor fleet label. */
  producer: string;
  /** Producer key id advertised on the bundle envelope. */
  kid: string;
  /**
   * Optional key-distribution reference. Omitted or undefined becomes null so
   * "not supplied" stays distinct from an explicitly supplied empty string.
   */
  keyDistribution?: string | null;
  /** Injected clock used to produce the generated_at ISO timestamp. */
  now: () => Date;
  /** Options for the existing producer-signature verification mapper. */
  mapOptions?: EnforcementEventMapOptions;
}

const PUBLIC_SIGNED_DETAIL_KEYS: ReadonlySet<string> = new Set([
  "destination",
  "dest_host",
  "dest_ip",
  "dest_port",
  "dest_protocol",
  "rule_id",
  "rule_id_matched",
  "agent",
  "agent_id",
  "agent_template",
  "decision",
  "decision_provenance",
  CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY,
  CASTLE_WALL_WAL_PRIOR_SHA256_HEX_DETAIL_KEY,
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readString(details: Record<string, unknown>, key: string): string | null {
  const value = details[key];
  return typeof value === "string" ? value : null;
}

function readSafeInteger(details: Record<string, unknown>, key: string): number | null {
  const value = details[key];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function signedCanonicalHasOnlyPublicDetails(signedCanonical: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedCanonical);
  } catch {
    return false;
  }
  if (!isRecord(parsed)) return false;
  const details = parsed.details;
  if (details === undefined || details === null) return true;
  if (!isRecord(details)) return false;
  return Object.keys(details).every((key) => PUBLIC_SIGNED_DETAIL_KEYS.has(key));
}

function producerEvidenceOf(entry: AuditEntry): ProducerEvidence | null {
  const details = entry.details;
  if (!details) return null;
  if (
    details[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY] !==
    CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED
  ) {
    return null;
  }

  const signature = readString(details, CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY);
  const kid = readString(details, CASTLE_WALL_PRODUCER_KID_DETAIL_KEY);
  const signedCanonical = readString(
    details,
    CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  );
  const capturedAtMs = readSafeInteger(
    details,
    CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  );
  const seq = readSafeInteger(details, CASTLE_WALL_WAL_SEQUENCE_DETAIL_KEY);
  if (
    signature === null ||
    kid === null ||
    signedCanonical === null ||
    capturedAtMs === null ||
    seq === null
  ) {
    return null;
  }
  if (!signedCanonicalHasOnlyPublicDetails(signedCanonical)) return null;

  return {
    signed_canonical: signedCanonical,
    signature,
    kid,
    seq,
    captured_at_ms: capturedAtMs,
  };
}

function summarize(records: readonly EnforcementBundleRecord[]): EnforcementBundleSummary {
  let allow = 0;
  let deny = 0;
  for (const record of records) {
    if (record.decision === "allow") {
      allow += 1;
    } else {
      deny += 1;
    }
  }
  return { total: records.length, allow, deny };
}

function mapEntryToBundleRecord(
  entry: AuditEntry,
  mapOptions: EnforcementEventMapOptions,
): EnforcementBundleRecord | null {
  const ev = mapAuditEntryToEnforcementEvent(entry, mapOptions);
  if (ev === null || ev.event_class !== "egress_decision") return null;
  const producerEvidence = producerEvidenceOf(entry);
  if (producerEvidence === null) return null;
  return {
    timestamp: ev.timestamp,
    decision: ev.decision,
    destination_host: ev.destination_host,
    destination_ip: ev.destination_ip,
    destination_port: ev.destination_port,
    destination_protocol: ev.destination_protocol,
    rule_id: ev.rule_id,
    agent_id: ev.agent_id,
    agent_template: ev.agent_template,
    enforcement_point: ev.enforcement_point,
    producer_evidence: producerEvidence,
  };
}

export function toNeutralWireEnvelope(
  body: InternalEnforcementBundleEnvelope,
): EnforcementBundleBody {
  return {
    [NEUTRAL_WIRE_FIELDS.typ]: body.type,
    [NEUTRAL_WIRE_FIELDS.schema]: body.schema,
    [NEUTRAL_WIRE_FIELDS.producer]: body.producer,
    [NEUTRAL_WIRE_FIELDS.kid]: body.producerKeyId,
    [NEUTRAL_WIRE_FIELDS.keyDistribution]: body.keyDistribution,
    [NEUTRAL_WIRE_FIELDS.generatedAt]: body.generatedAt,
    [NEUTRAL_WIRE_FIELDS.claimsScope]: body.claimsScope,
    [NEUTRAL_WIRE_FIELDS.records]: body.records,
    [NEUTRAL_WIRE_FIELDS.summary]: body.summary,
  };
}

export function buildEnforcementBundleBody(
  entries: readonly AuditEntry[],
  options: BuildEnforcementBundleOptions,
): EnforcementBundleBody {
  const mapOptions = options.mapOptions ?? {};
  const records: EnforcementBundleRecord[] = [];
  for (const entry of entries) {
    const record = mapEntryToBundleRecord(entry, mapOptions);
    if (record !== null) records.push(record);
  }
  return toNeutralWireEnvelope({
    type: ENFORCEMENT_BUNDLE_TYP,
    schema: ENFORCEMENT_BUNDLE_SCHEMA,
    producer: options.producer,
    producerKeyId: options.kid,
    keyDistribution: options.keyDistribution ?? null,
    generatedAt: options.now().toISOString(),
    claimsScope: ENFORCEMENT_BUNDLE_CLAIMS_SCOPE,
    records,
    summary: summarize(records),
  });
}
