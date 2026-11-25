/**
 * state_STATEMENT: the ONE runtime schema for the verified provenance payload,
 * and the pin policy over its typed result.
 *
 * The parse is the agreement between this step and the subject step: both read
 * `ProvenanceStatement`, so no stage re-reads raw JSON with its own idea of
 * the shape. Every element of `subject` is validated here, not only the array.
 */

import {
  DSSE_PAYLOAD_TYPE_IN_TOTO,
  IN_TOTO_STATEMENT_TYPE,
  PINNED_BUILDER_ID,
  PINNED_BUILD_TYPE,
  PINNED_REF,
  PINNED_REPOSITORY_ID,
  PINNED_REPOSITORY_OWNER_ID,
  PINNED_REPOSITORY_URI,
  PINNED_TRIGGER,
  PINNED_WORKFLOW_PATH,
  SLSA_PROVENANCE_V1,
} from "./constants.js";
import { passed, type IdentityEvidence, type StatementEvidence, type StatementSubject } from "./evidence.js";
import { refuse, type StepOutcome } from "./reasons.js";

export interface ProvenanceStatement {
  payloadType: string;
  type: string;
  predicateType: string;
  subjects: StatementSubject[];
  buildType: string;
  workflowRepository: string;
  workflowPath: string;
  workflowRef: string;
  eventName: string;
  repositoryId: string;
  repositoryOwnerId: string;
  builderId: string;
}

/** The statement field each pin reads, as named in refusals. */
export const STATEMENT_FIELDS = {
  payloadType: "payloadType",
  type: "_type",
  predicateType: "predicateType",
  subjects: "subject",
  buildType: "predicate.buildDefinition.buildType",
  workflowRepository: "predicate.buildDefinition.externalParameters.workflow.repository",
  workflowPath: "predicate.buildDefinition.externalParameters.workflow.path",
  workflowRef: "predicate.buildDefinition.externalParameters.workflow.ref",
  eventName: "predicate.buildDefinition.internalParameters.github.event_name",
  repositoryId: "predicate.buildDefinition.internalParameters.github.repository_id",
  repositoryOwnerId: "predicate.buildDefinition.internalParameters.github.repository_owner_id",
  builderId: "predicate.runDetails.builder.id",
} as const satisfies Record<keyof ProvenanceStatement, string>;

function at(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const key of path) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) return undefined;
    current = Object.prototype.hasOwnProperty.call(current, key) ? (current as Record<string, unknown>)[key] : undefined;
  }
  return current;
}

function parseSubjects(value: unknown): StatementSubject[] | null {
  if (!Array.isArray(value)) return null;
  const subjects: StatementSubject[] = [];
  for (const element of value) {
    const name = at(element, ["name"]);
    const digest = at(element, ["digest"]);
    if (typeof name !== "string" || typeof digest !== "object" || digest === null || Array.isArray(digest)) return null;
    const sha512 = at(digest, ["sha512"]);
    if (sha512 !== undefined && typeof sha512 !== "string") return null;
    subjects.push({ name, sha512 });
  }
  return subjects;
}

/** The shared schema. A missing field, or one of the wrong JSON type, names that field. */
export function parseProvenanceStatement(
  payloadType: string,
  payload: Buffer,
): { ok: true; statement: ProvenanceStatement } | { ok: false; field: string } {
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payload));
  } catch {
    return { ok: false, field: "payload" };
  }
  const strings: Array<[Exclude<keyof ProvenanceStatement, "payloadType" | "subjects">, readonly string[]]> = [
    ["type", ["_type"]],
    ["predicateType", ["predicateType"]],
    ["buildType", ["predicate", "buildDefinition", "buildType"]],
    ["workflowRepository", ["predicate", "buildDefinition", "externalParameters", "workflow", "repository"]],
    ["workflowPath", ["predicate", "buildDefinition", "externalParameters", "workflow", "path"]],
    ["workflowRef", ["predicate", "buildDefinition", "externalParameters", "workflow", "ref"]],
    ["eventName", ["predicate", "buildDefinition", "internalParameters", "github", "event_name"]],
    ["repositoryId", ["predicate", "buildDefinition", "internalParameters", "github", "repository_id"]],
    ["repositoryOwnerId", ["predicate", "buildDefinition", "internalParameters", "github", "repository_owner_id"]],
    ["builderId", ["predicate", "runDetails", "builder", "id"]],
  ];
  const parsed: Partial<ProvenanceStatement> = { payloadType };
  for (const [key, path] of strings) {
    const value = at(json, path);
    if (typeof value !== "string") return { ok: false, field: STATEMENT_FIELDS[key] };
    parsed[key] = value;
  }
  const subjects = parseSubjects(at(json, ["subject"]));
  if (subjects === null) return { ok: false, field: STATEMENT_FIELDS.subjects };
  parsed.subjects = subjects;
  return { ok: true, statement: parsed as ProvenanceStatement };
}

/**
 * Each pinned statement field and its one accepted value. These restate the
 * certificate identity inside the signed statement; checking both means a
 * statement that describes another build cannot ride on a valid certificate.
 */
export const STATEMENT_PINS: ReadonlyArray<[Exclude<keyof ProvenanceStatement, "subjects">, string]> = [
  ["payloadType", DSSE_PAYLOAD_TYPE_IN_TOTO],
  ["type", IN_TOTO_STATEMENT_TYPE],
  ["predicateType", SLSA_PROVENANCE_V1],
  ["buildType", PINNED_BUILD_TYPE],
  ["workflowRepository", PINNED_REPOSITORY_URI],
  ["workflowPath", PINNED_WORKFLOW_PATH],
  ["workflowRef", PINNED_REF],
  ["eventName", PINNED_TRIGGER],
  ["repositoryId", PINNED_REPOSITORY_ID],
  ["repositoryOwnerId", PINNED_REPOSITORY_OWNER_ID],
  ["builderId", PINNED_BUILDER_ID],
];

/** Pure policy over the typed statement and the identity evidence from the same bundle's certificate. */
export function checkStatement(statement: ProvenanceStatement, identity: IdentityEvidence): StepOutcome<StatementEvidence> {
  for (const [key, value] of STATEMENT_PINS) {
    if (statement[key] !== value) return refuse(`provenance-pin-mismatch:${STATEMENT_FIELDS[key]}`);
  }
  // The statement and the certificate must describe one build: each shared fact is compared across them.
  const crossChecks: Array<[string, string, string]> = [
    ["statement-repository-uri", statement.workflowRepository, identity.repositoryUri],
    ["statement-repository-id", statement.repositoryId, identity.repositoryId],
    ["statement-repository-owner-id", statement.repositoryOwnerId, identity.repositoryOwnerId],
    ["statement-ref", statement.workflowRef, identity.ref],
    ["statement-trigger", statement.eventName, identity.trigger],
  ];
  for (const [name, fromStatement, fromCertificate] of crossChecks) {
    if (fromStatement !== fromCertificate) return refuse(`identity-mismatch:${name}`);
  }
  return passed({ state: "state_STATEMENT", subjects: statement.subjects });
}

export function state_STATEMENT(
  payloadType: string,
  payload: Buffer,
  identity: IdentityEvidence,
): StepOutcome<StatementEvidence> {
  const parsed = parseProvenanceStatement(payloadType, payload);
  if (!parsed.ok) return refuse(`provenance-field-absent:${parsed.field}`);
  return checkStatement(parsed.statement, identity);
}
