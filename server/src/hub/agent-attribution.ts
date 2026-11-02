/**
 * Hub-side projection helpers for verified Castle Wall attribution.
 *
 * The signature verifier returns the verified attribution subject. On Linux
 * that subject is normally the wrapped agent id. On macOS audit-token evidence
 * it is an OS protection subject, so public hub surfaces must resolve it back
 * through the local agent registry before displaying or filtering by agent id.
 */

import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";

type AgentAttributionRecord = Pick<
  LocalAgentRecord,
  "agent_id" | "protection_subject"
>;

export function agentRecordAttributionIds(
  record: AgentAttributionRecord,
): Set<string> {
  const ids = new Set<string>([record.agent_id]);
  if (
    typeof record.protection_subject === "string" &&
    record.protection_subject.length > 0
  ) {
    ids.add(record.protection_subject);
  }
  return ids;
}

export function publicAgentIdForVerifiedAttribution(
  verifiedSubject: string,
  records: ReadonlyArray<AgentAttributionRecord>,
): string {
  let matchedAgentId: string | null = null;
  for (const record of records) {
    if (record.protection_subject !== verifiedSubject) continue;
    if (matchedAgentId !== null && matchedAgentId !== record.agent_id) {
      return verifiedSubject;
    }
    matchedAgentId = record.agent_id;
  }
  return matchedAgentId ?? verifiedSubject;
}

/** Constant-time subject lookup distinguishes uniqueness from ambiguity without a roster scan. */
export type ProtectionSubjectLookup = { kind: "none" } | { kind: "unique"; record: LocalAgentRecord } | { kind: "ambiguous" };

/** Bind only authenticated subjects with a unique enrollment owned by the trusted header identity. */
export function enrolledAgentBindingForVerifiedSubject(
  metadata: import("../contracts/v1.1/blocked-egress.js").BlockedEgressMetadata,
  ownerIdentityId: string,
  lookup?: (subject: string) => ProtectionSubjectLookup,
): { agent_binding: "bound"; agent_id: string } | { agent_binding: "unattributed" } {
  // The header identity is the trusted hub operator; an agent id requires one same-owner enrolled match for a verified subject, otherwise the event is explicitly unattributed.
  if (metadata.attribution.state !== "verified" || !metadata.subject || !lookup) return { agent_binding: "unattributed" };
  const result = lookup(metadata.subject);
  if (result.kind !== "unique" || result.record.identity_id !== ownerIdentityId) return { agent_binding: "unattributed" };
  return { agent_binding: "bound", agent_id: result.record.agent_id };
}
