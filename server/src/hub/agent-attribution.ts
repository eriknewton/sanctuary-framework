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
