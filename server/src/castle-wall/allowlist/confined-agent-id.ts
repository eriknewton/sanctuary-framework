/**
 * Linux confined-agent id helpers.
 *
 * Policy `scope.agent_ids` for the Linux install profile names the daemon's
 * confined id, not the protection-subject id used in audit evidence.
 */

import type { AllowlistRule } from "./schema.js";

export const CONFINED_AGENT_ID_PREFIX = "uid-";
// Must match `CONFINED_AGENT_ID_FORM` in `castle-wall-daemon/src/nftables.rs`.
export const CONFINED_AGENT_ID_FORM = "uid-<decimal uid>";

export function confinedAgentIdForUid(uid: number): string | null {
  if (!Number.isInteger(uid) || uid < 0 || uid > 0xffffffff) return null;
  return `${CONFINED_AGENT_ID_PREFIX}${uid}`;
}

export function parseConfinedAgentId(id: string): number | null {
  if (!id.startsWith(CONFINED_AGENT_ID_PREFIX)) return null;
  const rawUid = id.slice(CONFINED_AGENT_ID_PREFIX.length);
  if (!/^(0|[1-9][0-9]*)$/.test(rawUid)) return null;
  const uid = Number(rawUid);
  if (!Number.isInteger(uid) || uid < 0 || uid > 0xffffffff) return null;
  return confinedAgentIdForUid(uid) === id ? uid : null;
}

export function validateLinuxInstallAgentIdScopes(
  rules: readonly AllowlistRule[],
  admittedUid: number,
): void {
  for (const rule of rules) {
    for (const agentId of rule.scope.agent_ids ?? []) {
      const uid = parseConfinedAgentId(agentId);
      if (uid === null) {
        throw new Error(
          `rule ${rule.id} scope.agent_ids entry ${JSON.stringify(agentId)}: expected ${CONFINED_AGENT_ID_FORM}`,
        );
      }
      // The install profile rejects gate_uid earlier, so the admitted confined-id set is the agent uid singleton.
      if (uid !== admittedUid) {
        throw new Error(
          `rule ${rule.id} scope.agent_ids entry ${JSON.stringify(agentId)}: expected admitted uid ${admittedUid}`,
        );
      }
    }
  }
}
