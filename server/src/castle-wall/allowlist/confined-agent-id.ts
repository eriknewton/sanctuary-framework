/**
 * Linux confined-agent id helpers.
 *
 * Policy `scope.agent_ids` for the Linux install profile names the daemon's
 * confined id, not the protection-subject id used in audit evidence.
 */

import type { AllowlistRule } from "./schema.js";
import { isGenuineDerivedHabeasRule } from "./habeas-port.js";

// Must match `CONFINED_AGENT_ID_PREFIX` in `castle-wall-daemon/src/nftables.rs`.
export const CONFINED_AGENT_ID_PREFIX = "uid-";
// Must match `CONFINED_AGENT_ID_FORM` in `castle-wall-daemon/src/nftables.rs`.
export const CONFINED_AGENT_ID_FORM = "uid-<decimal uid>";

const UINT32_BIT_COUNT = 32;
/** u32 max = 2^32 - 1, matching Rust `u32::MAX`. */
const UINT32_MAX = 2 ** UINT32_BIT_COUNT - 1;

/** Format the canonical Linux confined-agent id for one admitted uid. */
export function confinedAgentIdForUid(uid: number): string | null {
  if (!Number.isInteger(uid) || uid < 0 || uid > UINT32_MAX) return null;
  return `${CONFINED_AGENT_ID_PREFIX}${uid}`;
}

/**
 * Parse the canonical Linux confined-agent id form.
 *
 * Must match `parse_confined_agent_id` in `castle-wall-daemon/src/nftables.rs`
 * and the shared vector file at
 * `castle-wall-daemon/test-vectors/confined-agent-id-v1.json`.
 */
export function parseConfinedAgentId(id: string): number | null {
  if (!id.startsWith(CONFINED_AGENT_ID_PREFIX)) return null;
  const rawUid = id.slice(CONFINED_AGENT_ID_PREFIX.length);
  if (!/^(0|[1-9][0-9]*)$/.test(rawUid)) return null;
  const uid = Number(rawUid);
  if (!Number.isInteger(uid) || uid < 0 || uid > UINT32_MAX) return null;
  return confinedAgentIdForUid(uid) === id ? uid : null;
}

/** Refuse Linux install scopes that do not name the single uid this profile admits. */
export function validateLinuxInstallAgentIdScopes(
  rules: readonly AllowlistRule[],
  admittedUid: number,
): void {
  for (const rule of rules) {
    // The reserved distress lane is code-derived and exact-shape checked; operator-authored scopes fall through.
    if (isGenuineDerivedHabeasRule(rule)) continue;
    for (const agentId of rule.scope.agent_ids ?? []) {
      const uid = parseConfinedAgentId(agentId);
      if (uid === null) {
        throw new Error(
          `rule ${rule.id} scope.agent_ids entry ${JSON.stringify(agentId)}: expected ${CONFINED_AGENT_ID_FORM}; re-sign with the uid-<uid> form`,
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
