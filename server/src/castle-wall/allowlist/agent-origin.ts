/**
 * Agent-origin descriptor validation (2026-05-29 origin-classifier
 * foundation).
 *
 * The daemon sources an `AgentOrigin` from config / test fixtures and must
 * NEVER emit a half-built descriptor into the signed manifest body. This
 * validator returns a fully-formed, normalized descriptor or `null`. A `null`
 * means "omit the field", which the macOS sysext interprets fail-closed as
 * "classify every flow as agent" (machine-wide default-deny preserved).
 *
 * FAIL-CLOSED RATIONALE: a malformed descriptor that still serialized would
 * risk the sysext mis-resolving a flow as operator (e.g. a UID-mode block with
 * no `agent_uid`, under which every non-system flow classifies operator). So
 * malformed always degrades to "no descriptor" (deny side), never to a
 * partially-trusted descriptor.
 *
 * This foundation build does NOT provision accounts or launch runtimes; the
 * descriptor is sourced from config/fixtures only. A follow-up wires real
 * provisioning.
 */

import type { AgentOrigin, AgentOriginMode } from "./manifest.js";

const VALID_MODES: ReadonlySet<string> = new Set<AgentOriginMode>(["nat", "uid"]);

/** True when `n` is a non-negative integer (uids, ports, ceilings). */
function isNonNegativeInt(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 0;
}

/** True when `s` is a non-empty string. */
function isNonEmptyString(s: unknown): s is string {
  return typeof s === "string" && s.length > 0;
}

/**
 * Validate and normalize a candidate agent-origin descriptor.
 *
 * Returns a NEW object containing only the fields valid for the declared
 * mode (so canonical-JSON is stable and no stray fields ride along), or
 * `null` if the candidate is unusable.
 */
export function validateAgentOrigin(candidate: unknown): AgentOrigin | null {
  if (candidate === null || typeof candidate !== "object") {
    return null;
  }
  const c = candidate as Record<string, unknown>;

  if (typeof c.mode !== "string" || !VALID_MODES.has(c.mode)) {
    return null;
  }
  const mode = c.mode as AgentOriginMode;

  // `system_uid_allow_ceiling` is required in both modes.
  if (!isNonNegativeInt(c.system_uid_allow_ceiling)) {
    return null;
  }
  const systemUidAllowCeiling = c.system_uid_allow_ceiling;

  if (mode === "uid") {
    // UID mode requires the dedicated agent account uid. Without it, the
    // sysext would classify every non-system flow as operator (fail-open).
    if (!isNonNegativeInt(c.agent_uid)) {
      return null;
    }
    // Floor invariant (fail-closed semantic reject): the confined agent uid must
    // be a real, above-the-system-band account.
    //  - `agent_uid < 1` (i.e. 0 / root) can NEVER be the confined agent:
    //    classifying root `.agent` would default-deny every system daemon
    //    (sshd, Tailscale, ...), the exact boot-cut this descriptor prevents.
    //  - `agent_uid < system_uid_allow_ceiling` places the agent INSIDE the
    //    system-daemon allow band, which is nonsensical (uids below the ceiling
    //    classify operator/allowed) and dangerous. Equal is allowed: `uid ==
    //    ceiling` is the boundary, not "strictly below".
    // A wrong uid can otherwise fail OPEN (agent unconfined) or cut a system
    // daemon; rejecting here protects `configure-origin`, the `enable` fold-in,
    // the #884 read-back guard, and any future caller at the one chokepoint.
    if (c.agent_uid < 1 || c.agent_uid < systemUidAllowCeiling) {
      return null;
    }

    // `gate_uid` (S5-0, 2026-07-14): a SECOND optional confined principal,
    // valid only in UID mode. Applies the SAME floor invariants as
    // `agent_uid` above, PLUS distinctness from it. Any violation rejects
    // the WHOLE descriptor -- never a half-built twin-uid config, because a
    // gate uid that silently degraded to "no gate_uid" would fall through to
    // today's binary classifier (`classifyUid`'s existing "any other
    // resolved high uid is operator" branch) and reach the OPERATOR
    // allow-all fast-path: exactly the fail-open this field exists to close.
    const agentUid = c.agent_uid;
    if (c.gate_uid !== undefined) {
      if (!isNonNegativeInt(c.gate_uid)) {
        return null;
      }
      if (
        c.gate_uid < 1 ||
        c.gate_uid < systemUidAllowCeiling ||
        c.gate_uid === agentUid
      ) {
        return null;
      }
      return {
        mode: "uid",
        agent_uid: agentUid,
        gate_uid: c.gate_uid,
        system_uid_allow_ceiling: systemUidAllowCeiling,
      };
    }
    return {
      mode: "uid",
      agent_uid: agentUid,
      system_uid_allow_ceiling: systemUidAllowCeiling,
    };
  }

  // NAT mode requires at least one egress-helper identity axis; otherwise an
  // egress-helper match can never be expressed and the descriptor is useless.
  const hasSigningId = isNonEmptyString(c.egress_helper_signing_id);
  const hasTeamId = isNonEmptyString(c.egress_helper_team_id);
  if (!hasSigningId && !hasTeamId) {
    return null;
  }

  // `gate_uid` is a UID-mode-only concept: NAT mode identifies the agent via
  // egress-helper signing identity, never a uid, so there is no meaningful
  // "second confined uid" to carry. A NAT candidate carrying `gate_uid` is an
  // unexpected/malformed shape (a caller bug, or a future NAT+gate combo not
  // yet designed) -- reject the whole descriptor rather than silently drop
  // or silently accept an ambiguous field, matching the "never a half-built
  // descriptor" doctrine above.
  if (c.gate_uid !== undefined) {
    return null;
  }

  const out: AgentOrigin = {
    mode: "nat",
    system_uid_allow_ceiling: systemUidAllowCeiling,
  };
  if (hasSigningId) {
    out.egress_helper_signing_id = c.egress_helper_signing_id as string;
  }
  if (hasTeamId) {
    out.egress_helper_team_id = c.egress_helper_team_id as string;
  }

  // Optional port range: a well-formed [lo, hi] integer pair with lo <= hi
  // and both in 1..65535. A malformed range drops the range (NOT the whole
  // descriptor): the signing-id axis still positively identifies the helper.
  const range = c.agent_runtime_port_range;
  if (Array.isArray(range) && range.length === 2) {
    const [lo, hi] = range;
    if (
      isNonNegativeInt(lo) &&
      isNonNegativeInt(hi) &&
      lo >= 1 &&
      hi <= 65535 &&
      lo <= hi
    ) {
      out.agent_runtime_port_range = [lo, hi];
    }
  }

  return out;
}
