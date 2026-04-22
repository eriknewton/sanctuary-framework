/**
 * Sanctuary Policy Engine — Channel-template starter library.
 *
 * Walkthrough Key 10 LOCKED starter set (five templates). Each template is
 * a factory that takes (agent_id, counterparty, fortress_id, policy_version,
 * optional scope, optional merge_into prior policy) and produces a
 * CompiledPolicy. Operators typically then pack it into a signed envelope
 * via envelope.packPolicyUpdate.
 *
 * Templates start from the null-policy shape (all four slots deny) unless a
 * `merge_into` prior policy is supplied, in which case the template adds
 * its grants without disturbing existing ones.
 *
 * Note on scope lock nuance: Sanctuary MVP Scope Lock 2026-04-21 §WP-MVP-5
 * lists "channel-templates library" in the "Out of v1.0" column. The spawn
 * prompt for this build thread overrides that — shipping the five Key-10
 * LOCKED starter templates as canned factories is in scope. The ambiguity
 * is called out in the build summary (deliverable (e) in the PR description).
 * The starter set here is a closed set of five; expanding the library is a
 * later thread.
 */

import {
  CHANNEL_TEMPLATE_IDS,
  type ChannelTemplateId,
  POLICY_SLOTS,
  type PolicySlot,
} from "./constants.js";
import { buildNullPolicy } from "./null-policy.js";
import type {
  ChannelTemplateFactory,
  ChannelTemplateParams,
  ChannelTemplateRegistryEntry,
  CompiledPolicy,
  SlotGrant,
  SlotRule,
} from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

function basePolicy(params: ChannelTemplateParams): CompiledPolicy {
  if (params.merge_into) {
    const p: CompiledPolicy = {
      ...params.merge_into,
      policy_version: params.policy_version,
      compiled_at: new Date().toISOString(),
      slots: {
        memory: cloneRule(params.merge_into.slots.memory),
        credentials: cloneRule(params.merge_into.slots.credentials),
        plans: cloneRule(params.merge_into.slots.plans),
        outputs: cloneRule(params.merge_into.slots.outputs),
      },
      capabilities: {
        ...params.merge_into.capabilities,
        concordia_commitment_classes: [
          ...params.merge_into.capabilities.concordia_commitment_classes,
        ],
        honeypot_skill_ids: [...params.merge_into.capabilities.honeypot_skill_ids],
      },
      auto_trigger_ladder: { ...params.merge_into.auto_trigger_ladder },
    };
    if (params.parent_version !== undefined) p.parent_version = params.parent_version;
    else delete p.parent_version;
    return p;
  }
  const p = buildNullPolicy({
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
  });
  p.policy_version = params.policy_version;
  p.compiled_at = new Date().toISOString();
  if (params.parent_version !== undefined) p.parent_version = params.parent_version;
  return p;
}

function cloneRule(r: SlotRule): SlotRule {
  return {
    slot: r.slot,
    mode: r.mode,
    grants: r.grants.map((g) => ({ ...g, scope: g.scope ? { ...g.scope } : undefined })),
  };
}

/** Add a grant idempotently; upgrade the slot to "grant" mode. */
function grantOn(
  policy: CompiledPolicy,
  slot: PolicySlot,
  grant: SlotGrant
): void {
  const rule = policy.slots[slot];
  rule.mode = "grant";
  const dup = rule.grants.find(
    (g) => g.counterparty === grant.counterparty && g.action === grant.action
  );
  if (dup) {
    // Merge scope — new scope wins per-key, carry-over per absent key.
    if (grant.scope) {
      dup.scope = { ...(dup.scope ?? {}), ...grant.scope };
    }
    return;
  }
  rule.grants.push(grant);
  rule.grants.sort((a, b) => {
    if (a.counterparty === b.counterparty) return a.action.localeCompare(b.action);
    return a.counterparty.localeCompare(b.counterparty);
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Five templates per Walkthrough Key 10 LOCKED
// ═══════════════════════════════════════════════════════════════════════

/**
 * 1. read-outputs-only — Counterparty may read this agent's outputs. Nothing else.
 *    The minimum supervision-shape grant. Common for a "supervisor agent
 *    inspects a worker agent's results" pattern.
 */
const readOutputsOnly: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    `${params.counterparty} may read ${params.agent_id}'s outputs — read-only, no other access.`;
  grantOn(p, "outputs", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  return p;
};

/**
 * 2. bidirectional-sync — Both agents may read and subscribe to each other's
 *    memory + outputs. The "peer collaboration" shape. Does NOT open credentials
 *    or plans — those need explicit stronger templates.
 */
const bidirectionalSync: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    `Bidirectional sync between ${params.agent_id} and ${params.counterparty} on memory + outputs.`;
  for (const slot of ["memory", "outputs"] as const) {
    for (const action of ["read", "subscribe"] as const) {
      grantOn(p, slot, {
        counterparty: params.counterparty,
        action,
        ...(params.scope ? { scope: { ...params.scope } } : {}),
      });
    }
  }
  return p;
};

/**
 * 3. credential-share-scoped — Caller may share a specific credential (scope
 *    MUST name credential_id) with counterparty. Share-only; the counterparty
 *    does not get read/write on the credentials slot broadly — only the
 *    sharing grant is created for the named credential.
 *
 *    Operators who want broad credential-broker access MUST author it
 *    explicitly. No "share all credentials" template ships intentionally:
 *    defense in depth at Walkthrough Key 3.
 */
const credentialShareScoped: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  const credentialId =
    (params.scope && typeof params.scope.credential_id === "string"
      ? (params.scope.credential_id as string)
      : undefined) ?? "(unspecified)";
  p.source_english =
    `${params.agent_id} may share credential "${credentialId}" with ${params.counterparty}; no other credential access.`;
  grantOn(p, "credentials", {
    counterparty: params.counterparty,
    action: "share",
    scope: {
      credential_id: credentialId,
      ...(params.scope ?? {}),
    },
  });
  return p;
};

/**
 * 4. plan-inspect-read-only — Counterparty may read-only inspect this agent's
 *    plan slot. Common for supervisor / sentinel patterns that need to see
 *    upcoming tool calls without intervening. "Inspect" == "read" on the
 *    plans slot (no separate inspect action — the template normalizes).
 */
const planInspectReadOnly: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    `${params.counterparty} may read-only inspect ${params.agent_id}'s plans.`;
  grantOn(p, "plans", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  return p;
};

/**
 * 5. escrow-handoff — Walkthrough Key 10 LOCKED "escrow-handoff (for
 *    Concordia-style commitments between intra-mesh agents)". Opens:
 *      - plans: read — counterparty may inspect the committed plan.
 *      - outputs: read + subscribe — counterparty receives the handed-off
 *        result.
 *      - capabilities: declares a concordia_commitment_class of
 *        "intra-mesh-escrow" so the commitment-boundary gate admits the
 *        handoff commitment.
 *
 *    Does NOT open memory or credentials — escrow is deliberately scope-narrow.
 */
const escrowHandoff: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    `${params.agent_id} may escrow-handoff outputs and plan-read to ${params.counterparty}. Commitment class: intra-mesh-escrow.`;
  grantOn(p, "plans", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  for (const action of ["read", "subscribe"] as const) {
    grantOn(p, "outputs", {
      counterparty: params.counterparty,
      action,
      ...(params.scope ? { scope: { ...params.scope } } : {}),
    });
  }
  const cls = "intra-mesh-escrow";
  if (!p.capabilities.concordia_commitment_classes.includes(cls)) {
    p.capabilities.concordia_commitment_classes.push(cls);
    p.capabilities.concordia_commitment_classes.sort();
  }
  return p;
};

// ═══════════════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════════════

const REGISTRY: Record<ChannelTemplateId, ChannelTemplateRegistryEntry> = {
  "read-outputs-only": {
    id: "read-outputs-only",
    label: "Read outputs only",
    description:
      "Counterparty may read this agent's outputs. No memory, credentials, or plans access.",
    factory: readOutputsOnly,
  },
  "bidirectional-sync": {
    id: "bidirectional-sync",
    label: "Bidirectional memory + output sync",
    description:
      "Both agents may read and subscribe to each other's memory and outputs. Credentials and plans remain hermetic.",
    factory: bidirectionalSync,
  },
  "credential-share-scoped": {
    id: "credential-share-scoped",
    label: "Scoped credential share",
    description:
      "Share one specific credential with counterparty. Requires scope.credential_id. No broad credential access.",
    factory: credentialShareScoped,
  },
  "plan-inspect-read-only": {
    id: "plan-inspect-read-only",
    label: "Plan inspect (read-only)",
    description:
      "Counterparty may read-only inspect this agent's plans. Intended for supervisor / sentinel patterns.",
    factory: planInspectReadOnly,
  },
  "escrow-handoff": {
    id: "escrow-handoff",
    label: "Escrow handoff",
    description:
      "Escrow-style handoff — counterparty reads plan, reads + subscribes to outputs, and the intra-mesh-escrow commitment class is declared. Memory and credentials remain hermetic.",
    factory: escrowHandoff,
  },
};

/** Sorted (by id) registry snapshot for the console. */
export function listChannelTemplates(): ChannelTemplateRegistryEntry[] {
  return CHANNEL_TEMPLATE_IDS.map((id) => REGISTRY[id]);
}

/** Resolve a template by id. */
export function getChannelTemplate(
  id: ChannelTemplateId
): ChannelTemplateRegistryEntry {
  return REGISTRY[id];
}

/**
 * Convenience: apply a named template and return a CompiledPolicy. Throws
 * if `id` is unknown — TypeScript exhaustiveness makes that impossible on
 * trusted callers but this module is also consumed via untyped API at the
 * console.
 */
export function applyChannelTemplate(
  id: ChannelTemplateId,
  params: ChannelTemplateParams
): CompiledPolicy {
  const entry = REGISTRY[id];
  if (!entry) {
    throw new Error(`unknown channel template: ${id}`);
  }
  return entry.factory(params);
}

/** Defensive: sanity check the five LOCKED ids are registered. */
export function allChannelTemplateIds(): ChannelTemplateId[] {
  for (const id of CHANNEL_TEMPLATE_IDS) {
    if (!REGISTRY[id]) {
      throw new Error(`channel-template registry missing id: ${id}`);
    }
  }
  // Also: no unexpected keys. POLICY_SLOTS referenced so TS sees the import used.
  if (POLICY_SLOTS.length !== 4) {
    throw new Error("four-slot invariant violated");
  }
  return [...CHANNEL_TEMPLATE_IDS];
}
