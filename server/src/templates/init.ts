/**
 * Sanctuary Template Library — Template init.
 *
 * `sanctuary template init <name> --agent-id <id>` loads a template into
 * the operator's fortress:
 *
 * 1. Applies the matching WP-MVP-5 channel template factory to produce a
 *    CompiledPolicy with the correct slot grants.
 * 2. Overlays WP-MVP-6 defaults (egress, budgets, retention) from the
 *    template's defaults.json.
 * 3. Seeds commitment classes from commitments.json into
 *    `capabilities.concordia_commitment_classes`.
 * 4. Sets `source_english` from the template's policy.md.
 * 5. Packs the result into a signed `policy_update` event.
 *
 * Determinism: same template + same agent-id + same fortress → byte-equal
 * CompiledPolicy canonical JSON across runs (the `compiled_at` is fixed
 * to a template-version-derived timestamp so the blob is stable).
 */

import { applyChannelTemplate } from "../policy-engine/channel-templates.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type {
  CompiledPolicy,
  BudgetPolicy,
  EgressPolicy,
  RetentionPolicy,
} from "../policy-engine/types.js";
import { validateCompiledPolicyShape } from "../policy-engine/canonical-policy.js";
import { packPolicyUpdate } from "../policy-engine/envelope.js";
import type { SignedEvent } from "../mesh/types.js";
import type { PolicyUpdatePayload } from "../mesh/types.js";
import type { TemplateBundle } from "./types.js";
import { getTemplate, type TemplateName } from "./registry.js";

// ═══════════════════════════════════════════════════════════════════════
// Init parameters
// ═══════════════════════════════════════════════════════════════════════

export interface TemplateInitParams {
  /** Template name (one of the five canonical names). */
  template_name: TemplateName;
  /** Agent ID to bind the policy to. */
  agent_id: string;
  /** Fortress ID. */
  fortress_id: string;
  /** Counterparty for the channel template (defaults to "*" wildcard). */
  counterparty?: string;
  /** Policy version (monotonic per-agent). Defaults to 1. */
  policy_version?: number;
  /** Node ID for the signed event emitter. */
  emitter_node: string;
  /** Principal ID for the signed event emitter. */
  emitter_principal: string;
  /** Monotonic sequence number for the signed event. */
  monotonic_seq: number;
  /** Ed25519 private key for node signing. */
  node_private_key: Uint8Array;
  /** Ed25519 private key for principal signing (optional). */
  principal_private_key?: Uint8Array;
}

export interface TemplateInitResult {
  /** The deterministic compiled policy. */
  compiled: CompiledPolicy;
  /** The signed policy_update event. */
  signed_event: SignedEvent<PolicyUpdatePayload>;
  /** The template bundle used. */
  bundle: TemplateBundle;
}

// ═══════════════════════════════════════════════════════════════════════
// Deterministic compiled-at
// ═══════════════════════════════════════════════════════════════════════

/**
 * Derive a deterministic `compiled_at` from the template version so the
 * policy blob is byte-stable across runs. The timestamp is
 * 2026-01-01T00:00:00.000Z plus the template version as offset
 * (1.0.0 → +0 days, all v1.0.0 templates share the same epoch).
 */
function deterministicCompiledAt(version: string): string {
  // For v1.0.0, this returns a fixed timestamp.
  // Future template versions can derive different timestamps.
  const [major, minor, patch] = version.split(".").map(Number);
  const epoch = new Date("2026-01-01T00:00:00.000Z");
  epoch.setUTCDate(epoch.getUTCDate() + (major - 1) * 365 + minor * 30 + patch);
  return epoch.toISOString();
}

// ═══════════════════════════════════════════════════════════════════════
// Build compiled policy from template
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a deterministic CompiledPolicy from a template bundle. Does not
 * sign or pack; the caller does that.
 */
export function buildCompiledPolicyFromTemplate(
  bundle: TemplateBundle,
  params: {
    agent_id: string;
    fortress_id: string;
    counterparty: string;
    policy_version: number;
  }
): CompiledPolicy {
  // 1. Apply the channel template factory to get the base policy
  const policy = applyChannelTemplate(
    bundle.metadata.channel as ChannelTemplateId,
    {
      agent_id: params.agent_id,
      counterparty: params.counterparty,
      fortress_id: params.fortress_id,
      policy_version: params.policy_version,
    }
  );

  // 2. Fix compiled_at for determinism
  policy.compiled_at = deterministicCompiledAt(bundle.metadata.version);

  // 3. Set source_english from the template's policy.md
  policy.source_english = bundle.policy_english;

  // 4. Overlay WP-MVP-6 egress from defaults
  if (bundle.defaults.egress.length > 0) {
    const egress: EgressPolicy = {
      allowlist: bundle.defaults.egress.map((e) => ({
        destination: e.destination,
        methods: [...e.methods],
      })),
    };
    policy.egress = egress;
  }

  // 5. Overlay WP-MVP-6 budgets from defaults
  const budgets: BudgetPolicy = {};
  if (bundle.defaults.budgets.daily) {
    budgets.daily = { ...bundle.defaults.budgets.daily };
  }
  if (bundle.defaults.budgets.monthly) {
    budgets.monthly = { ...bundle.defaults.budgets.monthly };
  }
  if (budgets.daily || budgets.monthly) {
    policy.budgets = budgets;
  }

  // 6. Overlay WP-MVP-6 retention from defaults
  const windows = bundle.defaults.retention.windows;
  if (Object.keys(windows).length > 0) {
    const retention: RetentionPolicy = {
      windows: {},
    };
    for (const [slot, win] of Object.entries(windows)) {
      if (win) {
        (retention.windows as Record<string, unknown>)[slot] = { ...win };
      }
    }
    policy.retention = retention;
  }

  // 7. Seed commitment classes from commitments.json
  const classes = bundle.commitments.shapes.map((s) => s.commitment_class);
  for (const cls of classes) {
    if (!policy.capabilities.concordia_commitment_classes.includes(cls)) {
      policy.capabilities.concordia_commitment_classes.push(cls);
    }
  }
  policy.capabilities.concordia_commitment_classes.sort();

  // 8. Validate the assembled policy shape
  validateCompiledPolicyShape(policy);

  return policy;
}

// ═══════════════════════════════════════════════════════════════════════
// Full init: build + sign
// ═══════════════════════════════════════════════════════════════════════

/**
 * Initialize a template: build the compiled policy and pack it into a
 * signed policy_update event.
 */
export function initTemplate(params: TemplateInitParams): TemplateInitResult {
  const bundle = getTemplate(params.template_name);
  if (!bundle) {
    throw new Error(`unknown template: ${params.template_name}`);
  }

  const compiled = buildCompiledPolicyFromTemplate(bundle, {
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    counterparty: params.counterparty ?? "*",
    policy_version: params.policy_version ?? 1,
  });

  const signed_event = packPolicyUpdate({
    policy: compiled,
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    monotonic_seq: params.monotonic_seq,
    node_private_key: params.node_private_key,
    principal_private_key: params.principal_private_key,
  });

  return { compiled, signed_event, bundle };
}
