/**
 * Sanctuary Policy Engine - Channel-template library.
 *
 * v1.2 ships the design-canonical set shown in the Policy Center. Each
 * template factory produces a CompiledPolicy that can be packed into a
 * signed policy-update envelope by the existing policy engine.
 */

import {
  CHANNEL_TEMPLATE_IDS,
  POLICY_SLOTS,
  type ChannelTemplateId,
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
      ...(params.merge_into.egress
        ? {
            egress: {
              allowlist: params.merge_into.egress.allowlist.map((r) => ({
                destination: r.destination,
                methods: [...r.methods],
              })),
            },
          }
        : {}),
      ...(params.merge_into.budgets ? { budgets: { ...params.merge_into.budgets } } : {}),
      ...(params.merge_into.retention
        ? { retention: { windows: { ...params.merge_into.retention.windows } } }
        : {}),
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

function grantOn(policy: CompiledPolicy, slot: PolicySlot, grant: SlotGrant): void {
  const rule = policy.slots[slot];
  rule.mode = "grant";
  const dup = rule.grants.find(
    (g) => g.counterparty === grant.counterparty && g.action === grant.action,
  );
  if (dup) {
    if (grant.scope) dup.scope = { ...(dup.scope ?? {}), ...grant.scope };
    return;
  }
  rule.grants.push(grant);
  rule.grants.sort((a, b) => {
    if (a.counterparty === b.counterparty) return a.action.localeCompare(b.action);
    return a.counterparty.localeCompare(b.counterparty);
  });
}

function allowHosts(
  policy: CompiledPolicy,
  hosts: string[],
  methods: string[] = ["GET"],
): void {
  policy.egress = {
    allowlist: hosts.map((destination) => ({ destination, methods: [...methods] })),
  };
}

function setDailyUsdBudget(policy: CompiledPolicy, amount: number): void {
  policy.budgets = {
    daily: { amount, unit: "usd", soft_warn_threshold: 0.8 },
  };
}

function setRetentionDays(policy: CompiledPolicy, days: number): void {
  const max_age_seconds = days * 24 * 60 * 60;
  policy.retention = {
    windows: {
      memory: { max_age_seconds },
      credentials: { max_age_seconds },
      plans: { max_age_seconds },
      outputs: { max_age_seconds },
    },
  };
}

const requestApproveAct: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    "Operator sends a task. Agent proposes writes, pauses for approval, then executes. Most wrapped agents live here.";
  grantOn(p, "memory", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  grantOn(p, "plans", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  grantOn(p, "outputs", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  setDailyUsdBudget(p, 5);
  setRetentionDays(p, 30);
  return p;
};

const readThenReport: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    "Agent reads allowed sources and reports back. Any fetch outside allowed-hosts surfaces as an approval request.";
  grantOn(p, "outputs", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  allowHosts(p, allowedHostsFromScope(params.scope));
  setRetentionDays(p, 30);
  return p;
};

const scheduledDigest: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    "Runs on timer or external trigger. Pushes summaries into chat. Cannot write outward without approval.";
  grantOn(p, "memory", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  grantOn(p, "outputs", {
    counterparty: params.counterparty,
    action: "subscribe",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  allowHosts(p, allowedHostsFromScope(params.scope));
  setDailyUsdBudget(p, 2);
  setRetentionDays(p, 14);
  return p;
};

const planDraftOnly: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    "Drafts plans you review before anything runs. Cannot execute, pay, or mutate state on its own.";
  grantOn(p, "plans", {
    counterparty: params.counterparty,
    action: "read",
    ...(params.scope ? { scope: { ...params.scope } } : {}),
  });
  setRetentionDays(p, 30);
  return p;
};

const fortressRelay: ChannelTemplateFactory = (params) => {
  const p = basePolicy(params);
  p.source_english =
    "Routes signed events between peer fortresses. Commits bind only when both sides sign.";
  for (const action of ["read", "subscribe"] as const) {
    grantOn(p, "outputs", {
      counterparty: params.counterparty,
      action,
      ...(params.scope ? { scope: { ...params.scope } } : {}),
    });
  }
  const cls = "fortress-relay-dual-signature";
  if (!p.capabilities.concordia_commitment_classes.includes(cls)) {
    p.capabilities.concordia_commitment_classes.push(cls);
    p.capabilities.concordia_commitment_classes.sort();
  }
  setRetentionDays(p, 90);
  return p;
};

function allowedHostsFromScope(scope: Record<string, unknown> | undefined): string[] {
  const raw = scope?.allowed_hosts;
  if (!Array.isArray(raw)) return [];
  return raw.filter((v): v is string => typeof v === "string" && v.length > 0);
}

const REGISTRY: Record<ChannelTemplateId, ChannelTemplateRegistryEntry> = {
  "request-approve-act": {
    id: "request-approve-act",
    severity: "MEDIUM",
    label: "Request -> approve -> act",
    description:
      "Operator sends a task. Agent proposes writes, pauses for approval, then executes. Most wrapped agents live here.",
    factory: requestApproveAct,
  },
  "read-then-report": {
    id: "read-then-report",
    severity: "LOW",
    label: "Read -> report",
    description:
      "Agent reads allowed sources and reports back. Any fetch outside allowed-hosts surfaces as an approval request.",
    factory: readThenReport,
  },
  "scheduled-digest": {
    id: "scheduled-digest",
    severity: "LOW",
    label: "Scheduled digest",
    description:
      "Runs on timer or external trigger. Pushes summaries into chat. Cannot write outward without approval.",
    factory: scheduledDigest,
  },
  "plan-draft-only": {
    id: "plan-draft-only",
    severity: "LOW",
    label: "Plan, draft-only",
    description:
      "Drafts plans you review before anything runs. Cannot execute, pay, or mutate state on its own.",
    factory: planDraftOnly,
  },
  "fortress-relay": {
    id: "fortress-relay",
    severity: "MEDIUM",
    label: "Fortress relay",
    description:
      "Routes signed events between peer fortresses. Commits bind only when both sides sign.",
    factory: fortressRelay,
  },
};

export function listChannelTemplates(): ChannelTemplateRegistryEntry[] {
  return CHANNEL_TEMPLATE_IDS.map((id) => REGISTRY[id]);
}

export function getChannelTemplate(id: ChannelTemplateId): ChannelTemplateRegistryEntry {
  return REGISTRY[id];
}

export function applyChannelTemplate(
  id: ChannelTemplateId,
  params: ChannelTemplateParams,
): CompiledPolicy {
  const entry = REGISTRY[id];
  if (!entry) throw new Error(`unknown channel template: ${id}`);
  return entry.factory(params);
}

export function allChannelTemplateIds(): ChannelTemplateId[] {
  for (const id of CHANNEL_TEMPLATE_IDS) {
    if (!REGISTRY[id]) throw new Error(`channel-template registry missing id: ${id}`);
  }
  if (POLICY_SLOTS.length !== 4) throw new Error("four-slot invariant violated");
  return [...CHANNEL_TEMPLATE_IDS];
}
