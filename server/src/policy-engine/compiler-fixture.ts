/**
 * Sanctuary Policy Engine — Fixture compile pass.
 *
 * The production compile pass is LLM-driven (authoring-time only, offline-able
 * per Walkthrough Key 3). For tests and local development we ship a fixture
 * compiler: a deterministic pattern-matcher that recognizes a small set of
 * operator phrasings and produces a valid CompiledPolicy.
 *
 * The fixture is NOT a full natural-language parser and is not a substitute
 * for an LLM at authoring time. It exists so:
 *   1. Tests can compile real English through a real compile pass and
 *      exercise the full pack → verify → evaluate pipeline with zero network
 *      dependencies and zero floating behavior.
 *   2. Developers without a local model can still author policies end-to-end
 *      (the "offline-able" Key 3 clause applies to this fixture as a fallback).
 *
 * Recognized phrasings (expand only with caution; each regex is a hard
 * surface the operator relies on):
 *
 *   - "Agent <X> may read <slot> from agent <Y>."  → grants X read on Y's <slot>
 *   - "Agent <X> may write <slot> to agent <Y>."   → grants X write on Y's <slot>
 *   - "Agent <X> may subscribe to agent <Y>'s <slot>."
 *   - "Agent <X> may share <slot> with agent <Y>."
 *   - "Agent <X> is a sentinel."                    → is_sentinel = true
 *   - "Agent <X> may emit commitments of class <C>." → adds class to concordia_commitment_classes
 *   - "Register honeypot <skill_id> on agent <X>."   → adds to honeypot_skill_ids
 *
 * All slot grants are default-hermetic: slots that receive no grants stay in
 * deny mode. Unrecognized sentences are ignored — the compiler does NOT
 * silently grant broad access for phrases it cannot parse.
 */

import type { PolicySlot } from "./constants.js";
import { POLICY_SLOTS, type BudgetUnit } from "./constants.js";
import type { AuthoringRequest, CompilePass } from "./compiler.js";
import type {
  BudgetLimit,
  BudgetPolicy,
  CompiledPolicy,
  EgressRule,
  RetentionPolicy,
  RetentionWindow,
  SlotGrant,
  SlotRule,
} from "./types.js";

const SLOT_WORDS: Record<string, PolicySlot> = {
  memory: "memory",
  memories: "memory",
  credentials: "credentials",
  credential: "credentials",
  plans: "plans",
  plan: "plans",
  outputs: "outputs",
  output: "outputs",
};

function slotFromWord(word: string): PolicySlot | undefined {
  return SLOT_WORDS[word.toLowerCase()];
}

interface ParsedGrantClause {
  agent: string;
  action: string;
  slot: PolicySlot;
  counterparty: string;
}

const GRANT_PATTERNS: Array<{
  regex: RegExp;
  extract: (m: RegExpExecArray) => ParsedGrantClause | undefined;
}> = [
  // "Agent X may read memory from agent Y."
  // "Agent X may write outputs to agent Y."
  {
    regex:
      /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+may\s+(?<action>read|write)\s+(?<slot>\w+)\s+(?:from|to)\s+agent\s+(?<cp>[A-Za-z0-9_-]+)/gi,
    extract: (m) => {
      const slot = slotFromWord(m.groups!.slot);
      if (!slot) return undefined;
      return {
        agent: m.groups!.agent,
        action: m.groups!.action.toLowerCase(),
        slot,
        counterparty: m.groups!.cp,
      };
    },
  },
  // "Agent X may subscribe to agent Y's outputs."
  {
    regex:
      /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+may\s+subscribe\s+to\s+agent\s+(?<cp>[A-Za-z0-9_-]+)'?s\s+(?<slot>\w+)/gi,
    extract: (m) => {
      const slot = slotFromWord(m.groups!.slot);
      if (!slot) return undefined;
      return {
        agent: m.groups!.agent,
        action: "subscribe",
        slot,
        counterparty: m.groups!.cp,
      };
    },
  },
  // "Agent X may share credentials with agent Y."
  {
    regex:
      /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+may\s+share\s+(?<slot>\w+)\s+with\s+agent\s+(?<cp>[A-Za-z0-9_-]+)/gi,
    extract: (m) => {
      const slot = slotFromWord(m.groups!.slot);
      if (!slot) return undefined;
      return {
        agent: m.groups!.agent,
        action: "share",
        slot,
        counterparty: m.groups!.cp,
      };
    },
  },
];

const SENTINEL_REGEX = /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+is\s+a\s+sentinel/gi;
// Dash and colon are allowed in class names; dot intentionally excluded so a
// sentence-terminating period does not get swallowed into the identifier.
const COMMITMENT_CLASS_REGEX =
  /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+may\s+emit\s+commitments\s+of\s+class\s+(?<cls>[A-Za-z0-9_:-]+)/gi;
const HONEYPOT_REGEX =
  /Register\s+honeypot\s+(?<skill>[A-Za-z0-9_:-]+)\s+on\s+agent\s+(?<agent>[A-Za-z0-9_-]+)/gi;

// WP-MVP-6: Egress, Budget, Retention patterns.
// "Agent X may egress to api.openai.com via POST."
// "Agent X may egress to api.openai.com." (all methods)
const EGRESS_REGEX =
  /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+may\s+egress\s+to\s+(?<dest>[A-Za-z0-9._:-]+)(?:\s+via\s+(?<method>[A-Z,\s]+))?/gi;

// "Agent X has a daily budget of 1000 tokens."
// "Agent X has a monthly budget of 50 usd."
// "Agent X has a daily budget of 10 usd with 90% warn."
const BUDGET_REGEX =
  /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+has\s+a\s+(?<window>daily|monthly)\s+budget\s+of\s+(?<amount>[0-9.]+)\s+(?<unit>tokens|usd)(?:\s+with\s+(?<warn>[0-9]+)%\s+warn)?/gi;

// "Agent X retains memory for 86400 seconds."
// "Agent X retains outputs for 604800 seconds with archive."
const RETENTION_REGEX =
  /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+retains\s+(?<slot>\w+)\s+for\s+(?<seconds>[0-9]+)\s+seconds(?:\s+with\s+archive)?/gi;
const RETENTION_ARCHIVE_REGEX =
  /Agent\s+(?<agent>[A-Za-z0-9_-]+)\s+retains\s+(?<slot>\w+)\s+for\s+(?<seconds>[0-9]+)\s+seconds\s+with\s+archive/gi;

function emptyDenySlots(): CompiledPolicy["slots"] {
  const make = (slot: PolicySlot): SlotRule => ({
    slot,
    mode: "deny",
    grants: [],
  });
  return {
    memory: make("memory"),
    credentials: make("credentials"),
    plans: make("plans"),
    outputs: make("outputs"),
  };
}

/**
 * Merge a grant into a slots map. Upgrades the slot's mode to "grant" on
 * first addition and deduplicates on (counterparty, action).
 */
function addGrant(
  slots: CompiledPolicy["slots"],
  slot: PolicySlot,
  grant: SlotGrant
): void {
  const rule = slots[slot];
  rule.mode = "grant";
  const dup = rule.grants.find(
    (g) => g.counterparty === grant.counterparty && g.action === grant.action
  );
  if (dup) return;
  rule.grants.push(grant);
  // Sort for determinism across authoring order.
  rule.grants.sort((a, b) => {
    if (a.counterparty === b.counterparty) return a.action.localeCompare(b.action);
    return a.counterparty.localeCompare(b.counterparty);
  });
}

/** Fixture compile implementation — pure function over the request. */
export function compileFixturePolicy(req: AuthoringRequest): CompiledPolicy {
  const slots = emptyDenySlots();
  const commitmentClasses = new Set<string>();
  const honeypotSkills = new Set<string>();
  let isSentinel = false;

  // If prior_policy is supplied, seed from it (merge semantics).
  if (req.prior_policy) {
    for (const slot of POLICY_SLOTS) {
      const priorRule = req.prior_policy.slots[slot];
      if (priorRule.mode === "grant") {
        slots[slot].mode = "grant";
        for (const g of priorRule.grants) {
          addGrant(slots, slot, { ...g });
        }
      }
    }
    for (const c of req.prior_policy.capabilities.concordia_commitment_classes) {
      commitmentClasses.add(c);
    }
    for (const h of req.prior_policy.capabilities.honeypot_skill_ids) {
      honeypotSkills.add(h);
    }
    isSentinel = isSentinel || req.prior_policy.capabilities.is_sentinel;
  }

  const text = req.source_english;

  for (const pat of GRANT_PATTERNS) {
    const regex = new RegExp(pat.regex.source, pat.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      const clause = pat.extract(m);
      if (!clause) continue;
      if (clause.agent !== req.agent_id) continue; // only apply to THIS agent's policy
      addGrant(slots, clause.slot, {
        counterparty: clause.counterparty,
        action: clause.action,
      });
    }
  }

  const sentRe = new RegExp(SENTINEL_REGEX.source, SENTINEL_REGEX.flags);
  let s: RegExpExecArray | null;
  while ((s = sentRe.exec(text)) !== null) {
    if (s.groups!.agent === req.agent_id) isSentinel = true;
  }

  const cRe = new RegExp(COMMITMENT_CLASS_REGEX.source, COMMITMENT_CLASS_REGEX.flags);
  let c: RegExpExecArray | null;
  while ((c = cRe.exec(text)) !== null) {
    if (c.groups!.agent === req.agent_id) commitmentClasses.add(c.groups!.cls);
  }

  const hRe = new RegExp(HONEYPOT_REGEX.source, HONEYPOT_REGEX.flags);
  let h: RegExpExecArray | null;
  while ((h = hRe.exec(text)) !== null) {
    if (h.groups!.agent === req.agent_id) honeypotSkills.add(h.groups!.skill);
  }

  // WP-MVP-6: Parse egress rules.
  // WP-MVP-6: Parse egress rules.
  const egressRules: EgressRule[] = [];
  const egressRe = new RegExp(EGRESS_REGEX.source, EGRESS_REGEX.flags);
  let eg: RegExpExecArray | null;
  while ((eg = egressRe.exec(text)) !== null) {
    if (eg.groups!.agent !== req.agent_id) continue;
    const dest = eg.groups!.dest.replace(/\.$/, ""); // strip trailing period
    const methods = eg.groups!.method
      ? eg.groups!.method
          .split(/[,\s]+/)
          .map((m) => m.trim().toUpperCase())
          .filter((m) => m.length > 0)
      : [];
    // Deduplicate on destination.
    const existing = egressRules.find((r) => r.destination === dest);
    if (existing) {
      for (const m of methods) {
        if (!existing.methods.includes(m)) existing.methods.push(m);
      }
    } else {
      egressRules.push({ destination: dest, methods });
    }
  }
  egressRules.sort((a, b) => a.destination.localeCompare(b.destination));

  // WP-MVP-6: Parse budget rules.
  let budgetPolicy: BudgetPolicy | undefined;
  const budgetRe = new RegExp(BUDGET_REGEX.source, BUDGET_REGEX.flags);
  let bg: RegExpExecArray | null;
  while ((bg = budgetRe.exec(text)) !== null) {
    if (bg.groups!.agent !== req.agent_id) continue;
    if (!budgetPolicy) budgetPolicy = {};
    const limit: BudgetLimit = {
      amount: parseFloat(bg.groups!.amount),
      unit: bg.groups!.unit as BudgetUnit,
    };
    if (bg.groups!.warn) {
      limit.soft_warn_threshold = parseInt(bg.groups!.warn, 10) / 100;
    }
    if (bg.groups!.window === "daily") {
      budgetPolicy.daily = limit;
    } else {
      budgetPolicy.monthly = limit;
    }
  }

  // WP-MVP-6: Parse retention rules.
  let retentionPolicy: RetentionPolicy | undefined;
  const retRe = new RegExp(RETENTION_REGEX.source, RETENTION_REGEX.flags);
  const retArchiveRe = new RegExp(
    RETENTION_ARCHIVE_REGEX.source,
    RETENTION_ARCHIVE_REGEX.flags
  );
  // Pre-scan for archive flags.
  const archiveSlots = new Set<string>();
  let ra: RegExpExecArray | null;
  while ((ra = retArchiveRe.exec(text)) !== null) {
    if (ra.groups!.agent === req.agent_id) {
      const slot = slotFromWord(ra.groups!.slot);
      if (slot) archiveSlots.add(slot);
    }
  }
  let rt: RegExpExecArray | null;
  while ((rt = retRe.exec(text)) !== null) {
    if (rt.groups!.agent !== req.agent_id) continue;
    const slot = slotFromWord(rt.groups!.slot);
    if (!slot) continue;
    if (!retentionPolicy) retentionPolicy = { windows: {} };
    const win: RetentionWindow = {
      max_age_seconds: parseInt(rt.groups!.seconds, 10),
    };
    if (archiveSlots.has(slot)) win.archive = true;
    retentionPolicy.windows[slot] = win;
  }

  const compiled: CompiledPolicy = {
    schema_version: "0.1",
    agent_id: req.agent_id,
    fortress_id: req.fortress_id,
    policy_version: req.policy_version,
    slots,
    capabilities: {
      concordia_commitment_classes: Array.from(commitmentClasses).sort(),
      honeypot_skill_ids: Array.from(honeypotSkills).sort(),
      is_sentinel: isSentinel,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: true,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english: req.source_english,
    compiled_at: "2026-04-21T00:00:00.000Z",
  };
  if (req.parent_version !== undefined) {
    compiled.parent_version = req.parent_version;
  }
  if (egressRules.length > 0) {
    compiled.egress = { allowlist: egressRules };
  }
  if (budgetPolicy) {
    compiled.budgets = budgetPolicy;
  }
  if (retentionPolicy) {
    compiled.retention = retentionPolicy;
  }
  return compiled;
}

/** Adapter: the fixture compiler fitted to the CompilePass interface. */
export const fixtureCompilePass: CompilePass = async (req) =>
  compileFixturePolicy(req);
