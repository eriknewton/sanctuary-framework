/**
 * Sanctuary Template Library — Types.
 *
 * Template metadata shape validated at load time. Each template ships as a
 * directory under `server/src/templates/<template-name>/` containing five
 * bundle files: template.json, policy.md, defaults.json, commitments.json,
 * onboarding.md.
 */

import type { ChannelTemplateId, PolicySlot, BudgetUnit } from "../policy-engine/constants.js";

/** Template metadata from template.json. */
export interface TemplateMetadata {
  /** Machine-readable template name (matches directory name). */
  name: string;
  /** Semver version string. v1.0 ships all templates at "1.0.0". */
  version: string;
  /** The WP-MVP-5 channel template this agent template maps to. */
  channel: ChannelTemplateId;
  /** Harness tier per Agent Contract §4: "A" | "B" | "C". */
  tier: "A" | "B" | "C";
  /** Operator archetype this template targets. */
  target_archetype: string;
  /** Short description for CLI + registry listing. */
  description: string;
}

/** A single egress allowlist seed entry from defaults.json. */
export interface TemplateEgressSeed {
  /** Domain or domain:port placeholder. */
  destination: string;
  /** HTTP methods. Empty = all methods. */
  methods: string[];
  /** Inline comment explaining why this destination is included. */
  comment: string;
}

/** Budget defaults from defaults.json. */
export interface TemplateBudgetDefaults {
  daily?: { amount: number; unit: BudgetUnit };
  monthly?: { amount: number; unit: BudgetUnit };
}

/** Retention window defaults from defaults.json, keyed by slot. */
export interface TemplateRetentionDefaults {
  windows: Partial<Record<PolicySlot, { max_age_seconds: number; archive?: boolean }>>;
}

/** defaults.json shape. */
export interface TemplateDefaults {
  egress: TemplateEgressSeed[];
  budgets: TemplateBudgetDefaults;
  retention: TemplateRetentionDefaults;
}

/** A single example commitment shape from commitments.json. */
export interface TemplateCommitmentShape {
  /** Commitment class from Agent Contract §7 (e.g. "task-accept"). */
  commitment_class: string;
  /** Example deliverable description. */
  example_deliverable: string;
  /** Example deadline or terminal condition. */
  example_deadline_or_terminal: string;
}

/** commitments.json shape. */
export interface TemplateCommitments {
  shapes: TemplateCommitmentShape[];
}

/** Fully loaded template bundle (all five files). */
export interface TemplateBundle {
  metadata: TemplateMetadata;
  /** Plain-English policy text (source for policy engine). */
  policy_english: string;
  defaults: TemplateDefaults;
  commitments: TemplateCommitments;
  /** Operator-facing onboarding blurb (rendered as plain text). */
  onboarding: string;
}

/** API response shape for a single template (registry). */
export interface TemplateRegistryEntry {
  metadata: TemplateMetadata;
  onboarding: string;
}
