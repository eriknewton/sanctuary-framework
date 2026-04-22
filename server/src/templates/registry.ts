/**
 * Sanctuary Template Library — Registry.
 *
 * Loads template bundles from `server/src/templates/<name>/`, validates
 * shapes, and exposes a read-only registry the CLI + dashboard API consume.
 *
 * Templates are shipped as source (not compiled) so operators can inspect
 * before loading. The registry loads lazily on first access and caches.
 */

import { readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CHANNEL_TEMPLATE_IDS } from "../policy-engine/constants.js";
import type {
  TemplateBundle,
  TemplateMetadata,
  TemplateDefaults,
  TemplateCommitments,
  TemplateRegistryEntry,
} from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

/** The five canonical template names (1:1 with channel templates). */
export const TEMPLATE_NAMES = [
  "research-assistant",
  "coding-assistant",
  "ops-runner",
  "planner",
  "handoff-coordinator",
] as const;

export type TemplateName = (typeof TEMPLATE_NAMES)[number];

export function isTemplateName(value: unknown): value is TemplateName {
  return (
    typeof value === "string" &&
    (TEMPLATE_NAMES as readonly string[]).includes(value)
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════

export class TemplateValidationError extends Error {
  constructor(templateName: string, message: string) {
    super(`template "${templateName}": ${message}`);
    this.name = "TemplateValidationError";
  }
}

function validateMetadata(name: string, data: unknown): asserts data is TemplateMetadata {
  if (typeof data !== "object" || data === null) {
    throw new TemplateValidationError(name, "template.json must be an object");
  }
  const d = data as Record<string, unknown>;
  if (typeof d.name !== "string" || d.name !== name) {
    throw new TemplateValidationError(name, `template.json name must be "${name}"`);
  }
  if (typeof d.version !== "string" || !/^\d+\.\d+\.\d+$/.test(d.version)) {
    throw new TemplateValidationError(name, "template.json version must be semver");
  }
  if (typeof d.channel !== "string" || !(CHANNEL_TEMPLATE_IDS as readonly string[]).includes(d.channel)) {
    throw new TemplateValidationError(
      name,
      `template.json channel must be one of: ${CHANNEL_TEMPLATE_IDS.join(", ")}`
    );
  }
  if (typeof d.tier !== "string" || !["A", "B", "C"].includes(d.tier)) {
    throw new TemplateValidationError(name, "template.json tier must be A, B, or C");
  }
  if (typeof d.target_archetype !== "string" || d.target_archetype.length === 0) {
    throw new TemplateValidationError(name, "template.json target_archetype must be a non-empty string");
  }
  if (typeof d.description !== "string" || d.description.length === 0) {
    throw new TemplateValidationError(name, "template.json description must be a non-empty string");
  }
}

function validateDefaults(name: string, data: unknown): asserts data is TemplateDefaults {
  if (typeof data !== "object" || data === null) {
    throw new TemplateValidationError(name, "defaults.json must be an object");
  }
  const d = data as Record<string, unknown>;
  if (!Array.isArray(d.egress)) {
    throw new TemplateValidationError(name, "defaults.json egress must be an array");
  }
  for (const entry of d.egress) {
    if (typeof entry !== "object" || entry === null) {
      throw new TemplateValidationError(name, "defaults.json egress entry must be an object");
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.destination !== "string" || e.destination.length === 0) {
      throw new TemplateValidationError(name, "egress entry destination must be a non-empty string");
    }
    if (!Array.isArray(e.methods)) {
      throw new TemplateValidationError(name, "egress entry methods must be an array");
    }
  }
  if (typeof d.budgets !== "object" || d.budgets === null) {
    throw new TemplateValidationError(name, "defaults.json budgets must be an object");
  }
  if (typeof d.retention !== "object" || d.retention === null) {
    throw new TemplateValidationError(name, "defaults.json retention must be an object");
  }
  const ret = d.retention as Record<string, unknown>;
  if (typeof ret.windows !== "object" || ret.windows === null) {
    throw new TemplateValidationError(name, "defaults.json retention.windows must be an object");
  }
}

function validateCommitments(name: string, data: unknown): asserts data is TemplateCommitments {
  if (typeof data !== "object" || data === null) {
    throw new TemplateValidationError(name, "commitments.json must be an object");
  }
  const d = data as Record<string, unknown>;
  if (!Array.isArray(d.shapes)) {
    throw new TemplateValidationError(name, "commitments.json shapes must be an array");
  }
  for (const shape of d.shapes) {
    if (typeof shape !== "object" || shape === null) {
      throw new TemplateValidationError(name, "commitment shape must be an object");
    }
    const s = shape as Record<string, unknown>;
    if (typeof s.commitment_class !== "string" || s.commitment_class.length === 0) {
      throw new TemplateValidationError(name, "commitment shape commitment_class must be a non-empty string");
    }
    if (typeof s.example_deliverable !== "string") {
      throw new TemplateValidationError(name, "commitment shape example_deliverable must be a string");
    }
    if (typeof s.example_deadline_or_terminal !== "string") {
      throw new TemplateValidationError(name, "commitment shape example_deadline_or_terminal must be a string");
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Naming discipline + no-em-dash lint
// ═══════════════════════════════════════════════════════════════════════

/** Check that public-facing onboarding.md passes naming-discipline + no-em-dash. */
export function lintOnboarding(
  _name: string,
  content: string
): { clean: boolean; violations: string[] } {
  const violations: string[] = [];
  // Em-dash check
  if (content.includes("\u2014")) {
    violations.push("onboarding.md contains em-dashes (U+2014). Replace with commas, semicolons, colons, or parentheses.");
  }
  // En-dash check (common substitute that also reads as LLM-generated)
  if (content.includes("\u2013")) {
    violations.push("onboarding.md contains en-dashes (U+2013). Replace with hyphens or other punctuation.");
  }
  return { clean: violations.length === 0, violations };
}

// ═══════════════════════════════════════════════════════════════════════
// Loader
// ═══════════════════════════════════════════════════════════════════════

function resolveTemplatesDir(): string {
  // Works in both source (ts) and compiled (js) contexts
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = dirname(thisFile);
  // In source: server/src/templates/registry.ts → server/src/templates/
  // In compiled: server/dist/templates/registry.js → server/dist/templates/
  // Templates ship as source under server/src/templates/<name>/.
  // When running compiled, we need to resolve back to src.
  if (thisDir.includes("/dist/")) {
    return thisDir.replace("/dist/templates", "/src/templates");
  }
  return thisDir;
}

function loadTemplateBundle(name: string, templatesDir: string): TemplateBundle {
  const dir = join(templatesDir, name);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    throw new TemplateValidationError(name, `template directory not found: ${dir}`);
  }

  // template.json
  const metadataRaw = JSON.parse(readFileSync(join(dir, "template.json"), "utf-8"));
  validateMetadata(name, metadataRaw);

  // policy.md
  const policyEnglish = readFileSync(join(dir, "policy.md"), "utf-8").trim();
  if (policyEnglish.length === 0) {
    throw new TemplateValidationError(name, "policy.md must not be empty");
  }

  // defaults.json
  const defaultsRaw = JSON.parse(readFileSync(join(dir, "defaults.json"), "utf-8"));
  validateDefaults(name, defaultsRaw);

  // commitments.json
  const commitmentsRaw = JSON.parse(readFileSync(join(dir, "commitments.json"), "utf-8"));
  validateCommitments(name, commitmentsRaw);

  // onboarding.md
  const onboarding = readFileSync(join(dir, "onboarding.md"), "utf-8").trim();
  if (onboarding.length === 0) {
    throw new TemplateValidationError(name, "onboarding.md must not be empty");
  }

  // Lint public-facing copy
  const lint = lintOnboarding(name, onboarding);
  if (!lint.clean) {
    throw new TemplateValidationError(name, lint.violations.join("; "));
  }

  return {
    metadata: metadataRaw as TemplateMetadata,
    policy_english: policyEnglish,
    defaults: defaultsRaw as TemplateDefaults,
    commitments: commitmentsRaw as TemplateCommitments,
    onboarding,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Registry (lazy singleton)
// ═══════════════════════════════════════════════════════════════════════

let _cache: Map<TemplateName, TemplateBundle> | null = null;

function ensureLoaded(): Map<TemplateName, TemplateBundle> {
  if (_cache) return _cache;
  _cache = new Map();
  const dir = resolveTemplatesDir();
  for (const name of TEMPLATE_NAMES) {
    _cache.set(name, loadTemplateBundle(name, dir));
  }
  return _cache;
}

/** Clear the cache (for testing). */
export function clearTemplateCache(): void {
  _cache = null;
}

/** List all template registry entries (metadata + onboarding). */
export function listTemplates(): TemplateRegistryEntry[] {
  const cache = ensureLoaded();
  return TEMPLATE_NAMES.map((name) => {
    const bundle = cache.get(name)!;
    return {
      metadata: bundle.metadata,
      onboarding: bundle.onboarding,
    };
  });
}

/** Get a single template bundle by name. Returns null if not found. */
export function getTemplate(name: string): TemplateBundle | null {
  if (!isTemplateName(name)) return null;
  const cache = ensureLoaded();
  return cache.get(name) ?? null;
}

/** Get a single template registry entry. Returns null if not found. */
export function getTemplateEntry(name: string): TemplateRegistryEntry | null {
  const bundle = getTemplate(name);
  if (!bundle) return null;
  return { metadata: bundle.metadata, onboarding: bundle.onboarding };
}

/**
 * Load a template bundle from a custom directory. Used by tests and
 * operator-supplied template directories.
 */
export function loadTemplateFromDir(name: string, dir: string): TemplateBundle {
  return loadTemplateBundle(name, dir);
}
