/**
 * Sanctuary Template Library — Barrel export.
 */

export type {
  TemplateMetadata,
  TemplateDefaults,
  TemplateCommitments,
  TemplateBundle,
  TemplateRegistryEntry,
  TemplateEgressSeed,
  TemplateBudgetDefaults,
  TemplateRetentionDefaults,
  TemplateCommitmentShape,
} from "./types.js";

export {
  TEMPLATE_NAMES,
  type TemplateName,
  isTemplateName,
  listTemplates,
  getTemplate,
  getTemplateEntry,
  clearTemplateCache,
  lintOnboarding,
  TemplateValidationError,
} from "./registry.js";

export {
  buildCompiledPolicyFromTemplate,
  initTemplate,
  type TemplateInitParams,
  type TemplateInitResult,
} from "./init.js";

export { runTemplateCommand, type TemplateCommandArgs } from "./cli.js";
