/**
 * DISTINCT local audit operation string for the Rung-1 memory-file ingest
 * classifier-override lifecycle (point 3, ratified 2026-08-22:
 * Wiki/decisions/rung1-classifier-refusal-ux-explain-never-redact-2026-08-22.md).
 *
 * Sole source for this op name, imported by both `cli/memory-file.ts` and
 * `sdw/memory-file-tools.ts` (cross-file pin: keep both in sync with this
 * constant, never re-type the string literal) so the CLI and MCP surfaces
 * cannot drift on what the override audit record is called.
 *
 * This is a LOCAL string, not a widened shared enum: `AuditLog.operation` is
 * `string`, and adding a new local op here fans out to nothing else.
 */
export const MEMORY_INGEST_CLASSIFIER_OVERRIDE = "memory_ingest_classifier_override" as const;
