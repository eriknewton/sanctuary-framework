/**
 * Single source of truth for the agent-native cooperative MCP tool names.
 *
 * These names are public protocol strings. Keep machine-facing registrations,
 * discovery catalogs, denial hints, and compound routing pointed at these
 * constants so an internal rename cannot drift across files.
 */
export const COOPERATIVE_TOOL_NAMES = {
  remember: "sanctuary_remember",
  recall: "sanctuary_recall",
  hide: "sanctuary_hide",
  forget: "sanctuary_forget",
  help: "sanctuary_help",
  capabilities: "sanctuary_capabilities",
  whoAmI: "sanctuary_who_am_i",
  activeProtections: "sanctuary_active_protections",
  eventsOpenCursor: "sanctuary_events_open_cursor",
  eventsRead: "sanctuary_events_read",
  eventsClose: "sanctuary_events_close",
  auditSearch: "sanctuary_audit_search",
  compoundExecute: "sanctuary_compound_execute",
} as const;

export type CooperativeToolName =
  (typeof COOPERATIVE_TOOL_NAMES)[keyof typeof COOPERATIVE_TOOL_NAMES];

export const CATALOG_COOPERATIVE_TOOL_NAMES = [
  COOPERATIVE_TOOL_NAMES.help,
  COOPERATIVE_TOOL_NAMES.whoAmI,
  COOPERATIVE_TOOL_NAMES.activeProtections,
  COOPERATIVE_TOOL_NAMES.remember,
  COOPERATIVE_TOOL_NAMES.recall,
  COOPERATIVE_TOOL_NAMES.hide,
  COOPERATIVE_TOOL_NAMES.forget,
  COOPERATIVE_TOOL_NAMES.eventsOpenCursor,
  COOPERATIVE_TOOL_NAMES.auditSearch,
] as const satisfies readonly CooperativeToolName[];

export type CatalogCooperativeToolName =
  (typeof CATALOG_COOPERATIVE_TOOL_NAMES)[number];

export const COMPOUND_EXECUTABLE_TOOL_NAMES = [
  COOPERATIVE_TOOL_NAMES.remember,
  COOPERATIVE_TOOL_NAMES.recall,
  COOPERATIVE_TOOL_NAMES.hide,
  COOPERATIVE_TOOL_NAMES.forget,
] as const satisfies readonly CooperativeToolName[];

export type CompoundExecutableToolName =
  (typeof COMPOUND_EXECUTABLE_TOOL_NAMES)[number];

const COMPOUND_EXECUTABLE_TOOL_NAME_SET = new Set<string>(
  COMPOUND_EXECUTABLE_TOOL_NAMES
);

export function isCompoundExecutableToolName(
  value: string
): value is CompoundExecutableToolName {
  return COMPOUND_EXECUTABLE_TOOL_NAME_SET.has(value);
}
