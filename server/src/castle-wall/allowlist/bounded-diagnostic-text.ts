const DIAGNOSTIC_ECHO_CELL_CHARS = 8;
// Must match `DIAGNOSTIC_ECHO_MAX_CHARS` in `castle-wall-daemon/src/policy.rs`.
export const DIAGNOSTIC_ECHO_MAX_CHARS =
  DIAGNOSTIC_ECHO_CELL_CHARS * DIAGNOSTIC_ECHO_CELL_CHARS;
const DIAGNOSTIC_LIST_CELL_COUNT = 2;
export const DIAGNOSTIC_MAX_LISTED_OFFENDERS =
  DIAGNOSTIC_LIST_CELL_COUNT * DIAGNOSTIC_LIST_CELL_COUNT * DIAGNOSTIC_LIST_CELL_COUNT;
const DIAGNOSTIC_ELLIPSIS_MARKER = "...";

export function formatBoundedDiagnosticValue(value: string): string {
  const chars = Array.from(value);
  if (chars.length <= DIAGNOSTIC_ECHO_MAX_CHARS) return value;
  return `${chars.slice(0, DIAGNOSTIC_ECHO_MAX_CHARS).join("")}${DIAGNOSTIC_ELLIPSIS_MARKER} (original length ${chars.length})`;
}

export function formatBoundedDiagnosticList<T>(
  values: readonly T[],
  formatValue: (value: T) => string,
): string {
  const shown = values.slice(0, DIAGNOSTIC_MAX_LISTED_OFFENDERS).map(formatValue);
  const remaining = values.length - shown.length;
  return remaining > 0 ? `${shown.join("; ")}; and ${remaining} more` : shown.join("; ");
}
