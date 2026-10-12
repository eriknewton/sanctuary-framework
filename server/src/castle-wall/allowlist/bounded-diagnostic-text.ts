const DIAGNOSTIC_ECHO_CELL_CHARS = 8;
// Must match `DIAGNOSTIC_ECHO_MAX_CHARS` in `castle-wall-daemon/src/policy.rs`.
export const DIAGNOSTIC_ECHO_MAX_CHARS =
  DIAGNOSTIC_ECHO_CELL_CHARS * DIAGNOSTIC_ECHO_CELL_CHARS;
const DIAGNOSTIC_LIST_CELL_COUNT = 2;
export const DIAGNOSTIC_MAX_LISTED_OFFENDERS =
  DIAGNOSTIC_LIST_CELL_COUNT * DIAGNOSTIC_LIST_CELL_COUNT * DIAGNOSTIC_LIST_CELL_COUNT;
const DIAGNOSTIC_ELLIPSIS_MARKER = "...";
const PRINTABLE_ASCII_MIN_CODE_POINT = 0x20;
const PRINTABLE_ASCII_MAX_CODE_POINT = 0x7e;
const DIAGNOSTIC_UNICODE_MIN_HEX_DIGITS = 4;

function escapeDiagnosticValue(value: string): string {
  let escaped = '"';
  for (const char of value) {
    if (char === '"') {
      escaped += '\\"';
      continue;
    }
    if (char === "\\") {
      escaped += "\\\\";
      continue;
    }
    const codePoint = char.codePointAt(0);
    if (
      codePoint !== undefined &&
      codePoint >= PRINTABLE_ASCII_MIN_CODE_POINT &&
      codePoint <= PRINTABLE_ASCII_MAX_CODE_POINT
    ) {
      escaped += char;
      continue;
    }
    const hex = codePoint?.toString(16).toUpperCase() ?? "";
    escaped += `\\u{${hex.padStart(DIAGNOSTIC_UNICODE_MIN_HEX_DIGITS, "0")}}`;
  }
  return `${escaped}"`;
}

export function formatBoundedDiagnosticValue(value: string): string {
  // INVARIANT: diagnostics quote echoed operator text, escape `"`/`\`, render non-printable-ASCII as `\u{XXXX}`,
  // and then truncate; must match `bounded_diagnostic_text` in `castle-wall-daemon/src/policy.rs`.
  const chars = Array.from(escapeDiagnosticValue(value));
  if (chars.length <= DIAGNOSTIC_ECHO_MAX_CHARS) return chars.join("");
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
