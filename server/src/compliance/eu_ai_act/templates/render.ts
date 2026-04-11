/**
 * Sanctuary MCP Server — EU AI Act Compliance Template Renderer
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hand-rolled minimal template engine — zero runtime dependencies.
 *
 * Supported syntax:
 *
 *   {{ variable_name }}
 *     Substituted with context[variable_name]. If undefined, null,
 *     or empty string, substituted with:
 *       [MANUAL INPUT REQUIRED: variable_name]
 *
 *   {{ variable_name | free-form hint }}
 *     Same as above but with a custom manual-input hint:
 *       [MANUAL INPUT REQUIRED: free-form hint]
 *
 * That is the entire grammar. No conditionals, no loops, no field
 * access, no partials, no escaping. Complex structures (iteration
 * over matrix rows, audit entry tables, signature blocks) are
 * pre-rendered as strings by the generator before being passed to
 * this engine.
 *
 * Rationale: Sanctuary has a strict minimal-dependency posture.
 * A 60-line engine that handles our exact needs is preferable to
 * pulling in Handlebars or Eta as a runtime dependency.
 */

/**
 * Values that can appear in a template context. All are coerced to
 * strings at render time via String(value).
 */
export type TemplateValue = string | number | boolean | null | undefined;

/**
 * Template context: a flat map of variable names to values.
 */
export type TemplateContext = Record<string, TemplateValue>;

/**
 * Regex matching one interpolation expression:
 *   {{ name }}            — group 1 = "name", group 2 = undefined
 *   {{ name | hint text}} — group 1 = "name", group 2 = "hint text"
 *
 * Variable names must match /[a-z_][a-z0-9_]* /i.
 *
 * The optional hint is everything after `|` up to `}}`, trimmed.
 */
const INTERPOLATION_RE =
  /\{\{\s*([a-z_][a-z0-9_]*)(?:\s*\|\s*([^}]*?))?\s*\}\}/gi;

/**
 * Sentinel marker rendered when a variable is missing or empty.
 * Written as a constant so tests can match on it exactly.
 */
export const MANUAL_INPUT_MARKER_PREFIX = "[MANUAL INPUT REQUIRED:";
export const MANUAL_INPUT_MARKER_SUFFIX = "]";

/**
 * Produce a MANUAL INPUT REQUIRED marker for a given hint.
 */
export function manualInputMarker(hint: string): string {
  return `${MANUAL_INPUT_MARKER_PREFIX} ${hint}${MANUAL_INPUT_MARKER_SUFFIX}`;
}

/**
 * Determine whether a value is considered "empty" for rendering
 * purposes. Empty values trigger the MANUAL INPUT REQUIRED marker.
 */
function isEmpty(value: TemplateValue): boolean {
  return value === undefined || value === null || value === "";
}

/**
 * Render a template string against a context.
 *
 * @param template The template source string.
 * @param context  A flat map of variable names to values.
 * @returns The rendered string with all {{ ... }} expressions resolved.
 */
export function render(template: string, context: TemplateContext): string {
  return template.replace(INTERPOLATION_RE, (_match, rawKey, rawHint) => {
    const key = String(rawKey).trim();
    const value = context[key];
    if (isEmpty(value)) {
      const hint = rawHint !== undefined ? String(rawHint).trim() : key;
      return manualInputMarker(hint || key);
    }
    return String(value);
  });
}

/**
 * Count the number of MANUAL INPUT REQUIRED markers in a rendered
 * string. Useful for validation: a bundle with many unfilled markers
 * may indicate the enterprise has not completed its portion of the
 * compliance work.
 */
export function countManualInputMarkers(rendered: string): number {
  const marker = MANUAL_INPUT_MARKER_PREFIX;
  let count = 0;
  let index = 0;
  while ((index = rendered.indexOf(marker, index)) !== -1) {
    count++;
    index += marker.length;
  }
  return count;
}

/**
 * Extract the list of unfilled hints from a rendered string.
 * Returns the text between `[MANUAL INPUT REQUIRED:` and the next
 * closing `]`. Useful for surfacing "the enterprise still needs to
 * fill in X, Y, Z" in the CLI output.
 */
export function extractManualInputHints(rendered: string): string[] {
  const hints: string[] = [];
  const re = /\[MANUAL INPUT REQUIRED:\s*([^\]]+?)\s*\]/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(rendered)) !== null) {
    hints.push(match[1]);
  }
  return hints;
}
