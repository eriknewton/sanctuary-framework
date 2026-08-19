/**
 * Sanctuary error types - untrusted-value diagnostic rendering.
 *
 * THE CHOKEPOINT for putting a STORED or WIRE-SUPPLIED value into a diagnostic
 * string (a thrown message, an error message, an operator log line).
 *
 * WHY THIS EXISTS (invariant, read before editing):
 *
 *   A field read back from disk or off the wire is attacker-influenced no
 *   matter what its declared TypeScript type says. `const e: StateEntry =
 *   JSON.parse(bytes)` is a bare assertion, so `e.kid` reads as `string` to the
 *   compiler while holding any JSON value at runtime. Interpolating such a
 *   field directly (`` `Writer key not found for ${e.kid}` ``) hands the value
 *   to `String()`, and `String()` on a deeply nested array recurses through
 *   `Array.prototype.toString` -> `Array.prototype.join` until the stack
 *   overflows. The RangeError is thrown while BUILDING the diagnostic, so the
 *   real, correctly-detected failure is replaced by an unrelated one and the
 *   operator is told the wrong thing. A long value is the same defect in a
 *   quieter form: it buries the diagnosis in megabytes of attacker text.
 *
 *   Therefore: BUILDING A DIAGNOSTIC MUST NEVER BE ABLE TO FAIL, AND MUST NEVER
 *   BE ABLE TO MISLEAD. {@link describeUntrusted} is total (it returns a
 *   code-chosen placeholder rather than throwing, for every input including
 *   cyclic, deeply nested, enormous, symbol, and throwing-getter values),
 *   bounded (its output length has a ceiling that does not depend on the
 *   input), and non-deceptive (a value that was shortened SAYS it was
 *   shortened, and control characters are escaped so a value cannot forge
 *   extra log lines in an operator's terminal).
 *
 *   It is deliberately NOT a redactor. It does not decide what is safe to
 *   disclose; that judgment belongs to the caller and, for the evidence pack,
 *   to `evidence-pack/read-outcome.ts`'s `sanitizeReason`, which is a
 *   DIFFERENT concern (scrubbing operator paths out of a signed document).
 *
 * This file is a pure declaration: no imports, no top-level side effects, no
 * I/O. Keep it that way so any module, including the crypto core, can depend
 * on it without pulling in a dependency edge.
 */

/**
 * Ceiling on the rendered length of one untrusted value, before the truncation
 * marker is appended.
 *
 * 128 = the next power of two above 87, and 87 is the longest legitimate value
 * any call site in this codebase renders: the base64url encoding of a 65-byte
 * raw P-256 point with no padding (ceil(65 / 3) * 4 = 88 characters minus the
 * one '=' that base64url drops). Base64url SHA-256 digests (43) and identity
 * ids are shorter still, so no honest value is ever truncated and every
 * truncation is a signal that the field is not what it claims to be.
 */
export const MAX_UNTRUSTED_DIAGNOSTIC_CHARS = 128;

/**
 * Ceiling on nesting depth explored while rendering.
 *
 * 4 is small enough that the renderer's own recursion cannot overflow the
 * stack (that is the defect this module exists to prevent, so the renderer must
 * not reintroduce it) and deep enough to show the shape of an ordinary record.
 */
const MAX_UNTRUSTED_RENDER_DEPTH = 4;

/** Appended when the rendering was cut short. Never omitted when it applies. */
export const UNTRUSTED_TRUNCATION_MARKER = "...<truncated>";

/** Returned when the value could not be rendered at all. Code-chosen, never derived from the value. */
export const UNRENDERABLE_UNTRUSTED_VALUE = "<unrenderable value>";

/** Stands in for a nested value the renderer refused to descend into or read. */
const ELIDED = "...";
const CIRCULAR = "<circular>";
const UNREADABLE = "<unreadable>";

/**
 * Render a primitive exactly as a template literal would, or return `null` when
 * the value is not a primitive.
 *
 * `symbol` is special-cased because a template literal THROWS on it
 * (TypeError: Cannot convert a Symbol value to a string); rendering it as a
 * placeholder is what keeps this function total.
 */
function renderPrimitive(value: unknown): string | null {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return value;
    case "number":
    case "boolean":
    case "bigint":
      return String(value);
    case "undefined":
      return "undefined";
    case "symbol":
      return "<symbol>";
    case "function":
      return "<function>";
    default:
      return null;
  }
}

/** Work budget shared across one whole render, so total work is O(budget), not O(input). */
interface RenderBudget {
  remaining: number;
}

function quoteKeyOrString(text: string): string {
  // Nested strings are quoted so `{"kid":"1"}` is distinguishable from
  // `{"kid":1}`; the TOP-LEVEL string is deliberately NOT quoted, so an
  // ordinary diagnostic renders byte-identically to the template literal it
  // replaced.
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Depth- and budget-bounded structural rendering. Never calls `toString()` on a
 * non-primitive, so a hostile `toString` cannot run at all; a throwing getter or
 * proxy trap is caught per-child and rendered as {@link UNREADABLE}.
 */
function renderStructured(
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
  budget: RenderBudget
): string {
  if (budget.remaining <= 0) return ELIDED;

  const primitive = renderPrimitive(value);
  if (primitive !== null) {
    const rendered = typeof value === "string" ? quoteKeyOrString(primitive) : primitive;
    budget.remaining -= rendered.length;
    return rendered;
  }

  const container = value as object;
  // Every return below charges the budget, including the cheap ones: a million
  // sibling values that each render as a free constant would otherwise let an
  // attacker drive a million iterations for a 128-character result.
  if (seen.has(container)) {
    budget.remaining -= CIRCULAR.length;
    return CIRCULAR;
  }
  const isArray = Array.isArray(container);
  if (depth >= MAX_UNTRUSTED_RENDER_DEPTH) {
    const capped = isArray ? "[...]" : "{...}";
    budget.remaining -= capped.length;
    return capped;
  }

  seen.add(container);
  try {
    const parts: string[] = [];
    if (isArray) {
      const elements = container as unknown[];
      for (let i = 0; i < elements.length; i += 1) {
        if (budget.remaining <= 0) {
          parts.push(ELIDED);
          break;
        }
        parts.push(renderChild(() => elements[i], depth, seen, budget));
      }
      budget.remaining -= parts.length + 1;
      return `[${parts.join(",")}]`;
    }
    // `for...in` rather than Object.entries: enumeration stays lazy, so a
    // record with a million attacker-supplied keys does not materialize an
    // array of a million entries just to print a few of them.
    for (const propertyKey in container) {
      if (budget.remaining <= 0) {
        parts.push(ELIDED);
        break;
      }
      if (!Object.prototype.hasOwnProperty.call(container, propertyKey)) continue;
      const renderedKey = quoteKeyOrString(propertyKey);
      budget.remaining -= renderedKey.length;
      const renderedValue = renderChild(
        () => (container as Record<string, unknown>)[propertyKey],
        depth,
        seen,
        budget
      );
      parts.push(`${renderedKey}:${renderedValue}`);
    }
    budget.remaining -= parts.length + 1;
    return `{${parts.join(",")}}`;
  } finally {
    seen.delete(container);
  }
}

/** Read + render one child, converting any throw (getter, proxy trap) into a placeholder. */
function renderChild(
  read: () => unknown,
  depth: number,
  seen: WeakSet<object>,
  budget: RenderBudget
): string {
  try {
    return renderStructured(read(), depth + 1, seen, budget);
  } catch {
    budget.remaining -= UNREADABLE.length;
    return UNREADABLE;
  }
}

/**
 * Escape characters that would let an untrusted value forge structure in an
 * operator's terminal or log file: C0 controls (which include newline, carriage
 * return, and the ESC that starts an ANSI sequence), DEL, and the C1 range.
 *
 * This is an ALLOW-shaped rule over a closed, complete set of code UNITS - every
 * character in these ranges is a single UTF-16 unit, so scanning by unit misses
 * none of them. It deliberately does NOT touch printable non-ASCII, because
 * legitimate namespaces and keys may be non-Latin and mangling them would make
 * ordinary diagnostics worse.
 */
function escapeControlCharacters(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    // 0x20 = space, the first printable ASCII code point; 0x7f = DEL;
    // 0x80-0x9f = the C1 control range.
    if (unit < 0x20 || unit === 0x7f || (unit >= 0x80 && unit <= 0x9f)) {
      out += `\\x${unit.toString(16).padStart(2, "0")}`;
    } else {
      out += text[i];
    }
  }
  return out;
}

/**
 * Render an untrusted (stored, imported, or wire-supplied) value for inclusion
 * in a diagnostic string.
 *
 * Total: returns {@link UNRENDERABLE_UNTRUSTED_VALUE} rather than throwing, for
 * every possible input.
 * Bounded: the result is at most
 * `MAX_UNTRUSTED_DIAGNOSTIC_CHARS + UNTRUSTED_TRUNCATION_MARKER.length`.
 * Non-deceptive: a shortened result carries {@link UNTRUSTED_TRUNCATION_MARKER},
 * and control characters are escaped rather than emitted.
 *
 * An ordinary short primitive renders EXACTLY as `${value}` would, so replacing
 * a template interpolation with this call does not change any honest
 * diagnostic - only the dishonest ones.
 */
export function describeUntrusted(value: unknown): string {
  let rendered: string;
  // Both branches below assign this before it is read, and the catch returns
  // early, so there is no initializer to go stale.
  let shortened: boolean;
  try {
    const primitive = renderPrimitive(value);
    if (primitive !== null) {
      // Clamp BEFORE escaping: escaping a hundred-megabyte stored string to
      // find out it is too long is exactly the unbounded-work-per-request shape
      // the bound exists to prevent.
      rendered = clampRaw(primitive);
      shortened = rendered.length < primitive.length;
    } else {
      const budget: RenderBudget = { remaining: MAX_UNTRUSTED_DIAGNOSTIC_CHARS };
      rendered = renderStructured(value, 0, new WeakSet<object>(), budget);
      shortened = budget.remaining <= 0;
      const clamped = clampRaw(rendered);
      if (clamped.length < rendered.length) shortened = true;
      rendered = clamped;
    }
  } catch {
    // Reached on a stack overflow raised anywhere below, on a hostile proxy
    // that traps enumeration itself, or on any other failure. Failing to
    // DESCRIBE a value must never fail the operation's real diagnosis.
    return UNRENDERABLE_UNTRUSTED_VALUE;
  }

  let escaped: string;
  try {
    escaped = escapeControlCharacters(rendered);
  } catch {
    return UNRENDERABLE_UNTRUSTED_VALUE;
  }
  if (escaped.length > MAX_UNTRUSTED_DIAGNOSTIC_CHARS) {
    // Escaping expands at most 1 code unit to 4, so this second clamp only ever
    // trims an already-bounded string.
    escaped = escaped.slice(0, MAX_UNTRUSTED_DIAGNOSTIC_CHARS);
    shortened = true;
  }

  return shortened ? escaped + UNTRUSTED_TRUNCATION_MARKER : escaped;
}

/**
 * Cut to the length ceiling without leaving a lone surrogate behind. A half
 * code point is not a truthful rendering of what was stored.
 */
function clampRaw(text: string): string {
  if (text.length <= MAX_UNTRUSTED_DIAGNOSTIC_CHARS) return text;
  let cut = MAX_UNTRUSTED_DIAGNOSTIC_CHARS;
  const last = text.charCodeAt(cut - 1);
  // 0xd800-0xdbff = the UTF-16 high-surrogate range; a high surrogate at the
  // cut point has lost its low half.
  if (last >= 0xd800 && last <= 0xdbff) cut -= 1;
  return text.slice(0, cut);
}
