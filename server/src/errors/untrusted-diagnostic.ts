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
 *   bounded (see WORK BOUND below), and non-deceptive (a value that was
 *   shortened SAYS it was shortened, control characters are escaped so a value
 *   cannot forge extra log lines in an operator's terminal, and the result is
 *   always well-formed UTF-16).
 *
 * WORK BOUND (state it exactly; an overstated bound is the same defect one
 * level up, and this block has been wrong twice):
 *
 *   OUTPUT length is strictly bounded, always, at
 *   MAX_UNTRUSTED_DIAGNOSTIC_CHARS + UNTRUSTED_TRUNCATION_MARKER.length.
 *
 *   WORK is bounded by the render budget for: string and property-key CONTENT
 *   (every stage clamps before it transforms), array elements, nesting depth,
 *   and bulk containers, which are described by their element count rather than
 *   walked.
 *
 * ACCESSOR GUARANTEE (stated at exactly its width; the wider version of this
 * sentence was here and was false):
 *
 *   FOR AN ORDINARY OBJECT, no caller-supplied accessor runs. Properties are
 *   read through `getOwnPropertyDescriptor` instead of being read, so a getter
 *   or setter is REPORTED and never called; a bulk container's count comes from
 *   the built-in getter taken off the prototype, which bypasses any own shadow;
 *   and the container's own name is never read, because `Symbol.toStringTag`
 *   would be caller code, so bulk labels are code-chosen and generic. Engine
 *   getters ARE invoked, deliberately; they are constant-time and not caller
 *   code.
 *
 *   FOR A HOSTILE PROXY THE GUARANTEE IS WEAKER, and the weakening is
 *   structural rather than a rounding error: a Proxy's traps ARE caller code,
 *   and reaching a Proxy's shape at all means running them. Two paths run
 *   caller code that this module cannot route around; both were observed by
 *   probe, not reasoned about:
 *
 *     - `getPrototypeOf` runs, because the `instanceof` checks that recognise a
 *       bulk container consult the prototype chain (measured: 4 invocations on
 *       one render of a trapping Proxy).
 *     - A `getOwnPropertyDescriptor` trap may return a descriptor OBJECT whose
 *       own `enumerable`, `value`, `get`, or `set` field is itself a getter,
 *       and the engine invokes those fields while converting the returned
 *       object into a property descriptor (measured: 3 invocations on the same
 *       render). The accessor that runs belongs to the descriptor the trap
 *       fabricated, not to the property being described, so the SUBJECT's own
 *       getter is still never called; caller code still ran.
 *
 *   So the honest form is: this module never READS a property in a way that
 *   runs the subject's own accessor, and for an ordinary object that means no
 *   caller code runs at all. It is not, and cannot be, a guarantee that no
 *   caller code runs when the caller supplied a Proxy.
 *
 *   WORK IS NOT BOUNDED for the three costs below. They are named because they
 *   are real, not because they are acceptable everywhere; a caller putting a
 *   value of unbounded WIDTH into a diagnostic still pays for it.
 *
 *     1. Enumerating a plain object's own keys is O(number of own keys) inside
 *        the engine, BEFORE any per-key work this function does. Measured on a
 *        1e6-key object: `for...in` that breaks on the first iteration costs
 *        ~112ms, the same as `Object.keys(...).length` (~111ms);
 *        `getOwnPropertyNames` and `Reflect.ownKeys` cost about twice that.
 *        No JavaScript API returns a bounded slice of an arbitrary object's
 *        keys, so this floor cannot be removed from here. What IS bounded is
 *        the work added ON TOP of that floor, and the test that asserts it is
 *        narrower than that sentence sounds: it counts this module's own
 *        property reads through a counting Proxy, which is the only vantage a
 *        test has, and shows they do not grow with the key count. The engine
 *        floor itself is not observable from there and is not measured. An
 *        earlier version of this test TIMED the render against the floor; it
 *        could false-pass and false-fail, and it is gone rather than tuned.
 *     2. A hostile Proxy runs its own `getPrototypeOf`, `ownKeys`,
 *        `getOwnPropertyDescriptor`, and `get` traps, plus any accessor the
 *        `getOwnPropertyDescriptor` trap plants on the descriptor it returns
 *        (see the ACCESSOR GUARANTEE above; the list is what a probe observed,
 *        so treat it as the traps this module is KNOWN to reach, not as a
 *        proof that no other trap can be). All of it is attacker code and can
 *        do arbitrary work before this function regains control. The budget
 *        stops the iteration; it cannot bound one trap.
 *     3. Rendering a BigInt compares it against a precomputed ceiling, which
 *        reads the value's existing binary representation. Cheap per digit, no
 *        allocation and no decimal conversion, but not constant.
 *
 * NOT A REDACTOR. This does not decide what is safe to disclose; that judgment
 * belongs to the caller and, for the evidence pack, to
 * `evidence-pack/read-outcome.ts`'s `sanitizeReason`, which is a DIFFERENT
 * concern (scrubbing operator paths out of a signed document).
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

/**
 * Stands in for a BigInt whose decimal form cannot fit the length bound.
 * Code-chosen and self-describing: nothing derived from the value appears in
 * it, and it does not pretend to be a number.
 */
export const OVERSIZED_BIGINT = "<bigint exceeds the diagnostic length bound>";

/**
 * Stands in for a property defined by a getter or setter. Code-chosen: that
 * property's own accessor is NEVER invoked, so nothing derived from running it
 * appears here. A Proxy can still run its own traps, and a descriptor its trap
 * fabricates can carry an accessor the engine invokes; neither produces this
 * string's content. See the ACCESSOR GUARANTEE in the file header.
 */
export const ACCESSOR_PLACEHOLDER = "<accessor>";

/**
 * A BigInt at or beyond this magnitude needs more than the bound's worth of
 * decimal digits, so it can never render in full and must not be converted.
 * 10 ** MAX = the smallest value with MAX + 1 decimal digits.
 */
const BIGINT_RENDER_CEILING = 10n ** BigInt(MAX_UNTRUSTED_DIAGNOSTIC_CHARS);

// The UTF-16 surrogate ranges, named once so no call site open-codes them.
// D800-DBFF is the high (leading) half, DC00-DFFF the low (trailing) half.
const HIGH_SURROGATE_FIRST = 0xd800;
const HIGH_SURROGATE_LAST = 0xdbff;
const LOW_SURROGATE_FIRST = 0xdc00;
const LOW_SURROGATE_LAST = 0xdfff;

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
      // Clamped BEFORE it is handed on: every later stage transforms what it
      // is given, so an unclamped string here is the one place a caller's size
      // could become this function's work (see the WORK BOUND note above).
      return clampAtCodePoint(value, MAX_UNTRUSTED_DIAGNOSTIC_CHARS);
    case "number":
    case "boolean":
      // A double's decimal form is at most ~24 characters and a boolean is at
      // most 5, so neither can exceed the bound or cost input-dependent work.
      return String(value);
    case "bigint":
      return renderBigInt(value);
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

/**
 * A BigInt has no length bound, and `String(bigint)` builds the WHOLE decimal
 * representation before anything can clamp it. That conversion is superlinear
 * (measured: a one-million-digit value took ~100ms to render a 142-character
 * result), so it must not run on a value that cannot fit the bound anyway.
 *
 * Comparing against a precomputed power of ten decides that without converting
 * or allocating: it reads the value's existing binary representation and stops.
 */
function renderBigInt(value: bigint): string {
  if (value > BIGINT_RENDER_CEILING || value < -BIGINT_RENDER_CEILING) {
    return OVERSIZED_BIGINT;
  }
  return String(value);
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
  //
  // CLAMP FIRST. The two replacements below each scan their whole input, so
  // running them on a twenty-megabyte nested string or property KEY costs work
  // and allocation proportional to the attacker's value for a result that is
  // then thrown away at the bound. Nothing downstream needs more than the
  // bound's worth of characters, so nothing upstream should produce more.
  const clamped = clampAtCodePoint(text, MAX_UNTRUSTED_DIAGNOSTIC_CHARS);
  return `"${clamped.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
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

  // BULK CONTAINERS ARE DESCRIBED, NOT WALKED. A typed array, buffer, Map, or
  // Set carries its element count as a property, so a million-element value can
  // be described in constant time. Iterating it instead makes the cost scale
  // with the caller's data for a result the length bound throws away anyway
  // (measured: a 1e6-element Uint8Array cost ~11ms to render ~128 characters).
  const bulk = describeBulkContainer(container);
  if (bulk !== null) {
    budget.remaining -= bulk.length;
    return bulk;
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
        parts.push(renderOwnProperty(container, String(i), depth, seen, budget));
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
      // Charge before the own-property filter: `for...in` walks the prototype
      // chain, so an inherited key that renders nothing must still consume
      // budget, or a long chain of them buys unbounded iterations for free.
      budget.remaining -= 1;
      if (!Object.prototype.hasOwnProperty.call(container, propertyKey)) continue;
      const renderedKey = quoteKeyOrString(propertyKey);
      budget.remaining -= renderedKey.length;
      const renderedValue = renderOwnProperty(
        container,
        propertyKey,
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

/**
 * Describe a container that carries its own element count, in constant time.
 * Returns null when `container` is not one of these and must be walked.
 *
 * NO TAG IS READ OFF THE VALUE. An earlier revision labelled the container from
 * `Object.prototype.toString` and that path was deliberately removed, because
 * it reads `Symbol.toStringTag` and so runs caller code (see the note on the
 * captured getters below). Recognition is by internal checks a caller cannot
 * forge, and every label here is a code-chosen literal.
 */
function describeBulkContainer(container: object): string | null {
  try {
    // `ArrayBuffer.isView` and `instanceof` are internal checks a caller cannot
    // forge. The COUNT is then read through the built-in getter taken off the
    // prototype, NOT off the instance: a caller can shadow `length`, `size`, or
    // `byteLength` with its own accessor, and reading the property normally
    // would invoke that accessor. `.call(container)` on the built-in bypasses
    // any own shadow and runs engine code rather than caller code.
    if (ArrayBuffer.isView(container)) {
      const count = TYPED_ARRAY_LENGTH_GETTER
        ? TYPED_ARRAY_LENGTH_GETTER.call(container)
        : undefined;
      // A DataView has no `length`; fall back to its byteLength getter.
      if (typeof count === "number") return `<typed-array length=${count}>`;
      const byteLength = DATA_VIEW_BYTE_LENGTH_GETTER?.call(container);
      if (typeof byteLength === "number") return `<data-view byteLength=${byteLength}>`;
      return null;
    }
    if (container instanceof ArrayBuffer) {
      const byteLength = ARRAY_BUFFER_BYTE_LENGTH_GETTER?.call(container);
      if (typeof byteLength === "number") return `<ArrayBuffer byteLength=${byteLength}>`;
      return null;
    }
    if (container instanceof Map) {
      const size = MAP_SIZE_GETTER?.call(container);
      if (typeof size === "number") return `<Map size=${size}>`;
      return null;
    }
    if (container instanceof Set) {
      const size = SET_SIZE_GETTER?.call(container);
      if (typeof size === "number") return `<Set size=${size}>`;
      return null;
    }
  } catch {
    // A built-in getter throws when applied to a forged receiver (a plain
    // object with a spoofed prototype). Such a value is simply walked instead.
    return null;
  }
  return null;
}

// Built-in count getters, captured once at module load so a later mutation of a
// prototype cannot redirect them. Deliberately NOT `Object.prototype.toString`:
// that reads `Symbol.toStringTag`, which is a caller-supplied accessor, so the
// container's own NAME cannot be trusted. The labels above are code-chosen and
// generic for that reason - `<typed-array>` rather than the element type.
function protoGetter(proto: object | null, key: string): (() => unknown) | undefined {
  if (proto === null) return undefined;
  return Object.getOwnPropertyDescriptor(proto, key)?.get;
}
const TYPED_ARRAY_LENGTH_GETTER = protoGetter(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  "length"
);
const DATA_VIEW_BYTE_LENGTH_GETTER = protoGetter(DataView.prototype, "byteLength");
const ARRAY_BUFFER_BYTE_LENGTH_GETTER = protoGetter(ArrayBuffer.prototype, "byteLength");
const MAP_SIZE_GETTER = protoGetter(Map.prototype, "size");
const SET_SIZE_GETTER = protoGetter(Set.prototype, "size");

/**
 * Render one OWN property without invoking an accessor.
 *
 * WHY A DESCRIPTOR AND NOT A READ: a plain `container[key]` runs a getter, and
 * a getter is attacker-supplied code that can burn arbitrary time, mutate
 * state, or throw. Building a diagnostic must never execute the subject it is
 * describing (measured before this change: a 30ms getter cost the render 30ms,
 * and it ran). `getOwnPropertyDescriptor` reports the accessor without calling
 * it. On a Proxy this still runs that trap, which stays a named cost, and a
 * trap may return a descriptor object whose own fields are getters that the
 * engine then invokes: see the ACCESSOR GUARANTEE in the file header for what
 * survives in that case and what does not.
 */
function renderOwnProperty(
  container: object,
  propertyKey: string,
  depth: number,
  seen: WeakSet<object>,
  budget: RenderBudget
): string {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(container, propertyKey);
  } catch {
    budget.remaining -= UNREADABLE.length;
    return UNREADABLE;
  }
  if (descriptor === undefined) {
    budget.remaining -= UNREADABLE.length;
    return UNREADABLE;
  }
  if (descriptor.get !== undefined || descriptor.set !== undefined) {
    budget.remaining -= ACCESSOR_PLACEHOLDER.length;
    return ACCESSOR_PLACEHOLDER;
  }
  return renderChild(() => descriptor.value, depth, seen, budget);
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
 * Escape anything that would let an untrusted value forge structure in an
 * operator's terminal or log file, or leave the result malformed:
 *
 *   - C0 controls (which include newline, carriage return, and the ESC that
 *     starts an ANSI sequence), DEL, and the C1 range;
 *   - LONE surrogates, i.e. a high surrogate with no low half after it or a low
 *     surrogate with no high half before it. These are not characters; emitting
 *     one produces a string that is not well-formed UTF-16, which downstream
 *     encoders silently replace with U+FFFD and which makes a later clamp
 *     unable to tell a boundary from a break.
 *
 * These are ALLOW-shaped rules over closed, complete ranges of code UNITS, so
 * scanning by unit misses none of them. Printable non-ASCII is deliberately
 * untouched: legitimate namespaces and keys may be non-Latin and mangling them
 * would make ordinary diagnostics worse.
 *
 * POSTCONDITION relied on by {@link clampAtCodePoint}: every surrogate left in
 * the result belongs to a complete pair, so backing a cut off a high surrogate
 * is sufficient to keep the output well-formed.
 */
function escapeForDiagnostic(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    // 0x20 = space, the first printable ASCII code point; 0x7f = DEL;
    // 0x80-0x9f = the C1 control range.
    if (unit < 0x20 || unit === 0x7f || (unit >= 0x80 && unit <= 0x9f)) {
      out += `\\x${unit.toString(16).padStart(2, "0")}`;
      continue;
    }
    if (unit >= HIGH_SURROGATE_FIRST && unit <= HIGH_SURROGATE_LAST) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : -1;
      if (next >= LOW_SURROGATE_FIRST && next <= LOW_SURROGATE_LAST) {
        // A complete pair: emit both units untouched and skip the low half.
        out += text[i]! + text[i + 1]!;
        i += 1;
        continue;
      }
      out += escapedSurrogate(unit);
      continue;
    }
    if (unit >= LOW_SURROGATE_FIRST && unit <= LOW_SURROGATE_LAST) {
      // Reached only when no high surrogate preceded it, because a complete
      // pair consumes its low half above.
      out += escapedSurrogate(unit);
      continue;
    }
    out += text[i];
  }
  return out;
}

function escapedSurrogate(unit: number): string {
  // 4 = the number of hex digits in a UTF-16 code unit (16 bits / 4 bits each).
  return `\\u${unit.toString(16).padStart(4, "0")}`;
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
 * A short string, number, boolean, null, or undefined renders EXACTLY as
 * `${value}` would, so replacing a template interpolation with this call does
 * not change any honest diagnostic - only the dishonest ones. The two
 * deliberate exceptions are the ones where `${value}` is not a rendering at
 * all: a symbol, where a template literal THROWS, and a BigInt too long for the
 * bound; both yield a code-chosen placeholder instead.
 */
export function describeUntrusted(value: unknown): string {
  let rendered: string;
  // Both branches below assign this before it is read, and the catch returns
  // early, so there is no initializer to go stale.
  let shortened: boolean;
  try {
    const primitive = renderPrimitive(value);
    if (primitive !== null) {
      // Already clamped inside `renderPrimitive`, which is where the clamp has
      // to happen: it is the only place that still holds the caller's value.
      rendered = primitive;
      shortened = typeof value === "string" && rendered.length < value.length;
    } else {
      const budget: RenderBudget = { remaining: MAX_UNTRUSTED_DIAGNOSTIC_CHARS };
      rendered = renderStructured(value, 0, new WeakSet<object>(), budget);
      shortened = budget.remaining <= 0;
      const clamped = clampAtCodePoint(rendered, MAX_UNTRUSTED_DIAGNOSTIC_CHARS);
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
    // `rendered` is at most the bound in length by construction, so this scan
    // is bounded no matter how large the caller's value was.
    escaped = escapeForDiagnostic(rendered);
  } catch {
    return UNRENDERABLE_UNTRUSTED_VALUE;
  }
  if (escaped.length > MAX_UNTRUSTED_DIAGNOSTIC_CHARS) {
    // Escaping expands at most 1 code unit to 6, so this second clamp only ever
    // trims an already-bounded string. It must be the CODE-POINT-aware clamp:
    // a raw slice here cut a surrogate pair in half, because escaping shifts
    // every later character by an amount the first clamp could not know.
    escaped = clampAtCodePoint(escaped, MAX_UNTRUSTED_DIAGNOSTIC_CHARS);
    shortened = true;
  }

  return shortened ? escaped + UNTRUSTED_TRUNCATION_MARKER : escaped;
}

/**
 * Cut to `max` code units without splitting a surrogate pair. A half code point
 * is not a truthful rendering of what was stored, and it leaves the result
 * malformed UTF-16.
 *
 * Backing off by one is sufficient because the only surrogates this is ever
 * asked to cut are complete pairs: raw input is clamped before any lone
 * surrogate could be introduced, and {@link escapeForDiagnostic} escapes lone
 * surrogates outright (see its POSTCONDITION).
 */
function clampAtCodePoint(text: string, max: number): string {
  if (text.length <= max) return text;
  let cut = max;
  const last = text.charCodeAt(cut - 1);
  // A high surrogate at the last kept position has lost its low half.
  if (last >= HIGH_SURROGATE_FIRST && last <= HIGH_SURROGATE_LAST) cut -= 1;
  return text.slice(0, cut);
}
