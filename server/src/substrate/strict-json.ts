/**
 * Plugin substrate — strict JSON parser for wire frames (design §3.1b).
 *
 * `JSON.parse` silently COLLAPSES duplicate object keys (last-wins), which is a
 * permit-bypass vector: a verdict `{"decision":"deny","decision":"no_objection",...}`
 * would parse to `no_objection` with no error (codex HIGH). It also accepts no extra
 * guarantees about depth or prototype keys. The wire profile therefore parses verdict
 * frames through THIS function, not bare `JSON.parse`:
 *
 *   - duplicate object keys → reject (json_duplicate_key)
 *   - __proto__/constructor/prototype keys → reject (json_prototype_key)
 *   - non-finite numbers are impossible in JSON text, but we still reject any literal
 *     that JSON allows yet we forbid (the grammar has no NaN/Infinity, so JSON.parse
 *     already rejects them; we add depth bounding)
 *   - max nesting depth → reject (json_too_deep)
 *
 * Implementation: a single pass over the text with a tiny tokenizer-driven recursive
 * descent. We do NOT delegate to JSON.parse for object construction because that is
 * exactly where duplicate keys are lost.
 */

import { reject } from "./errors.js";

const MAX_DEPTH = 32;

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

export function parseStrictJson(text: string): unknown {
  const parser = new StrictParser(text);
  const value = parser.parseValue(0);
  parser.skipWhitespace();
  if (!parser.atEnd()) {
    reject("frame_trailing_bytes", "trailing bytes after JSON value");
  }
  return value;
}

class StrictParser {
  private i = 0;
  constructor(private readonly s: string) {}

  atEnd(): boolean {
    return this.i >= this.s.length;
  }

  skipWhitespace(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i]!;
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else break;
    }
  }

  parseValue(depth: number): unknown {
    if (depth > MAX_DEPTH) reject("json_too_deep", `JSON nesting exceeds ${MAX_DEPTH}`);
    this.skipWhitespace();
    if (this.atEnd()) reject("json_too_deep", "unexpected end of JSON");
    const c = this.s[this.i]!;
    if (c === "{") return this.parseObject(depth);
    if (c === "[") return this.parseArray(depth);
    if (c === '"') return this.parseString();
    if (c === "-" || (c >= "0" && c <= "9")) return this.parseNumber();
    if (this.s.startsWith("true", this.i)) {
      this.i += 4;
      return true;
    }
    if (this.s.startsWith("false", this.i)) {
      this.i += 5;
      return false;
    }
    if (this.s.startsWith("null", this.i)) {
      this.i += 4;
      return null;
    }
    reject("frame_trailing_bytes", `unexpected token at position ${this.i}`);
  }

  private parseObject(depth: number): Record<string, unknown> {
    // null-proto so a "__proto__" own key cannot mutate the prototype.
    const obj: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    this.i++; // {
    this.skipWhitespace();
    if (this.s[this.i] === "}") {
      this.i++;
      return obj;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.s[this.i] !== '"') reject("frame_trailing_bytes", "expected string key in object");
      const key = this.parseString();
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        reject("json_prototype_key", `object contains a prototype-pollution key "${key}"`);
      }
      if (seen.has(key)) reject("json_duplicate_key", `duplicate object key "${key}"`);
      seen.add(key);
      this.skipWhitespace();
      if (this.s[this.i] !== ":") reject("frame_trailing_bytes", 'expected ":" in object');
      this.i++;
      const value = this.parseValue(depth + 1);
      obj[key] = value;
      this.skipWhitespace();
      const next = this.s[this.i];
      if (next === ",") {
        this.i++;
        continue;
      }
      if (next === "}") {
        this.i++;
        return obj;
      }
      reject("frame_trailing_bytes", 'expected "," or "}" in object');
    }
  }

  private parseArray(depth: number): unknown[] {
    const arr: unknown[] = [];
    this.i++; // [
    this.skipWhitespace();
    if (this.s[this.i] === "]") {
      this.i++;
      return arr;
    }
    for (;;) {
      const value = this.parseValue(depth + 1);
      arr.push(value);
      this.skipWhitespace();
      const next = this.s[this.i];
      if (next === ",") {
        this.i++;
        continue;
      }
      if (next === "]") {
        this.i++;
        return arr;
      }
      reject("frame_trailing_bytes", 'expected "," or "]" in array');
    }
  }

  private parseString(): string {
    // Delegate to JSON.parse for a single string literal: it correctly handles escapes
    // and Unicode and there is no duplicate-key hazard for a scalar.
    const start = this.i;
    this.i++; // opening quote
    while (this.i < this.s.length) {
      const c = this.s[this.i]!;
      if (c === "\\") {
        this.i += 2;
        continue;
      }
      if (c === '"') {
        this.i++;
        const lit = this.s.slice(start, this.i);
        try {
          return JSON.parse(lit) as string;
        } catch {
          reject("frame_trailing_bytes", "malformed string literal");
        }
      }
      this.i++;
    }
    reject("frame_trailing_bytes", "unterminated string literal");
  }

  private parseNumber(): number {
    // Enforce the EXACT JSON number grammar (RFC 8259) so non-JSON spellings like
    // "01", "1.", "+1", ".5" are rejected rather than coerced by Number() (codex MEDIUM).
    const start = this.i;

    // optional minus (no leading +)
    if (this.s[this.i] === "-") this.i++;

    // int: "0" OR [1-9][0-9]*  — no leading zeros
    if (this.s[this.i] === "0") {
      this.i++;
    } else if (this.s[this.i] !== undefined && this.s[this.i]! >= "1" && this.s[this.i]! <= "9") {
      this.i++;
      while (this.i < this.s.length && isDigit(this.s[this.i]!)) this.i++;
    } else {
      reject("frame_trailing_bytes", `malformed number literal at position ${start}`);
    }

    // optional fraction: "." digit+
    if (this.s[this.i] === ".") {
      this.i++;
      if (!(this.i < this.s.length && isDigit(this.s[this.i]!))) {
        reject("frame_trailing_bytes", `malformed number fraction at position ${start}`);
      }
      while (this.i < this.s.length && isDigit(this.s[this.i]!)) this.i++;
    }

    // optional exponent: [eE] [+-]? digit+
    if (this.s[this.i] === "e" || this.s[this.i] === "E") {
      this.i++;
      if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
      if (!(this.i < this.s.length && isDigit(this.s[this.i]!))) {
        reject("frame_trailing_bytes", `malformed number exponent at position ${start}`);
      }
      while (this.i < this.s.length && isDigit(this.s[this.i]!)) this.i++;
    }

    const lit = this.s.slice(start, this.i);
    const n = Number(lit);
    if (!Number.isFinite(n)) {
      reject("json_non_finite_number", `non-finite number literal "${lit}"`);
    }
    return n;
  }
}
