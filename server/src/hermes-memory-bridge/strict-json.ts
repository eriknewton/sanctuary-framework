import { MAX_JSON_NESTING_DEPTH } from "./constants.js";

export type StrictJsonErrorCode =
  | "invalid_json"
  | "invalid_utf8"
  | "top_level_not_object"
  | "duplicate_key"
  | "depth_exceeded"
  | "unsafe_number";

export class StrictJsonError extends Error {
  constructor(
    readonly code: StrictJsonErrorCode,
    message: string = code,
  ) {
    super(message);
    this.name = "StrictJsonError";
  }
}

export function parseStrictJson(bytes: Uint8Array, maxDepth = MAX_JSON_NESTING_DEPTH): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new StrictJsonError("invalid_utf8");
  }
  const parser = new StrictJsonParser(text, maxDepth);
  return parser.parse();
}

export function parseStrictJsonObject(
  bytes: Uint8Array,
  maxDepth = MAX_JSON_NESTING_DEPTH,
): Record<string, unknown> {
  const value = parseStrictJson(bytes, maxDepth);
  if (!isRecord(value)) {
    throw new StrictJsonError("top_level_not_object");
  }
  return value;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class StrictJsonParser {
  private index = 0;

  constructor(
    private readonly text: string,
    private readonly maxDepth: number,
  ) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(1);
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      throw new StrictJsonError("invalid_json");
    }
    return value;
  }

  private parseValue(depth: number): unknown {
    this.assertDepth(depth);
    const ch = this.peek();
    if (ch === "{") return this.parseObject(depth);
    if (ch === "[") return this.parseArray(depth);
    if (ch === "\"") return this.parseString();
    if (ch === "t") return this.consumeLiteral("true", true);
    if (ch === "f") return this.consumeLiteral("false", false);
    if (ch === "n") return this.consumeLiteral("null", null);
    if (ch === "-" || this.isDigit(ch)) return this.parseNumber();
    throw new StrictJsonError("invalid_json");
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.assertDepth(depth);
    this.consume("{");
    this.skipWhitespace();
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    const keys = new Set<string>();
    if (this.tryConsume("}")) return result;
    while (true) {
      this.skipWhitespace();
      if (this.peek() !== "\"") throw new StrictJsonError("invalid_json");
      const key = this.parseString();
      // The decoded key is the parser agreement point, so escaped and literal spellings cannot create two meanings.
      if (keys.has(key)) throw new StrictJsonError("duplicate_key", "duplicate object key");
      keys.add(key);
      this.skipWhitespace();
      this.consume(":");
      this.skipWhitespace();
      Object.defineProperty(result, key, {
        value: this.parseValue(depth + 1),
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.skipWhitespace();
      if (this.tryConsume("}")) return result;
      this.consume(",");
    }
  }

  private parseArray(depth: number): unknown[] {
    this.assertDepth(depth);
    this.consume("[");
    this.skipWhitespace();
    const result: unknown[] = [];
    if (this.tryConsume("]")) return result;
    while (true) {
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.tryConsume("]")) return result;
      this.consume(",");
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    this.consume("\"");
    let out = "";
    while (this.index < this.text.length) {
      const ch = this.text[this.index]!;
      this.index += 1;
      if (ch === "\"") return out;
      if (ch < " ") throw new StrictJsonError("invalid_json");
      if (ch !== "\\") {
        out += ch;
        continue;
      }
      const esc = this.text[this.index];
      this.index += 1;
      if (esc === "\"" || esc === "\\" || esc === "/") out += esc;
      else if (esc === "b") out += "\b";
      else if (esc === "f") out += "\f";
      else if (esc === "n") out += "\n";
      else if (esc === "r") out += "\r";
      else if (esc === "t") out += "\t";
      else if (esc === "u") out += this.parseEscapedCodePoint();
      else throw new StrictJsonError("invalid_json");
    }
    throw new StrictJsonError("invalid_json");
  }

  private parseEscapedCodePoint(): string {
    const high = this.readHexCodeUnit();
    if (high >= 0xD800 && high <= 0xDBFF) {
      if (this.text[this.index] !== "\\" || this.text[this.index + 1] !== "u") {
        throw new StrictJsonError("invalid_json", "lone surrogate");
      }
      this.index += 2;
      const low = this.readHexCodeUnit();
      if (low < 0xDC00 || low > 0xDFFF) {
        throw new StrictJsonError("invalid_json", "lone surrogate");
      }
      return String.fromCodePoint(
        0x10000 + ((high - 0xD800) * 0x400) + (low - 0xDC00),
      );
    }
    if (high >= 0xDC00 && high <= 0xDFFF) {
      throw new StrictJsonError("invalid_json", "lone surrogate");
    }
    return String.fromCharCode(high);
  }

  private readHexCodeUnit(): number {
    const raw = this.text.slice(this.index, this.index + 4);
    if (!/^[0-9a-fA-F]{4}$/u.test(raw)) throw new StrictJsonError("invalid_json");
    this.index += 4;
    return Number.parseInt(raw, 16);
  }

  private parseNumber(): number {
    const start = this.index;
    this.tryConsume("-");
    if (this.peek() === "0") {
      this.index += 1;
    } else {
      if (!this.isDigitOneToNine(this.peek())) throw new StrictJsonError("invalid_json");
      while (this.isDigit(this.peek())) this.index += 1;
    }
    if (this.tryConsume(".")) {
      if (!this.isDigit(this.peek())) throw new StrictJsonError("invalid_json");
      while (this.isDigit(this.peek())) this.index += 1;
    }
    const exp = this.peek();
    if (exp === "e" || exp === "E") {
      this.index += 1;
      const sign = this.peek();
      if (sign === "+" || sign === "-") this.index += 1;
      if (!this.isDigit(this.peek())) throw new StrictJsonError("invalid_json");
      while (this.isDigit(this.peek())) this.index += 1;
    }
    const parsed = Number(this.text.slice(start, this.index));
    if (!Number.isFinite(parsed) || Math.abs(parsed) > Number.MAX_SAFE_INTEGER) {
      throw new StrictJsonError("unsafe_number", "number outside safe range");
    }
    return parsed;
  }

  private consumeLiteral<T>(literal: string, value: T): T {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) {
      throw new StrictJsonError("invalid_json");
    }
    this.index += literal.length;
    return value;
  }

  private skipWhitespace(): void {
    while (/[\t\n\r ]/u.test(this.peek())) this.index += 1;
  }

  private consume(expected: string): void {
    if (!this.tryConsume(expected)) throw new StrictJsonError("invalid_json");
  }

  private tryConsume(expected: string): boolean {
    if (this.text[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  private peek(): string {
    return this.text[this.index] ?? "";
  }

  private isDigit(ch: string): boolean {
    return ch >= "0" && ch <= "9";
  }

  private isDigitOneToNine(ch: string): boolean {
    return ch >= "1" && ch <= "9";
  }

  private assertDepth(depth: number): void {
    // The top-level frame object plus one arguments object leaves exactly 63 nested arrays inside the seam bound.
    if (depth > this.maxDepth + 2) throw new StrictJsonError("depth_exceeded", "JSON nesting exceeds bound");
  }
}
