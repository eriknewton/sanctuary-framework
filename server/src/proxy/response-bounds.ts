import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { RESPONSE_LIMITS as L } from "./response-limits.js";

/** Bounded JSON traversal before serialization, copying, or schema parsing. */
export function responseJsonBytes(value: unknown, pretty = false): number {
  let bytes = 0;
  let nodes = 0;
  const seen = new Set<object>();
  const add = (amount: number): void => {
    bytes += amount;
    if (bytes > L.CONTENT_UTF8_BYTES) throw new Error("Response byte budget exceeded");
  };
  const string = (text: string): void => {
    add(2); // JSON quotation marks.
    for (const ch of text) {
      const cp = ch.codePointAt(0)!;
      // JSON escapes quotes, backslashes, controls and lone UTF-16 surrogates.
      add(ch === '"' || ch === "\\" || "\b\f\n\r\t".includes(ch) ? 2
        : cp < 0x20 || (cp >= 0xd800 && cp <= 0xdfff) ? 6 : Buffer.byteLength(ch));
    }
  };
  const walk = (node: unknown, depth: number): void => {
    if (++nodes > L.MAX_NODES || depth > L.MAX_DEPTH) throw new Error("Response traversal budget exceeded");
    if (typeof node === "string") { string(node); return; }
    if (node === null || typeof node === "boolean") { add(String(node).length); return; }
    if (typeof node === "number" && Number.isFinite(node)) { add(String(node).length); return; }
    if (!node || typeof node !== "object" || seen.has(node)) throw new Error("Invalid response JSON");
    const array = Array.isArray(node);
    if (!array && Object.getPrototypeOf(node) !== Object.prototype && Object.getPrototypeOf(node) !== null) {
      throw new Error("Invalid response object");
    }
    seen.add(node);
    add(2); // Container delimiters.
    let count = 0;
    for (const key in node) {
      if (!Object.hasOwn(node, key)) continue;
      if (++count > L.MAX_NODES) throw new Error("Response traversal budget exceeded");
      const descriptor = Object.getOwnPropertyDescriptor(node, key)!;
      if (!Object.hasOwn(descriptor, "value")) throw new Error("Invalid response accessor");
      if (count > 1) add(1); // Comma.
      if (pretty) add(1 + (depth + 1) * 2); // Newline and two-space JSON indentation.
      if (!array) { string(key); add(pretty ? 2 : 1); }
      walk(descriptor.value, depth + 1);
    }
    if (array && count !== node.length) throw new Error("Invalid sparse response");
    if (pretty && count > 0) add(1 + depth * 2);
    seen.delete(node);
  };
  walk(value, 0);
  return bytes;
}

export type CanonicalResponse = { content: Array<{ type: string; text?: string; [key: string]: unknown }> };
export type DeliveredResponse = { content: Array<{ type: "text"; text: string }> };

/** Validate the complete canonical envelope, including fields normalization drops. */
export function validateResponse(value: unknown): asserts value is CanonicalResponse {
  responseJsonBytes(value);
  const content = (value as CanonicalResponse)?.content;
  if (!Array.isArray(content) || content.length > L.MAX_BLOCKS) throw new Error("Invalid response blocks");
  // SDK shape validation alone is not a work bound: bounded traversal must run first.
  if (!CallToolResultSchema.safeParse(value).success) throw new Error("Invalid response shape");
}

/** Preserve proxy normalization; no downstream transformation may follow screening. */
export function normalizeScreenedResponse(result: CanonicalResponse): DeliveredResponse {
  const textContent = result.content.filter(c => c.type === "text").map(c => ({
    type: "text" as const,
    text: c.text!.length > L.NORMALIZE_BLOCK_UTF16
      ? c.text!.substring(0, L.NORMALIZE_BLOCK_UTF16) + "\n[response truncated]" : c.text!,
  }));
  let delivered: DeliveredResponse;
  if (textContent.length) {
    delivered = { content: textContent };
  } else {
    const wrapper = { upstream_response: result.content };
    responseJsonBytes(wrapper, true);
    // Must match toolResult in router.ts: the exact pretty JSON string is scanned and delivered once.
    delivered = { content: [{ type: "text", text: JSON.stringify(wrapper, null, 2) }] };
  }
  responseJsonBytes(delivered);
  if (delivered.content.reduce((n, c) => n + c.text.length, 0) > L.NORMALIZE_TOTAL_UTF16) {
    throw new Error("Response normalization budget exceeded");
  }
  return delivered;
}

/** Incremental allocation guard paired with LocalPrivacyEngine.rehydrateNode/rehydrateString. */
export function rehydrationBudget(assertLive: () => void, resolvePlaceholder: (placeholder: string) => string | null): import("../operational/privacy-core.js").RehydrationBudget {
  let bytes = 0;
  let lookups = 0;
  return {
    assertLive,
    resolvePlaceholder(placeholder) {
      assertLive();
      // Each replacement consumes work even when it expands to an empty string.
      if (++lookups > L.MAX_NODES) throw new Error("Response replacement budget exceeded");
      return resolvePlaceholder(placeholder);
    },
    stringBytes: value => responseJsonBytes(value) - 2, // Exclude JSON quotes for string pieces.
    addBytes(amount) {
      assertLive();
      bytes += amount;
      if (bytes > L.CONTENT_UTF8_BYTES) throw new Error("Response expansion budget exceeded");
    },
  };
}

/** Bounded request-owned bindings, discarded with the admitted request; never response history. */
export class RequestResponseBindings {
  private readonly values = new Map<string, string>();
  private bytes = 0;
  private complete = true;
  private captures = 0;
  constructor(private readonly assertLive: () => void) {}
  capture(placeholder: string, rawValue: string): void {
    try {
      this.assertLive();
      // Repeated values still consume capture work; unique-map size alone would not bound findings.
      if (++this.captures > L.MAX_NODES) throw new Error("Response capture budget exceeded");
      if (this.values.get(placeholder) === rawValue) return;
      if (this.values.has(placeholder)) throw new Error("Ambiguous response binding");
      const bytes = responseJsonBytes(placeholder) + responseJsonBytes(rawValue);
      if (this.bytes + bytes > L.CONTENT_UTF8_BYTES) {
        throw new Error("Response binding budget exceeded");
      }
      this.bytes += bytes;
      this.values.set(placeholder, rawValue);
    } catch (error) { this.complete = false; throw error; }
  }
  assertComplete(): void {
    // An outbound policy override cannot turn a failed capture into proof of complete response work.
    if (!this.complete) throw new Error("Response binding budget unproven");
  }
  resolve(placeholder: string): string | null {
    this.assertComplete();
    // Must match the response-only resolver in operational/privacy-core.ts; unknown labels stay unresolved.
    return this.values.get(placeholder) ?? null;
  }
}
