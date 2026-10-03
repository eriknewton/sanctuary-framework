/** Canonical, normalized and expanded response representations stay bounded. */
import { describe, expect, it } from "vitest";
import { responseJsonBytes, validateResponse, normalizeScreenedResponse, rehydrationBudget, RequestResponseBindings } from "../../src/proxy/response-bounds.js";
import { RESPONSE_LIMITS as L } from "../../src/proxy/response-limits.js";

const text = (s: string) => ({ content: [{ type: "text", text: s }] });
describe("bounded response representations", () => {
  it.each(["hello", "😀é\n\u0000\ud800\\\"", { content: [{ type: "text", text: "💙" }] }, [true, false, null, 12]])("counts exact JSON bytes and escapes: %j", value => {
    expect(responseJsonBytes(value)).toBe(Buffer.byteLength(JSON.stringify(value)));
    expect(responseJsonBytes(value, true)).toBe(Buffer.byteLength(JSON.stringify(value, null, 2)));
  });
  it("accepts the byte cap and refuses cap plus one before serialization", () => {
    expect(responseJsonBytes(" ".repeat(L.CONTENT_UTF8_BYTES - 2))).toBe(L.CONTENT_UTF8_BYTES);
    expect(() => responseJsonBytes(" ".repeat(L.CONTENT_UTF8_BYTES - 1))).toThrow();
  });
  it("bounds multibyte and astral strings by encoded size", () => {
    expect(() => validateResponse(text("😀".repeat(L.CONTENT_UTF8_BYTES / 4)))).toThrow();
    expect(() => validateResponse(text("é".repeat(L.CONTENT_UTF8_BYTES / 2)))).toThrow();
  });
  it("bounds depth at cap and cap plus one", () => {
    let value: unknown = null;
    for (let n = 0; n < L.MAX_DEPTH; n++) value = [value];
    expect(() => responseJsonBytes(value)).not.toThrow();
    expect(() => responseJsonBytes([value])).toThrow();
  });
  it("bounds node count at cap and cap plus one", () => {
    expect(() => responseJsonBytes(Array(L.MAX_NODES - 1).fill(null))).not.toThrow();
    expect(() => responseJsonBytes(Array(L.MAX_NODES).fill(null))).toThrow();
  });
  it("bounds block count before schema copying", () => {
    expect(() => validateResponse({ content: Array(L.MAX_BLOCKS).fill({ type: "text", text: "" }) })).not.toThrow();
    expect(() => validateResponse({ content: Array(L.MAX_BLOCKS + 1).fill({ type: "text", text: "" }) })).toThrow();
  });
  it.each([null, { content: [null] }, { content: [{ type: "unknown" }] }, { content: [{ type: "text", text: 3 }] }])("refuses malformed elements: %j", value => {
    expect(() => validateResponse(value)).toThrow();
  });
  it("rejects non-JSON object prototypes", () => {
    expect(() => responseJsonBytes(new Date())).toThrow();
  });
  it("rejects accessors, cycles and sparse arrays without executing accessors", () => {
    let called = false;
    expect(() => responseJsonBytes({ get x() { called = true; return "x"; } })).toThrow();
    expect(called).toBe(false);
    const cycle: unknown[] = []; cycle.push(cycle);
    expect(() => responseJsonBytes(cycle)).toThrow();
    expect(() => responseJsonBytes(Array(3))).toThrow();
  });
  it("preserves block truncation suffixes and drops schema-valid extra fields", () => {
    const value = { content: [{ type: "text", text: " ".repeat(L.NORMALIZE_BLOCK_UTF16 + 1), annotations: { audience: ["assistant"] }, _meta: { extra: "discard" } }, { type: "image", data: "AA==", mimeType: "image/png" }], structuredContent: { extra: "discard" } };
    validateResponse(value);
    expect(normalizeScreenedResponse(value)).toEqual(text(" ".repeat(L.NORMALIZE_BLOCK_UTF16) + "\n[response truncated]"));
  });
  it("serializes JSON-only content exactly once with the delivered escapes", () => {
    const value = { content: [{ type: "resource", resource: { uri: "file:///fixture", text: "\n\\\"😀" } }] };
    validateResponse(value);
    expect(normalizeScreenedResponse(value)).toEqual(text(JSON.stringify({ upstream_response: value.content }, null, 2)));
  });
  it("bounds expanded pieces before retaining them", () => {
    const budget = rehydrationBudget(() => {}, () => null);
    budget.addBytes(L.CONTENT_UTF8_BYTES);
    expect(() => budget.addBytes(1)).toThrow();
  });
  it("caps replacement work even when resolved values are empty", () => {
    const budget = rehydrationBudget(() => {}, () => "");
    for (let n = 0; n < L.MAX_NODES; n++) expect(budget.resolvePlaceholder("EMAIL_1")).toBe("");
    expect(() => budget.resolvePlaceholder("EMAIL_1")).toThrow();
  });
  it("caps current-request binding count and fails sticky after overflow", () => {
    const bindings = new RequestResponseBindings(() => {});
    for (let n = 0; n < L.MAX_NODES; n++) bindings.capture(`LABEL_${n}`, "x");
    expect(() => bindings.capture("extra", "x")).toThrow();
    expect(() => bindings.assertComplete()).toThrow();
  });
  it("caps captured value bytes before retention", () => {
    const bindings = new RequestResponseBindings(() => {});
    const piece = " ".repeat(L.CONTENT_UTF8_BYTES / 2);
    bindings.capture("EMAIL_1", piece);
    expect(() => bindings.capture("EMAIL_2", piece)).toThrow();
    expect(() => bindings.assertComplete()).toThrow();
  });
  it("rejects ambiguous bindings and never resolves unknown labels", () => {
    const bindings = new RequestResponseBindings(() => {});
    bindings.capture("EMAIL_1", "first"); bindings.capture("EMAIL_1", "first");
    expect(bindings.resolve("EMAIL_1")).toBe("first"); expect(bindings.resolve("EMAIL_2")).toBeNull();
    expect(() => bindings.capture("EMAIL_1", "second")).toThrow();
  });

});
