/**
 * Canonical JSON unit tests (full-sweep #42 regression).
 *
 * The cross-language parity test at server/test/integration/canonical-json-parity.test.ts
 * covers TS<->Python byte equality for valid JSON values. This file covers the
 * rejection rules: top-level undefined, undefined-in-array, NaN/Infinity, and
 * confirms the object-undefined-omit behavior the array fix must not regress.
 */

import { describe, it, expect } from "vitest";
import {
  canonicalize,
  MeshCanonicalJsonError,
} from "../../src/mesh/canonical-json.js";

describe("canonicalize: rejection rules", () => {
  it("rejects top-level undefined", () => {
    expect(() => canonicalize(undefined)).toThrow(MeshCanonicalJsonError);
    expect(() => canonicalize(undefined)).toThrow(/top-level undefined/);
  });

  it("rejects undefined inside arrays per RFC 8785 (full-sweep #42)", () => {
    // The bug: prior implementation silently coerced [undefined] -> "[null]",
    // so a producer-side mistake produced a signed envelope whose receiver
    // could not reproduce the canonical bytes from the original JS object.
    expect(() => canonicalize([undefined])).toThrow(MeshCanonicalJsonError);
    expect(() => canonicalize([undefined])).toThrow(/array index 0/);
  });

  it("reports the correct array index for undefined", () => {
    expect(() => canonicalize([1, 2, undefined, 4])).toThrow(/array index 2/);
    expect(() => canonicalize([undefined, 1])).toThrow(/array index 0/);
  });

  it("rejects undefined nested inside an object's array value", () => {
    expect(() => canonicalize({ list: [undefined] })).toThrow(/array index 0/);
    expect(() =>
      canonicalize({ outer: { inner: [1, undefined] } })
    ).toThrow(/array index 1/);
  });

  it("rejects non-finite numbers (regression, pre-existing)", () => {
    expect(() => canonicalize(NaN)).toThrow(/non-finite/);
    expect(() => canonicalize(Infinity)).toThrow(/non-finite/);
    expect(() => canonicalize(-Infinity)).toThrow(/non-finite/);
    expect(() => canonicalize([NaN])).toThrow(/non-finite/);
  });

  it("rejects unsupported types", () => {
    expect(() => canonicalize(() => 1)).toThrow(/unsupported type function/);
    expect(() => canonicalize(Symbol("x"))).toThrow(/unsupported type symbol/);
  });
});

describe("canonicalize: object undefined-omit (regression guard for #42 fix)", () => {
  it("omits undefined values from objects (does NOT regress to throw)", () => {
    // RFC 8785 + Sanctuary policy: undefined in object position is omitted,
    // matching JSON.stringify behavior. The #42 fix must not over-correct
    // and start throwing on object-undefined too.
    expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
    expect(canonicalize({ a: undefined })).toBe("{}");
    expect(canonicalize({ a: undefined, b: undefined })).toBe("{}");
  });

  it("preserves null distinctly from undefined in objects", () => {
    expect(canonicalize({ a: null, b: undefined })).toBe('{"a":null}');
  });

  it("preserves null inside arrays", () => {
    // null is valid JSON and must pass through. Only undefined is rejected.
    expect(canonicalize([null])).toBe("[null]");
    expect(canonicalize([1, null, 3])).toBe("[1,null,3]");
  });
});

describe("canonicalize: basic shape (smoke)", () => {
  it("sorts object keys lexicographically", () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  it("emits compact form (no whitespace)", () => {
    expect(canonicalize({ a: [1, 2, 3] })).toBe('{"a":[1,2,3]}');
  });

  it("recurses into nested arrays and objects", () => {
    expect(canonicalize({ x: { y: [1, { z: 2 }] } })).toBe(
      '{"x":{"y":[1,{"z":2}]}}'
    );
  });
});

/**
 * Cross-language edge-class vectors (#915 adversarial review follow-up,
 * LOW finding). Each `it` here has a Swift-side counterpart in
 * castle-wall-macos/Tests/CastleWallExtensionTests/ManifestParityVectorTests.swift
 * asserting the SAME expected bytes (parity) or the language-specific
 * divergent behavior (documented, not silently papered over).
 */
describe("canonicalize: cross-language edge classes (castle-wall #915 follow-up)", () => {
  it("keeps canonically-equivalent but raw-distinct object keys as separate entries, sorted by UTF-16 code unit", () => {
    // "é" (precomposed e-acute) and "é" (decomposed e + combining
    // acute) are the SAME string under Unicode canonical equivalence (NFC)
    // but are DIFFERENT raw UTF-16 code-unit sequences. canonicalize() must
    // NOT normalize -- it sorts/serializes the raw code units, matching
    // RFC 8785 and Array.prototype.sort's default string comparator.
    //
    // Swift's counterpart (testCanonicalKeyOrderCollapsesCanonicallyEquivalentKeysOnDecode)
    // documents a DIFFERENT, real divergence here: Swift's String equality
    // is canonical-equivalence-aware, so decoding this same raw JSON text
    // into a Swift `[String: JSONValue]` dictionary SILENTLY COLLAPSES the
    // two keys into one entry (last-write-wins) before canonicalization
    // ever runs. That collapse happens only for genuinely dynamic
    // `[String: JSONValue]` maps (e.g. IPC-delivered `receivedRules`
    // content); every current signed field in AllowlistManifest /
    // ManifestRuleEntry / AgentOrigin / OperatorBaseline is a fixed-key
    // Codable struct, not a dynamic map, so this class is contained today
    // by the existing per-rule digest / manifest-signature checks (a
    // mismatched byte count from a dropped key fails verification --
    // fail-closed). Flagged to the coordinator as a structural landmine for
    // any FUTURE dynamic-map field; not fixed here (test-only build).
    const precomposed = "é"; // é
    const decomposed = "é"; // e + combining acute (U+0301)
    const value: Record<string, number> = { m: 1 };
    value[precomposed] = 2;
    value[decomposed] = 3;

    expect(Object.keys(value)).toHaveLength(3);
    const canonical = canonicalize(value);
    expect(canonical).toBe('{"é":3,"m":1,"é":2}');
    expect(Buffer.from(canonical, "utf8").toString("hex")).toBe(
      "7b2265cc81223a332c226d223a312c22c3a9223a327d",
    );
  });

  it("agrees with Swift at the Number.MAX_SAFE_INTEGER boundary (both exact)", () => {
    // 2^53-1 is the largest integer a JS `number` (float64) represents
    // exactly, and Swift's JSONValue.integer(Int64) case represents it
    // exactly too (decoded from a bare JSON integer literal, no decimal
    // point, so Swift's Codable-generated JSONValue picks the `.integer`
    // branch, not `.number(Double)`). Both sides emit the same digit string.
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(Number.MAX_SAFE_INTEGER).toBe(9007199254740991);
  });

  // FIXED (#915 follow-up security finding, closed): canonicalize()'s number
  // branch operates on the JS `number` (float64) primitive, which cannot
  // exactly represent integers beyond Number.MAX_SAFE_INTEGER (2^53-1).
  // Swift's JSONValue.integer(Int64) case (see
  // testCanonicalNumberBoundsAtSafeIntegerAndInt64Max in the Swift suite)
  // preserves full 64-bit precision for a bare JSON integer literal. A value
  // like Int64.max (9223372036854775807) used to silently round-trip through
  // Node's JSON.parse -> canonicalize() -> JSON.stringify as
  // "9223372036854776000" -- a byte-level divergence from Swift's exact
  // "9223372036854775807", with NO exception thrown on either side. That was
  // NOT fail-closed: a hypothetical future manifest field carrying a true
  // u64-scale value would have been silently corrupted by the Node signer
  // rather than rejected. canonicalize() now mirrors the existing
  // server/src/bridge/bridge.ts stableStringify unsafe-integer guard and
  // throws instead of mangling. No field in today's signed-manifest schema
  // carries values in this range (uids/ports/schema_version are all small),
  // so this was a structural landmine, not a live exploit -- but the fix
  // closes the class fail-closed rather than leaving it latent.
  it("rejects u64-scale integers instead of silently losing precision (cross-language parity, fail-closed)", () => {
    const raw = "9223372036854775807"; // Int64.max; Swift preserves this exactly
    const parsed = JSON.parse(`{"n":${raw}}`) as { n: number };
    // Node's JSON.parse has already lost precision by this point (the
    // float64 literal 9223372036854775807 parses to the nearest
    // representable double); the point of the guard is that canonicalize()
    // refuses to emit a confidently-wrong digit string rather than that it
    // recovers the original value. It must throw, loudly, every time.
    expect(() => canonicalize(parsed)).toThrow(MeshCanonicalJsonError);
    expect(() => canonicalize(parsed)).toThrow(/unsafe integer/);
    expect(() => canonicalize(9223372036854775807)).toThrow(MeshCanonicalJsonError);
  });

  it("still round-trips a safe integer with byte-parity after the unsafe-integer guard", () => {
    // Proves the guard only rejects previously-silently-mangled inputs and
    // does not change the canonical bytes of any currently-valid value.
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalize(0)).toBe("0");
    expect(canonicalize(-1)).toBe("-1");
    expect(canonicalize(42)).toBe("42");
    expect(canonicalize({ n: Number.MAX_SAFE_INTEGER })).toBe(
      '{"n":9007199254740991}',
    );
  });

  it("matches Swift on deeply nested (but bounded) array recursion", () => {
    // Both canonicalizers recurse one call frame per nesting level (TS via
    // encode(), Swift via appendCanonicalJSON()). 300 levels is far beyond
    // any real manifest shape but well within both languages' default call
    // stacks -- this is a "does it blow up or diverge" vector, not a
    // performance test.
    const depth = 300;
    let value: unknown = 42;
    for (let i = 0; i < depth; i++) value = [value];
    const canonical = canonicalize(value);
    const expected = "[".repeat(depth) + "42" + "]".repeat(depth);
    expect(canonical).toBe(expected);
  });
});
