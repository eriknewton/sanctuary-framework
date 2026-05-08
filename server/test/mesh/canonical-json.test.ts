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

describe("canonicalize — rejection rules", () => {
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

  it("rejects non-finite numbers (regression — pre-existing)", () => {
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

describe("canonicalize — object undefined-omit (regression guard for #42 fix)", () => {
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

describe("canonicalize — basic shape (smoke)", () => {
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
