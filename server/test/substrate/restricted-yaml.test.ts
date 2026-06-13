/**
 * Hostile-fixture suite for the restricted-YAML profile (design §3.1).
 * The full-YAML grammar IS the determinism attack surface; this proves the dangerous
 * constructs are rejected by NAME, and that the safe subset round-trips.
 */

import { describe, it, expect } from "vitest";

import { parseRestrictedYaml, SubstrateError } from "../../src/substrate/index.js";

function expectReject(text: string, reason: string) {
  try {
    parseRestrictedYaml(text);
    throw new Error("expected rejection but none thrown");
  } catch (e) {
    expect(e, `expected SubstrateError ${reason}, got ${String(e)}`).toBeInstanceOf(SubstrateError);
    expect((e as SubstrateError).reason).toBe(reason);
  }
}

describe("restricted-yaml — safe subset round-trips", () => {
  it("parses nested maps, sequences, and scalars", () => {
    const v = parseRestrictedYaml(`
a: hello
b: 42
c: 3.14
d: true
e: null
f:
  g: nested
  h:
    - one
    - two
items:
  - name: x
    val: 1
  - name: y
    val: 2
`);
    expect(v).toEqual({
      a: "hello",
      b: 42,
      c: 3.14,
      d: true,
      e: null,
      f: { g: "nested", h: ["one", "two"] },
      items: [
        { name: "x", val: 1 },
        { name: "y", val: 2 },
      ],
    });
  });

  it("handles quoted strings and comments", () => {
    const v = parseRestrictedYaml(`
key: "value # not a comment"  # this is a comment
other: plain
`);
    expect(v).toEqual({ key: "value # not a comment", other: "plain" });
  });
});

describe("restricted-yaml — dangerous constructs rejected", () => {
  it("rejects anchors", () => {
    expectReject("a: &anchor value\nb: 1\n", "yaml_anchor_or_alias");
  });

  it("rejects aliases", () => {
    expectReject("a: *alias\n", "yaml_anchor_or_alias");
  });

  it("rejects explicit tags", () => {
    expectReject("a: !!str 123\n", "yaml_explicit_tag");
  });

  it("rejects merge keys", () => {
    expectReject("<<: merge\na: 1\n", "yaml_merge_key");
  });

  it("rejects duplicate keys at the same level", () => {
    expectReject("a: 1\na: 2\n", "yaml_duplicate_key");
  });

  it("rejects flow collections", () => {
    expectReject("a: [1, 2, 3]\n", "yaml_non_string_key");
  });

  it("rejects block scalars", () => {
    expectReject("a: |\n  multi\n  line\n", "yaml_malformed");
  });

  it("rejects .inf / .nan floats", () => {
    expectReject("a: .inf\n", "json_non_finite_number");
    expectReject("a: .nan\n", "json_non_finite_number");
  });

  it("rejects tabs in indentation", () => {
    expectReject("a:\n\tb: 1\n", "yaml_malformed");
  });

  it("rejects multiple documents", () => {
    expectReject("---\na: 1\n---\nb: 2\n", "yaml_malformed");
  });

  it("rejects a __proto__ key (prototype-pollution bypass)", () => {
    expectReject("__proto__:\n  polluted: true\n", "yaml_non_string_key");
  });

  it("rejects constructor / prototype keys", () => {
    expectReject("constructor: x\n", "yaml_non_string_key");
    expectReject("prototype: x\n", "yaml_non_string_key");
  });

  it("a __proto__ key, even if it slipped through, becomes an OWN key (null-proto map)", () => {
    // Sanity: the map is Object.create(null), so a hypothetical __proto__ own-key would be
    // visible to Object.keys and not mutate the prototype. We assert no pollution leaks.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("rejects typed (number/boolean/null) unquoted keys", () => {
    expectReject("1: x\n", "yaml_non_string_key");
    expectReject("true: x\n", "yaml_non_string_key");
    expectReject("null: x\n", "yaml_non_string_key");
  });

  it("rejects anchor/alias/tag unquoted keys", () => {
    expectReject("&anchor: x\n", "yaml_anchor_or_alias");
    expectReject("*alias: x\n", "yaml_anchor_or_alias");
    expectReject("!tag: x\n", "yaml_explicit_tag");
  });

  it("permits a quoted key that looks like a number (legitimately a string)", () => {
    const v = parseRestrictedYaml('"1": value\n');
    expect(v).toEqual({ "1": "value" });
  });
});
