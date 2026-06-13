/**
 * Hostile-fixture suite for wire-verdict parsing (design §3.1b, §3.3, §3.3b).
 * Every rejection asserts the NAMED reason so the contract is provably enforced.
 */

import { describe, it, expect } from "vitest";

import { parsePluginVerdict, parseVerdictFrame, parseStrictJson, SubstrateError } from "../../src/substrate/index.js";

const EXPECTED = { request_id: "r1", nonce: "n1", declaredSignalKeys: ["score", "tag"] as string[] };

function expectReject(fn: () => unknown, reason: string) {
  try {
    fn();
    throw new Error("expected rejection but none thrown");
  } catch (e) {
    expect(e).toBeInstanceOf(SubstrateError);
    expect((e as SubstrateError).reason).toBe(reason);
  }
}

describe("parsePluginVerdict — hostile fixtures", () => {
  it("accepts a valid deny verdict", () => {
    const v = parsePluginVerdict(
      { decision: "deny", request_id: "r1", nonce: "n1", rationale: "blocked", confidence: 0.9, signals: { score: 0.9 } },
      EXPECTED,
    );
    expect(v.decision).toBe("deny");
    expect(v.confidence).toBe(0.9);
  });

  it('rejects "allow" — no such verdict exists', () => {
    expectReject(
      () => parsePluginVerdict({ decision: "allow", request_id: "r1", nonce: "n1", rationale: "x" }, EXPECTED),
      "verdict_allow_not_permitted",
    );
  });

  it('rejects "permit" the same way', () => {
    expectReject(
      () => parsePluginVerdict({ decision: "permit", request_id: "r1", nonce: "n1", rationale: "x" }, EXPECTED),
      "verdict_allow_not_permitted",
    );
  });

  it("rejects a vendor-supplied plugin_error (host-minted only)", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "plugin_error", request_id: "r1", nonce: "n1", rationale: "x" }, EXPECTED),
      "verdict_vendor_supplied_plugin_error",
    );
  });

  it("rejects an unknown decision string", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "maybe", request_id: "r1", nonce: "n1", rationale: "x" }, EXPECTED),
      "verdict_unknown_decision",
    );
  });

  it("rejects an unknown extra key (closed shape)", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "deny", request_id: "r1", nonce: "n1", rationale: "x", extra: 1 }, EXPECTED),
      "verdict_unknown_key",
    );
  });

  it("rejects a prototype-pollution key", () => {
    const malicious = JSON.parse('{"decision":"deny","request_id":"r1","nonce":"n1","rationale":"x","__proto__":{"polluted":true}}');
    expectReject(() => parsePluginVerdict(malicious, EXPECTED), "json_prototype_key");
  });

  it("rejects a nonce mismatch (anti-replay/desync)", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "deny", request_id: "r1", nonce: "STALE", rationale: "x" }, EXPECTED),
      "verdict_nonce_mismatch",
    );
  });

  it("rejects a request_id mismatch (desync to another in-flight request)", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "deny", request_id: "OTHER", nonce: "n1", rationale: "x" }, EXPECTED),
      "verdict_request_id_mismatch",
    );
  });

  it("rejects a non-finite confidence", () => {
    const v = JSON.parse('{"decision":"observe","request_id":"r1","nonce":"n1","rationale":"x","confidence":1e999}');
    expectReject(() => parsePluginVerdict(v, EXPECTED), "json_non_finite_number");
  });

  it("rejects confidence out of [0,1]", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "observe", request_id: "r1", nonce: "n1", rationale: "x", confidence: 1.5 }, EXPECTED),
      "invalid_field_value",
    );
  });

  it("rejects an undeclared signal key (return-path exfil control)", () => {
    expectReject(
      () =>
        parsePluginVerdict(
          { decision: "observe", request_id: "r1", nonce: "n1", rationale: "x", signals: { secret_exfil: "data" } },
          EXPECTED,
        ),
      "verdict_undeclared_signal_key",
    );
  });

  it("accepts only declared signal keys", () => {
    const v = parsePluginVerdict(
      { decision: "observe", request_id: "r1", nonce: "n1", rationale: "x", signals: { score: 1, tag: "x" } },
      EXPECTED,
    );
    expect(v.signals).toEqual({ score: 1, tag: "x" });
  });

  it("rejects an over-long rationale", () => {
    expectReject(
      () => parsePluginVerdict({ decision: "deny", request_id: "r1", nonce: "n1", rationale: "z".repeat(5000) }, EXPECTED),
      "frame_too_large",
    );
  });
});

describe("parseVerdictFrame — raw-text strict parse (duplicate-key bypass closed)", () => {
  it("accepts a valid frame", () => {
    const v = parseVerdictFrame('{"decision":"deny","request_id":"r1","nonce":"n1","rationale":"x"}', EXPECTED);
    expect(v.decision).toBe("deny");
  });

  it("rejects a duplicate decision key (the deny→no_objection downgrade, codex HIGH)", () => {
    expectReject(
      () =>
        parseVerdictFrame(
          '{"decision":"deny","decision":"no_objection","request_id":"r1","nonce":"n1","rationale":"x"}',
          EXPECTED,
        ),
      "json_duplicate_key",
    );
  });

  it("rejects a __proto__ key in the raw frame", () => {
    expectReject(
      () => parseVerdictFrame('{"decision":"deny","__proto__":{"x":1},"request_id":"r1","nonce":"n1","rationale":"x"}', EXPECTED),
      "json_prototype_key",
    );
  });

  it("rejects trailing bytes after the frame", () => {
    expectReject(
      () => parseVerdictFrame('{"decision":"deny","request_id":"r1","nonce":"n1","rationale":"x"}  garbage', EXPECTED),
      "frame_trailing_bytes",
    );
  });
});

describe("parseStrictJson — primitives", () => {
  it("parses nested structures without collapsing distinct keys", () => {
    expect(parseStrictJson('{"a":1,"b":[true,null,"s"]}')).toEqual({ a: 1, b: [true, null, "s"] });
  });

  it("rejects duplicate keys at a nested level", () => {
    try {
      parseStrictJson('{"o":{"k":1,"k":2}}');
      throw new Error("expected rejection");
    } catch (e) {
      expect((e as SubstrateError).reason).toBe("json_duplicate_key");
    }
  });

  it("rejects over-deep nesting", () => {
    const deep = "[".repeat(40) + "1" + "]".repeat(40);
    try {
      parseStrictJson(deep);
      throw new Error("expected rejection");
    } catch (e) {
      expect((e as SubstrateError).reason).toBe("json_too_deep");
    }
  });

  it("enforces the exact JSON number grammar (no 01, 1., +1, .5)", () => {
    expect(parseStrictJson("0")).toBe(0);
    expect(parseStrictJson("-12.5e3")).toBe(-12500);
    for (const bad of ["01", "1.", ".5", "+1", "1e", "1e+"]) {
      let threw = false;
      try {
        parseStrictJson(bad);
      } catch {
        threw = true;
      }
      expect(threw, `expected "${bad}" to be rejected`).toBe(true);
    }
  });
});
