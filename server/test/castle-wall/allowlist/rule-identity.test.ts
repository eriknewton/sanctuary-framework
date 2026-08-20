import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  classifyManifestRuleFilename,
  encodeRuleFilename,
  parseRuleId,
  preflightManifestRuleEntries,
} from "../../../src/castle-wall/allowlist/rule-identity.js";

describe("castle-wall/allowlist/rule-identity", () => {
  it("matches the shared Rust and Swift contract vectors exactly", () => {
    const fixture = JSON.parse(
      readFileSync("../castle-wall-daemon/test-vectors/rule-id-filename-v1.json", "utf8")
    ) as {
      valid: Array<{ id: string; encoded_v1: string; legacy_safe: string }>;
      invalid_ids: string[];
      invalid_filenames: string[];
    };
    for (const vector of fixture.valid) {
      const parsed = parseRuleId(vector.id);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) expect(encodeRuleFilename(parsed.value)).toBe(vector.encoded_v1);
      expect(classifyManifestRuleFilename(vector.id, vector.legacy_safe).ok).toBe(true);
    }
    for (const id of fixture.invalid_ids) expect(parseRuleId(id).ok).toBe(false);
    for (const filename of fixture.invalid_filenames) {
      expect(classifyManifestRuleFilename("a", filename).ok).toBe(false);
    }
  });
  it("accepts the canonical ASCII alphabet and pins encoded-v1 bytes", () => {
    const id = parseRuleId("curated:alpha_1.2-3");
    expect(id).toEqual({ ok: true, value: "curated:alpha_1.2-3" });
    if (id.ok) expect(encodeRuleFilename(id.value)).toBe("rid1_Y3VyYXRlZDphbHBoYV8xLjItMw.json");
  });

  it("rejects non-canonical, unsafe, and overlong rule ids", () => {
    for (const value of ["", ".leading", "has space", "a/b", "a\\b", "café", "a".repeat(121)]) {
      expect(parseRuleId(value).ok).toBe(false);
    }
  });

  it("accepts only exact encoded-v1 or legacy-safe relations", () => {
    expect(classifyManifestRuleFilename("safe-id", "safe-id.json").ok).toBe(true);
    expect(classifyManifestRuleFilename("safe-id", "rid1_c2FmZS1pZA.json").ok).toBe(true);
    expect(classifyManifestRuleFilename("safe-id", "safe-id.json.bak").ok).toBe(false);
    expect(classifyManifestRuleFilename("safe-id", "rid1_c2FmZS1pZA=.json").ok).toBe(false);
  });

  it("preflights the complete persisted set before any filename is consumed", () => {
    const issues = preflightManifestRuleEntries([
      { rule_id: "safe-id", file: "safe-id.json" },
      { rule_id: "safe-id", file: "safe-id.json" },
      { rule_id: "bad/id", file: "bad/id.json" },
      { rule_id: "other", file: "outside.json" },
    ]);
    expect(issues).toHaveLength(4);
    expect(issues.join("\n")).toContain("duplicate rule id");
    expect(issues.join("\n")).toContain("duplicate rule filename");
  });
});
