import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import {
  classifyManifestRuleFilename,
  encodeRuleFilename,
  parseRuleId,
  preflightManifestRuleEntries,
} from "../../../src/castle-wall/allowlist/rule-identity.js";
import { CURATED_ALLOWLIST } from "../../../src/castle-wall/runtime/curated-allowlist.js";
import { DERIVED_DNS_RULE_ID } from "../../../src/castle-wall/allowlist/dns-derivation.js";
import { DERIVED_GATE_RULE_ID } from "../../../src/castle-wall/allowlist/gate-derivation.js";
import {
  HABEAS_LOCAL_RULE_ID,
  HABEAS_WEBHOOK_RULE_ID,
} from "../../../src/castle-wall/allowlist/habeas-port.js";
import { OBSERVE_PROMOTED_RULE_ID_PREFIX } from "../../../src/castle-wall/constants.js";
import { provisionedRuleId } from "../../../src/castle-wall/provision/egress.js";

function fixtureRuleIds(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(fixtureRuleIds);
  if (value === null || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  const ownId =
    typeof record.id === "string" &&
    "schema_version" in record &&
    "match" in record &&
    "scope" in record &&
    "disposition" in record
      ? [record.id]
      : [];
  return ownId.concat(...Object.values(record).flatMap(fixtureRuleIds));
}

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

  it("records the curated, derived, reserved, fixture, and cross-language id inventory", () => {
    const crossLanguageFixture = JSON.parse(
      readFileSync("../castle-wall-daemon/test-vectors/rule-id-filename-v1.json", "utf8"),
    ) as { valid: Array<{ id: string }> };
    const fixtureIds = readdirSync("test/castle-wall/fixtures")
      .filter((name) => name.endsWith(".json"))
      .flatMap((name) => fixtureRuleIds(JSON.parse(readFileSync(`test/castle-wall/fixtures/${name}`, "utf8"))));
    const inventory = {
      curated: CURATED_ALLOWLIST.map((entry) => entry.rule_id),
      derived: [
        DERIVED_DNS_RULE_ID,
        DERIVED_GATE_RULE_ID,
        `${OBSERVE_PROMOTED_RULE_ID_PREFIX}0123456789abcdef`,
        provisionedRuleId("claude-code", {
          name: "inventory endpoint",
          host: "api.example.com",
          port: 443,
          protocol: "tcp",
          riskClass: "standard",
        }),
      ],
      reserved: [HABEAS_LOCAL_RULE_ID, HABEAS_WEBHOOK_RULE_ID],
      fixtures: fixtureIds,
      cross_language_vectors: crossLanguageFixture.valid.map((entry) => entry.id),
    };

    for (const ids of Object.values(inventory)) {
      for (const id of ids) expect(parseRuleId(id).ok).toBe(true);
    }
  });
});
