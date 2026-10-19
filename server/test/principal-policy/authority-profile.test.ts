/** Strict profile parsing remains isolated from ordinary policy loading. */
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { enforceForcedTiers, generateDefaultPolicyYaml, loadPrincipalPolicy, parsePolicy, principalPolicyPath } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";

// Must match PROFILE in src/principal-policy/authority-profile.ts, including every nested field.
function profile(): PrincipalPolicy {
  return {
    version: 1, // First authority profile.
    tier1_always_approve: ["memory_insert"],
    tier3_always_allow: ["memory_get", "memory_search"],
    approval_channel: { type: "callback", timeout_seconds: 83 }, // (120000 - 30000 - 2000 - 5000) / 1000.
    tier2_anomaly: {
      new_namespace_access: "approve", new_counterparty: "approve",
      frequency_spike_multiplier: 5, // Fivefold frequency increase.
      max_signs_per_minute: 10, // Profile signing ceiling.
      bulk_read_threshold: 20, // Profile bulk-read ceiling.
      first_session_policy: "approve",
    },
  };
}
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
const digest = (bytes: Uint8Array) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
// Import inside each test so pre-change absence fails every test, not just collection.
const moduleUnderTest = () => import("../../src/principal-policy/authority-profile.js");

describe("strict authority profile", () => {
  it("preserves the entire profile and applies exactly the shared forced tiers", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const input = profile();
    const bytes = encode(input);
    expect(parseStrictAuthorityPolicy(bytes, digest(bytes))).toEqual(enforceForcedTiers(input));
    const reordered = profile();
    reordered.tier3_always_allow.reverse();
    expect(parseStrictAuthorityPolicy(encode(reordered), digest(encode(reordered))))
      .toEqual(enforceForcedTiers(reordered));
  });

  it("rejects every missing or unknown field and every changed profile value", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const reject = (value: unknown) => {
      const bytes = encode(value);
      expect(() => parseStrictAuthorityPolicy(bytes, digest(bytes))).toThrow();
    };
    // Traverse the whole schema, not a selected first key, so field additions extend coverage.
    function variants(value: Record<string, unknown>, path: string[] = []): void {
      const at = (root: Record<string, unknown>) => path.reduce((node, key) => node[key] as Record<string, unknown>, root);
      for (const key of Object.keys(value)) {
        const missing = structuredClone(profile()) as unknown as Record<string, unknown>;
        delete at(missing)[key];
        reject(missing);
        for (const replacement of [null, false, "wrong", [], {}, 0]) {
          const changed = structuredClone(profile()) as unknown as Record<string, unknown>;
          at(changed)[key] = replacement;
          reject(changed);
        }
        if (typeof value[key] === "object" && !Array.isArray(value[key]) && value[key] !== null) {
          variants(value[key] as Record<string, unknown>, [...path, key]);
        }
      }
      for (const key of ["unknown", "approval_redirect", "per_agent", "__proto__"]) {
        const extra = structuredClone(profile()) as unknown as Record<string, unknown>;
        Object.defineProperty(at(extra), key, { value: {}, enumerable: true });
        reject(extra);
      }
    }
    variants(profile() as unknown as Record<string, unknown>);
    for (const tier3 of [["memory_get", "memory_get"], ["memory_get", "memory_insert"], ["memory_get", "memory_search", "state_read"]]) {
      reject({ ...profile(), tier3_always_allow: tier3 });
    }
    reject({ ...profile(), tier1_always_approve: ["memory_insert", "memory_insert"] });
  });

  it("rejects duplicate decoded keys and malformed JSON or UTF-8 before normalization", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const valid = JSON.stringify(profile());
    const invalid = [
      valid.replace('"version":1', '"version":1,"version":1'),
      valid.replace('"version":1', '"version":1,"\\u0076ersion":1'),
      valid.replace('"type":"callback"', '"type":"callback","\\u0074ype":"callback"'),
      valid.replace('"frequency_spike_multiplier":5', '"frequency_spike_multiplier":5,"frequency_spike_multiplier":5'),
      valid.replace('"version":1', '"version":1e999'),
      valid.replace('"version":1', '"version":NaN'),
      valid.replace('"callback"', '"\\ud800"'),
      "version: 1", valid + "{}", "[]", "null", "",
    ].map((text) => Buffer.from(text));
    invalid.push(Buffer.from([0xff])); // Invalid leading UTF-8 octet.
    for (const bytes of invalid) expect(() => parseStrictAuthorityPolicy(bytes, digest(bytes))).toThrow();
  });

  it("requires the exact protected byte digest without canonicalizing the input", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const bytes = encode(profile());
    const spaced = Buffer.from(JSON.stringify(profile(), null, " "));
    expect(parseStrictAuthorityPolicy(spaced, digest(spaced))).toEqual(enforceForcedTiers(profile()));
    for (const wrong of [digest(spaced), "", digest(bytes).toUpperCase(), undefined]) {
      expect(() => parseStrictAuthorityPolicy(bytes, wrong as string)).toThrow();
    }
  });

  it("bounds policy bytes before parsing and accepts the exact allocation ceiling", async () => {
    const { parseStrictAuthorityPolicy, MAX_POLICY_BYTES } = await moduleUnderTest();
    const bytes = encode(profile());
    const atLimit = Buffer.concat([bytes, Buffer.alloc(MAX_POLICY_BYTES - bytes.length, " ")]);
    expect(parseStrictAuthorityPolicy(atLimit, digest(atLimit))).toEqual(enforceForcedTiers(profile()));
    const overLimit = Buffer.concat([atLimit, Buffer.from(" ")]);
    expect(() => parseStrictAuthorityPolicy(overLimit, digest(overLimit))).toThrow();
  });

  it("recursively freezes every effective policy object and array", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const bytes = encode(profile());
    const parsed = parseStrictAuthorityPolicy(bytes, digest(bytes));
    function check(value: unknown): void {
      if (value === null || typeof value !== "object") return;
      expect(Object.isFrozen(value)).toBe(true);
      for (const child of Object.values(value)) check(child);
    }
    check(parsed);
    expect(() => parsed.tier1_always_approve.pop()).toThrow();
    expect(() => { parsed.approval_channel.type = "stderr"; }).toThrow();
  });

  it("keeps ordinary JSON and YAML loader bytes and default merging unchanged", async () => {
    const { parseStrictAuthorityPolicy } = await moduleUnderTest();
    const dir = await mkdtemp(join(tmpdir(), "p1-policy-"));
    try {
      const duplicateVersion = JSON.stringify(profile()).replace('"version":1', '"version":1,"version":1');
      for (const content of [generateDefaultPolicyYaml(), duplicateVersion, JSON.stringify(profile())]) {
        const bytes = Buffer.from(content);
        await writeFile(principalPolicyPath(dir), bytes);
        const expected = JSON.stringify(parsePolicy(content));
        expect(JSON.stringify(await loadPrincipalPolicy(dir))).toBe(expected);
        expect(await readFile(principalPolicyPath(dir))).toEqual(bytes);
        if (content === JSON.stringify(profile())) {
          const strict = parseStrictAuthorityPolicy(bytes, digest(bytes));
          expect(strict.tier3_always_allow).not.toContain("state_read");
          expect((await loadPrincipalPolicy(dir)).tier3_always_allow).toContain("state_read");
        } else {
          expect(() => parseStrictAuthorityPolicy(bytes, digest(bytes))).toThrow();
        }
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
