/**
 * Security Guard: Tool-registry raw signing classification
 *
 * Structural regression guard for the Identity signing authority row in
 * ASSURANCE_MATRIX.md. Enumerates every MCP tool registered in source,
 * flags any whose name contains "sign" as a word-boundary token, and
 * requires each flagged tool to be either:
 *   - Tier 1 in the Principal Policy, OR
 *   - In the documented DOMAIN_SEPARATED_ALLOWLIST (signs typed payloads
 *     under an explicit domain prefix, not raw bytes).
 *
 * If a new tool surfaces raw Ed25519 signing without one of these
 * classifications, this test fails and blocks the PR.
 *
 * Driver: PR #270 made identity_sign Tier 1 and pulled typed internal
 * helpers out of the MCP surface. This guard prevents regression.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

// ── Configuration ──���──────────────────────────────────────────────────

/**
 * Word-boundary regex for "sign" as a token in tool names.
 * Excludes substring matches inside words like "assign", "design", "signal".
 */
const SIGN_NAME_RE = /(?:^|_)sign(?:_|$)/i;

/**
 * Domain-separated allowlist: tools whose name matches SIGN_NAME_RE but
 * sign typed payloads under an explicit domain-separation prefix (not raw
 * bytes). Each entry documents its domain prefix.
 *
 * To add an entry:
 *   1. Verify the tool's handler constructs a domain-prefixed message
 *      (e.g., "sanctuary-sign-challenge-v1\x00purpose\x00nonce")
 *   2. Verify the input schema requires a domain-binding field (e.g., purpose)
 *   3. Add the entry below with its domain prefix documented
 *   4. Update server/docs/tool-registry-raw-signing-policy.md
 */
const DOMAIN_SEPARATED_ALLOWLIST: ReadonlyMap<string, string> = new Map([
  // sanctuary_sign_challenge: signs under domain prefix
  // "sanctuary-sign-challenge-v1\x00{purpose}\x00{nonce}"
  // Input schema requires `purpose` field for domain separation.
  // Source: server/src/sanctuary-tools.ts
  ["sanctuary_sign_challenge", "sanctuary-sign-challenge-v1"],
]);

// ── Source scanner ──────��─────────────────────────────────────────────

/**
 * Recursively scan TypeScript source files in src/ for MCP tool name
 * declarations (pattern: `name: "tool_name"`). Returns all registered
 * tool names found in source.
 */
function scanToolNames(dir: string): string[] {
  const names: string[] = [];
  const nameRe = /name:\s*"([a-z][a-z0-9_]*)"/g;

  function walk(d: string): void {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
        const content = readFileSync(full, "utf-8");
        let match: RegExpExecArray | null;
        while ((match = nameRe.exec(content)) !== null) {
          names.push(match[1]!);
        }
      }
    }
  }

  walk(dir);
  return [...new Set(names)];
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("tool-registry raw signing guard", () => {
  const srcDir = join(__dirname, "../../src");
  const allToolNames = scanToolNames(srcDir);
  const tier1Set = new Set(DEFAULT_POLICY.tier1_always_approve);
  const signTools = allToolNames.filter((name) => SIGN_NAME_RE.test(name));

  it("scanner finds at least 50 tools (sanity check)", () => {
    expect(allToolNames.length).toBeGreaterThan(50);
  });

  it("scanner detects known sign-named tools", () => {
    expect(signTools).toContain("identity_sign");
    expect(signTools).toContain("sanctuary_sign_challenge");
  });

  for (const toolName of signTools) {
    if (DOMAIN_SEPARATED_ALLOWLIST.has(toolName)) continue;

    it(`${toolName}: must be Tier 1 classified (raw signing guard)`, () => {
      expect(
        tier1Set.has(toolName),
        `Tool "${toolName}" contains "sign" as a word-boundary token but is ` +
          `NOT in tier1_always_approve and NOT in the domain-separated ` +
          `allowlist. Either:\n` +
          `  (a) Add it to tier1_always_approve in principal-policy/loader.ts, or\n` +
          `  (b) If it signs typed payloads under a domain prefix, add it to\n` +
          `      DOMAIN_SEPARATED_ALLOWLIST in this test with documentation, or\n` +
          `  (c) Remove it from the MCP tool registry (make it an internal helper).`
      ).toBe(true);
    });
  }

  it("every DOMAIN_SEPARATED_ALLOWLIST entry still exists in the registry", () => {
    const nameSet = new Set(allToolNames);
    for (const [allowed, domainPrefix] of DOMAIN_SEPARATED_ALLOWLIST) {
      expect(
        nameSet.has(allowed),
        `Allowlist entry "${allowed}" (domain: ${domainPrefix}) no longer ` +
          `exists in the tool registry. Remove it from the allowlist.`
      ).toBe(true);
    }
  });

  it("every DOMAIN_SEPARATED_ALLOWLIST entry has a non-empty domain prefix", () => {
    for (const [name, prefix] of DOMAIN_SEPARATED_ALLOWLIST) {
      expect(
        prefix.length > 0,
        `Allowlist entry "${name}" has an empty domain prefix. ` +
          `Document the actual domain-separation prefix used by the handler.`
      ).toBe(true);
    }
  });

  it("tier 1 list includes identity_sign (structural anchor)", () => {
    expect(tier1Set.has("identity_sign")).toBe(true);
  });
});
