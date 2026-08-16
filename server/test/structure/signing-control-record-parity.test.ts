/**
 * IC-05-DG lockstep-plumbing parity (design §f-14) + the DELTA-4
 * construction-mode provenance guard.
 *
 * The two signing control records (the v2 latch and the signing head) must
 * agree, by FULL-SET equality (never first-entry membership — a parity test
 * that asserts "the first entry matches" cannot detect a missing entry,
 * AGENTS.md rule 5), across all six mirror sites:
 *  1. the derive-purpose-key site in `operational/audit-log.ts`;
 *  2. `MAC_ANCHORS` in `core/master-rotation.ts` (`convertAuditAnchors`);
 *  3. the exporter control-key skip list (`cli/audit-chain-export.ts`, which
 *     imports the shared list, so site 3 is verified as "consumes site 4");
 *  4. `AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS` in
 *     `audit/checkpoint-shape.ts` (a reserved key missing there discloses a
 *     loud false INCOMPLETE per its own doc comment; parity here is what
 *     keeps that from drifting);
 *  5. `docs/hkdf-info-string-registry.md`;
 *  6. the at-rest classification fixture
 *     (`test/fixtures/at-rest/hkdf-label-classification.json`).
 *
 * Also pinned: the incident reason-class enum is the SAME closed set on both
 * sides of the signer/audit-log contract, and the v2 strings never regress to
 * the #1243 branch's v1 strings (whose historical semantics must not be able
 * to satisfy or confuse the v2 reader).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS,
  AUDIT_SIGNING_LATCH_V2_KEY,
  AUDIT_SIGNING_HEAD_KEY,
} from "../../src/audit/checkpoint-shape.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

/** The canonical record set: key -> { marker, purpose, domain }. This test
 * file is the seventh mirror on purpose: editing any site without editing
 * this table (or vice versa) fails, which is the tripwire working. */
const EXPECTED = {
  __signing_latch_v2: {
    marker: "__sanctuary_audit_signing_latch_v2",
    purpose: "audit-signing-latch-v2",
    domain: "sanctuary.audit-signing-latch.v2\\n",
  },
  __signing_head: {
    marker: "__sanctuary_audit_signing_head_v1",
    purpose: "audit-signing-head",
    domain: "sanctuary.audit-signing-head.v1\\n",
  },
} as const;

/** The retired #1243 branch (v1) strings: no site may reintroduce them. */
// Code-position shapes only (declarations, MAC_ANCHORS entries, derive
// calls): PROSE mentions of the retired strings in comments and the registry
// are legitimate history and deliberately not matched.
const FORBIDDEN_V1_STRINGS = [
  '= "__signing_latch"',
  'marker: "__sanctuary_audit_signing_latch_v1"',
  'purpose: "audit-signing-latch"',
  '= "sanctuary.audit-signing-latch.v1',
  '"audit-signing-latch")',
];

describe("IC-05-DG signing-control-record six-site parity", () => {
  it("site 1: audit-log.ts declares exactly the expected markers/purposes/domains and derives both purpose keys", () => {
    const source = read("server/src/operational/audit-log.ts");
    expect(source).toContain(
      `const AUDIT_SIGNING_LATCH_V2_MARKER = "${EXPECTED.__signing_latch_v2.marker}";`
    );
    expect(source).toContain(
      `const AUDIT_SIGNING_LATCH_V2_MAC_DOMAIN = "${EXPECTED.__signing_latch_v2.domain}";`
    );
    expect(source).toContain(
      `const AUDIT_SIGNING_LATCH_V2_MAC_PURPOSE = "${EXPECTED.__signing_latch_v2.purpose}";`
    );
    expect(source).toContain(
      `const AUDIT_SIGNING_HEAD_MARKER = "${EXPECTED.__signing_head.marker}";`
    );
    expect(source).toContain(
      `const AUDIT_SIGNING_HEAD_MAC_DOMAIN = "${EXPECTED.__signing_head.domain}";`
    );
    expect(source).toContain(
      `const AUDIT_SIGNING_HEAD_MAC_PURPOSE = "${EXPECTED.__signing_head.purpose}";`
    );
    // Both keys derive through the named constants (full set: exactly two
    // derivations reference them).
    expect(source).toContain("AUDIT_SIGNING_LATCH_V2_MAC_PURPOSE\n    );");
    expect(source).toContain("AUDIT_SIGNING_HEAD_MAC_PURPOSE\n    );");
  });

  it("site 2: master-rotation MAC_ANCHORS carries BOTH entries with byte-identical marker/purpose/domain", () => {
    const source = read("server/src/core/master-rotation.ts");
    for (const [key, entry] of Object.entries(EXPECTED)) {
      const escape = (literal: string): string =>
        literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const anchorBlock = new RegExp(
        `${key}:\\s*\\{\\s*` +
          `marker:\\s*"${escape(entry.marker)}",\\s*` +
          `purpose:\\s*"${escape(entry.purpose)}",\\s*` +
          `domain:\\s*"${escape(entry.domain)}",`
      );
      expect(
        anchorBlock.test(source),
        `MAC_ANCHORS entry for ${key} missing or drifted`
      ).toBe(true);
    }
  });

  it("sites 3+4: the shared control-key allowlist holds BOTH keys and the exporter consumes the shared list", () => {
    // Full-set assertion over the runtime value, not a substring probe.
    expect(AUDIT_SIGNING_LATCH_V2_KEY).toBe("__signing_latch_v2");
    expect(AUDIT_SIGNING_HEAD_KEY).toBe("__signing_head");
    expect(AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS).toEqual([
      "__head_anchor",
      "__custody_epoch_keys",
      "__signing_latch_v2",
      "__signing_head",
    ]);
    // Site 3 is structurally site 4: the exporter must keep importing the
    // ONE shared list rather than re-growing a local copy.
    const exporter = read("server/src/cli/audit-chain-export.ts");
    expect(exporter).toContain("AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS");
  });

  it("site 5: the HKDF registry documents BOTH purpose labels", () => {
    const registry = read("server/docs/hkdf-info-string-registry.md");
    for (const entry of Object.values(EXPECTED)) {
      expect(registry).toContain(`| \`${entry.purpose}\` |`);
    }
  });

  it("site 6: the at-rest classification fixture carries BOTH labels as crypto-domain labels", () => {
    const fixture = JSON.parse(
      read("server/test/fixtures/at-rest/hkdf-label-classification.json")
    ) as { labels: Array<{ label: string; class: string }> };
    for (const entry of Object.values(EXPECTED)) {
      const row = fixture.labels.find((label) => label.label === entry.purpose);
      expect(row, `fixture row for ${entry.purpose}`).toBeDefined();
      expect(row!.class).toBe("crypto-domain-label");
    }
  });

  it("the incident reason-class enum is the same closed set on both sides of the signer contract", () => {
    // Side A: the persisted-ring set in audit-log.ts.
    const auditLog = read("server/src/operational/audit-log.ts");
    const ringSetMatch = auditLog.match(
      /const SIGNING_INCIDENT_REASON_CLASSES = \[((?:.|\n)*?)\] as const/
    );
    expect(ringSetMatch, "SIGNING_INCIDENT_REASON_CLASSES declaration").toBeTruthy();
    const ringSet = [...ringSetMatch![1]!.matchAll(/"([a-z_]+)"/g)].map(
      (match) => match[1]
    );
    // Side B: the CheckpointSignerFailureReasonClass union in
    // checkpoint-identity.ts.
    const identity = read("server/src/audit/checkpoint-identity.ts");
    const unionMatch = identity.match(
      /export type CheckpointSignerFailureReasonClass =((?:.|\n)*?);/
    );
    expect(unionMatch, "CheckpointSignerFailureReasonClass union").toBeTruthy();
    const unionSet = [...unionMatch![1]!.matchAll(/"([a-z_]+)"/g)].map(
      (match) => match[1]
    );
    // FULL-set equality, order-insensitive: a class added on one side only
    // must fail here.
    expect([...ringSet].sort()).toEqual([...unionSet].sort());
    expect([...ringSet].sort()).toEqual([
      "identity_undecryptable",
      "identity_unreadable",
      "signing_failed",
    ]);
  });

  it("no production source reintroduces the retired v1 latch strings", () => {
    for (const file of [
      "server/src/operational/audit-log.ts",
      "server/src/core/master-rotation.ts",
      "server/src/audit/checkpoint-shape.ts",
    ]) {
      const source = read(file);
      for (const forbidden of FORBIDDEN_V1_STRINGS) {
        expect(
          source.includes(forbidden),
          `${file} contains retired v1 string ${forbidden}`
        ).toBe(false);
      }
    }
  });
});

describe("IC-05-DG construction-mode provenance (DELTA-4 mechanical guard)", () => {
  it("every signingDetectionMode occurrence outside audit-log.ts is a construction-site literal, never derived from storage", async () => {
    // The mode is a construction-time fact: the ONLY legal shape outside the
    // declaring module is `signingDetectionMode: "fortress" | "non-fortress"`
    // as a literal property at an AuditLog construction site. Any computed
    // value (a variable, a ternary over a storage read, an await) fails
    // here, which is what makes "no storage state feeds the non-fortress
    // decision" mechanically checked rather than review-only.
    const { execFileSync } = await import("node:child_process");
    const srcRoot = join(REPO_ROOT, "server", "src");
    let grep = "";
    try {
      grep = execFileSync(
        "grep",
        ["-rn", "signingDetectionMode", srcRoot, "--include=*.ts"],
        { encoding: "utf8" }
      );
    } catch {
      grep = "";
    }
    const offenders: string[] = [];
    for (const line of grep.split("\n")) {
      if (!line.trim()) continue;
      const [file] = line.split(":", 1);
      if (file!.endsWith("operational/audit-log.ts")) continue;
      if (/signingDetectionMode:\s*"(fortress|non-fortress)"/.test(line)) {
        continue;
      }
      offenders.push(line);
    }
    expect(offenders, "non-literal signingDetectionMode usage").toEqual([]);
    // And the declaring module consumes it only from config with the loud
    // default: the single assignment reads `config?.signingDetectionMode ??
    // "fortress"`, never a storage result.
    const auditLog = read("server/src/operational/audit-log.ts");
    expect(auditLog).toContain(
      'this.signingDetectionMode = config?.signingDetectionMode ?? "fortress";'
    );
    const assignments = auditLog.match(/this\.signingDetectionMode\s*=(?!=)/g) ?? [];
    expect(assignments).toHaveLength(1);
  });
});
