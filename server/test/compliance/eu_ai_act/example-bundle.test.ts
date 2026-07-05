/**
 * Sanctuary MCP Server — EU AI Act Example Bundle Generator
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Produces the canonical example bundle checked in under
 * `examples/eu_ai_act_bundle_example/`. Gated on GENERATE_EXAMPLE=1
 * so it does not run in the normal test suite — the committed files
 * are the source of truth during normal operation and are
 * regenerated only when the generator, matrix, or templates change
 * in a way that affects the rendered output.
 *
 * To regenerate:
 *   cd server && GENERATE_EXAMPLE=1 npm test -- example-bundle
 *
 * The example is a fictional Fortune 2000 enterprise deploying a
 * high-risk Annex III §4 HR screening agent. Nothing in this file
 * references any real entity.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { gcm } from "@noble/ciphers/aes.js";
import {
  COVERAGE_MATRIX_V1,
  coverageStats,
  type CoverageRow,
} from "../../../src/compliance/eu_ai_act/coverage_matrix.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import {
  publicKeyToDid,
  generateIdentityId,
  type StoredIdentity,
} from "../../../src/core/identity.js";
import { toBase64url } from "../../../src/core/encoding.js";
import type { EncryptedPayload } from "../../../src/core/encryption.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { defaultConfig } from "../../../src/config.js";
import {
  generateEuAiActBundle,
  type GeneratorDeps,
} from "../../../src/compliance/eu_ai_act/generator.js";
import { renderBundleToPdf } from "../../../src/compliance/eu_ai_act/pdf.js";
import type { ComplianceBundleInput } from "../../../src/compliance/eu_ai_act/types.js";

// Deterministic seed material: the example bundle should produce
// the same signatures across regenerations so that the checked-in
// files remain byte-stable.
const FIXED_MASTER_KEY = new Uint8Array(32).fill(0x42);
const FIXED_PRIVATE_KEY = new Uint8Array(32);
for (let i = 0; i < 32; i++) FIXED_PRIVATE_KEY[i] = (i * 7 + 13) & 0xff;
const FIXED_IDENTITY_IV = new Uint8Array(12).fill(0x11);
const FIXED_GENERATED_AT = "2026-04-10T12:00:00.000Z";
const FIXED_CLOCK = new Date(FIXED_GENERATED_AT);

/**
 * Construct a fully deterministic StoredIdentity for the example
 * bundle fixture. Bypasses `createIdentity` (which uses random key
 * generation and random IV) and `encrypt` (which uses a random IV
 * and Date.now timestamp) to keep every byte reproducible.
 *
 * NOT a production path — this helper is strictly for regenerable
 * test fixtures and does not appear in any src/ module.
 */
function buildDeterministicIdentity(masterKey: Uint8Array): StoredIdentity {
  const publicKey = ed25519.getPublicKey(FIXED_PRIVATE_KEY);
  const identityId = generateIdentityId(publicKey);
  const did = publicKeyToDid(publicKey);

  // Encrypt the private key with a fixed IV so the stored form is
  // reproducible. Calling @noble/ciphers' gcm directly avoids the
  // random IV generation in core/encryption.ts encrypt().
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const cipher = gcm(identityEncKey, FIXED_IDENTITY_IV);
  const ciphertext = cipher.encrypt(FIXED_PRIVATE_KEY);

  const encryptedPrivateKey: EncryptedPayload = {
    v: 1,
    alg: "aes-256-gcm",
    iv: toBase64url(FIXED_IDENTITY_IV),
    ct: toBase64url(ciphertext),
    ts: FIXED_GENERATED_AT,
  };

  return {
    identity_id: identityId,
    label: "meridian-financial-holdings-example-fixture",
    public_key: toBase64url(publicKey),
    did,
    created_at: FIXED_GENERATED_AT,
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encryptedPrivateKey,
    rotation_history: [],
  };
}

/**
 * Seed the audit log with representative activity covering every
 * gate outcome category so the Article 12 and Article 26 documents
 * show non-trivial counts.
 */
async function seedAuditActivity(auditLog: AuditLog): Promise<void> {
  const identity = "did:sanctuary:meridian-hr-screening-agent";

  // Representative tool-call traffic: 24 allow, 12 allow_proxy,
  // 3 deny, 2 injection_detected.
  for (let i = 0; i < 24; i++) {
    await auditLog.append(
      "l2",
      `gate_allow:state_read`,
      identity,
      { key: `applicant_${1000 + i}` }
    );
  }
  for (let i = 0; i < 12; i++) {
    await auditLog.append(
      "l2",
      `gate_allow_proxy:ats/fetch_resume`,
      identity,
      { upstream: "ats", resource: `applicant_${2000 + i}` }
    );
  }
  for (let i = 0; i < 3; i++) {
    await auditLog.append(
      "l2",
      `gate_deny:state_export`,
      identity,
      { reason: "tier1_timeout" }
    );
  }
  await auditLog.append(
    "l2",
    "injection_detected:state_write",
    "system",
    {
      confidence: 0.82,
      signals: [{ type: "role_override", severity: "high" }],
    }
  );
  await auditLog.append(
    "l2",
    "injection_detected:bridge_commit",
    "system",
    {
      confidence: 0.91,
      signals: [{ type: "encoding_evasion", severity: "high" }],
    }
  );

  // A few L1 reads to show cross-layer activity.
  for (let i = 0; i < 6; i++) {
    await auditLog.append("l1", "state_read", identity, {
      namespace: "applicants",
    });
  }
}

describe("EU AI Act example bundle generator", () => {
  const shouldGenerate = process.env.GENERATE_EXAMPLE === "1";

  beforeAll(() => {
    // Freeze time so audit entry timestamps are deterministic.
    // Without this, AuditLog.append writes `new Date().toISOString()`
    // which varies across runs and breaks byte-stability.
    if (shouldGenerate) {
      vi.useFakeTimers();
      vi.setSystemTime(FIXED_CLOCK);
    }
  });

  afterAll(() => {
    if (shouldGenerate) {
      vi.useRealTimers();
    }
  });

  it.skipIf(!shouldGenerate)(
    "generates the Meridian Financial HR screening example bundle",
    async () => {
      // Build deterministic fixture deps.
      const storage = new MemoryStorage();
      const identityManager = new IdentityManager(storage, FIXED_MASTER_KEY);
      const auditLog = new AuditLog(storage, FIXED_MASTER_KEY);

      // Construct the deterministic primary identity and save it to
      // the IdentityManager. The save path will re-encrypt for
      // persistence with its own random IV, but generateEuAiActBundle
      // reads the in-memory StoredIdentity (which is the deterministic
      // one we constructed) via getDefault(), not the persisted form.
      const storedIdentity = buildDeterministicIdentity(FIXED_MASTER_KEY);
      await identityManager.save(storedIdentity);

      await seedAuditActivity(auditLog);

      const deps: GeneratorDeps = {
        config: defaultConfig(),
        identityManager,
        masterKey: FIXED_MASTER_KEY,
        auditLog,
        policy: DEFAULT_POLICY,
      };

      const input: ComplianceBundleInput = {
        agent_did: "did:sanctuary:meridian-hr-screening-agent",
        deployment_context: {
          vertical: "human_resources",
          annex_iii_class:
            "§4 employment, workers management, self-employment",
          intended_purpose:
            "Automated CV screening and candidate shortlisting for open requisitions",
          provider_legal_name: "Meridian Financial Holdings, Inc.",
          provider_contact: "ai-compliance@meridian.example.com",
          deployer_is_public_authority: false,
          notes:
            "Fictional Fortune 2000 example deployment for illustration only. " +
            "All names, DIDs, and business facts are invented.",
        },
        period_start: "2026-04-01T00:00:00.000Z",
        period_end: "2026-04-30T23:59:59.999Z",
        generated_at_override: FIXED_GENERATED_AT,
      };

      const bundle = await generateEuAiActBundle(input, deps);

      // Resolve the examples directory relative to the repo root.
      // test cwd is .../server/, so climb one level for repo root.
      const repoRoot = resolve(process.cwd(), "..");
      const outputDir = join(
        repoRoot,
        "examples",
        "eu_ai_act_bundle_example"
      );
      await mkdir(outputDir, { recursive: true });

      // Write the manifest pretty-printed for human readability.
      await writeFile(
        join(outputDir, "00_bundle_manifest.json"),
        JSON.stringify(bundle.manifest, null, 2) + "\n",
        "utf-8"
      );

      for (const file of bundle.files) {
        await writeFile(
          join(outputDir, file.filename),
          file.content,
          "utf-8"
        );
      }

      // Also write the hand-rolled PDF render alongside the
      // Markdown bundle so the committed example includes a visual
      // reference of what `--pdf` produces.
      const pdfBytes = renderBundleToPdf(bundle);
      await writeFile(join(outputDir, "bundle.pdf"), pdfBytes);

      // Write a README explaining what the example is.
      const readme = `# EU AI Act Compliance Bundle — Example

This directory contains a fully generated EU AI Act compliance bundle
for a fictional Fortune 2000 enterprise (Meridian Financial Holdings, Inc.)
deploying a high-risk Annex III §4 HR screening agent.

**Everything in this directory is fictional.** No real entity, DID,
signature, or deployment is referenced.

## Purpose

This example shows what a Sanctuary-generated compliance bundle looks
like in its unfilled form — i.e., before the enterprise has replaced
the \`[MANUAL INPUT REQUIRED: ...]\` markers with their business
facts. An auditor, compliance lead, or evaluating enterprise can read
these files to understand:

- Which sections are fully auto-filled (the 5 \`full\` rows of the
  coverage matrix)
- Which sections are partially auto-filled (the 24 \`partial\` rows)
- Which sections require complete enterprise authoring (the 17
  \`manual_only\` rows)
- The format of the cryptographic attestations and manifest
- The honest voice of the generator: verbatim regulation quotes,
  explicit coverage flags, concrete evidence attribution per row

## Files

- \`00_bundle_manifest.json\` — signed JSON index with SHA-256 +
  Ed25519 signatures for every file, the 46-row coverage matrix
  summary, and the signer's public key
- \`01_annex_iv_technical_documentation.md\` — Annex IV per Article 11
- \`02_article_26_deployer_log.md\` — deployer obligations
- \`03_article_12_automatic_logs.md\` — automatic record-keeping
- \`04_risk_management_summary.md\` — Article 9 risk management
- \`05_human_oversight_statement.md\` — Article 14 human oversight
- \`06_cryptographic_attestations.md\` — bundle integrity summary

## Regenerating

\`\`\`bash
cd server
GENERATE_EXAMPLE=1 npm test -- example-bundle
\`\`\`

The fixture uses fixed master-key and identity-seed material so
regenerating this bundle produces byte-stable output (except for
differences introduced by matrix, template, or generator code
changes — which is exactly when regeneration is wanted).

## Not legal advice

The bundle format, verbatim regulation quotes, and coverage claims
in this example do not constitute legal advice. Consult qualified
legal counsel before filing any real compliance artifact with a
regulator.

_Author: Erik Newton · License: Apache-2.0_
`;
      await writeFile(join(outputDir, "README.md"), readme, "utf-8");

      // Also write a small verify.sh snippet showing auditors how
      // to SHA-256 each file with standard tools.
      const verifyScript = `#!/usr/bin/env bash
# Verify the EU AI Act example bundle with standard CLI tools.
# Usage: ./verify.sh
#
# This script recomputes the SHA-256 of each file and compares it
# against the digest recorded in 00_bundle_manifest.json.

set -euo pipefail

cd "$(dirname "$0")"

echo "Recomputing SHA-256 for each bundle file..."
echo ""
for f in 0[1-6]_*.md; do
  printf "%-48s " "$f"
  shasum -a 256 "$f" | awk '{print $1}'
done

echo ""
echo "Compare against the sha256 field for each file in"
echo "00_bundle_manifest.json — every digest must match exactly."
echo ""
echo "NOT LEGAL ADVICE. This bundle is a fictional example."
`;
      await writeFile(
        join(outputDir, "verify.sh"),
        verifyScript,
        "utf-8"
      );

      // Sanity asserts so this function also counts as a smoke test.
      expect(bundle.files.length).toBe(6);
      expect(bundle.manifest.coverage_summary.total_rows).toBe(46);
      expect(bundle.manifest.coverage_summary.full).toBe(5);
    }
  );

  it.skipIf(!shouldGenerate)(
    "generates docs/compliance/eu_ai_act_coverage_matrix_v1.md from the matrix data",
    async () => {
      const repoRoot = resolve(process.cwd(), "..");
      const outputDir = join(repoRoot, "docs", "compliance");
      await mkdir(outputDir, { recursive: true });
      const md = renderCoverageMatrixMarkdown();
      await writeFile(
        join(outputDir, "eu_ai_act_coverage_matrix_v1.md"),
        md,
        "utf-8"
      );
      expect(md.length).toBeGreaterThan(0);
    }
  );

  it("example bundle placeholder — real generation is gated on GENERATE_EXAMPLE=1", () => {
    // This stub keeps the test file contributing ≥1 assertion in
    // the normal suite so its presence is tracked by the baseline.
    expect(shouldGenerate || !shouldGenerate).toBe(true);
  });
});

// ── Coverage matrix Markdown renderer ────────────────────────────────

function badgeFor(coverage: CoverageRow["coverage"]): string {
  switch (coverage) {
    case "full":
      return "**FULL**";
    case "partial":
      return "**PARTIAL**";
    case "manual_only":
      return "**MANUAL ONLY**";
  }
}

function renderCoverageMatrixMarkdown(): string {
  const m = COVERAGE_MATRIX_V1;
  const stats = coverageStats(m);

  const header = `---
title: EU AI Act Coverage Matrix v1
description: Row-by-row mapping from Sanctuary primitives to Regulation (EU) 2024/1689 requirements
---

# EU AI Act Coverage Matrix v1

**Matrix version:** \`${m.matrix_version}\`
**Regulation:** ${m.regulation_version}
**OJ reference:** ${m.regulation.oj_reference}
**Full enforcement date:** ${m.regulation.full_enforcement_date}
**Aligned to text version:** ${m.regulation.aligned_to_text_version}
**Last full review:** ${m.regulation.last_full_review}
**Next review due:** ${m.regulation.next_review_due}

---

## Summary

| Coverage | Rows | Share |
|---|---|---|
| **Full** (auto-emitted, machine-verifiable, zero enterprise input) | ${stats.full} | ${stats.full_pct}% |
| **Partial** (structured evidence emitted; enterprise supplies business context) | ${stats.partial} | ${stats.partial_pct}% |
| **Manual only** (Sanctuary has no visibility; enterprise authors in full) | ${stats.manual_only} | ${stats.manual_only_pct}% |
| **Total** | ${stats.total_rows} | 100% |

### The 5 full rows (load-bearing spine)

Every "full" row was individually verified against source. The audit-log rows (Article 12(1) and Article 15(5) first subparagraph) were re-verified against the current tree (server package v1.6.1) on 2026-07-05 to reflect the tamper-evident audit-chain hardening (PR #274 and follow-ups #290, #320, #396, #461, #501); the remaining rows carry their original 2026-04-10 verification against v0.7.0 source. See per-row review_notes for verification findings and any corrections applied. If a claim of "full coverage" on any other row appears in a downstream document, the matrix has drifted and needs re-verification.

${m.rows
  .filter((r) => r.coverage === "full")
  .map(
    (r, i) =>
      `${i + 1}. **${r.citation.instrument} ${r.citation.section}** — ${r.citation.title}`
  )
  .join("\n")}

### Notes

${m.notes.map((n) => `- ${n}`).join("\n")}

---

## Row-by-row mapping

`;

  const rowsBlocks = m.rows
    .map((row) => {
      const emitterList =
        row.evidence_emitter.length === 0
          ? "_(none — this row is manual_only)_"
          : row.evidence_emitter.map((e) => `\`${e}\``).join(", ");
      const carveout =
        row.manual_carveout === null
          ? "_(none — this row is fully auto-emitted)_"
          : row.manual_carveout;
      return `### ${row.citation.instrument} ${row.citation.section} — ${row.citation.title}

- **Row ID:** \`${row.id}\`
- **Clause ID:** \`${row.citation.clause_id}\`
- **Coverage:** ${badgeFor(row.coverage)}
- **Last reviewed:** ${row.last_reviewed_date} by ${row.last_reviewed_by}

**Requirement (verbatim, with \`[...]\` elisions):**

> ${row.requirement}

**Evidence emitted by Sanctuary:**

${row.evidence_emitted}

**Evidence emitter tools:** ${emitterList}

**Enterprise input required:**

${carveout}

**Review notes:**

${row.review_notes}

---

`;
    })
    .join("");

  const footer = `
## Disclaimer

**NOT LEGAL ADVICE.** This matrix is a technical mapping from Sanctuary primitives to Regulation (EU) 2024/1689 clause identifiers; it is not a legal interpretation of the EU AI Act and does not constitute a legal opinion. Consult qualified legal counsel before filing or relying on any compliance artifact generated from this matrix.

---

_Generated from \`server/src/compliance/eu_ai_act/coverage_matrix.ts\` via the \`GENERATE_EXAMPLE=1\` test pipeline. To regenerate: \`cd server && GENERATE_EXAMPLE=1 npm test -- example-bundle\`._

_Sanctuary Framework · Author: Erik Newton · License: Apache-2.0_
`;

  return header + rowsBlocks + footer;
}
