/**
 * Sanctuary MCP Server — EU AI Act Bundle Generator Tests
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * End-to-end integration tests for the EU AI Act compliance bundle
 * generator. Each test sets up a fresh fixture Sanctuary runtime
 * (in-memory storage + generated keys + default principal policy),
 * generates a bundle, and verifies:
 *
 *   - Bundle contains all 6 expected Markdown documents
 *   - Every file's SHA-256 matches hash(content)
 *   - Every file's Ed25519 signature verifies against the signer
 *   - Manifest signature verifies over canonical manifest body
 *   - Coverage summary matches the known 5/24/17 distribution
 *   - Generator errors cleanly when no primary identity is set
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../../src/core/identity.js";
import {
  fromBase64url,
  stringToBytes,
} from "../../../src/core/encoding.js";
import { hash } from "../../../src/core/hashing.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { IdentityManager } from "../../../src/cognitive/tools.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import { defaultConfig } from "../../../src/config.js";

import {
  generateEuAiActBundle,
  computeAuditPeriodSummary,
  createComplianceTools,
  type GeneratorDeps,
} from "../../../src/compliance/eu_ai_act/generator.js";
import type {
  ComplianceBundleInput,
  ComplianceBundle,
  BundleFile,
} from "../../../src/compliance/eu_ai_act/types.js";

// ── Fixture deps ─────────────────────────────────────────────────────

interface Fixture {
  deps: GeneratorDeps;
  masterKey: Uint8Array;
  storage: MemoryStorage;
  identityManager: IdentityManager;
  auditLog: AuditLog;
}

async function buildFixture(
  opts: { withPrimaryIdentity?: boolean } = {}
): Promise<Fixture> {
  const masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);

  if (opts.withPrimaryIdentity !== false) {
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "test-provider",
      identityEncKey,
      "fixture-passphrase"
    );
    await identityManager.save(storedIdentity);
  }

  const deps: GeneratorDeps = {
    config: defaultConfig(),
    identityManager,
    masterKey,
    auditLog,
    policy: DEFAULT_POLICY,
  };

  return { deps, masterKey, storage, identityManager, auditLog };
}

async function seedAuditEntries(auditLog: AuditLog, count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await auditLog.append(
      i % 2 === 0 ? "l1" : "l2",
      i % 3 === 0 ? `gate_allow:test_tool_${i}` : `gate_allow_proxy:upstream_${i}`,
      "test-principal",
      { iteration: i }
    );
  }
  await auditLog.append("l2", "gate_deny:dangerous_op", "test-principal", {});
  await auditLog.append(
    "l2",
    "injection_detected:malicious_op",
    "system",
    { confidence: 0.95 }
  );
}

function highRiskHRInput(): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:test-hr-agent",
    deployment_context: {
      vertical: "human_resources",
      annex_iii_class: "§4 employment, workers management, self-employment",
      intended_purpose: "CV screening and candidate shortlisting",
      provider_legal_name: "Meridian Financial Holdings, Inc.",
      provider_contact: "ai-compliance@meridian.example.com",
      deployer_is_public_authority: false,
    },
    period_start: "2026-04-01T00:00:00Z",
    period_end: "2026-04-30T23:59:59Z",
  };
}

function limitedRiskChatbotInput(): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:test-support-chatbot",
    deployment_context: {
      vertical: "customer_support",
      annex_iii_class: "limited-risk (Art. 50 transparency only)",
      intended_purpose: "Customer support chat with human handoff",
      provider_legal_name: "AcmeCo Support Division",
      provider_contact: "support-ai@acme.example.com",
    },
    period_start: "2026-04-01T00:00:00Z",
    period_end: "2026-04-30T23:59:59Z",
  };
}

function minimalRiskInternalInput(): ComplianceBundleInput {
  return {
    agent_did: "did:sanctuary:test-internal-tool",
    deployment_context: {
      vertical: "engineering",
      annex_iii_class: "minimal-risk (no specific obligations)",
      intended_purpose: "Internal developer productivity assistant",
      provider_legal_name: "Meridian Financial Holdings, Inc.",
    },
    period_start: "2026-04-01T00:00:00Z",
    period_end: "2026-04-30T23:59:59Z",
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("computeAuditPeriodSummary", () => {
  it("returns zeros for an empty audit log", async () => {
    const fx = await buildFixture();
    const summary = await computeAuditPeriodSummary(
      fx.auditLog,
      "2026-04-01T00:00:00Z",
      "2026-04-30T23:59:59Z"
    );
    expect(summary.total_entries).toBe(0);
    expect(summary.gate_decisions.allow).toBe(0);
    expect(summary.gate_decisions.allow_proxy).toBe(0);
    expect(summary.gate_decisions.deny).toBe(0);
    expect(summary.injection_detected).toBe(0);
  });

  it("counts gate decisions across all prefixes including gate_allow_proxy", async () => {
    const fx = await buildFixture();
    await seedAuditEntries(fx.auditLog, 6);
    const summary = await computeAuditPeriodSummary(
      fx.auditLog,
      "2020-01-01T00:00:00Z",
      "2030-12-31T23:59:59Z"
    );
    // 6 seed entries + 1 deny + 1 injection = 8 total
    expect(summary.total_entries).toBe(8);
    // i % 3 === 0 → gate_allow (i=0, 3) = 2
    expect(summary.gate_decisions.allow).toBe(2);
    // else → gate_allow_proxy (i=1, 2, 4, 5) = 4
    expect(summary.gate_decisions.allow_proxy).toBe(4);
    expect(summary.gate_decisions.deny).toBe(1);
    expect(summary.injection_detected).toBe(1);
  });

  it("filters entries by period_end upper bound", async () => {
    const fx = await buildFixture();
    // Entries get now() timestamps; pick an end in the past to filter all out.
    await seedAuditEntries(fx.auditLog, 3);
    const summary = await computeAuditPeriodSummary(
      fx.auditLog,
      "1970-01-01T00:00:00Z",
      "1970-01-01T00:00:01Z"
    );
    expect(summary.total_entries).toBe(0);
  });
});

describe("generateEuAiActBundle", () => {
  let fx: Fixture;

  beforeEach(async () => {
    fx = await buildFixture();
    await seedAuditEntries(fx.auditLog, 4);
  });

  it("throws a clear error if no primary identity is configured", async () => {
    const emptyFx = await buildFixture({ withPrimaryIdentity: false });
    await expect(
      generateEuAiActBundle(highRiskHRInput(), emptyFx.deps)
    ).rejects.toThrow(/primary identity/i);
  });

  it("produces a bundle with exactly 7 Markdown documents and a manifest", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    expect(bundle.files.length).toBe(7);
    expect(bundle.files[0]!.filename).toBe("01_annex_iv_technical_documentation.md");
    expect(bundle.files[1]!.filename).toBe("02_article_26_deployer_log.md");
    expect(bundle.files[2]!.filename).toBe("03_article_12_automatic_logs.md");
    expect(bundle.files[3]!.filename).toBe("04_risk_management_summary.md");
    expect(bundle.files[4]!.filename).toBe("05_human_oversight_statement.md");
    expect(bundle.files[5]!.filename).toBe("06_cryptographic_attestations.md");
    expect(bundle.files[6]!.filename).toBe("07_annex_iii_classification.md");
    for (const f of bundle.files) {
      expect(f.content_type).toBe("text/markdown");
    }
  });

  it("every file's sha256 field matches SHA-256 of its content bytes", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    for (const file of bundle.files) {
      const computed = Buffer.from(hash(stringToBytes(file.content))).toString(
        "hex"
      );
      expect(file.sha256).toBe(computed);
    }
  });

  it("every file's Ed25519 signature verifies against the signer's public key", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const signerPubkey = fromBase64url(bundle.manifest.signer.public_key_base64url);
    for (const file of bundle.files) {
      expect(file.signature).toBeDefined();
      const sigBytes = fromBase64url(file.signature!);
      const digest = hash(stringToBytes(file.content));
      expect(verify(digest, sigBytes, signerPubkey)).toBe(true);
    }
  });

  it("manifest carries the exact 46-row coverage summary", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    expect(bundle.manifest.coverage_summary.total_rows).toBe(46);
    expect(bundle.manifest.coverage_summary.full).toBe(5);
    expect(bundle.manifest.coverage_summary.partial).toBe(24);
    expect(bundle.manifest.coverage_summary.manual_only).toBe(17);
    expect(bundle.manifest.coverage_rows.length).toBe(46);
  });

  it("manifest includes NOT LEGAL ADVICE disclaimer", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    expect(bundle.manifest.disclaimer).toContain("NOT legal advice");
  });

  it("manifest has a non-empty signature and signer block", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    expect(bundle.manifest.manifest_signature).toBeTruthy();
    expect(bundle.manifest.signer.did).toBeTruthy();
    expect(bundle.manifest.signer.public_key_base64url).toBeTruthy();
    // Ed25519 signatures are 64 bytes → 86 base64url chars (no padding)
    expect(fromBase64url(bundle.manifest.manifest_signature).length).toBe(64);
  });

  it("Annex IV document contains [MANUAL INPUT REQUIRED] markers for business context", async () => {
    const bundle = await generateEuAiActBundle(
      minimalRiskInternalInput(), // has fewer deployment facts supplied
      fx.deps
    );
    const annexIV = bundle.files.find((f) =>
      f.filename.includes("annex_iv")
    )!;
    expect(annexIV.content).toContain("[MANUAL INPUT REQUIRED:");
  });

  it("Annex IV document cites Regulation (EU) 2024/1689 verbatim", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const annexIV = bundle.files.find((f) =>
      f.filename.includes("annex_iv")
    )!;
    expect(annexIV.content).toContain("2024/1689");
    expect(annexIV.content).toContain("Annex IV");
  });

  it("Article 26 document includes the reporting period audit summary table", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const art26 = bundle.files.find((f) =>
      f.filename.includes("article_26")
    )!;
    expect(art26.content).toContain("Total audit entries");
    expect(art26.content).toContain("Gate decisions — allow_proxy");
  });

  it("Article 12 document enumerates gate_allow_proxy in the outcome taxonomy", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const art12 = bundle.files.find((f) =>
      f.filename.includes("article_12")
    )!;
    expect(art12.content).toContain("gate_allow_proxy");
  });

  it("every document carries the NOT legal advice footer", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    for (const file of bundle.files) {
      expect(file.content.toLowerCase()).toContain("not legal advice");
    }
  });

  it("every document carries the signer DID in its header table", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const signerDid = bundle.manifest.signer.did;
    for (const file of bundle.files) {
      expect(file.content).toContain(signerDid);
    }
  });

  it("attestations document lists the first 5 files with their hashes", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const attestations = bundle.files.find((f) =>
      f.filename.includes("cryptographic_attestations")
    )!;
    for (let i = 0; i < 5; i++) {
      expect(attestations.content).toContain(bundle.files[i]!.filename);
      expect(attestations.content).toContain(bundle.files[i]!.sha256);
    }
  });

  it("bundles for distinct deployment contexts produce distinct content", async () => {
    const hr = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const chat = await generateEuAiActBundle(limitedRiskChatbotInput(), fx.deps);
    const internal = await generateEuAiActBundle(
      minimalRiskInternalInput(),
      fx.deps
    );
    // Agent DIDs are distinct and appear in every document
    const hrAnnex = hr.files[0]!.content;
    const chatAnnex = chat.files[0]!.content;
    const internalAnnex = internal.files[0]!.content;
    expect(hrAnnex).toContain("test-hr-agent");
    expect(chatAnnex).toContain("test-support-chatbot");
    expect(internalAnnex).toContain("test-internal-tool");
    expect(hrAnnex).not.toEqual(chatAnnex);
    expect(chatAnnex).not.toEqual(internalAnnex);
  });

  it("minimal-risk bundle still produces all 7 documents", async () => {
    const bundle = await generateEuAiActBundle(
      minimalRiskInternalInput(),
      fx.deps
    );
    expect(bundle.files.length).toBe(7);
  });

  it("Annex III classification document reports no candidates for out-of-scope agents", async () => {
    const bundle = await generateEuAiActBundle(
      minimalRiskInternalInput(),
      fx.deps
    );
    const doc7 = bundle.files.find((f) =>
      f.filename.includes("annex_iii_classification")
    )!;
    expect(doc7).toBeDefined();
    // Minimal-risk internal tool has "developer productivity assistant"
    // as intended_purpose which should not match any Annex III category
    expect(doc7.content).toContain("No candidate category cleared");
  });

  it("Annex III classification document reports §4(a) for HR screening agent", async () => {
    const bundle = await generateEuAiActBundle(highRiskHRInput(), fx.deps);
    const doc7 = bundle.files.find((f) =>
      f.filename.includes("annex_iii_classification")
    )!;
    expect(doc7.content).toContain("Annex III §4(a)");
    expect(doc7.content).toContain("employment");
  });
});

describe("createComplianceTools MCP factory", () => {
  it("registers the bundle generator tool", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    const names = tools.map((t) => t.name);
    expect(names).toContain("compliance_generate_eu_ai_act_bundle");
  });

  it("tool handler returns a bundle summary on success", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    const bundleTool = tools.find(
      (t) => t.name === "compliance_generate_eu_ai_act_bundle"
    )!;
    const result = await bundleTool.handler(
      highRiskHRInput() as unknown as Record<string, unknown>
    );
    const parsed = JSON.parse(
      (result.content[0] as { text: string }).text
    ) as {
      bundle_version: string;
      file_count: number;
      coverage_summary: { total_rows: number; full: number };
    };
    expect(parsed.bundle_version).toBe("1.0");
    expect(parsed.file_count).toBe(7);
    expect(parsed.coverage_summary.total_rows).toBe(46);
    expect(parsed.coverage_summary.full).toBe(5);
  });

  it("tool input schema requires the 4 expected fields", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    const bundleTool = tools.find(
      (t) => t.name === "compliance_generate_eu_ai_act_bundle"
    )!;
    const required = (bundleTool.inputSchema as { required: string[] }).required;
    expect(required).toEqual([
      "agent_did",
      "deployment_context",
      "period_start",
      "period_end",
    ]);
  });

  it("also registers compliance_eu_ai_act_annex_iii_classify", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    expect(tools.length).toBe(2);
    const classifyTool = tools.find(
      (t) => t.name === "compliance_eu_ai_act_annex_iii_classify"
    );
    expect(classifyTool).toBeDefined();
  });

  it("classify tool returns candidates for an HR-screening description", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    const classifyTool = tools.find(
      (t) => t.name === "compliance_eu_ai_act_annex_iii_classify"
    )!;
    const result = await classifyTool.handler({
      description:
        "CV screening and candidate shortlisting for open positions, analyzes job applications and evaluates candidates before human review",
    });
    const parsed = JSON.parse(
      (result.content[0] as { text: string }).text
    ) as {
      candidates: Array<{ category_id: string; rule_based_confidence: number }>;
      advisory: string;
    };
    expect(parsed.candidates.length).toBeGreaterThan(0);
    const topMatch = parsed.candidates[0]!;
    expect(topMatch.category_id).toBe("annex_iii_4_a_employment_recruitment");
    expect(topMatch.rule_based_confidence).toBeGreaterThan(0.8);
    expect(parsed.advisory).toContain("NOT legal advice");
  });

  it("classify tool returns an error for empty description", async () => {
    const fx = await buildFixture();
    const { tools } = createComplianceTools(fx.deps);
    const classifyTool = tools.find(
      (t) => t.name === "compliance_eu_ai_act_annex_iii_classify"
    )!;
    const result = await classifyTool.handler({ description: "" });
    const parsed = JSON.parse(
      (result.content[0] as { text: string }).text
    ) as { error?: string };
    expect(parsed.error).toBeDefined();
  });
});
