/**
 * Sanctuary v1.1 Acceptance Drill - Pillar 1: Query Privacy.
 *
 * Proves that an outbound payload containing PII, secrets, project, and
 * client identifiers is filtered, audited safely, and rehydrated only when
 * the bound policy permits. Plus a fail-closed sub-drill: missing policy
 * denies; operator-override permits with audit trail.
 *
 * The drill exercises `LocalPrivacyEngine` end-to-end against a real
 * `MemoryStorage`, real `PrivacyPlaceholderVault`, real `AuditLog`, and a
 * real fortress master key. No mocks at the engine boundary. The proof
 * shape mirrors `server/test/privacy-enforcement/end-to-end.test.ts`:
 * magic-string substring search against the audit payload + filtered
 * payload bytes is the authoritative leak gate.
 *
 * Acceptance checklist mapping: Pillar 1 of
 * `server/docs/v1.1-acceptance-checklist.md`.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { PrivacyPlaceholderVault } from "../../src/operational/privacy-filter.js";
import {
  LocalPrivacyEngine,
  type PrivacyPolicy,
} from "../../src/operational/privacy-core.js";
import type {
  PrivacyAllowedPayload,
  PrivacyAuditPayload,
  PrivacyDeniedPayload,
  PrivacyDestinationCategory,
  PrivacyFilteredPayload,
  PrivacyRehydratedPayload,
} from "../../src/contracts/v1.1/index.js";

const IDENTITY_ID = "did:example:operator-drill-privacy";
const AGENT_ID = "agent-drill-alpha";
const POLICY_ID = "drill-privacy-policy";

// High-entropy magic literals: a substring grep of any of these against
// the filtered payload OR the audit payload is the leak proof.
const MAGIC_EMAIL = "alice.zzqq42@worldsuniqueprivacytestmail.example";
const MAGIC_CLIENT = "Hexapod-Industries-LLC-9f4e";
const MAGIC_PROJECT = "Project-Quintessence-XR-882";
const MAGIC_SECRET = "sk-drill-Z9fA7QwELx3pKvNs1234567";
const MAGIC_PERSON_NAME = "Charlotte Wessenberg";

interface DrillContext {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  vault: PrivacyPlaceholderVault;
  engine: LocalPrivacyEngine;
  auditLog: AuditLog;
}

function setupDrill(): DrillContext {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  const engine = new LocalPrivacyEngine(vault, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  return { storage, masterKey, vault, engine, auditLog };
}

function makePolicy(overrides: Partial<PrivacyPolicy> = {}): PrivacyPolicy {
  return {
    version: 1,
    policy_id: POLICY_ID,
    policy_name: "Drill Privacy Policy",
    identity_id: IDENTITY_ID,
    detector_actions: {},
    client_names: [MAGIC_CLIENT],
    project_names: [MAGIC_PROJECT],
    person_names: [MAGIC_PERSON_NAME],
    rehydration: { allowed_destinations: ["tool-api", "inference"] },
    max_depth: 16,
    max_payload_bytes: 64 * 1024,
    max_string_bytes: 16 * 1024,
    placeholder_scope: "identity",
    created_at: "2026-04-25T00:00:00.000Z",
    updated_at: "2026-04-25T00:00:00.000Z",
    ...overrides,
  };
}

function buildPayload(): Record<string, unknown> {
  return {
    role: "user",
    content:
      `Email ${MAGIC_EMAIL} re ${MAGIC_CLIENT} on ${MAGIC_PROJECT}. ` +
      `Use credential ${MAGIC_SECRET} and loop in ${MAGIC_PERSON_NAME}.`,
    nested: {
      project_ref: MAGIC_PROJECT,
      client_ref: MAGIC_CLIENT,
    },
  };
}

describe("v1.1 acceptance drill - Pillar 1: query privacy", () => {
  it("filterOutbound replaces every magic span with placeholders and emits a safe filtered audit payload", async () => {
    const ctx = setupDrill();
    const policy = makePolicy();

    const decision = await ctx.engine.filterOutbound({
      payload: buildPayload(),
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });

    expect(decision.status).toBe("filtered");
    expect(decision.payload).toBeDefined();

    // The wire bytes after filter MUST contain zero raw magic spans.
    const wireBytes = JSON.stringify(decision.payload);
    expect(wireBytes).not.toContain(MAGIC_EMAIL);
    expect(wireBytes).not.toContain(MAGIC_CLIENT);
    expect(wireBytes).not.toContain(MAGIC_PROJECT);
    expect(wireBytes).not.toContain(MAGIC_SECRET);
    expect(wireBytes).not.toContain(MAGIC_PERSON_NAME);
    // Placeholders are present.
    expect(wireBytes).toContain("EMAIL_");
    expect(wireBytes).toContain("CLIENT_");
    expect(wireBytes).toContain("PROJECT_");
    expect(wireBytes).toContain("PERSON_");

    const audit = decision.audit_payload as PrivacyFilteredPayload;
    expect(audit.kind).toBe("filtered");
    expect(audit.policy_id).toBe(POLICY_ID);
    expect(audit.identity_id).toBe(IDENTITY_ID);
    expect(audit.agent_id).toBe(AGENT_ID);
    expect(audit.destination_category).toBe<PrivacyDestinationCategory>(
      "inference",
    );
    expect(audit.outbound_payload_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(audit.payload_hash_alg).toBe("hmac-sha256-fortress-keyed-v1");

    // Every detector that fired surfaces in field_decisions; the contract
    // narrows them to PRIVACY_DETECTOR_CLASSES from the v1.1 constants. We
    // assert the set is non-empty, every entry has the expected shape, and
    // the set is a subset of the documented enum (deliberately loose on
    // exact membership; the underlying detector-class taxonomy collapses
    // person/email/phone/url/etc. into "person" by design).
    expect(audit.field_decisions.length).toBeGreaterThan(0);
    const VALID_DETECTOR_CLASSES = new Set([
      "person",
      "client",
      "project",
      "secret",
      "credential",
      "account",
      "file_path",
      "domain_term",
      "custom",
    ]);
    const detectorClasses = new Set(
      audit.field_decisions.map((d) => d.detector_class),
    );
    for (const cls of detectorClasses) {
      expect(VALID_DETECTOR_CLASSES.has(cls)).toBe(true);
    }
    // Sanity: at least three distinct detector classes fired across the
    // payload (covers client/project + person/credential).
    expect(detectorClasses.size).toBeGreaterThanOrEqual(3);
    for (const decisionEntry of audit.field_decisions) {
      expect(decisionEntry.action).toMatch(/^(redact|hash|placeholder)$/);
      expect(decisionEntry.content_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(decisionEntry.hash_alg).toBe(
        "hmac-sha256-fortress-keyed-v1",
      );
      // Placeholder labels follow the documented detector-id pattern.
      if (decisionEntry.placeholder_label) {
        expect(decisionEntry.placeholder_label).toMatch(
          /^(EMAIL|PHONE|SSN|CARD|PERSON|CLIENT|PROJECT|SECRET|CREDENTIAL|ACCOUNT|FILE_PATH|TERM|ADDRESS|URL|DATE|PRIVATE)_\d+$/,
        );
      }
    }

    // No raw magic value appears anywhere in the audit payload either.
    const auditBytes = JSON.stringify(audit);
    expect(auditBytes).not.toContain(MAGIC_EMAIL);
    expect(auditBytes).not.toContain(MAGIC_CLIENT);
    expect(auditBytes).not.toContain(MAGIC_PROJECT);
    expect(auditBytes).not.toContain(MAGIC_SECRET);
    expect(auditBytes).not.toContain(MAGIC_PERSON_NAME);
  });

  it("rehydrateResponse swaps placeholders back to vault-stored values when policy permits", async () => {
    const ctx = setupDrill();
    const policy = makePolicy();

    // Step 1: outbound filter establishes the placeholder mapping.
    const filtered = await ctx.engine.filterOutbound({
      payload: { content: `Draft for ${MAGIC_CLIENT} on ${MAGIC_PROJECT}.` },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "tool-api",
      audit_log: ctx.auditLog,
    });
    expect(filtered.status).toBe("filtered");
    const filteredText = JSON.stringify(filtered.payload);
    // Capture the placeholder ids that were minted.
    const clientPlaceholder = filteredText.match(/CLIENT_\d+/)?.[0];
    const projectPlaceholder = filteredText.match(/PROJECT_\d+/)?.[0];
    expect(clientPlaceholder).toBeDefined();
    expect(projectPlaceholder).toBeDefined();

    // Step 2: simulate provider response containing those placeholders.
    const providerResponse = {
      output: `Draft for ${clientPlaceholder} on ${projectPlaceholder} ready.`,
    };
    const rehydration = await ctx.engine.rehydrateResponse({
      response: providerResponse,
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "tool-api",
      audit_log: ctx.auditLog,
    });
    expect(rehydration.status).toBe("rehydrated");
    expect(rehydration.rehydrated_count).toBeGreaterThan(0);

    const rehydratedText = JSON.stringify(rehydration.response);
    expect(rehydratedText).toContain(MAGIC_CLIENT);
    expect(rehydratedText).toContain(MAGIC_PROJECT);
    expect(rehydratedText).not.toContain(clientPlaceholder!);
    expect(rehydratedText).not.toContain(projectPlaceholder!);

    const audit = rehydration.audit_payload as PrivacyRehydratedPayload;
    expect(audit.kind).toBe("rehydrated");
    expect(audit.policy_id).toBe(POLICY_ID);
    expect(audit.rehydrated_count).toBeGreaterThan(0);
  });

  it("payload that contains no sensitive content returns kind=allowed with zero findings", async () => {
    const ctx = setupDrill();
    const policy = makePolicy();
    const decision = await ctx.engine.filterOutbound({
      payload: { content: "What is the weather forecast for tomorrow?" },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });
    expect(decision.status).toBe("allowed");
    const audit = decision.audit_payload as PrivacyAllowedPayload;
    expect(audit.kind).toBe("allowed");
    expect(audit.outbound_payload_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("v1.1 acceptance drill - Pillar 1 fail-closed sub-drill", () => {
  it("filterOutbound denies fail-closed when no policy is bound", async () => {
    const ctx = setupDrill();
    const decision = await ctx.engine.filterOutbound({
      payload: buildPayload(),
      policy: null,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });
    expect(decision.status).toBe("denied");
    expect(decision.payload).toBeUndefined();
    const audit = decision.audit_payload as PrivacyDeniedPayload;
    expect(audit.kind).toBe("denied");
    expect(audit.denial_reason_class).toBe("fail_closed_no_policy");
  });

  it("rehydrateResponse denies fail-closed when no policy is bound", async () => {
    const ctx = setupDrill();
    const decision = await ctx.engine.rehydrateResponse({
      response: { output: "anything" },
      policy: null,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });
    expect(decision.status).toBe("denied");
    const audit = decision.audit_payload as PrivacyDeniedPayload;
    expect(audit.kind).toBe("denied");
    expect(audit.denial_reason_class).toBe("fail_closed_no_policy");
  });

  it("filterOutbound denies fail-closed when payload exceeds the size limit", async () => {
    const ctx = setupDrill();
    const tinyPolicy = makePolicy({ max_payload_bytes: 64 });
    const decision = await ctx.engine.filterOutbound({
      payload: {
        content: "x".repeat(200),
        more: "y".repeat(200),
      },
      policy: tinyPolicy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });
    expect(decision.status).toBe("denied");
    const audit = decision.audit_payload as PrivacyDeniedPayload;
    expect(audit.denial_reason_class).toBe("fail_closed_filter_error");
  });

  it("operator override allow_on_filter_error permits the call when filter raises", async () => {
    const ctx = setupDrill();
    const overridePolicy = makePolicy({
      max_payload_bytes: 64,
      operator_override: { allow_on_filter_error: true },
    });
    const decision = await ctx.engine.filterOutbound({
      payload: {
        content: "x".repeat(200),
        more: "y".repeat(200),
      },
      policy: overridePolicy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: ctx.auditLog,
    });
    expect(decision.status).toBe("allowed");
    const audit = decision.audit_payload as PrivacyAuditPayload;
    expect(audit.kind).toBe("allowed");
  });
});
