import { describe, expect, it } from "vitest";
import {
  LocalPrivacyEngine,
  PrivacyPolicyStore,
  type PrivacyPolicy,
} from "../../src/l2-operational/privacy-core.js";
import { PrivacyPlaceholderVault } from "../../src/l2-operational/privacy-filter.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { PRIVACY_FIELD_PATH_PATTERN } from "../../src/contracts/v1.1/constants.js";

const IDENTITY_ID = "did:example:operator";
const AGENT_ID = "agent-privacy-core";

describe("v1.1 local privacy core", () => {
  it("filters nested objects and arrays with audit-safe metadata", async () => {
    const { engine, vault, auditLog, storage } = setup();
    const policy = makePolicy({
      client_names: ["Acme Corp", "Acme"],
      project_names: ["Project Phoenix"],
      domain_terms: ["merger price"],
    });

    const result = await engine.filterOutbound({
      payload: {
        messages: [
          {
            role: "user",
            content:
              "Email jane@example.com at Acme Corp about Project Phoenix. " +
              "Use sk-1234567890abcdef and /Users/erik/Clients/Acme/plan.md. " +
              "Domain term: merger price.",
          },
        ],
        metadata: {
          owner_name: "Jane Smith",
          account_ref: "acct_PROD12345",
        },
        client_Acme: "Project Phoenix",
      },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
      audit_log: auditLog,
    });

    expect(result.status).toBe("filtered");
    expect(JSON.stringify(result.payload)).not.toContain("jane@example.com");
    expect(JSON.stringify(result.payload)).not.toContain("Acme Corp");
    expect(JSON.stringify(result.payload)).not.toContain("Project Phoenix");
    expect(JSON.stringify(result.payload)).not.toContain("/Users/erik");
    expect(JSON.stringify(result.payload)).toContain("EMAIL_1");
    expect(JSON.stringify(result.payload)).toContain("CLIENT_1");
    expect(JSON.stringify(result.payload)).toContain("PROJECT_1");
    expect(JSON.stringify(result.payload)).toContain("SECRET_1");
    expect(JSON.stringify(result.payload)).toContain("FILE_PATH_1");
    expect(JSON.stringify(result.payload)).toContain("TERM_1");
    expect(JSON.stringify(result.payload)).toContain("PERSON_1");
    expect(JSON.stringify(result.payload)).toContain("ACCOUNT_1");

    const audit = await auditLog.query({ operation_type: "privacy_event", limit: 10 });
    expect(audit.entries).toHaveLength(1);
    const details = audit.entries[0]!.details!;
    const serializedDetails = JSON.stringify(details);
    expect(serializedDetails).not.toContain("jane@example.com");
    expect(serializedDetails).not.toContain("Acme");
    expect(serializedDetails).not.toContain("Project Phoenix");
    expect(serializedDetails).not.toContain("/Users/erik");
    expect(details.kind).toBe("filtered");
    expect(details.policy_id).toBe(policy.policy_id);
    expect(details.identity_id).toBe(IDENTITY_ID);
    expect(details.destination_category).toBe("inference");

    const decisions = details.field_decisions as Array<{
      field_path: string;
      content_hash: string;
      hash_alg: string;
      placeholder_label?: string;
    }>;
    expect(decisions.length).toBeGreaterThanOrEqual(8);
    for (const decision of decisions) {
      expect(PRIVACY_FIELD_PATH_PATTERN.test(decision.field_path)).toBe(true);
      expect(decision.content_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(decision.hash_alg).toBe("hmac-sha256-fortress-keyed-v1");
      expect(decision.field_path).not.toContain("messages");
      expect(decision.field_path).not.toContain("metadata");
    }

    const vaultEntries = await storage.list("_privacy_placeholder_vault");
    expect(vaultEntries.length).toBeGreaterThan(0);
    for (const entry of vaultEntries) {
      const raw = await storage.read(entry.namespace, entry.key);
      expect(raw).not.toBeNull();
      const stored = bytesToString(raw!);
      expect(stored).not.toContain("jane@example.com");
      expect(stored).not.toContain("Acme");
      expect(stored).not.toContain("Project Phoenix");
      expect(stored).not.toContain("/Users/erik");
    }

    await expect(vault.resolvePlaceholder("CLIENT_1", IDENTITY_ID)).resolves.toBe(
      "Acme Corp"
    );
  });

  it("uses repeated stable placeholders across payloads for the same identity", async () => {
    const { engine } = setup();
    const policy = makePolicy({ client_names: ["Acme Corp"] });

    const first = await engine.filterOutbound({
      payload: { prompt: "Acme Corp asked Acme Corp to email jane@example.com" },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "tool-api",
    });
    const second = await engine.filterOutbound({
      payload: { prompt: "Follow up with Acme Corp at jane@example.com" },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "tool-api",
    });

    expect(JSON.stringify(first.payload)).toContain("CLIENT_1 asked CLIENT_1");
    expect(JSON.stringify(first.payload)).toContain("EMAIL_1");
    expect(JSON.stringify(second.payload)).toContain("CLIENT_1");
    expect(JSON.stringify(second.payload)).toContain("EMAIL_1");
  });

  it("maps distinct sensitive values in the same class to distinct placeholders", async () => {
    const { engine } = setup();
    const policy = makePolicy({ client_names: ["Acme Corp", "Beta LLC"] });

    const result = await engine.filterOutbound({
      payload: { prompt: "Route Acme Corp and Beta LLC through separate plans" },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });

    expect(result.status).toBe("filtered");
    expect(JSON.stringify(result.payload)).toContain("CLIENT_1");
    expect(JSON.stringify(result.payload)).toContain("CLIENT_2");
    expect(JSON.stringify(result.payload)).not.toContain("Acme Corp");
    expect(JSON.stringify(result.payload)).not.toContain("Beta LLC");
  });

  it("filters long payloads that stay within the configured size limit", async () => {
    const { engine } = setup();
    const policy = makePolicy({ max_payload_bytes: 20_000, max_string_bytes: 20_000 });
    const longPrompt = `${"context ".repeat(900)}Contact jane@example.com`;

    const result = await engine.filterOutbound({
      payload: { prompt: longPrompt },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });

    expect(result.status).toBe("filtered");
    expect(JSON.stringify(result.payload)).toContain("EMAIL_1");
    expect(JSON.stringify(result.payload)).not.toContain("jane@example.com");
  });

  it("denies payloads that exceed depth limits", async () => {
    const { engine } = setup();
    const policy = makePolicy({ max_depth: 2 });

    const result = await engine.filterOutbound({
      payload: { a: { b: { c: "Contact jane@example.com" } } },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });

    expect(result.status).toBe("denied");
    expect(result.audit_payload.kind).toBe("denied");
    expect(result.audit_payload.denial_reason_class).toBe("fail_closed_filter_error");
  });

  it("denies payloads that exceed size limits", async () => {
    const { engine } = setup();
    const policy = makePolicy({ max_payload_bytes: 32 });

    const result = await engine.filterOutbound({
      payload: { prompt: "Contact jane@example.com about a sensitive project" },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });

    expect(result.status).toBe("denied");
    expect(result.audit_payload.denial_reason_class).toBe("fail_closed_filter_error");
  });

  it("detects secret-like values and account identifiers", async () => {
    const { engine } = setup();
    const policy = makePolicy();

    const result = await engine.filterOutbound({
      payload: {
        headers: {
          authorization: "Bearer abcdefghijklmnop123456",
          account: "acct_PROD12345",
        },
      },
      policy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "tool-api",
    });

    expect(result.status).toBe("filtered");
    expect(JSON.stringify(result.payload)).toContain("SECRET_1");
    expect(JSON.stringify(result.payload)).toContain("ACCOUNT_1");
    expect(JSON.stringify(result.payload)).not.toContain("abcdefghijklmnop123456");
    expect(JSON.stringify(result.payload)).not.toContain("acct_PROD12345");
  });

  it("rehydrates responses only when policy allows it", async () => {
    const { engine } = setup();
    const allowPolicy = makePolicy({
      client_names: ["Acme Corp"],
      rehydration: { allowed_destinations: ["inference"] },
    });
    const denyPolicy = makePolicy({
      policy_id: "privacy-policy-deny-rehydrate",
      client_names: ["Acme Corp"],
      rehydration: { default_action: "deny" },
    });

    const filtered = await engine.filterOutbound({
      payload: { prompt: "Email jane@example.com at Acme Corp" },
      policy: allowPolicy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });
    expect(filtered.status).toBe("filtered");

    const allowed = await engine.rehydrateResponse({
      response: { text: "Send the draft to EMAIL_1 for CLIENT_1." },
      policy: allowPolicy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });
    expect(allowed.status).toBe("rehydrated");
    expect(allowed.response).toEqual({
      text: "Send the draft to jane@example.com for Acme Corp.",
    });
    expect(allowed.rehydrated_count).toBe(2);

    const denied = await engine.rehydrateResponse({
      response: { text: "Send the draft to EMAIL_1 for CLIENT_1." },
      policy: denyPolicy,
      identity_id: IDENTITY_ID,
      agent_id: AGENT_ID,
      destination_category: "inference",
    });
    expect(denied.status).toBe("denied");
    expect(denied.response).toEqual({
      text: "Send the draft to EMAIL_1 for CLIENT_1.",
    });
    expect(denied.audit_payload.denial_reason_class).toBe("policy_deny_rule");
  });

  it("stores identity-bound policies encrypted at rest", async () => {
    const storage = new MemoryStorage();
    const store = new PrivacyPolicyStore(storage, generateRandomKey());
    const policy = await store.create(makePolicy({
      policy_id: "privacy-policy-store-test",
      client_names: ["Acme Corp"],
    }));

    await expect(store.get(policy.policy_id, IDENTITY_ID)).resolves.toMatchObject({
      policy_id: policy.policy_id,
      identity_id: IDENTITY_ID,
    });
    await expect(store.get(policy.policy_id, "did:example:other")).resolves.toBeNull();

    const entries = await storage.list("_privacy_policies");
    expect(entries).toHaveLength(1);
    const raw = await storage.read(entries[0]!.namespace, entries[0]!.key);
    expect(raw).not.toBeNull();
    expect(bytesToString(raw!)).not.toContain("Acme Corp");
    expect(bytesToString(raw!)).not.toContain(IDENTITY_ID);
  });
});

function setup(): {
  storage: MemoryStorage;
  vault: PrivacyPlaceholderVault;
  engine: LocalPrivacyEngine;
  auditLog: AuditLog;
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const vault = new PrivacyPlaceholderVault(storage, masterKey);
  return {
    storage,
    vault,
    engine: new LocalPrivacyEngine(vault, masterKey),
    auditLog: new AuditLog(storage, masterKey),
  };
}

function makePolicy(overrides: Partial<PrivacyPolicy> = {}): PrivacyPolicy {
  return {
    version: 1,
    policy_id: "privacy-policy",
    policy_name: "Test Privacy Policy",
    identity_id: IDENTITY_ID,
    detector_actions: {},
    rehydration: { default_action: "deny" },
    max_depth: 16,
    max_payload_bytes: 1024 * 1024,
    max_string_bytes: 128 * 1024,
    created_at: "2026-04-25T00:00:00.000Z",
    updated_at: "2026-04-25T00:00:00.000Z",
    ...overrides,
  };
}
