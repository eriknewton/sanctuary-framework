/**
 * Capability: a broker open reads BOTH policy files, and every way the pair can
 * be wrong yields zero grants plus one audit line carrying a fixed class. Covers
 * the conflict rule, the ENOENT-versus-present-and-broken split on each file,
 * and the silence an absent file is entitled to.
 *
 * Host-free: a temp storage directory and an in-memory audit chain per test. No
 * keychain, no `security` subprocess, nothing under the operator's fortress.
 *
 * Defect id: SURROGATE-POLICY-LOAD-COLLAPSED.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  brokerPolicyPath,
  loadBrokerAndSurrogatePolicies,
  loadBrokerGrantsClassified,
  surrogatePolicyPath,
} from "../../../src/disclosure/broker/open.js";
import { SURROGATE_POLICY_VERSION } from "../../../src/disclosure/broker/policy.js";
import { AuditLog, BROKER_OPS } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

let storagePath: string;
const PRINCIPAL = "did:sanctuary:principal";

const BINDING = {
  secret: "openai-api-key",
  agent: "hermes",
  env: "OPENAI_API_KEY",
  destinations: [{ host: "api.openai.com", port: 443 }],
  header: "Authorization",
};

function freshAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

async function writeSurrogate(bindings: unknown[]): Promise<void> {
  await writeFile(
    surrogatePolicyPath(storagePath),
    JSON.stringify({ surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings }),
    "utf8",
  );
}

async function writeBroker(
  skills: Array<{ name: string; secrets: Array<{ name: string; scope?: string }> }>,
): Promise<void> {
  await writeFile(brokerPolicyPath(storagePath), JSON.stringify({ skills }), "utf8");
}

async function loadFailures(auditLog: AuditLog) {
  await auditLog.flush();
  return (await auditLog.query({ operation_type: BROKER_OPS.POLICY_LOAD_FAILED })).entries;
}

beforeEach(async () => {
  storagePath = await mkdtemp(join(tmpdir(), "sanctuary-surrogate-reconcile-"));
});

afterEach(async () => {
  await rm(storagePath, { recursive: true, force: true });
});

describe("broker open reconciles both policy files", () => {
  it("both files absent yields zero grants, zero bindings and NO audit line", async () => {
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.grants).toEqual([]);
    expect(result.bindings).toEqual([]);
    // Silence is the point: a line here would land on every open of every
    // fortress that never used the broker.
    expect(await loadFailures(auditLog)).toHaveLength(0);
  });

  it("ordinary grants with no surrogate policy load unchanged and silently", async () => {
    await writeBroker([{ name: "mailer", secrets: [{ name: "sendgrid-key", scope: "read" }] }]);
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.grants).toHaveLength(1);
    expect(result.grants[0]!.secret).toBe("sendgrid-key");
    expect(result.bindings).toEqual([]);
    expect(await loadFailures(auditLog)).toHaveLength(0);
  });

  it("bindings and unrelated grants coexist", async () => {
    await writeSurrogate([BINDING]);
    await writeBroker([{ name: "mailer", secrets: [{ name: "sendgrid-key", scope: "read" }] }]);
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.grants.map((g) => g.secret)).toEqual(["sendgrid-key"]);
    expect(result.bindings.map((b) => b.secret)).toEqual(["openai-api-key"]);
    expect(await loadFailures(auditLog)).toHaveLength(0);
  });

  it("a secret both bound and granted yields ZERO grants and one conflict line", async () => {
    await writeSurrogate([BINDING]);
    await writeBroker([
      { name: "mailer", secrets: [{ name: "openai-api-key", scope: "read" }] },
      { name: "mailer", secrets: [{ name: "sendgrid-key", scope: "read" }] },
    ]);
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    // Not "drop the conflicting grant and keep the rest": the unrelated
    // sendgrid grant is withheld too, so the disagreement is loud.
    expect(result.grants).toEqual([]);
    const failures = await loadFailures(auditLog);
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details?.failure_class).toBe("conflict");
    expect(failures[0]!.details?.secrets).toEqual(["openai-api-key"]);
  });

  it("a rotate grant on a bound secret is a conflict too", async () => {
    await writeSurrogate([BINDING]);
    await writeBroker([
      { name: "mailer", secrets: [{ name: "openai-api-key", scope: "rotate" }] },
    ]);
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.grants).toEqual([]);
    expect((await loadFailures(auditLog))[0]!.details?.failure_class).toBe("conflict");
  });

  it("a present but unparseable surrogate file yields zero grants and one json_error line", async () => {
    await writeBroker([{ name: "mailer", secrets: [{ name: "sendgrid-key", scope: "read" }] }]);
    await writeFile(surrogatePolicyPath(storagePath), "{ not json", "utf8");
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    // A fortress that meant to bind a secret away from the broker must not fall
    // back to the broker serving its grants because the binding file broke.
    expect(result.grants).toEqual([]);
    expect(result.bindings).toEqual([]);
    const failures = await loadFailures(auditLog);
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details?.file).toBe("surrogate");
    expect(failures[0]!.details?.failure_class).toBe("json_error");
  });

  it("an unknown surrogate policy version is refused as bad_version", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({ surrogate_policy_version: 99, bindings: [BINDING] }),
      "utf8",
    );
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.bindings).toEqual([]);
    expect((await loadFailures(auditLog))[0]!.details?.failure_class).toBe("bad_version");
  });

  it("a present but unparseable broker file yields zero grants and one json_error line", async () => {
    await writeFile(brokerPolicyPath(storagePath), "{ not json", "utf8");
    const auditLog = freshAuditLog();
    const result = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    expect(result.grants).toEqual([]);
    const failures = await loadFailures(auditLog);
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details?.file).toBe("broker");
    expect(failures[0]!.details?.failure_class).toBe("json_error");
  });

  it("an absent broker file is classified absent, not failed", async () => {
    expect(await loadBrokerGrantsClassified(storagePath)).toEqual({ outcome: "absent" });
  });

  it("a broker file that is a directory is a read_error, not an absence", async () => {
    // The pre-split code returned zero grants for BOTH, so an operator whose
    // grants stopped working had nothing to look at.
    const { mkdir } = await import("node:fs/promises");
    await mkdir(brokerPolicyPath(storagePath));
    const classified = await loadBrokerGrantsClassified(storagePath);
    expect(classified.outcome).toBe("failed");
    expect(classified).toMatchObject({ failureClass: "read_error" });
  });

  it("no audit detail ever carries parser text or policy content", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({
        surrogate_policy_version: SURROGATE_POLICY_VERSION,
        bindings: [{ ...BINDING, header: "Host" }],
      }),
      "utf8",
    );
    const auditLog = freshAuditLog();
    await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
      principalIdentityId: PRINCIPAL,
    });
    const failures = await loadFailures(auditLog);
    expect(failures).toHaveLength(1);
    const serialized = JSON.stringify(failures[0]!.details);
    expect(serialized).not.toContain("Host");
    expect(serialized).not.toContain("api.openai.com");
    expect(serialized).not.toContain("OPENAI_API_KEY");
    expect(Object.keys(failures[0]!.details ?? {}).sort()).toEqual(["failure_class", "file"]);
  });
});
