/**
 * Rung-1 point 3 TIGHTEN (2026-08-22): memory_ingest with a non-empty
 * allow_files list waives the secret classifier for those paths, so it must
 * be Tier 1 even when a hand-authored policy relaxed memory_ingest itself to
 * Tier 3. memory_ingest is NOT in FORCED_TIER1_OPERATIONS (unlike
 * memory_delete): an operator may legitimately relax plain, non-waiving
 * ingest to unattended. Only the WAIVING call is non-relaxable.
 */

import { describe, expect, it } from "vitest";

import { AutoApproveChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { parsePolicy } from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

function gateFor(policy: ReturnType<typeof parsePolicy>): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new ApprovalGate(
    policy,
    new BaselineTracker(storage, masterKey),
    new AutoApproveChannel(),
    new AuditLog(storage, masterKey),
  );
}

/** A policy that relaxes memory_ingest to Tier 3: legal today, unlike memory_delete. */
function policyRelaxingMemoryIngest(): ReturnType<typeof parsePolicy> {
  return parsePolicy(
    [
      "version: 1",
      "tier1_always_approve: []",
      "tier3_always_allow:",
      "  - memory_ingest",
      "approval_channel:",
      "  type: stderr",
      "  timeout_seconds: 300",
    ].join("\n"),
  );
}

describe("Rung-1 point 3: memory_ingest allow_files forces Tier 1 regardless of policy", () => {
  it("loader legally relaxes plain memory_ingest to Tier 3 (not force-pinned like memory_delete)", () => {
    const relaxed = policyRelaxingMemoryIngest();
    expect(relaxed.tier1_always_approve).not.toContain("memory_ingest");
    expect(relaxed.tier3_always_allow).toContain("memory_ingest");
  });

  it("a relaxed policy still classifies a NON-waiving memory_ingest call as Tier 3", async () => {
    const result = await gateFor(policyRelaxingMemoryIngest()).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
    });
    expect(result.tier).toBe(3);
  });

  it("a relaxed policy CANNOT relax a WAIVING memory_ingest call (allow_files present) below Tier 1", async () => {
    const result = await gateFor(policyRelaxingMemoryIngest()).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
      allow_files: ["note-with-secret.md"],
    });
    expect(result.tier).toBe(1);
  });

  it("an EMPTY allow_files array does not force Tier 1 under a relaxed policy", async () => {
    // Nothing is waived by an empty list, so it is indistinguishable from
    // omitting the field; forcing Tier 1 here would be a false positive.
    const result = await gateFor(policyRelaxingMemoryIngest()).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
      allow_files: [],
    });
    expect(result.tier).toBe(3);
  });

  it("a malformed allow_files (not an array) does not force Tier 1 by itself", async () => {
    // The handler denies a malformed allow_files as invalid_args regardless
    // of tier; the gate classifier just must not crash or mis-force on it.
    const result = await gateFor(policyRelaxingMemoryIngest()).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
      allow_files: "not-an-array",
    });
    expect(result.tier).toBe(3);
  });

  it("the DEFAULT (unrelaxed) policy already requires approval either way", async () => {
    const defaultPolicy = parsePolicy(
      [
        "version: 1",
        "tier1_always_approve:",
        "  - memory_ingest",
        "tier3_always_allow: []",
        "approval_channel:",
        "  type: stderr",
        "  timeout_seconds: 300",
      ].join("\n"),
    );
    const withoutWaiver = await gateFor(defaultPolicy).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
    });
    const withWaiver = await gateFor(defaultPolicy).evaluate("memory_ingest", {
      harness: "claude-code",
      dir: "/tmp/source",
      allow_files: ["note-with-secret.md"],
    });
    expect(withoutWaiver.tier).toBe(1);
    expect(withWaiver.tier).toBe(1);
  });
});
