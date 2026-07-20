/**
 * Castle Wall wrap-banner enforcement probes (fix-round MED-4c for PR #843,
 * protection-claim chokepoint 2026-07-19).
 *
 * The wrap success banner's affirmative "protected / Castle Wall Full" hero
 * is reserved for OBSERVED enforcement, judged by the SAME
 * adjudicated-flow-evidence standard the dashboard's feature-health panel
 * uses. These tests pin the probe's gating directly against a real audit
 * log (no mocked panel):
 *
 *   - fresh adjudicated evidence (egress_allowed with the Castle Wall
 *     provenance marker) reads true;
 *   - policy loads and heartbeats never do (the honesty seam);
 *   - stale adjudicated evidence (outside the 10-minute freshness window)
 *     never does;
 *   - any probe error reads false (fail-closed), never true.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  probeCastleWallProtectionClaim,
  probeCoarseCastleWallEnforcementObserved,
  resolveWrapProtectionClaim,
} from "../../src/wrap/cli.js";
import { protectionStateAdvice } from "../../src/egress-gate/protection-claim.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  AUDIT_DAEMON_NAMESPACE,
  createDaemonAuditLog,
  migrateFortressAuditStoreSplit,
} from "../../src/operational/audit-store-split.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import type { ExclusiveEgressStatus } from "../../src/principal-policy/posture.js";

function exclusiveStatus(): ExclusiveEgressStatus {
  return {
    fine_grained_declared: true,
    exclusive_egress_live: true,
    mode: "exclusive",
    agents: [],
    reasons: [],
  };
}

function coarseOnlyStatus(): ExclusiveEgressStatus {
  return {
    fine_grained_declared: true,
    exclusive_egress_live: false,
    mode: "coarse-only",
    agents: [],
    reasons: ["uid 503: coarse-only"],
  };
}

function coarseFleetStatus(): ExclusiveEgressStatus {
  return {
    fine_grained_declared: false,
    exclusive_egress_live: true,
    mode: null,
    agents: [],
    reasons: [],
  };
}

function currentWrapSince(ageMs: number = 2 * 60_000): Date {
  return new Date(Date.now() - ageMs);
}

describe("Castle Wall wrap-banner evidence probes", () => {
  let storagePath: string;
  let fortressId: string;
  let log: AuditLog;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    // No producer key file exists under it, matching a macOS fortress where
    // the panel accepts marker-gated entries without a pinned key.
    storagePath = await mkdtemp(join(tmpdir(), "sanctuary-banner-probe-"));
    fortressId = fortressIdFromStoragePath(storagePath);
    log = new AuditLog(new MemoryStorage(), generateRandomKey());
  });

  afterEach(async () => {
    try {
      await chmod(storagePath, 0o700).catch(() => undefined);
      await chmod(join(storagePath, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(
        () => undefined,
      );
      await rm(storagePath, { recursive: true, force: true });
    } catch {}
  });

  const daemonSocketPath = "/tmp/sanctuary-test-castle.sock";
  const daemonSource = "sanctuary-wrap";

  /** A Castle-Wall-originated entry carrying the provenance marker. */
  async function appendCW(
    operation: string,
    ageMs: number,
    details: Record<string, unknown> = {},
    identityId: string = fortressId,
  ): Promise<void> {
    await log.appendCritical({
      layer: "l1",
      operation,
      identity_id: identityId,
      result: "success",
      details: { ...details, cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(Date.now() - ageMs).toISOString(),
    });
  }

  async function appendDaemonStart(
    ageMs: number,
    result: "success" | "failure" = "success",
  ): Promise<void> {
    await log.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: fortressId,
      result,
      details: { socket_path: daemonSocketPath, source: daemonSource },
      timestamp: new Date(Date.now() - ageMs).toISOString(),
    });
  }

  async function appendDaemonHeartbeat(ageMs: number): Promise<void> {
    await appendCW("castle_wall_heartbeat", ageMs, {
      socket_path: daemonSocketPath,
      source: daemonSource,
      daemon_mode: "full",
    });
  }

  async function appendOperatorProtectionEvidence(
    auditLog: AuditLog,
    identityId: string = fortressId,
  ) {
    await appendDaemonLivenessEvidence(auditLog, identityId);
    await appendEgressEvidence(auditLog, identityId);
  }

  async function appendDaemonLivenessEvidence(
    auditLog: AuditLog,
    identityId: string = fortressId,
  ) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: identityId,
      result: "success",
      details: { socket_path: daemonSocketPath, source: daemonSource },
      timestamp: new Date(Date.now() - 31_000).toISOString(),
    });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "castle_wall_heartbeat",
      identity_id: identityId,
      result: "success",
      details: {
        socket_path: daemonSocketPath,
        source: daemonSource,
        daemon_mode: "full",
        cw_source: "castle_wall_audit_consumer",
      },
      timestamp: new Date(Date.now() - 30_000).toISOString(),
    });
    await auditLog.flush();
  }

  async function appendEgressEvidence(
    auditLog: AuditLog,
    identityId: string = fortressId,
  ) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: identityId,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(Date.now() - 29_000).toISOString(),
    });
    await auditLog.flush();
  }

  async function appendDaemonProtectionEvidence(
    daemonLog: AuditLog,
    identityId: string = fortressId,
  ) {
    await appendOperatorProtectionEvidence(daemonLog, identityId);
  }

  async function splitMigratedFortressWithDaemonEvidence() {
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const masterKey = generateRandomKey();
    const operatorLog = new AuditLog(storage, masterKey);
    await operatorLog.appendCritical({
      layer: "l1",
      operation: "identity_create",
      identity_id: fortressId,
      result: "success",
      details: { source: "operator-chain-fixture" },
    });
    await operatorLog.flush();
    await migrateFortressAuditStoreSplit({ storage, masterKey });

    const daemonLog = createDaemonAuditLog(storage, masterKey);
    await appendDaemonProtectionEvidence(daemonLog);

    return {
      auditLog: new AuditLog(storage, masterKey),
      auditStorage: storage,
      masterKey,
      statePath: join(storagePath, "state"),
    };
  }

  async function splitMigratedFortressWithOperatorEvidenceAndDaemonChain() {
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const masterKey = generateRandomKey();
    const operatorLog = new AuditLog(storage, masterKey);
    await operatorLog.appendCritical({
      layer: "l1",
      operation: "identity_create",
      identity_id: fortressId,
      result: "success",
      details: { source: "operator-chain-fixture" },
    });
    await operatorLog.flush();
    await migrateFortressAuditStoreSplit({ storage, masterKey });
    await appendOperatorProtectionEvidence(new AuditLog(storage, masterKey));
    await appendDaemonProtectionEvidence(createDaemonAuditLog(storage, masterKey));
    return {
      auditLog: new AuditLog(storage, masterKey),
      auditStorage: storage,
      masterKey,
      statePath: join(storagePath, "state"),
    };
  }

  async function tamperDaemonEntry(statePath: string) {
    const daemonDir = join(statePath, AUDIT_DAEMON_NAMESPACE);
    const files = (await readdir(daemonDir)).filter((f) => f.startsWith("entry-")).sort();
    const target = join(daemonDir, files[1]!);
    const raw = JSON.parse(await readFile(target, "utf-8"));
    raw.timestamp = "1999-01-01T00:00:00.000Z";
    await writeFile(target, JSON.stringify(raw));
  }

  async function deleteMiddleDaemonEntry(statePath: string) {
    const daemonDir = join(statePath, AUDIT_DAEMON_NAMESPACE);
    const files = (await readdir(daemonDir)).filter((f) => f.startsWith("entry-")).sort();
    await rm(join(daemonDir, files[1]!), { force: true });
  }

  it("fresh adjudicated evidence (egress_allowed, inside the freshness window) reads true", async () => {
    await appendCW("egress_allowed", 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(true);
  });

  it("policy loads and heartbeats NEVER arm the banner (the honesty seam)", async () => {
    await appendCW("policy_loaded", 60_000);
    await appendCW("castle_wall_heartbeat", 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(false);
  });

  it("stale adjudicated evidence (outside the 10-minute window) reads false", async () => {
    await appendCW("egress_allowed", 30 * 60_000);
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(false);
  });

  it("a probe error reads false (fail-closed), never true", async () => {
    const throwing = {
      runEagerReads: async () => {
        throw new Error("audit log unreadable");
      },
    } as unknown as AuditLog;
    expect(
      await probeCoarseCastleWallEnforcementObserved(throwing, storagePath),
    ).toBe(false);
  });

  it("protection claim renders exclusive only when the capped resolver proves exclusive-egress live", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => exclusiveStatus(),
    );
    expect(claim.state).toBe("exclusive");
  });

  it("fresh coarse default evidence stays green when no fine-grained agent was declared", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => coarseFleetStatus(),
    );
    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("castle_wall_enforcement_observed");
  });

  it("fresh coarse evidence without exclusive live maps to coarse-only, not green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => coarseOnlyStatus(),
    );
    expect(claim.state).toBe("coarse-only");
  });

  it("an unresolvable exclusive-egress provider maps to unknown, never green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => {
        throw new Error("registry unreadable");
      },
    );
    expect(claim.state).toBe("unknown");
  });

  it("a hanging exclusive-egress provider times out to unknown, never green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => new Promise<ExclusiveEgressStatus | null>(() => {}),
      { providerTimeoutMs: 5 },
    );
    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("provider_unavailable");
  });

  it("dead_no_heartbeat maps to unknown lockout copy, not traffic-not-filtered", async () => {
    await appendCW("castle_wall_heartbeat", 30 * 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => exclusiveStatus(),
    );
    const advice = protectionStateAdvice(claim);
    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("daemon_liveness_missing");
    expect(advice.castleWallLabel).toContain("daemon heartbeat missing");
    expect(advice.castleWallLabel).not.toContain("traffic not filtered");
    expect(advice.castleWallLabel).not.toContain("NOT ARMED");
  });

  it("composed drill 1: newer wall_disarmed beats older fresh enforcement", async () => {
    const livenessSince = currentWrapSince(6 * 60_000);
    await appendCW("egress_allowed", 5 * 60_000);
    await appendDaemonStart(4 * 60_000 + 1_000);
    await appendDaemonHeartbeat(4 * 60_000);
    await appendCW("wall_disarmed", 60_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "aborted",
          stage: "ensure-policy-daemon",
          reason: "policy daemon refused fortress",
          rolledBack: true,
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });
    expect(claim.state).toBe("unknown");
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("current-wrap daemon liveness is observed, not inferred from a handle", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: { ran: false },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });
    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("flagship armed-exclusive path reaches green with current-wrap daemon liveness and fresh egress", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });
    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
  });

  it("foreign-identity fresh egress cannot render the current in-memory banner green", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000, {}, "foreign-agent");
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("insufficient_evidence");
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain(
      "Castle Wall Full",
    );
  });

  it("split-migrated fortress reaches green when current-wrap daemon evidence lives in _audit-daemon", async () => {
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey } =
      await splitMigratedFortressWithDaemonEvidence();
    const claim = await resolveWrapProtectionClaim({
      auditLog,
      auditStorage,
      masterKey,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
  });

  it("foreign-identity fresh egress cannot render the split _audit-daemon banner green", async () => {
    const livenessSince = currentWrapSince();
    const storage = new FilesystemStorage(join(storagePath, "state"));
    const masterKey = generateRandomKey();
    const operatorLog = new AuditLog(storage, masterKey);
    await operatorLog.appendCritical({
      layer: "l1",
      operation: "identity_create",
      identity_id: fortressId,
      result: "success",
      details: { source: "operator-chain-fixture" },
    });
    await operatorLog.flush();
    await migrateFortressAuditStoreSplit({ storage, masterKey });

    const daemonLog = createDaemonAuditLog(storage, masterKey);
    await appendDaemonLivenessEvidence(daemonLog, fortressId);
    await appendEgressEvidence(daemonLog, "foreign-agent");

    const claim = await resolveWrapProtectionClaim({
      auditLog: new AuditLog(storage, masterKey),
      auditStorage: storage,
      masterKey,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("insufficient_evidence");
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain(
      "Castle Wall Full",
    );
  });

  it("split-migrated fortress can reach green from operator evidence when the daemon chain is permission-unreadable", async () => {
    if (typeof process.getuid === "function" && process.getuid() === 0) {
      return;
    }
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey, statePath } =
      await splitMigratedFortressWithOperatorEvidenceAndDaemonChain();
    const daemonDir = join(statePath, AUDIT_DAEMON_NAMESPACE);
    await chmod(daemonDir, 0o000);
    try {
      const claim = await resolveWrapProtectionClaim({
        auditLog,
        auditStorage,
        masterKey,
        autoProvisionSummary: {
          ran: true,
          outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
        },
        castleWallDaemonLivenessSince: livenessSince,
        storagePath,
        providerTimeoutMs: 20,
        resolveExclusiveEgress: async () => exclusiveStatus(),
      });

      expect(claim.state).toBe("exclusive");
      expect(claim.basis).toBe("exclusive_egress_observed");
      expect(claim.reasons.join("\n")).toContain("daemon audit store exists");
      expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
    } finally {
      await chmod(daemonDir, 0o700).catch(() => undefined);
    }
  });

  it("split-migrated fortress stays unknown when the readable daemon chain is byte-tampered", async () => {
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey, statePath } =
      await splitMigratedFortressWithOperatorEvidenceAndDaemonChain();
    await tamperDaemonEntry(statePath);
    const claim = await resolveWrapProtectionClaim({
      auditLog,
      auditStorage,
      masterKey,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
  });

  it("split-migrated fortress stays unknown when the daemon chain has a mid-chain deletion", async () => {
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey, statePath } =
      await splitMigratedFortressWithOperatorEvidenceAndDaemonChain();
    await deleteMiddleDaemonEntry(statePath);
    const claim = await resolveWrapProtectionClaim({
      auditLog,
      auditStorage,
      masterKey,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
  });

  it("split-migrated fortress stays unknown when the migrated daemon chain is missing", async () => {
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey, statePath } =
      await splitMigratedFortressWithOperatorEvidenceAndDaemonChain();
    await rm(join(statePath, AUDIT_DAEMON_NAMESPACE), {
      recursive: true,
      force: true,
    });
    const claim = await resolveWrapProtectionClaim({
      auditLog,
      auditStorage,
      masterKey,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
  });

  it("failed filter_started cannot satisfy current-wrap daemon liveness", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonStart(31_000, "failure");
    await appendDaemonHeartbeat(30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("heartbeat before its matching filter_started cannot satisfy current-wrap daemon liveness", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonHeartbeat(30_000);
    await appendDaemonStart(29_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("marker-only same-process heartbeats do not satisfy current-wrap daemon liveness", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendCW("castle_wall_heartbeat", 30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: { ran: false },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });
    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("composed drill 2: arm abort without observed-off evidence stays probe-driven", async () => {
    const livenessSince = currentWrapSince();
    await appendDaemonStart(61_000);
    await appendDaemonHeartbeat(60_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "aborted",
          stage: "arm",
          reason: "arm failed after save-timeout",
          rolledBack: true,
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });
    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("insufficient_evidence");
  });

  it("composed drill 3: degraded exclusive bring-up demotes a green coarse probe", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "exclusive-egress-unarmed-coarse-active",
          uid: 503,
          stage: "bring-up",
          reason: "generation bring-up failed",
          coarseCompositionRestored: true,
          harnessStartedCoarse: true,
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });
    expect(claim.state).toBe("coarse-only");
    expect(claim.basis).toBe("exclusive_egress_unarmed_coarse_active");
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("degraded exclusive bring-up cannot create a coarse-only claim before probing", async () => {
    const claim = await resolveWrapProtectionClaim({
      auditLog: undefined,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "exclusive-egress-unarmed-coarse-active",
          uid: 503,
          stage: "bring-up",
          reason: "generation bring-up failed",
          coarseCompositionRestored: true,
          harnessStartedCoarse: true,
          cleanupErrors: ["cleanup marker failed"],
        },
      },
      castleWallDaemonLivenessSince: currentWrapSince(),
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("provider_unavailable");
    expect(claim.reasons).toContain("no audit log was available to observe enforcement");
    expect(claim.reasons).toContain("generation bring-up failed");
    expect(claim.reasons).toContain("cleanup marker failed");
  });

  it("degraded exclusive bring-up preserves the daemon-liveness no-probe reason", async () => {
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "exclusive-egress-unarmed-coarse-active",
          uid: 503,
          stage: "bring-up",
          reason: "generation bring-up failed",
          coarseCompositionRestored: true,
          harnessStartedCoarse: true,
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: currentWrapSince(),
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.reasons).toContain(
      "Castle Wall daemon liveness was not observed during this wrap",
    );
    expect(claim.reasons).toContain("generation bring-up failed");
  });

  it("degraded exclusive bring-up cannot upgrade a fresh not-enforcing probe", async () => {
    const livenessSince = currentWrapSince();
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    await appendCW("filter_crashed", 10_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "exclusive-egress-unarmed-coarse-active",
          uid: 503,
          stage: "bring-up",
          reason: "generation bring-up failed",
          coarseCompositionRestored: true,
          harnessStartedCoarse: true,
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });

    expect(claim.state).toBe("unprotected");
    expect(claim.basis).toBe("not_enforcing_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toContain("NOT ARMED");
  });

  it("degraded exclusive bring-up cannot claim coarse-only when coarse fallback was not restored", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "exclusive-egress-unarmed-coarse-active",
          uid: 503,
          stage: "bring-up",
          reason: "coarse restore failed",
          coarseCompositionRestored: false,
          harnessStartedCoarse: false,
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("provision_outcome_not_observation");
    expect(claim.reasons).toContain("coarse restore failed");
  });

  it("composed override: observed-off and repark-failed demote a green probe", async () => {
    const livenessSince = currentWrapSince();
    await appendCW("egress_allowed", 60_000);
    await appendDaemonStart(31_000);
    await appendDaemonHeartbeat(30_000);
    const observedOff = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "aborted",
          stage: "arm",
          reason: "arm failed and status observed disabled",
          rolledBack: true,
          disarmObservedOff: true,
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });
    expect(observedOff.state).toBe("unprotected");
    expect(observedOff.basis).toBe("disarm_observed_off");

    const reparkFailed = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: {
          kind: "armed-exclusive-repark-failed",
          uid: 503,
          generationId: 9,
          reparkError: "launchctl disable failed",
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
    });
    expect(reparkFailed.state).toBe("unknown");
    expect(reparkFailed.basis).toBe("exclusive_egress_repark_failed");
    expect(protectionStateAdvice(reparkFailed).castleWallLabel).not.toContain("Castle Wall Full");
  });
});
