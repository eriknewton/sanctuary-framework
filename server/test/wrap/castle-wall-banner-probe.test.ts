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
import { startedCoarseDisposition, type HarnessDisposition } from "../../src/egress-gate/parked-claim.js";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ed25519 } from "@noble/curves/ed25519";

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
import {
  protectionSubjectForUid,
  resolveProtectionSubjectFromAgentOrigin,
} from "../../src/castle-wall/subject-binding.js";
import type { FlowDecisionRecordedNotification } from "../../src/castle-wall/ipc/messages.js";
import { MacOSFlowEventConsumer } from "../../src/castle-wall/runtime/macos-flow-events.js";
import type { ResolvedEnforcementAvailability } from "../../src/castle-wall/runtime/enforcement-availability.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import { canonicalize } from "../../src/mesh/canonical-json.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
} from "../../src/castle-wall/constants.js";

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

function liveAvailability(): ResolvedEnforcementAvailability {
  return {
    status: "live",
    reason: "ok",
    observed_at: new Date().toISOString(),
    freshness_window_ms: 30_000,
    active_connection_count: 1,
  };
}

function providerUnboundAvailability(): ResolvedEnforcementAvailability {
  return {
    status: "non_green",
    reason: "provider_unbound",
    observed_at: new Date().toISOString(),
    freshness_window_ms: 30_000,
    active_connection_count: 1,
  };
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
  const agentUid = 503;

  function agentSubject(): string {
    const subject = protectionSubjectForUid(fortressId, agentUid);
    if (subject === null) throw new Error("test subject could not be derived");
    return subject;
  }

  function subjectForUid(uid: number): string {
    const subject = protectionSubjectForUid(fortressId, uid);
    if (subject === null) throw new Error("test subject could not be derived");
    return subject;
  }

  function toBase64url(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function auditTokenForRuid(uid: number): string {
    const vals = [
      0xffffffff,
      uid,
      uid,
      uid,
      uid,
      0x00000269,
      0x000186ae,
      0x00000566,
    ];
    return vals
      .map((value) => {
        const bytes = new Uint8Array(4);
        new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
        return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
      })
      .join("");
  }

  async function publishPinnedProducerKey(
    privateKey: Uint8Array = ed25519.utils.randomPrivateKey(),
  ): Promise<Uint8Array> {
    const dir = join(storagePath, "policy", "egress");
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, "audit-producer.pub"),
      Buffer.from(ed25519.getPublicKey(privateKey)),
    );
    return privateKey;
  }

  function signedWalBody(input: {
    operation: "egress_allowed" | "egress_blocked";
    timestamp: string;
    identityId: string;
  }): string {
    return JSON.stringify({
      timestamp: input.timestamp,
      layer: "l1",
      operation:
        input.operation === "egress_allowed"
          ? "egress_approved"
          : "egress_blocked",
      identity_id: input.identityId,
      result: input.operation === "egress_blocked" ? "blocked" : "success",
      details: {
        agent_id: "agent-producer-name",
        dest_host: "api.anthropic.com",
      },
    });
  }

  /** A Castle-Wall-originated entry carrying the provenance marker. */
  async function appendCW(
    operation: string,
    ageMs: number,
    details: Record<string, unknown> = {},
    identityId: string = agentSubject(),
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
    identityId: string = agentSubject(),
  ): Promise<void> {
    await log.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: identityId,
      result,
      details: { socket_path: daemonSocketPath, source: daemonSource },
      timestamp: new Date(Date.now() - ageMs).toISOString(),
    });
  }

  async function appendDaemonHeartbeat(
    ageMs: number,
    identityId: string = agentSubject(),
  ): Promise<void> {
    await appendCW("castle_wall_heartbeat", ageMs, {
      socket_path: daemonSocketPath,
      source: daemonSource,
      daemon_mode: "full",
    }, identityId);
  }

  async function appendSignedCW(
    auditLog: AuditLog,
    operation: "egress_allowed" | "egress_blocked",
    ageMs: number,
    privateKey: Uint8Array,
    identityId: string = agentSubject(),
    seq: number = 1,
    persistedIdentityId: string = identityId,
  ): Promise<void> {
    const capturedAtMs = Date.now() - ageMs;
    const timestamp = new Date(capturedAtMs).toISOString();
    const canonical = signedWalBody({ operation, timestamp, identityId });
    const signature = ed25519.sign(
      producerSigningBytes(canonical, capturedAtMs, seq),
      privateKey,
    );
    await auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: persistedIdentityId,
      result: "success",
      timestamp,
      details: {
        seq,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(signature),
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
          CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: capturedAtMs,
        [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
          CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
        [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
          CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]:
          CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    });
  }

  async function appendMacOSProducerSignedFlow(input: {
    privateKey: Uint8Array;
    uid: number;
    seq?: number;
    ageMs?: number;
  }): Promise<void> {
    const seq = input.seq ?? 0;
    const capturedAtMs = Date.now() - (input.ageMs ?? 60_000);
    const recordedAt = new Date(capturedAtMs).toISOString();
    const agentId = auditTokenForRuid(input.uid);
    const destination = {
      host: "api.anthropic.com",
      ip: "104.18.32.10",
      port: 443,
      protocol: "tcp" as const,
      hostname_source: "sni" as const,
      opaque: false,
    };
    const details = {
      agent_id: agentId,
      agent_template: "coding-assistant",
      dest_host: destination.host,
      dest_ip: destination.ip,
      dest_port: destination.port,
      dest_protocol: destination.protocol,
      decision: "allow",
      prior_sha256_hex: null,
      rule_id: "rule-anthropic",
      seq,
      source: "macos_extension",
    };
    const eventCanonicalJson = canonicalize({
      timestamp: recordedAt,
      layer: "l1",
      operation: "egress_approved",
      identity_id: agentId,
      result: "success",
      details,
    });
    const signature = ed25519.sign(
      producerSigningBytes(eventCanonicalJson, capturedAtMs, seq),
      input.privateKey,
    );
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination,
      agent: { id: agentId, template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: recordedAt,
      producer: {
        event_canonical_json: eventCanonicalJson,
        captured_at_unix_ms: capturedAtMs,
        seq,
        prior_sha256_hex: null,
        signature_b64url: toBase64url(signature),
        key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      },
    };
    const consumer = new MacOSFlowEventConsumer({
      fortressId,
      auditSink: log,
      defaultApprovalTimeoutSeconds: 30,
      pinnedProducerKeyB64url: toBase64url(
        ed25519.getPublicKey(input.privateKey),
      ),
      approvalQueue: {
        async enqueue() {},
      },
      manifestProvider: {
        currentSnapshot() {
          return {
            signed_manifest: {
              manifest: {
                schema_version: 1,
                fortress_id: fortressId,
                issued_at: recordedAt,
                rules: [],
              },
              signature: {
                signature_scheme: "ed25519",
                signing_key_id: "test",
                signature_b64url: "dGVzdA",
              },
            },
            rules: [],
          };
        },
      },
    });
    await consumer.handleFlowDecisionRecorded(notification);
  }

  async function appendOperatorProtectionEvidence(
    auditLog: AuditLog,
    identityId: string = agentSubject(),
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
    identityId: string = agentSubject(),
  ) {
    await appendOperatorProtectionEvidence(daemonLog, identityId);
  }

  async function appendSignedDaemonProtectionEvidence(
    daemonLog: AuditLog,
    privateKey: Uint8Array,
    identityId: string = agentSubject(),
  ) {
    await daemonLog.appendCritical({
      layer: "l1",
      operation: "filter_started",
      identity_id: identityId,
      result: "success",
      details: { socket_path: daemonSocketPath, source: daemonSource },
      timestamp: new Date(Date.now() - 31_000).toISOString(),
    });
    await daemonLog.appendCritical({
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
    await appendSignedCW(daemonLog, "egress_allowed", 29_000, privateKey, identityId);
    await daemonLog.flush();
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

  async function splitMigratedFortressWithPinnedDaemonEvidence() {
    const privateKey = await publishPinnedProducerKey();
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
    await appendSignedDaemonProtectionEvidence(daemonLog, privateKey);

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
    expect(
      await probeCoarseCastleWallEnforcementObserved(
        log,
        storagePath,
        liveAvailability(),
      ),
    ).toBe(true);
  });

  it("fresh producer-signed evidence with a pinned key reads true through the fortress-scoped coarse probe", async () => {
    const privateKey = await publishPinnedProducerKey();
    await appendSignedCW(log, "egress_allowed", 60_000, privateKey);
    expect(
      await probeCoarseCastleWallEnforcementObserved(
        log,
        storagePath,
        liveAvailability(),
      ),
    ).toBe(true);
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
      {
        protectionClaimSubject: agentSubject(),
        enforcementAvailability: liveAvailability(),
      },
    );
    expect(claim.state).toBe("exclusive");
  });

  it("fresh coarse default evidence stays green when no fine-grained agent was declared", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => coarseFleetStatus(),
      {
        protectionClaimSubject: agentSubject(),
        enforcementAvailability: liveAvailability(),
      },
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
      {
        protectionClaimSubject: agentSubject(),
        enforcementAvailability: liveAvailability(),
      },
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
      { protectionClaimSubject: agentSubject() },
    );
    expect(claim.state).toBe("unknown");
  });

  it("a hanging exclusive-egress provider times out to unknown, never green", async () => {
    await appendCW("egress_allowed", 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => new Promise<ExclusiveEgressStatus | null>(() => {}),
      { providerTimeoutMs: 5, protectionClaimSubject: agentSubject() },
    );
    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("provider_unavailable");
  });

  it("missing v3 availability maps to unknown lockout copy, not traffic-not-filtered", async () => {
    await appendCW("castle_wall_heartbeat", 30 * 60_000);
    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => exclusiveStatus(),
      { protectionClaimSubject: fortressId },
    );
    const advice = protectionStateAdvice(claim);
    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("insufficient_evidence");
    expect(advice.castleWallLabel).not.toContain("Castle Wall Full");
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("flagship armed-exclusive path reaches green with current-wrap daemon liveness and fresh egress", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
      enforcementAvailability: liveAvailability(),
    });
    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
  });

  it("flagship armed-exclusive path reaches green with a pinned producer key and producer-realistic subject", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    const privateKey = await publishPinnedProducerKey();
    await appendSignedCW(log, "egress_allowed", 60_000, privateKey, subject);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
      enforcementAvailability: liveAvailability(),
    });
    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
  });

  it("cross-derived green path: agent-origin claim subject and real macOS producer evidence agree", async () => {
    const livenessSince = currentWrapSince();
    const agentOrigin = {
      mode: "uid",
      agent_uid: 503,
      system_uid_allow_ceiling: 500,
    };
    const resolved = resolveProtectionSubjectFromAgentOrigin(
      fortressId,
      agentOrigin,
    );
    expect(resolved.status).toBe("resolved");
    expect(resolved.subject).toBe(agentSubject());
    await mkdir(join(storagePath, "policy", "egress"), { recursive: true });
    await writeFile(
      join(storagePath, "policy", "egress", "agent-origin.json"),
      JSON.stringify(agentOrigin),
    );
    const privateKey = await publishPinnedProducerKey();
    await appendMacOSProducerSignedFlow({ privateKey, uid: 503 });
    await appendDaemonStart(31_000, "success", fortressId);
    await appendDaemonHeartbeat(30_000, fortressId);

    const claim = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: { ran: false },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
      enforcementAvailability: liveAvailability(),
    });

    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
  });

  it("scenario B: bare-fortress daemon heartbeats plus uid-503 signed enforcement reaches green", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    const privateKey = await publishPinnedProducerKey();
    await appendSignedCW(log, "egress_allowed", 60_000, privateKey, subject);
    await appendDaemonStart(31_000, "success", fortressId);
    await appendDaemonHeartbeat(30_000, fortressId);

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
      enforcementAvailability: liveAvailability(),
    });

    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
  });

  it("two confined agents require live v3 availability before either can render protected", async () => {
    const livenessSince = currentWrapSince();
    const subjectA = subjectForUid(503);
    const subjectB = subjectForUid(777);
    const privateKey = await publishPinnedProducerKey();
    await appendDaemonStart(31_000, "success", fortressId);
    await appendDaemonHeartbeat(30_000, fortressId);
    await appendSignedCW(log, "egress_allowed", 60_000, privateKey, subjectA, 1);

    const claimA = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 503, generationId: 9 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
      enforcementAvailability: liveAvailability(),
    });
    const claimBFromAOnly = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 777, generationId: 10 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    await appendSignedCW(log, "egress_allowed", 50_000, privateKey, subjectB, 2);
    const claimBAfterOwnEvidence = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 777, generationId: 10 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
      enforcementAvailability: liveAvailability(),
    });

    expect(claimA.state).toBe("exclusive");
    expect(claimA.basis).toBe("exclusive_egress_observed");
    expect(claimBFromAOnly.state).toBe("unknown");
    expect(claimBFromAOnly.basis).toBe("insufficient_evidence");
    expect(claimBAfterOwnEvidence.state).toBe("exclusive");
    expect(claimBAfterOwnEvidence.basis).toBe("exclusive_egress_observed");
  });

  it("foreign enforcement evidence greens no claim without v3 availability", async () => {
    const livenessSince = currentWrapSince();
    const privateKey = await publishPinnedProducerKey();
    await appendDaemonStart(31_000, "success", fortressId);
    await appendDaemonHeartbeat(30_000, fortressId);
    await appendSignedCW(
      log,
      "egress_allowed",
      60_000,
      privateKey,
      "foreign-fortress/uid-503",
    );

    const claimA = await resolveWrapProtectionClaim({
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
    const claimB = await resolveWrapProtectionClaim({
      auditLog: log,
      autoProvisionSummary: {
        ran: true,
        outcome: { kind: "armed-exclusive", uid: 777, generationId: 10 },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => exclusiveStatus(),
    });

    expect(claimA.state).not.toBe("exclusive");
    expect(claimB.state).not.toBe("exclusive");
    expect(claimA.basis).toBe("insufficient_evidence");
    expect(claimB.basis).toBe("insufficient_evidence");
  });

  it("producer-signed relabel attack is refused: signed uid-504 persisted as uid-503", async () => {
    const livenessSince = currentWrapSince();
    const privateKey = await publishPinnedProducerKey();
    await appendDaemonStart(31_000, "success", fortressId);
    await appendDaemonHeartbeat(30_000, fortressId);
    await appendSignedCW(
      log,
      "egress_allowed",
      60_000,
      privateKey,
      subjectForUid(504),
      1,
      subjectForUid(503),
    );

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

  it("foreign fine evidence without v3 availability cannot green the per-agent wrap banner", async () => {
    const subject = agentSubject();
    const privateKey = await publishPinnedProducerKey();
    await appendSignedCW(
      log,
      "egress_allowed",
      60_000,
      privateKey,
      subjectForUid(504),
    );
    expect(await probeCoarseCastleWallEnforcementObserved(log, storagePath)).toBe(false);

    const claim = await probeCastleWallProtectionClaim(
      log,
      storagePath,
      async () => exclusiveStatus(),
      { protectionClaimSubject: subject },
    );

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("insufficient_evidence");
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain(
      "Castle Wall Full",
    );
  });

  it("old-format 64-hex macOS evidence fails closed when v3 availability is absent", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    const legacyAuditToken =
      "ffffffff4100000041000000410000004100000069020000ae86010066050000";
    await appendCW("egress_allowed", 60_000, {}, legacyAuditToken);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);

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
    expect(claim.reasons.join("\n")).not.toContain("daemon liveness");
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
      enforcementAvailability: liveAvailability(),
    });

    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
  });

  it("split-migrated fortress reaches green from _audit-daemon with a pinned producer key", async () => {
    const livenessSince = currentWrapSince();
    const { auditLog, auditStorage, masterKey } =
      await splitMigratedFortressWithPinnedDaemonEvidence();
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
      enforcementAvailability: liveAvailability(),
    });

    expect(claim.state).toBe("exclusive");
    expect(claim.basis).toBe("exclusive_egress_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toBe("Castle Wall Full");
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
        enforcementAvailability: liveAvailability(),
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
    );
  });

  it("failed filter_started cannot satisfy current-wrap daemon liveness", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonStart(31_000, "failure", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("heartbeat before its matching filter_started cannot satisfy current-wrap daemon liveness", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonHeartbeat(30_000, subject);
    await appendDaemonStart(29_000, "success", subject);
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
    );
    expect(protectionStateAdvice(claim).castleWallLabel).not.toContain("Castle Wall Full");
  });

  it("composed drill 2: arm abort without observed-off evidence stays probe-driven", async () => {
    const livenessSince = currentWrapSince();
    await appendDaemonStart(61_000, "success", fortressId);
    await appendDaemonHeartbeat(60_000, fortressId);
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
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
          harness: startedCoarseDisposition(),
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
      enforcementAvailability: liveAvailability(),
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
          harness: startedCoarseDisposition(),
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
          harness: startedCoarseDisposition(),
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
      "Castle Wall current-wrap daemon heartbeat could not be confirmed",
    );
    expect(claim.reasons).toContain("generation bring-up failed");
  });

  it("degraded exclusive bring-up cannot upgrade a fresh not-enforcing probe", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
    await appendCW("filter_crashed", 10_000, {}, subject);
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
          harness: startedCoarseDisposition(),
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
      enforcementAvailability: providerUnboundAvailability(),
    });

    expect(claim.state).toBe("unprotected");
    expect(claim.basis).toBe("not_enforcing_observed");
    expect(protectionStateAdvice(claim).castleWallLabel).toContain("NOT ARMED");
  });

  it("degraded exclusive bring-up cannot claim coarse-only when coarse fallback was not restored", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
          harness: { disposition: "not-started" } as unknown as HarnessDisposition,
          cleanupErrors: [],
        },
      },
      castleWallDaemonLivenessSince: livenessSince,
      storagePath,
      providerTimeoutMs: 20,
      resolveExclusiveEgress: async () => coarseFleetStatus(),
      enforcementAvailability: liveAvailability(),
    });

    expect(claim.state).toBe("unknown");
    expect(claim.basis).toBe("provision_outcome_not_observation");
    expect(claim.reasons).toContain("coarse restore failed");
  });

  it("composed override: observed-off and repark-failed demote a green probe", async () => {
    const livenessSince = currentWrapSince();
    const subject = agentSubject();
    await appendCW("egress_allowed", 60_000, {}, subject);
    await appendDaemonStart(31_000, "success", subject);
    await appendDaemonHeartbeat(30_000, subject);
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
      enforcementAvailability: liveAvailability(),
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
      enforcementAvailability: liveAvailability(),
    });
    expect(reparkFailed.state).toBe("unknown");
    expect(reparkFailed.basis).toBe("exclusive_egress_repark_failed");
    expect(protectionStateAdvice(reparkFailed).castleWallLabel).not.toContain("Castle Wall Full");
  });

});
