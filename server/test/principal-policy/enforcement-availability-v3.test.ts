import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { describe, expect, it } from "vitest";

import { runStatus } from "../../src/cli/castle-wall.js";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import type { AggregatorSources } from "../../src/dashboard/aggregator.js";
import type { PublicIdentity, StoredIdentity } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { buildFeatureHealthPanel } from "../../src/principal-policy/feature-health.js";
import { buildCastleWallPosture } from "../../src/principal-policy/posture.js";
import type { ResolvedEnforcementAvailability } from "../../src/castle-wall/runtime/enforcement-availability.js";
import { protectionSubjectForUid } from "../../src/castle-wall/subject-binding.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";

const FORTRESS = "fortress:test";
const NOW = Date.parse("2026-07-30T18:00:00.000Z");
const CLAIM_UID = 503;

function subjectForUid(uid: number): string {
  const subject = protectionSubjectForUid(FORTRESS, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
}

const CLAIM_SUBJECT = subjectForUid(CLAIM_UID);

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

async function appendCW(
  log: AuditLog,
  operation: string,
  timestampMs: number,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: CLAIM_SUBJECT,
    result: operation === "egress_blocked" ? "failure" : "success",
    details: {
      cw_source: "castle_wall_audit_consumer",
      agent_id: CLAIM_SUBJECT,
    },
    timestamp: new Date(timestampMs).toISOString(),
  });
}

function availability(
  overrides: Partial<ResolvedEnforcementAvailability> = {},
): ResolvedEnforcementAvailability {
  return {
    status: "live",
    reason: "ok",
    observed_at: new Date(NOW).toISOString(),
    freshness_window_ms: 30_000,
    active_connection_count: 1,
    ...overrides,
  };
}

function stubIdentity(overrides: Partial<PublicIdentity> = {}): StoredIdentity {
  return {
    identity_id: overrides.identity_id ?? FORTRESS,
    label: overrides.label ?? "Agent",
    public_key: overrides.public_key ?? "pk",
    did: overrides.did ?? "did:key:z6Mkabcdef1234567890abcdef1234567890abcdef1234567890",
    created_at: overrides.created_at ?? new Date(NOW).toISOString(),
    key_type: "ed25519",
    key_protection: overrides.key_protection ?? "passphrase",
    encrypted_private_key: {} as StoredIdentity["encrypted_private_key"],
    rotation_history: [],
  };
}

function stubIdentityManager(identity: StoredIdentity): IdentityManager {
  const publicIdentity: PublicIdentity = {
    identity_id: identity.identity_id,
    label: identity.label,
    public_key: identity.public_key,
    did: identity.did,
    created_at: identity.created_at,
    key_type: identity.key_type,
    key_protection: identity.key_protection,
  };
  return {
    getDefault: () => identity,
    list: () => [publicIdentity],
    getPrimaryIdentityId: () => identity.identity_id,
    get: (id: string) => (id === identity.identity_id ? identity : undefined),
  } as unknown as IdentityManager;
}

function dashboardSources(
  log: AuditLog,
  overrides: Partial<AggregatorSources> = {},
): AggregatorSources {
  return {
    mode: "co-located",
    server_version: "test",
    platform: "darwin",
    identityManager: stubIdentityManager(stubIdentity()),
    auditLog: log,
    teeAvailable: true,
    reputation: { score: 95, profile_url: "https://verascore.example/test" },
    resolveProtectionClaimSubject: () => CLAIM_SUBJECT,
    ...overrides,
  };
}

class CaptureStream extends Writable {
  private readonly chunks: string[] = [];

  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }

  text(): string {
    return this.chunks.join("");
  }
}

async function withTempFortress<T>(fn: (path: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-status-"));
  try {
    await writeFile(
      join(dir, "castle-pinned-pubkey.bin"),
      Buffer.from(new Uint8Array(32).fill(7)),
      { mode: 0o600 },
    );
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function enoent(): NodeJS.ErrnoException {
  const error = new Error("ENOENT") as NodeJS.ErrnoException;
  error.code = "ENOENT";
  return error;
}

describe("level-triggered enforcement availability surfaces", () => {
  it("I1/I9: macOS audit-only and daemon-heartbeat evidence cannot green posture or feature-health", async () => {
    const log = newAuditLog();
    await appendCW(log, "egress_allowed", NOW - 1_000);
    await appendCW(log, "castle_wall_heartbeat", NOW - 500);

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("no_evidence");
    expect(posture.enforcement_availability?.status).toBe("undetermined");
    expect(posture.enforcement_availability?.reason).toBe("availability_not_queried");

    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const row = panel.rows.find((r) => r.feature_id === "castle_wall_egress");
    expect(row?.status).toBe("unknown");
    expect(row?.basis).toBe("no_evidence_self_reporting");
    expect(row?.enforcement_availability?.status).toBe("undetermined");
  });

  it("I2/I5/I11: non-green availability dominates fresh flow evidence past the old ten-minute window", async () => {
    const log = newAuditLog();
    for (let minute = 0; minute <= 12; minute += 1) {
      const now = NOW + minute * 60_000;
      await appendCW(log, "egress_blocked", now);
      const resolved = availability({
        status: "non_green",
        reason: "lease:arm_lease_missing",
        observed_at: new Date(now).toISOString(),
      });

      const posture = await buildCastleWallPosture({
        auditLog: log,
        originMachine: FORTRESS,
        platform: "darwin",
        now,
        enforcementAvailability: resolved,
        protectionClaimSubject: CLAIM_SUBJECT,
      });
      const panel = await buildFeatureHealthPanel({
        auditLog: log,
        originMachine: FORTRESS,
        platform: "darwin",
        now,
        enforcementAvailability: resolved,
        protectionClaimSubject: CLAIM_SUBJECT,
      });
      const row = panel.rows.find((r) => r.feature_id === "castle_wall_egress");

      expect(posture.arm_state, `minute ${minute}`).toBe("degraded");
      expect(posture.enforcement_availability?.reason, `minute ${minute}`).toBe(
        "lease:arm_lease_missing",
      );
      expect(row?.status, `minute ${minute}`).toBe("fault");
      expect(row?.enforcement_availability?.reason, `minute ${minute}`).toBe(
        "lease:arm_lease_missing",
      );
    }
  });

  it("I5/I6: posture and feature-health green only together on the same fresh live availability", async () => {
    const log = newAuditLog();
    const live = availability();
    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      enforcementAvailability: live,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      enforcementAvailability: live,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const row = panel.rows.find((r) => r.feature_id === "castle_wall_egress");

    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("producer_signed");
    expect(row?.status).toBe("active");

    const undetermined = availability({
      status: "undetermined",
      reason: "stale_report",
    });
    const stalePosture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      enforcementAvailability: undetermined,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const stalePanel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "darwin",
      now: NOW,
      enforcementAvailability: undetermined,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const staleRow = stalePanel.rows.find(
      (r) => r.feature_id === "castle_wall_egress",
    );
    expect(stalePosture.arm_state).not.toBe("armed");
    expect(stalePosture.evidence_basis).toBe("stale_evidence");
    expect(staleRow?.status).not.toBe("active");
    expect(staleRow?.basis).toBe("stale_evidence");
  });

  it("§4.0 Linux evidence path still greens from existing audit-drain evidence", async () => {
    const log = newAuditLog();
    await appendCW(log, "egress_allowed", NOW - 1_000);

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      platform: "linux",
      now: NOW,
      protectionClaimSubject: CLAIM_SUBJECT,
    });
    const row = panel.rows.find((r) => r.feature_id === "castle_wall_egress");

    expect(posture.arm_state).toBe("armed");
    expect(row?.status).toBe("active");
  });

  it("I1/I5 dashboard snapshot hero follows macOS availability, not audit-only evidence", async () => {
    const log = newAuditLog();
    await appendCW(log, "egress_allowed", NOW - 1_000);

    const noAvailability = await getProtectionSnapshot(dashboardSources(log));
    expect(noAvailability.overall.light).toBe("yellow");
    expect(noAvailability.overall.headline).toMatch(
      /Castle Wall enforcement not confirmed/,
    );

    const live = await getProtectionSnapshot(
      dashboardSources(log, {
        resolveEnforcementAvailability: () => availability(),
      }),
    );
    expect(live.overall.light).toBe("green");
  });

  it("I6/I7 CLI status prints undetermined/non-green availability reasons instead of protected wording", async () => {
    await withTempFortress(async (fortressPath) => {
      const out = new CaptureStream();
      const code = await runStatus({
        out,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () =>
          "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
        hostAppCandidates: [],
        globalPinReader: async () => {
          throw enoent();
        },
        enforcementAvailabilityQuery: async () =>
          availability({
            status: "undetermined",
            reason: "no_report",
            observed_at: null,
            active_connection_count: 1,
          }),
      });

      expect(code).toBe(0);
      expect(out.text()).toContain(
        "Enforcement availability: undetermined (no_report; observed=none; active_connections=1)",
      );
      expect(out.text()).not.toMatch(/protected|enforcing/);

      const failed = new CaptureStream();
      const failedCode = await runStatus({
        out: failed,
        env: { SANCTUARY_STORAGE_PATH: fortressPath },
        platform: "darwin",
        execSyncFn: () =>
          "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
        hostAppCandidates: [],
        globalPinReader: async () => {
          throw enoent();
        },
        enforcementAvailabilityQuery: async () => {
          throw new Error("malformed enforcement availability response");
        },
      });

      expect(failedCode).toBe(0);
      expect(failed.text()).toContain(
        "Enforcement availability: undetermined (availability_query_failed:malformed enforcement availability response; observed=none; active_connections=0)",
      );
    });
  });
});
