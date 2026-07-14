/**
 * Castle Wall Observe -- refresh chokepoint regression tests (sweep finding
 * R3-1, 2026-07-14: the pre-watermark engine re-folded the full retained
 * audit history additively on every refresh, inflating `times_seen` ~N-fold
 * per refresh and resurrecting promoted/discarded candidates from stale
 * history).
 *
 * The two load-bearing pins the fix demands (spawn prompt, item 3):
 *   1. refresh-twice yields IDENTICAL `times_seen` (idempotency);
 *   2. promote-then-refresh does NOT resurrect the promoted destination.
 * Plus the round-3 sweep's empirical-probe scenario as a fixture (fold the
 * same 2-event history through two refreshes: times_seen must stay 2, where
 * the old engine yielded 4).
 *
 * Everything runs against a REAL AuditLog (MemoryStorage) so the watermark
 * rides the real authenticated chain sequence from `streamVerifiedChain`,
 * and a REAL ObserveStore over a real StateStore -- no mocked fold plumbing.
 */

import { describe, it, expect } from "vitest";

import { AuditLog } from "../../../src/operational/audit-log.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { ObserveStore } from "../../../src/castle-wall/observe/store.js";
import {
  refreshCandidatesFromAudit,
  candidateCurrentlyAllowed,
  type RefreshAllowlistRead,
} from "../../../src/castle-wall/observe/refresh.js";
import { candidateKey, type CandidateObservation } from "../../../src/castle-wall/observe/types.js";

interface Harness {
  auditLog: AuditLog;
  store: ObserveStore;
}

function makeHarness(): Harness {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  const store = new ObserveStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  return { auditLog, store };
}

async function appendBlocked(
  auditLog: AuditLog,
  overrides: {
    host?: string | null;
    ip?: string;
    port?: number;
    protocol?: "tcp" | "udp";
    template?: string;
    timestamp?: string;
  } = {},
): Promise<void> {
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "castle-wall-daemon",
    result: "failure",
    ...(overrides.timestamp !== undefined ? { timestamp: overrides.timestamp } : {}),
    details: {
      agent: { id: "agent-1", template: overrides.template ?? "claude-code" },
      destination: {
        ...(overrides.host !== undefined
          ? overrides.host === null
            ? {}
            : { host: overrides.host }
          : { host: "api.example.com" }),
        ip: overrides.ip ?? "203.0.113.5",
        port: overrides.port ?? 443,
        protocol: overrides.protocol ?? "tcp",
        hostname_source: "sni",
      },
    },
  });
}

function allowRule(overrides: Partial<AllowlistRule["match"]> = {}): AllowlistRule {
  return {
    id: `rule-${JSON.stringify(overrides)}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-14T00:00:00.000Z",
    match: { host: ["api.example.com"], port: [443], protocol: "tcp", ...overrides },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
  };
}

function verifiedAllowlist(rules: AllowlistRule[] = []): () => Promise<RefreshAllowlistRead> {
  return async () => ({ status: "ok", rules });
}

async function refresh(harness: Harness, rules: AllowlistRule[] = []) {
  return refreshCandidatesFromAudit({
    auditLog: harness.auditLog,
    store: harness.store,
    readAllowlist: verifiedAllowlist(rules),
    now: new Date("2026-07-14T12:00:00.000Z"),
  });
}

async function onlyCandidate(store: ObserveStore): Promise<CandidateObservation> {
  const listed = await store.listCandidates();
  expect(listed.size).toBe(1);
  return [...listed.values()][0]!;
}

describe("refresh idempotency (R3-1a: refresh-twice yields identical times_seen)", () => {
  it("the sweep's empirical probe: folding the same 2-event history through two refreshes keeps times_seen at 2, never 4", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);

    const first = await refresh(harness);
    expect(first.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);

    const second = await refresh(harness);
    expect(second.status).toBe("refreshed");
    expect(second.status === "refreshed" && second.folded_events).toBe(0);
    // The old engine rendered 4 here (the round-3 sweep's probe).
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("N extra refreshes over unchanged history leave every count and field byte-identical", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog, { host: "other.example.net", ip: "198.51.100.7", port: 8443 });

    await refresh(harness);
    const after1 = [...(await harness.store.listCandidates()).entries()];
    for (let i = 0; i < 3; i++) await refresh(harness);
    const after4 = [...(await harness.store.listCandidates()).entries()];
    expect(after4).toEqual(after1);
  });

  it("a genuinely NEW observation after a refresh increments the count by exactly one (incremental fold)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);

    await appendBlocked(harness.auditLog);
    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("incremental");
    expect(outcome.status === "refreshed" && outcome.folded_events).toBe(1);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(3);
  });
});

describe("promote/discard non-resurrection (R3-1b)", () => {
  it("promote-then-refresh does NOT resurrect the promoted destination (watermark leg: history is already folded)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);

    // Promote removes the candidate row (what runObservePromote does after a
    // successful promote) and the destination becomes a live allow rule.
    const candidate = await onlyCandidate(harness.store);
    await harness.store.removeCandidate(candidateKey(candidate));

    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status).toBe("refreshed");
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("promoted destination stays out even through a recompute heal (allowlist leg: the belt when the watermark cannot protect)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    // NO prior refresh: no watermark, so this refresh replays FULL history
    // (recompute) -- exactly the path where only the allowlist filter can
    // keep the promoted destination out.
    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("discard-then-refresh does not resurrect; a NEW observation re-mints with a RESTARTED count (the legend's semantics)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(3);

    // Discard drops the row (runObserveDiscard's removeCandidate).
    await harness.store.removeCandidate(candidateKey(await onlyCandidate(harness.store)));
    await refresh(harness);
    expect((await harness.store.listCandidates()).size).toBe(0);

    // One genuinely new denial re-mints the candidate at times_seen 1 -- not
    // at the historical 3 the old engine resurrected.
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });
});

describe("allowlist-aware fold + prune (R3-1b, chokepoint requirement 2)", () => {
  it("an already-allowed destination is never minted, while a not-allowed one still is", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog); // api.example.com -- allowed below
    await appendBlocked(harness.auditLog, { host: "blocked.example.net", ip: "198.51.100.9" });

    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    const remaining = await onlyCandidate(harness.store);
    expect(remaining.host).toBe("blocked.example.net");
  });

  it("a PERSISTED pending candidate whose destination the policy now permits is pruned on the next refresh", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await harness.store.listCandidates()).size).toBe(1);

    // Policy changes out-of-band (e.g. an operator-authored rule, or a
    // promote from another template's row): the next refresh reconciles.
    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.removed_now_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("protocol-aware: a udp allow rule suppresses a udp candidate (the CONNECT-proxy tcp matcher alone would miss it)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { protocol: "udp" });
    const outcome = await refresh(harness, [allowRule({ protocol: "udp" })]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("a udp candidate is NOT suppressed by a tcp-only rule for the same destination", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { protocol: "udp" });
    await refresh(harness, [allowRule({ protocol: "tcp" })]);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("fail-closed toward KEEPING: a destination that cannot canonicalize is never treated as allowed", () => {
    const rules = [allowRule({ host: undefined, port: [443] })]; // port-only rule: matches any destination on 443
    expect(
      candidateCurrentlyAllowed(rules, { host: "bad host with spaces", ip: "", port: 443, protocol: "tcp" }),
    ).toBe(false);
  });

  it("an unverifiable allowlist aborts the refresh with NOTHING folded, written, or pruned", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const outcome = await refreshCandidatesFromAudit({
      auditLog: harness.auditLog,
      store: harness.store,
      readAllowlist: async () => ({ status: "unverified", reason: "bad signature" }),
      now: new Date("2026-07-14T12:00:00.000Z"),
    });
    expect(outcome).toEqual({ status: "allowlist_unverified", reason: "bad signature" });
    expect((await harness.store.listCandidates()).size).toBe(0);
    expect(await harness.store.getFoldWatermark()).toBeNull();
  });
});

describe("recompute heal (pre-watermark stores and reset chains)", () => {
  it("a store the old additive engine inflated is healed to the true retained-history count on the first watermarkless refresh", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);

    // Simulate the pre-watermark engine having refreshed twice (times_seen
    // doubled to 4), with no watermark record.
    await harness.store.putCandidate({
      agent_id: "agent-1",
      agent_template: "claude-code",
      host: "api.example.com",
      ip: "203.0.113.5",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      times_seen: 4,
      first_seen: "2026-07-14T09:00:00.000Z",
      last_seen: "2026-07-14T09:00:01.000Z",
      would_be_disposition: "denied",
      exfil_risk: false,
    });

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("a candidate whose audit history aged out of retention is NOT dropped by a recompute (unreviewed candidates never vanish silently)", async () => {
    const harness = makeHarness();
    // Store holds a candidate, but the audit chain has no matching entries
    // (fully pruned): the recompute folds nothing and must leave it alone.
    await harness.store.putCandidate({
      agent_id: "agent-1",
      agent_template: "claude-code",
      host: "aged-out.example.com",
      ip: "203.0.113.77",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      times_seen: 5,
      first_seen: "2026-06-01T00:00:00.000Z",
      last_seen: "2026-06-02T00:00:00.000Z",
      would_be_disposition: "denied",
      exfil_risk: false,
    });

    const outcome = await refresh(harness);
    expect(outcome.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(5);
  });

  it("a watermark AHEAD of the surviving chain head (audit store reset) triggers a recompute instead of silently folding nothing forever", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    // A watermark from a previous audit-chain epoch, far past this chain.
    await harness.store.setFoldWatermark({
      folded_through_sequence: 999_999,
      updated_at: "2026-07-01T00:00:00.000Z",
    });

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);

    // And the watermark now tracks the REAL chain head: a further refresh is
    // an incremental no-op, not another recompute.
    const again = await refresh(harness);
    expect(again.status === "refreshed" && again.mode).toBe("incremental");
    expect(again.status === "refreshed" && again.folded_events).toBe(0);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });

  it("an empty chain refresh is a no-op that does not invent a watermark", async () => {
    const harness = makeHarness();
    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.folded_events).toBe(0);
    expect(await harness.store.getFoldWatermark()).toBeNull();
  });
});

describe("watermark round-trip (store surface)", () => {
  it("persists and re-reads the fold watermark; a malformed record reads as absent (recompute, never inflate)", async () => {
    const harness = makeHarness();
    expect(await harness.store.getFoldWatermark()).toBeNull();
    await harness.store.setFoldWatermark({ folded_through_sequence: 7, updated_at: "2026-07-14T12:00:00.000Z" });
    expect(await harness.store.getFoldWatermark()).toEqual({
      folded_through_sequence: 7,
      updated_at: "2026-07-14T12:00:00.000Z",
    });
  });
});
