/**
 * Aggregator protection-snapshot audit LISTING read - eager-read path
 * (perf + per-tenant isolation + honesty/content-parity).
 *
 * Follow-up to #717/#719. #717 added `AuditLog.runEagerReads` (an
 * AsyncLocalStorage eager-view scope so audit reads inside it serve from the
 * eagerly-maintained verified view, O(1), instead of a full-chain re-verify).
 * #719 wrapped `getProtectionSnapshot`'s hero-shield ARM read
 * (`buildCastleWallPosture`) in that scope. But `getProtectionSnapshot` does a
 * SECOND full-chain read - the snapshot audit LISTING
 * (`sources.auditLog.query({ limit: MAX_AUDIT })`) - which stayed OUTSIDE the
 * eager scope and so still re-read, re-decrypted, re-hashed and chain-walked the
 * WHOLE chain on every snapshot poll (11-30s on a real 10k-entry chain, the #714
 * wedge). So the snapshot was only HALF-bounded. This change wraps that listing
 * read in the SAME per-tenant `runEagerReads` scope.
 *
 * These tests assert the full contract on the real `getProtectionSnapshot` path
 * (a real per-tenant `AuditLog`, not the in-memory stub the shape tests use):
 *   (a) PERF: a snapshot over a >=10k chain is bounded-cost / non-scaling - warm
 *       polls serve from the eager view, well under the bound, and do not scale
 *       with chain length (it would be ~linear if the listing read re-scanned the
 *       whole chain per poll), like #717/#719's perf tests; and
 *   (b) ISOLATION: per-tenant only - one tenant's snapshot reads ONLY that
 *       tenant's own `AuditLog` instance's verified view; a second tenant with a
 *       DISTINCT chain gets its own data, never the first tenant's (no shared
 *       mutable state, no cross-tenant read across the AsyncLocalStorage scope);
 *       and
 *   (c) HONESTY / CONTENT PARITY: the eager listing read returns the SAME audit
 *       content the non-eager (per-request re-verify) read returns for the same
 *       data - the change is read COST only, never WHAT the snapshot reports.
 *
 * Synthetic-fixture coverage (the soaks-are-fake-without-users rule): the >=10k
 * chain is built cheaply from byte-identical valid envelopes plus one real tail
 * append, mirroring `audit-log-eager-query.test.ts` and
 * `castle-wall-badge-eager.test.ts`.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import { getProtectionSnapshot } from "../../src/dashboard/aggregator.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  computeAuditEntryHash,
} from "../../src/audit/chain.js";

const LARGE_CHAIN = 10_200; // > 10k, the drill's real chain size class.

/**
 * Build a valid chain of `count` entries CHEAPLY (byte-identical to a real
 * chain), then do ONE genuine critical append so a valid head anchor is written
 * over the resulting head and a FRESH strict-mode reader loads cleanly. Mirrors
 * `audit-log-eager-query.test.ts` / `castle-wall-badge-eager.test.ts`'s helper.
 * `tenantTag` distinguishes one tenant's entry details from another's so the
 * isolation test can prove a snapshot only ever serves its own tenant's data.
 */
async function buildChain(
  count: number,
  tenantTag: string,
): Promise<{ storage: MemoryStorage; masterKey: Uint8Array; reader: AuditLog }> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const encryptionKey = derivePurposeKey(masterKey, "audit-log");

  const rawCount = Math.max(count - 1, 0);
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (let i = 0; i < rawCount; i++) {
    const sequence = i + 1;
    const timestamp = new Date(
      Date.now() - (count - sequence) * 1000,
    ).toISOString();
    const normalized = {
      timestamp,
      layer: "l1" as const,
      operation: "egress_allowed",
      identity_id: `agent-${i % 4}`,
      result: "success" as const,
      details: { tenant: tenantTag, op: i },
    };
    const serialized = stringToBytes(JSON.stringify(normalized));
    const encrypted = encrypt(serialized, encryptionKey);
    const encryptedPayloadBytes = toBase64url(
      stringToBytes(JSON.stringify(encrypted)),
    );
    const entryHash = computeAuditEntryHash({
      sequence,
      prev_hash: prevHash,
      timestamp,
      encrypted_payload_bytes: encryptedPayloadBytes,
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
    });
    const envelope: PersistedAuditEnvelopeV2 = {
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
      sequence,
      prev_hash: prevHash,
      entry_hash: entryHash,
      timestamp,
      encrypted_payload_bytes: encryptedPayloadBytes,
    };
    const key = `entry-${String(sequence).padStart(20, "0")}-fixture-${i}`;
    await storage.write("_audit", key, stringToBytes(JSON.stringify(envelope)));
    prevHash = entryHash;
  }

  // One genuine critical append carrying a tenant-distinguishing detail. Lenient
  // ONLY for this bootstrap append (the raw prefix is anchorless until this
  // append writes the head anchor); the FRESH strict-mode reader loads cleanly.
  const writer = new AuditLog(storage, masterKey, {
    checkpointInterval: 0,
    integrityMode: "lenient",
  });
  await writer.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: `fortress:${tenantTag}`,
    result: "success",
    details: { tenant: tenantTag, tail: true },
    timestamp: new Date(Date.now() - 30_000).toISOString(),
  });
  await writer.flush();

  const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
  return { storage, masterKey, reader };
}

function snapshotSources(reader: AuditLog) {
  return {
    mode: "co-located" as const,
    server_version: "0.9.0-test",
    auditLog: reader,
  };
}

describe("Aggregator snapshot listing read - eager performance (does not scale with chain length)", () => {
  it(
    "serves a warm snapshot over a >=10k chain well under the bound, and warm snapshots do not scale with chain length",
    async () => {
      const { reader } = await buildChain(LARGE_CHAIN, "perf");

      // Cold snapshot pays the unconditional load-time full verify (the tamper
      // floor) on the first eager read of a fresh reader.
      const cold0 = performance.now();
      const cold = await getProtectionSnapshot(snapshotSources(reader));
      const coldMs = performance.now() - cold0;
      // The snapshot reflects the chain; the listing it carries is bounded by
      // MAX_AUDIT and the content is real (never a fabricated empty list).
      expect(cold.audit.length).toBeGreaterThan(0);

      // Warm snapshots (within the re-verify throttle) serve from the eager view
      // and must be FAST and bounded - independent of chain length.
      const warmTimings: number[] = [];
      for (let r = 0; r < 5; r++) {
        const t0 = performance.now();
        const res = await getProtectionSnapshot(snapshotSources(reader));
        warmTimings.push(performance.now() - t0);
        expect(res.audit.length).toBeGreaterThan(0);
      }
      const maxWarm = Math.max(...warmTimings);
      // Defensible bound: a warm snapshot over 10k entries must complete well
      // under 500ms (the drill measured 11-30s on the OLD full-rescan path the
      // unwrapped listing read used). 500ms leaves generous CI headroom while
      // still failing hard if the full-rescan regressed back onto this path.
      expect(maxWarm).toBeLessThan(500);

      // Scale-independence: a warm snapshot on a 10k chain is not dramatically
      // slower than a warm snapshot on a tiny chain (it would be ~linear if the
      // listing read re-scanned the whole chain per poll).
      const small = await buildChain(50, "perf-small");
      await getProtectionSnapshot(snapshotSources(small.reader)); // warm it
      const s0 = performance.now();
      await getProtectionSnapshot(snapshotSources(small.reader));
      const smallWarmMs = performance.now() - s0;
      expect(maxWarm).toBeLessThan(smallWarmMs * 25 + 100);

      // Sanity: cold (full-verify) over 10k is itself far under the OLD 11-30s.
      expect(coldMs).toBeLessThan(10_000);
    },
    60_000,
  );
});

describe("Aggregator snapshot listing read - per-tenant isolation (no cross-tenant leak)", () => {
  it("each tenant's snapshot serves ONLY its own AuditLog instance's data, even with the eager scope open on both", async () => {
    const tenantA = await buildChain(120, "tenant-A");
    const tenantB = await buildChain(120, "tenant-B");

    // Warm both eager views, then read interleaved so any cross-tenant bleed of
    // the AsyncLocalStorage scope or shared mutable state would surface.
    await getProtectionSnapshot(snapshotSources(tenantA.reader));
    await getProtectionSnapshot(snapshotSources(tenantB.reader));

    const snapA = await getProtectionSnapshot(snapshotSources(tenantA.reader));
    const snapB = await getProtectionSnapshot(snapshotSources(tenantB.reader));

    const tenantsOf = (snap: { audit: Array<{ details?: unknown }> }) =>
      new Set(
        snap.audit.map((e) => {
          const d = (e.details ?? {}) as { tenant?: unknown };
          return String(d.tenant);
        }),
      );

    const aTenants = tenantsOf(snapA);
    const bTenants = tenantsOf(snapB);

    // Tenant A's snapshot contains ONLY tenant-A entries; tenant B's ONLY
    // tenant-B. No entry from the other tenant ever appears (no cross-tenant
    // read across the per-instance eager scope).
    expect(aTenants).toEqual(new Set(["tenant-A"]));
    expect(bTenants).toEqual(new Set(["tenant-B"]));
  });
});

describe("Aggregator snapshot listing read - honesty / content parity (eager vs non-eager)", () => {
  it("returns the SAME audit content the per-request (non-eager) listing read returns for the same data", async () => {
    // A chain comfortably larger than MAX_AUDIT (50) so the snapshot's
    // `slice(-MAX_AUDIT)` actually bounds, and the parity check exercises the
    // tail-window the operator surface shows.
    const { reader } = await buildChain(300, "parity");

    // Eager path: the snapshot's listing read inside the wrapped scope.
    const eagerSnap = await getProtectionSnapshot(snapshotSources(reader));

    // Non-eager baseline: the SAME shaper composition the snapshot performs
    // (`query({ limit: MAX_AUDIT })` then `.slice(-MAX_AUDIT).reverse()`) but
    // from a plain per-request `query` OUTSIDE any eager scope, which re-reads +
    // re-verifies the whole chain from disk. The snapshot reads from the eager
    // view; both reflect the same on-disk data, so the reported audit listing
    // must be byte-for-byte identical - the change is read COST only, never WHAT
    // is reported.
    const MAX_AUDIT = 50;
    const direct = await reader.query({ limit: MAX_AUDIT });
    const baselineAudit = direct.entries.slice(-MAX_AUDIT).reverse();

    // The bound actually engaged (more than MAX_AUDIT entries exist).
    expect(eagerSnap.audit.length).toBe(MAX_AUDIT);
    expect(eagerSnap.audit.length).toBe(baselineAudit.length);
    expect(JSON.stringify(eagerSnap.audit)).toBe(JSON.stringify(baselineAudit));
  });
});
