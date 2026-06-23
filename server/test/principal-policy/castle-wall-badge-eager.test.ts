/**
 * Castle Wall arm-BADGE eager-read path - perf + never-fake-green honesty.
 *
 * Backs the follow-up to #717: #717 wrapped the six `/api/posture/home` builders
 * (and the `/api/posture/castle-wall` route) in `AuditLog.runEagerReads` so the
 * always-on board stops re-verifying the whole chain per request. But two
 * `buildCastleWallPosture` call sites stayed OUTSIDE the eager scope and so still
 * re-verified the FULL chain on every badge poll:
 *   - the `/v1/status` document (`Dashboard.buildStatusCastleWall`), which the
 *     native host app polls for the arm badge, and
 *   - the multi-tenant hero-shield rollup (`getProtectionSnapshot`).
 * Both now run their `buildCastleWallPosture` audit read inside `runEagerReads`.
 *
 * The badge is THE never-fake-green surface, so these tests assert BOTH halves of
 * the contract on the exact code path the two call sites use (the canonical
 * `buildCastleWallPosture` shaper wrapped in `auditLog.runEagerReads(...)`):
 *   (a) PERF: a badge read over a >=10k chain is bounded-cost / non-scaling
 *       (warm well under the bound), like #717's home perf test; and
 *   (b) HONESTY: server-known arm-state with zero lag (a just-appended enforcement
 *       entry arms the badge on the very next eager read); the badge falls to
 *       `unknown` (never armed) once evidence ages past the freshness window; and
 *       an out-of-band on-disk tamper is still detected on the eager path (the
 *       chain reads NOT integrity-ok, so the badge never serves stale green).
 *
 * Synthetic-fixture coverage (the soaks-are-fake-without-users rule): the >=10k
 * chain is built cheaply from byte-identical valid envelopes plus one real tail
 * append, mirroring `audit-log-eager-query.test.ts`.
 */
import { describe, expect, it } from "vitest";
import {
  AuditLog,
  type PersistedAuditEnvelopeV2,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  computeAuditEntryHash,
} from "../../src/audit/chain.js";
import {
  buildCastleWallPosture,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
} from "../../src/principal-policy/posture.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../../src/castle-wall/constants.js";

const LARGE_CHAIN = 10_200; // > 10k, the drill's real chain size class.
const FORTRESS = "fortress:badge-test";

/**
 * Build a valid chain of `count` entries CHEAPLY (byte-identical to a real
 * chain), then do ONE genuine critical append carrying a FRESH Castle Wall
 * `egress_allowed` enforcement entry so the canonical shaper reads `armed`. The
 * real append establishes a valid head anchor over the resulting head, so the
 * returned FRESH strict-mode reader loads cleanly and the first eager read pays
 * the unconditional load-time full verify (the tamper floor), exactly like a
 * freshly-booted dashboard. Mirrors `audit-log-eager-query.test.ts`'s helper.
 */
async function buildChainWithFreshArmEvidence(
  count: number,
  tailTimestampMs: number = Date.now() - 30_000,
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
      // NO provenance marker on the bulk prefix: these are non-Castle-Wall L1
      // rows, so they never arm the badge on their own (only the marked tail
      // append below is enforcement evidence).
      details: { op: i },
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

  // One genuine critical append: a FRESH Castle-Wall-marked enforcement entry.
  // Lenient ONLY for this bootstrap append (the raw prefix is anchorless until
  // this append writes the head anchor); the FRESH strict-mode reader loads
  // cleanly afterward.
  const writer = new AuditLog(storage, masterKey, {
    checkpointInterval: 0,
    integrityMode: "lenient",
  });
  await writer.appendCritical({
    layer: "l1",
    operation: "egress_allowed",
    identity_id: FORTRESS,
    result: "success",
    details: {
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
    timestamp: new Date(tailTimestampMs).toISOString(),
  });
  await writer.flush();

  const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
  return { storage, masterKey, reader };
}

/**
 * The exact badge read both wrapped call sites perform: the canonical shaper run
 * inside the eager scope (no pinned producer key, i.e. the macOS / channel-basis
 * floor, which is what the native badge surface uses today).
 */
function badgeRead(reader: AuditLog, now?: number) {
  return reader.runEagerReads(() =>
    buildCastleWallPosture({
      auditLog: reader,
      originMachine: FORTRESS,
      pinnedProducerKeyB64url: null,
      ...(now !== undefined ? { now } : {}),
    }),
  );
}

describe("Castle Wall badge eager read - performance (does not scale with chain length)", () => {
  it(
    "serves a warm badge read over a >=10k chain well under the bound, and warm reads do not scale with chain length",
    async () => {
      const { reader } = await buildChainWithFreshArmEvidence(LARGE_CHAIN);

      // Cold read pays the unconditional load-time full verify (the tamper floor).
      const cold0 = performance.now();
      const cold = await badgeRead(reader);
      const coldMs = performance.now() - cold0;
      // Fresh enforcement evidence ⇒ the badge is armed AND the chain verified
      // clean (never a fabricated green; the evidence is real and in-window).
      expect(cold.arm_state).toBe("armed");
      expect(cold.audit_integrity_ok).toBe(true);

      // Warm reads (within the re-verify throttle) serve from the eager view and
      // must be FAST and bounded - independent of chain length.
      const warmTimings: number[] = [];
      for (let r = 0; r < 5; r++) {
        const t0 = performance.now();
        const res = await badgeRead(reader);
        warmTimings.push(performance.now() - t0);
        expect(res.arm_state).toBe("armed");
      }
      const maxWarm = Math.max(...warmTimings);
      // Defensible bound: a warm badge read over 10k entries must complete well
      // under 500ms (the drill measured 11-30s on the OLD full-rescan path the
      // unwrapped call site used). 500ms leaves generous CI headroom while still
      // failing hard if the full-rescan regressed back onto the badge path.
      expect(maxWarm).toBeLessThan(500);

      // Scale-independence: a warm badge read on a 10k chain is not dramatically
      // slower than a warm read on a tiny chain (it would be ~linear if it
      // re-scanned the whole chain per request).
      const small = await buildChainWithFreshArmEvidence(50);
      await badgeRead(small.reader); // warm it
      const s0 = performance.now();
      await badgeRead(small.reader);
      const smallWarmMs = performance.now() - s0;
      expect(maxWarm).toBeLessThan(smallWarmMs * 25 + 100);

      // Sanity: cold (full-verify) over 10k is itself far under the OLD 11-30s.
      expect(coldMs).toBeLessThan(10_000);
    },
    60_000,
  );
});

describe("Castle Wall badge eager read - never-fake-green honesty", () => {
  it("reflects a just-appended enforcement entry with NO stale lag (server-known arm-state, zero lag)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const log = new AuditLog(storage, masterKey, { checkpointInterval: 0 });

    // Before any enforcement evidence the badge is unknown (never armed).
    const before = await badgeRead(log);
    expect(before.arm_state).toBe("unknown");

    // Append a fresh Castle-Wall enforcement entry (server-written), then read
    // the badge immediately. The eager view is maintained on append, so the
    // next eager read reflects it with NO lag - the badge arms at once.
    await log.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: {
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      timestamp: new Date(Date.now() - 5_000).toISOString(),
    });
    const after = await badgeRead(log);
    expect(after.arm_state).toBe("armed");
    expect(after.audit_integrity_ok).toBe(true);
  });

  it("the badge falls to unknown (never armed) once the only evidence ages past the freshness window", async () => {
    const now = Date.now();
    // Tail enforcement evidence stamped 30s ago is fresh under the default 10m
    // window, so the badge arms.
    const { reader } = await buildChainWithFreshArmEvidence(
      200,
      now - 30_000,
    );
    const fresh = await badgeRead(reader, now);
    expect(fresh.arm_state).toBe("armed");

    // Re-read the SAME chain with a clock advanced past the freshness window:
    // the once-armed evidence is now stale, so the badge must read unknown -
    // never a stale green. (The eager view is the SAME; only the freshness
    // judgment moves, exactly as the shaper computes it today.)
    const later = await badgeRead(
      reader,
      now + DEFAULT_ENFORCEMENT_FRESHNESS_MS + 60_000,
    );
    expect(later.arm_state).toBe("unknown");
  });

  it("an out-of-band tampered chain reads NOT integrity-ok on the badge path - never stale green", async () => {
    const { storage, masterKey } = await buildChainWithFreshArmEvidence(200);

    // Out-of-band edit: flip a byte in the encrypted payload of one persisted
    // entry directly on disk (bypassing the server append path). This is the
    // exact tamper shape the eager load-time / sentinel / backstop re-verify
    // must catch - it must NOT let the badge serve a stale green.
    const metas = await storage.list("_audit");
    const victimKey = metas[Math.floor(metas.length / 2)]!.key;
    const raw = await storage.read("_audit", victimKey);
    const env = JSON.parse(bytesToString(raw!)) as PersistedAuditEnvelopeV2;
    const chars = env.encrypted_payload_bytes.split("");
    chars[10] = chars[10] === "A" ? "B" : "A";
    env.encrypted_payload_bytes = chars.join("");
    await storage.write(
      "_audit",
      victimKey,
      stringToBytes(JSON.stringify(env)),
    );

    // A FRESH reader pays the unconditional load-time full verify, so the tamper
    // is caught immediately. The shaper's read fails closed: integrity NOT ok and
    // the badge is NOT armed (it never serves green over a tampered chain). The
    // shaper catches the strict-mode AuditIntegrityError internally and returns
    // an honest unknown / integrity-flagged posture rather than throwing.
    const reader = new AuditLog(storage, masterKey, { checkpointInterval: 0 });
    const posture = await badgeRead(reader);
    expect(posture.audit_integrity_ok).toBe(false);
    expect(posture.arm_state).not.toBe("armed");
  });
});
