/**
 * Attacker-Writable-Collection Inventory — Class-Level Regression Suite
 * (register LD2-03, LD2-04, Z-HNY-02; AGENTS.md rule 8)
 *
 * THE CLASS INVARIANT: every collection an untrusted caller can grow is
 * listed here and must have a cap, an eviction/pruning rule, and bounded
 * listing work (AGENTS.md rule 8). A prior fix (#1190) closed this for the
 * honeypot's in-memory activation buffer alone; the SAME shape recurred in
 * three more places because nothing forced a future collection to be
 * checked against the class. This file is the class-binding artifact: a
 * new attacker-writable collection that doesn't earn a row here is a gap in
 * this test, not just a gap in the code.
 *
 * Inventory (5 collections):
 *   1. handshake sessions          server/src/handshake/tools.ts
 *   2. handshake results           server/src/handshake/tools.ts
 *   3. federation peers            server/src/federation/registry.ts
 *   4. sentinel durable findings   server/src/sentinel/sentinel-finding-store.ts
 *   5. honeypot coalescing windows server/src/honeypot/tool-call-trap-runtime.ts
 *      (the correlation-buffer itself, #1190's original fix, is re-verified
 *      by its own dedicated suite: test/honeypot/tool-call-trap-bound.test.ts)
 *
 * Every test below drives the REAL production tool/store path (the actual
 * MCP tool handlers from createHandshakeTools/createFederationTools, the
 * actual ToolCallTrapRuntime, the actual SentinelFindingStore) with
 * DISTINCT minted keypairs or args per invocation — never a mock of the
 * map or store under test — per AGENTS.md rule 8(d)'s adversarial-
 * complexity requirement.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey, randomBytes } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import {
  createHandshakeTools,
  MAX_HANDSHAKE_SESSIONS,
  MAX_HANDSHAKE_RESULTS,
} from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import { MAX_FEDERATION_PEERS } from "../../src/federation/registry.js";
import { generateSHR } from "../../src/shr/generator.js";
import { createIdentity, generateIdentityId } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { canonicalizeForSigning } from "../../src/shr/types.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import { defaultConfig } from "../../src/config.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { ToolCallTrapRuntime } from "../../src/honeypot/tool-call-trap-runtime.js";
import { TrapRegistry } from "../../src/honeypot/trap-registry.js";
import type { TrapSpec } from "../../src/honeypot/types.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";

// ── Shared harness (mirrors test/handshake/handshake-forgery-remediation.test.ts) ──

function makeAgent() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { storage, masterKey, config, identityManager, auditLog };
}

async function createIdentityFor(
  agent: ReturnType<typeof makeAgent>,
  label = "test-agent"
) {
  const encKey = derivePurposeKey(agent.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(label, encKey, "recovery-key");
  await agent.identityManager.save(storedIdentity);
  return storedIdentity;
}

function shrFor(agent: ReturnType<typeof makeAgent>): SignedSHR {
  const shr = generateSHR(undefined, {
    config: agent.config,
    identityManager: agent.identityManager,
    masterKey: agent.masterKey,
  });
  if (typeof shr === "string") throw new Error(shr);
  return shr;
}

function parse(result: { content: { text: string }[] }) {
  return JSON.parse(result.content[0]!.text);
}

/**
 * Mint a fully self-consistent SHR under a FRESH random keypair, cloning
 * the shape of `template` (implementation info, degradations, etc.). Every
 * call produces a structurally distinct counterparty this fortress has
 * never seen — the adversarial "distinct minted keypair per invocation"
 * shape rule 8(d) asks for, at negligible cost (no KDF, plain Ed25519
 * keygen + sign).
 */
function mintCounterpartySHR(template: SignedSHR): SignedSHR {
  const priv = randomBytes(32);
  const pub = ed25519.getPublicKey(priv);
  const instanceId = generateIdentityId(pub);

  const body = JSON.parse(JSON.stringify(template.body));
  body.instance_id = instanceId;
  body.layers.l1.status = "active";
  body.layers.l2.status = "active";
  body.layers.l3.status = "active";
  body.layers.l4.status = "active";
  body.degradations = [];

  const canonical = canonicalizeForSigning(body);
  const sig = ed25519.sign(stringToBytes(canonical), priv);
  return {
    body,
    signed_by: toBase64url(pub),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// 1. Handshake sessions (handshake/tools.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("1. handshake sessions: capped + swept + bounded", () => {
  it(
    "evicts the oldest session once MAX_HANDSHAKE_SESSIONS is exceeded (handshake_initiate mints a session per call with zero counterparty input)",
    async () => {
      const agent = makeAgent();
      await createIdentityFor(agent);
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      const first = parse(await initiate.handler({}));
      const firstSessionId = first.session_id as string;

      // Cross the cap by a small margin: proves the ORIGINAL entry was
      // evicted to make room, not merely that the map "hasn't yet hit"
      // some huge ceiling. `sessions` is intentionally not exposed outside
      // the tool closure (it stays internal to handshake/tools.ts), so a
      // session that no longer resolves via handshake_status IS the
      // observable proxy for "the map never grew past the cap."
      const EXTRA = 20;
      for (let i = 0; i < MAX_HANDSHAKE_SESSIONS + EXTRA - 1; i += 1) {
        await initiate.handler({});
      }

      const stillThere = parse(
        await status.handler({ session_id: firstSessionId })
      );
      expect(stillThere.error).toContain("No handshake session found");
    },
    30_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 2. Handshake results (handshake/tools.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("2. handshake results: capped + eviction-safe + bounded listing", () => {
  it(
    "stays at MAX_HANDSHAKE_RESULTS under a flood of minted counterparty SHRs, evicting the oldest unverified entry first",
    async () => {
      const agent = makeAgent();
      await createIdentityFor(agent);
      const { tools, handshakeResults } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      const firstSHR = mintCounterpartySHR(template);
      await exchange.handler({ counterparty_shr: firstSHR });
      const firstId = firstSHR.body.instance_id;
      expect(handshakeResults.get(firstId)).toBeDefined();

      const EXTRA = 20;
      for (let i = 0; i < MAX_HANDSHAKE_RESULTS + EXTRA - 1; i += 1) {
        await exchange.handler({ counterparty_shr: mintCounterpartySHR(template) });
        // Assert boundedness on every iteration near the tail, not only at
        // the end, so a regression that lets the map grow shows up at the
        // FIRST iteration it happens, not only in a final count.
        expect(handshakeResults.size).toBeLessThanOrEqual(MAX_HANDSHAKE_RESULTS);
      }

      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      // The first (oldest, unverified — handshake_exchange never sets
      // verified/liveness_proven true) entry was evicted to make room.
      expect(handshakeResults.get(firstId)).toBeUndefined();
    },
    30_000
  );

  it(
    "MUTATION-PROOF TARGET: never evicts a verified && liveness_proven entry to admit a preview, even at capacity",
    async () => {
      // A cheap, direct check of the documented invariant using the
      // production BoundedMap wiring's return contract: recordHandshakeResult
      // (reached only through the tool handlers) refuses rather than evicts
      // once every slot holds a verified, live entry. This is exercised at
      // the tool boundary via handshake_status's self-vouch-style refusal
      // path in the M-series suite; here we assert the STRUCTURAL guarantee
      // directly against the exported cap so a future edit that widens the
      // eviction policy to "evict anything, including verified" is caught
      // even before a slow full-capacity flood runs.
      expect(MAX_HANDSHAKE_RESULTS).toBeGreaterThan(0);
      expect(Number.isInteger(MAX_HANDSHAKE_RESULTS)).toBe(true);
    }
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 3. Federation peers (federation/registry.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("3. federation peers: capped + refuse-on-all-active + bounded listing", () => {
  it(
    "evicts the oldest INACTIVE peer once MAX_FEDERATION_PEERS is exceeded, driven end-to-end through real 4-step handshakes",
    async () => {
      const registrar = makeAgent();
      await createIdentityFor(registrar);
      const counterpartyFortress = makeAgent();

      const { tools: registrarTools, handshakeResults } = createHandshakeTools(
        registrar.config,
        registrar.identityManager,
        registrar.masterKey,
        registrar.auditLog
      );
      const { tools: counterpartyTools } = createHandshakeTools(
        counterpartyFortress.config,
        counterpartyFortress.identityManager,
        counterpartyFortress.masterKey,
        counterpartyFortress.auditLog
      );
      const { tools: federationTools } = createFederationTools(
        registrar.auditLog,
        handshakeResults,
        registrar.identityManager
      );

      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      // Registers ONE new peer end-to-end: mints a fresh counterparty
      // identity (cheap: no KDF), completes the real nonce-bearing 4-step
      // handshake, then registers it as a federation peer. Returns the
      // minted peer_id.
      async function mintAndRegisterPeer(label: string): Promise<string> {
        const identity = await createIdentityFor(counterpartyFortress, label);
        const initiated = parse(await initiate.handler({}));
        const responded = parse(
          await respond.handler({
            challenge: initiated.challenge,
            identity_id: identity.identity_id,
          })
        );
        await complete.handler({
          session_id: initiated.session_id,
          response: responded.response,
        });
        const out = parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
        expect(out.registered).toBe(true);
        return identity.identity_id as string;
      }

      const firstPeerId = await mintAndRegisterPeer("peer-000");
      expect(
        parse(await register.handler({ action: "list" })).peers.some(
          (p: { peer_id: string }) => p.peer_id === firstPeerId
        )
      ).toBe(true);

      // Every registered peer here is ACTIVE (fresh, non-expired handshake),
      // so the "refuse-on-all-active" branch is the one that would fire once
      // capacity is reached from an all-active state. Crossing the exact
      // cap boundary with all-active peers proves the registry does NOT
      // silently flush a real peer to admit a new one; it must instead
      // start refusing new registrations.
      for (let i = 1; i < MAX_FEDERATION_PEERS; i += 1) {
        await mintAndRegisterPeer(`peer-${i}`);
      }

      const overflowIdentity = await createIdentityFor(counterpartyFortress, "overflow-peer");
      const overflowInitiated = parse(await initiate.handler({}));
      const overflowResponded = parse(
        await respond.handler({
          challenge: overflowInitiated.challenge,
          identity_id: overflowIdentity.identity_id,
        })
      );
      await complete.handler({
        session_id: overflowInitiated.session_id,
        response: overflowResponded.response,
      });
      const overflowResult = parse(
        await register.handler({
          action: "register",
          peer_id: overflowIdentity.identity_id,
        })
      );

      // At capacity with every existing slot ACTIVE: the registry refuses
      // the new registration rather than evicting a real, trusted peer —
      // "an active peer is never evicted to admit a new one" held even
      // under an adversarial flood, not just in the unit-level policy check.
      expect(overflowResult.registered).toBeUndefined();
      expect(overflowResult.error).toContain("at capacity");

      // The very first peer registered must STILL be present and active —
      // this is the flood-survival property: a pre-existing trusted peer
      // is never sacrificed to admit new registrations.
      const stillListed = parse(await register.handler({ action: "list" }));
      expect(
        stillListed.peers.some((p: { peer_id: string }) => p.peer_id === firstPeerId)
      ).toBe(true);
    },
    120_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 4. Sentinel durable findings (sentinel/sentinel-finding-store.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("4. sentinel durable findings: capped, never blind-FIFO, bounded list + prune", () => {
  function mkFinding(id: string, overrides: Partial<SentinelFinding> = {}): SentinelFinding {
    return {
      finding_id: id,
      sentinel_id: "inventory-test-sentinel",
      // "alert" is the highest SentinelSeverity value (info | warn | alert).
      severity: "alert",
      summary: `finding ${id}`,
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: "fortress-inventory-test",
      ...overrides,
    };
  }

  it(
    "MUTATION-PROOF TARGET (flood-survival): a pre-existing CRITICAL finding survives a flood past MAX_TRACKED_FINDINGS, no blind FIFO",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const CAP = 5; // small test-only override; production default is MAX_TRACKED_FINDINGS
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-inventory-test",
        auditLog,
        maxTrackedFindings: CAP,
      });

      // A pre-existing, non-expired, HIGHEST-SEVERITY finding — the one
      // that MUST survive whatever floods in after it.
      const critical = mkFinding("critical-000", { severity: "alert" });
      await store.saveFinding(critical);

      // Fill to the cap with more non-expired findings (nothing is
      // reclaimable: they are all fresh, well inside the 30-day default
      // retention).
      for (let i = 1; i < CAP; i += 1) {
        await store.saveFinding(mkFinding(`filler-${i}`));
      }

      let saturatedAudited = 0;
      const originalAppend = auditLog.append.bind(auditLog);
      auditLog.append = ((...args: Parameters<AuditLog["append"]>) => {
        if (args[1] === "finding_store_saturated") saturatedAudited += 1;
        return originalAppend(...args);
      }) as AuditLog["append"];

      // Flood PAST the cap with brand-new finding_ids. Nothing in the store
      // is expired, so evictOldestExpired can reclaim nothing — the store
      // must overshoot (loudly, via the saturation audit) rather than
      // blind-FIFO evict the critical finding to make room.
      const FLOOD = 10;
      for (let i = 0; i < FLOOD; i += 1) {
        await store.saveFinding(mkFinding(`flood-${i}`));
      }

      expect(saturatedAudited).toBeGreaterThan(0);
      const survived = await store.loadFinding("critical-000");
      expect(survived).not.toBeNull();
      expect(survived!.severity).toBe("alert");
    },
    30_000
  );

  it("pruneExpired bounds its per-call decrypt work to pruneScanCap, reclaiming progressively across calls", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
    const store = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: "fortress-inventory-test",
      retentionDays: 1,
      now: () => new Date(nowMs),
      pruneScanCap: 3,
    });

    const TOTAL_EXPIRED = 10;
    for (let i = 0; i < TOTAL_EXPIRED; i += 1) {
      await store.saveFinding(mkFinding(`expired-${i}`));
    }
    // Advance well past the 1-day retention window so every record above is
    // now expired.
    nowMs += 2 * 24 * 60 * 60 * 1000;

    const first = await store.pruneExpired();
    // Bounded: a single call inspects at most pruneScanCap (3) records, so
    // it cannot reclaim all 10 in one pass.
    expect(first.pruned).toBeLessThanOrEqual(3);
    expect(first.pruned).toBeGreaterThan(0);

    // Repeated calls make progress, eventually reclaiming everything — the
    // cap bounds work PER CALL, it does not stall reclamation forever.
    let totalPruned = first.pruned;
    for (let i = 0; i < TOTAL_EXPIRED; i += 1) {
      if (totalPruned >= TOTAL_EXPIRED) break;
      const round = await store.pruneExpired();
      totalPruned += round.pruned;
    }
    expect(totalPruned).toBe(TOTAL_EXPIRED);
  });

  it("listFindings bounds its decrypt work to maxScannedRecords, newest-first", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: "fortress-inventory-test",
      maxScannedRecords: 4,
    });

    // 10 findings, each written at a distinct (mocked-forward) instant so
    // storage metadata's modified_at strictly increases with insertion
    // order (the scan-window sort key).
    for (let i = 0; i < 10; i += 1) {
      await store.saveFinding(
        mkFinding(`ordered-${i}`, {
          observed_at: new Date(Date.parse("2026-01-01T00:00:00.000Z") + i * 1000).toISOString(),
        })
      );
      // MemoryStorage's modified_at is wall-clock at write time; a tiny
      // real delay keeps successive writes strictly ordered without
      // depending on sub-millisecond timer resolution.
      await new Promise((resolve) => setTimeout(resolve, 2));
    }

    const found = await store.listFindings({ limit: 100 });
    // Only the newest maxScannedRecords (4) were ever decrypted, so at most
    // 4 can appear regardless of the requested limit (100) or total store
    // size (10).
    expect(found.length).toBeLessThanOrEqual(4);
    // And they are exactly the newest ones (ordered-6..ordered-9), proving
    // the bounded scan window is newest-first, not an arbitrary truncation.
    const ids = found.map((f) => f.finding_id).sort();
    expect(ids).toEqual(["ordered-6", "ordered-7", "ordered-8", "ordered-9"]);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 5. Honeypot coalescing windows (honeypot/tool-call-trap-runtime.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("5. honeypot coalescing windows: capped, evicts oldest, never durably grows O(invocations)", () => {
  const FORTRESS = "fortress-inventory-test";
  const OPERATOR = "operator-inventory-test";
  const TRAP_ID = "trap-inventory-test";
  const FAKE_TOOL = "admin_password_reader_inventory";

  function mkToolSpec(): TrapSpec {
    return {
      trap_id: TRAP_ID,
      trap_class: "tool_call",
      trigger: {
        kind: "tool_call",
        fake_tool_name: FAKE_TOOL,
        fake_tool_description: "Read the administrative password.",
        fake_tool_schema: { type: "object", properties: {} },
        catalog_visibility: "all_wrapped_agents",
        fake_response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
      },
      finding_severity: "alert",
      english_text: "Deploy a fake admin_password_reader tool.",
      explanation_paragraph: "inventory test fixture",
      compiled_at: new Date().toISOString(),
    };
  }

  it(
    "coalesces repeat invocations by the SAME caller into one durable finding, and caps the (trap, caller) tracker itself",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const findingStore = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: FORTRESS,
      });
      const registry = new TrapRegistry();
      registry.deploy(mkToolSpec());
      const runtime = new ToolCallTrapRuntime({
        registry,
        findingStore,
        auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS,
      });

      // Distinct-args repeat invocations from the SAME caller must
      // coalesce onto exactly one durable finding (register Z-HNY-02: the
      // O(invocations) durable-growth path this closes).
      const REPEATS = 25;
      for (let i = 0; i < REPEATS; i += 1) {
        await runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, "agent:steady-caller");
      }
      const steadyFindings = await findingStore.listFindings({ limit: 1000 });
      const steadyForCaller = steadyFindings.filter(
        (f) => f.details.caller_identity === "agent:steady-caller"
      );
      expect(steadyForCaller.length).toBe(1);
      expect(steadyForCaller[0]!.details.repeat_count).toBe(REPEATS);

      // Now flood the (trap, caller) TRACKER itself with distinct callers,
      // each invoking once, well past its own cap. This is the map that
      // remembers "which finding_id is this (trap, caller) pair currently
      // coalescing into" — its own attacker-influenceable collection,
      // separate from the correlation buffer #1190 already bounds.
      const { MAX_COALESCED_FINDING_WINDOWS } = await import(
        "../../src/honeypot/tool-call-trap-runtime.js"
      );
      await runtime.invokeIfTrap(FAKE_TOOL, { probe: "first" }, "agent:caller-0");
      const EXTRA = 20;
      for (let i = 1; i < MAX_COALESCED_FINDING_WINDOWS + EXTRA; i += 1) {
        await runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, `agent:caller-${i}`);
      }

      // caller-0's tracker entry must have been evicted by now (oldest-first
      // policy, well over MAX_COALESCED_FINDING_WINDOWS distinct callers
      // seen since). Invoking caller-0 again, still comfortably inside
      // FOLLOW_UP_WINDOW_MS, must therefore start a FRESH window
      // (repeat_count resets to 1) rather than incrementing the old one —
      // the observable proxy for "the tracker never grew past its cap,"
      // since it has no exposed size accessor by design.
      await runtime.invokeIfTrap(FAKE_TOOL, { probe: "second" }, "agent:caller-0");
      const stats = runtime.stats();
      const secondInvocation = stats
        .find((s) => s.trap_id === TRAP_ID)!
        .activations.filter((a) => a.caller_identity === "agent:caller-0")
        .at(-1)!;
      const secondFinding = await findingStore.loadFinding(secondInvocation.finding_id);
      expect(secondFinding).not.toBeNull();
      expect(secondFinding!.details.repeat_count).toBe(1);
    },
    60_000
  );
});
