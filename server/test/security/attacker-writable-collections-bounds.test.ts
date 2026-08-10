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
  MAX_HANDSHAKE_SESSIONS_PER_ORIGIN,
  MAX_HANDSHAKE_RESULTS,
  MAX_HANDSHAKE_RESULTS_PER_ORIGIN,
} from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import {
  MAX_FEDERATION_PEERS,
  MAX_FEDERATION_PEERS_PER_ORIGIN,
} from "../../src/federation/registry.js";
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

describe("1. handshake sessions: capped + swept + bounded + per-origin fair", () => {
  it(
    "MUTATION-PROOF TARGET (per-origin): refuses the (quota+1)-th in-flight session for ONE identity WITHOUT evicting or blocking a DIFFERENT identity's session",
    async () => {
      const agent = makeAgent();
      const identityA = await createIdentityFor(agent, "origin-a");
      const identityB = await createIdentityFor(agent, "origin-b");
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      // Fill identity A's OWN per-origin quota. Every one of these must
      // succeed (well under both the per-origin and global caps).
      const firstForA = parse(
        await initiate.handler({ identity_id: identityA.identity_id })
      );
      const firstSessionIdForA = firstForA.session_id as string;
      for (let i = 1; i < MAX_HANDSHAKE_SESSIONS_PER_ORIGIN; i += 1) {
        const out = parse(
          await initiate.handler({ identity_id: identityA.identity_id })
        );
        expect(out.error).toBeUndefined();
      }

      // The (quota+1)-th session for A is REFUSED — a real, surfaced error,
      // never a silently-dropped success.
      const overflowForA = parse(
        await initiate.handler({ identity_id: identityA.identity_id })
      );
      expect(overflowForA.session_id).toBeUndefined();
      expect(overflowForA.error).toContain("too many in-flight handshake sessions");

      // A's FIRST session is still resolvable — refusing never evicted it
      // (refuse-only per-origin quota, never "evict this origin's own
      // oldest to make room").
      const stillThereForA = parse(
        await status.handler({ session_id: firstSessionIdForA })
      );
      expect(stillThereForA.error).toBeUndefined();
      expect(stillThereForA.session_id).toBe(firstSessionIdForA);

      // B is a COMPLETELY DIFFERENT origin: A's flood must not have touched
      // B's headroom at all — this is the property the fix exists for
      // ("500 handshake_initiate calls from one principal cannot evict
      // ANOTHER principal's in-flight session").
      const forB = parse(
        await initiate.handler({ identity_id: identityB.identity_id })
      );
      expect(forB.error).toBeUndefined();
      expect(forB.session_id).toBeDefined();
    },
    30_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct identities (each within its own quota), the store still evicts the oldest session to admit a new one",
    async () => {
      const agent = makeAgent();
      // At least ceil(MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN) + 1
      // distinct identities are needed so the flood can reach the GLOBAL
      // cap without any single identity ever exceeding its own quota
      // (which would refuse before the global cap is ever reached).
      const identityCount =
        Math.ceil(MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN) + 1;
      const identities = [];
      for (let i = 0; i < identityCount; i += 1) {
        identities.push(await createIdentityFor(agent, `spread-${i}`));
      }
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      const first = parse(
        await initiate.handler({ identity_id: identities[0]!.identity_id })
      );
      const firstSessionId = first.session_id as string;

      // Round-robin across identities so no single one exceeds its
      // per-origin quota, while collectively exceeding the GLOBAL cap by a
      // small margin — proves the ORIGINAL entry was evicted to make room
      // under genuine multi-identity pressure (the disclosed residual:
      // per-origin quota stops ONE flooding origin, not legitimate load
      // spread thin across many).
      const EXTRA = 20;
      for (let i = 1; i < MAX_HANDSHAKE_SESSIONS + EXTRA; i += 1) {
        const identity = identities[i % identities.length]!;
        const out = parse(
          await initiate.handler({ identity_id: identity.identity_id })
        );
        expect(out.error).toBeUndefined();
      }

      const stillThere = parse(
        await status.handler({ session_id: firstSessionId })
      );
      expect(stillThere.error).toContain("No handshake session found");
    },
    60_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 2. Handshake results (handshake/tools.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("2. handshake results: capped + per-origin fair + expires_at-aware eviction + bounded listing", () => {
  it(
    "MUTATION-PROOF TARGET (per-origin): refuses the (quota+1)-th preview for ONE identity WITHOUT evicting or blocking a DIFFERENT identity",
    async () => {
      const agent = makeAgent();
      const identityA = await createIdentityFor(agent, "origin-a");
      const identityB = await createIdentityFor(agent, "origin-b");
      const { tools, handshakeResults } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      const firstSHRForA = mintCounterpartySHR(template);
      const firstResultForA = parse(
        await exchange.handler({
          counterparty_shr: firstSHRForA,
          identity_id: identityA.identity_id,
        })
      );
      expect(firstResultForA.verification.recorded).toBe(true);
      const firstIdForA = firstSHRForA.body.instance_id;
      expect(handshakeResults.get(firstIdForA)).toBeDefined();

      for (let i = 1; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
        const out = parse(
          await exchange.handler({
            counterparty_shr: mintCounterpartySHR(template),
            identity_id: identityA.identity_id,
          })
        );
        expect(out.verification.recorded).toBe(true);
      }

      // The (quota+1)-th preview for A is refused — surfaced via
      // verification.recorded/record_error (FAIL-LOUD fix), never a
      // silently-dropped "success". The attestation itself is still valid
      // (a structural preview does not depend on being cached).
      const overflowForA = parse(
        await exchange.handler({
          counterparty_shr: mintCounterpartySHR(template),
          identity_id: identityA.identity_id,
        })
      );
      expect(overflowForA.verification.recorded).toBe(false);
      expect(overflowForA.verification.record_error).toContain(
        "too many handshake results"
      );
      expect(overflowForA.attestation).toBeDefined();

      // A's FIRST entry is still present — refusing never evicted it.
      expect(handshakeResults.get(firstIdForA)).toBeDefined();

      // B is a COMPLETELY DIFFERENT origin: A's flood must not have
      // touched B's headroom.
      const forB = parse(
        await exchange.handler({
          counterparty_shr: mintCounterpartySHR(template),
          identity_id: identityB.identity_id,
        })
      );
      expect(forB.verification.recorded).toBe(true);
    },
    30_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct identities (each within its own quota), the store still evicts the oldest unverified entry to admit a new one",
    async () => {
      const agent = makeAgent();
      const identityCount =
        Math.ceil(MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN) + 1;
      const identities = [];
      for (let i = 0; i < identityCount; i += 1) {
        identities.push(await createIdentityFor(agent, `spread-${i}`));
      }
      const { tools, handshakeResults } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      const firstSHR = mintCounterpartySHR(template);
      await exchange.handler({
        counterparty_shr: firstSHR,
        identity_id: identities[0]!.identity_id,
      });
      const firstId = firstSHR.body.instance_id;
      expect(handshakeResults.get(firstId)).toBeDefined();

      const EXTRA = 20;
      for (let i = 1; i < MAX_HANDSHAKE_RESULTS + EXTRA; i += 1) {
        const identity = identities[i % identities.length]!;
        await exchange.handler({
          counterparty_shr: mintCounterpartySHR(template),
          identity_id: identity.identity_id,
        });
        expect(handshakeResults.size).toBeLessThanOrEqual(MAX_HANDSHAKE_RESULTS);
      }

      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      expect(handshakeResults.get(firstId)).toBeUndefined();
    },
    60_000
  );

  it(
    "MUTATION-PROOF TARGET (expires_at): refuses a new result while every slot holds a live verified peer, then EVICTS one once they expire — never blind-FIFOs a live peer",
    async () => {
      // Short SHR validity (test-only override) so 1000 real handshakes can
      // all complete WITHIN their validity window, and then all become
      // expired together after one short sleep — without waiting the real
      // 1-hour default. 30s is generous headroom over the ~7-10s this fill
      // takes in practice; too short and entries start expiring mid-fill,
      // which the "while-live" probe below cannot distinguish from the
      // eviction-on-expiry behavior it is NOT yet testing.
      const SHR_VALIDITY_MS = 30_000;
      const registrar = makeAgent();
      const { tools: registrarTools, handshakeResults } = createHandshakeTools(
        registrar.config,
        registrar.identityManager,
        registrar.masterKey,
        registrar.auditLog,
        { shrValidityMs: SHR_VALIDITY_MS }
      );
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;

      const fillerOriginCount = MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN;
      const fillerIdentities = [];
      for (let i = 0; i < fillerOriginCount; i += 1) {
        fillerIdentities.push(await createIdentityFor(registrar, `filler-${i}`));
      }
      const probeIdentity = await createIdentityFor(registrar, "probe");

      // Runs a REAL 3-step handshake (initiate/respond/complete) between the
      // registrar (as `localIdentityId`) and a freshly-minted counterparty
      // fortress, and returns the PARSED handshake_complete response —
      // callers assert success or refusal as appropriate (a refused
      // recordHandshakeResult is an EXPECTED outcome for the overflow
      // probes below, so this helper must not assert success itself).
      async function completeRealHandshake(
        localIdentityId: string,
        counterpartyLabel: string
      ): Promise<{ result?: { verified: boolean }; error?: string }> {
        const counterpartyFortress = makeAgent();
        const counterpartyIdentity = await createIdentityFor(
          counterpartyFortress,
          counterpartyLabel
        );
        const { tools: counterpartyTools } = createHandshakeTools(
          counterpartyFortress.config,
          counterpartyFortress.identityManager,
          counterpartyFortress.masterKey,
          counterpartyFortress.auditLog,
          { shrValidityMs: SHR_VALIDITY_MS }
        );
        const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
        const initiated = parse(
          await initiate.handler({ identity_id: localIdentityId })
        );
        const responded = parse(
          await respond.handler({
            challenge: initiated.challenge,
            identity_id: counterpartyIdentity.identity_id,
          })
        );
        return parse(
          await complete.handler({
            session_id: initiated.session_id,
            response: responded.response,
          })
        );
      }

      // Fill handshakeResults to EXACTLY the global cap, spread across
      // `fillerOriginCount` distinct local identities so no single one
      // ever exceeds its own per-origin quota (which would refuse before
      // the global cap is ever reached).
      let counter = 0;
      for (const identity of fillerIdentities) {
        for (let i = 0; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
          const completed = await completeRealHandshake(identity.identity_id, `peer-${counter}`);
          expect(completed.result?.verified).toBe(true);
          counter += 1;
        }
      }
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);

      let saturatedAudited = 0;
      let evictedAudited: { expired?: boolean } | undefined;
      const originalAppend = registrar.auditLog.append.bind(registrar.auditLog);
      registrar.auditLog.append = ((...args: Parameters<AuditLog["append"]>) => {
        if (args[1] === "handshake_results_saturated") saturatedAudited += 1;
        if (args[1] === "handshake_result_evicted") {
          evictedAudited = args[3] as { expired?: boolean };
        }
        return originalAppend(...args);
      }) as AuditLog["append"];

      // Every slot holds a verified, live, UNEXPIRED peer — the probe
      // identity's own new handshake is REFUSED, not admitted by evicting
      // one of them (never blind-FIFO a live peer).
      const whileLive = await completeRealHandshake(
        probeIdentity.identity_id,
        "overflow-while-live"
      );
      expect(whileLive.result).toBeUndefined();
      expect(whileLive.error).toContain("live, unexpired peer");
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      expect(saturatedAudited).toBeGreaterThan(0);

      // Wait past SHR_VALIDITY_MS: every filler entry's expires_at is now
      // in the past. A fresh handshake for the SAME probe identity must
      // now SUCCEED — the MEDIUM #1 fix: an expired verified entry rolls
      // off to admit a new one, exactly like federation/registry.ts's
      // isPeerCurrentlyActive-gated eviction, instead of wedging the store
      // for the server's lifetime.
      await sleep(SHR_VALIDITY_MS + 500);
      const afterExpiry = await completeRealHandshake(
        probeIdentity.identity_id,
        "overflow-after-expiry"
      );
      expect(afterExpiry.result?.verified).toBe(true);
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      expect(evictedAudited).toBeDefined();
      expect(evictedAudited!.expired).toBe(true);
    },
    240_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 3. Federation peers (federation/registry.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("3. federation peers: capped + per-origin fair + refuse-on-all-active + bounded listing", () => {
  it(
    "MUTATION-PROOF TARGET (per-origin): 500 attacker-completed handshakes against ONE local identity cannot lock out a DIFFERENT identity's legitimate registration",
    async () => {
      // register LD2-04 RECHECK: the original cut of this fix let ONE
      // registrar identity fill the ENTIRE shared registry, permanently
      // locking out every other identity's registration (the gate's own
      // reproduction). MAX_FEDERATION_PEERS_PER_ORIGIN closes that — an
      // identity floods only its OWN quota and is refused there, never
      // evicting an active peer to make room and never touching a
      // different identity's headroom.
      const registrar = makeAgent();
      const identityA = await createIdentityFor(registrar, "origin-a");
      const identityB = await createIdentityFor(registrar, "origin-b");
      const counterpartyFortress = makeAgent();

      const { tools: registrarTools, handshakeResults, handshakeResultOrigins } =
        createHandshakeTools(
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
        registrar.identityManager,
        handshakeResultOrigins
      );

      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      // Registers ONE new peer end-to-end AS `localIdentityId`: mints a
      // fresh counterparty identity (cheap: no KDF), completes the real
      // nonce-bearing 4-step handshake, then registers it as a federation
      // peer. Returns the parsed register response (callers assert success
      // or refusal as appropriate — refusal is an EXPECTED outcome for the
      // overflow probes below).
      async function mintAndRegisterPeer(
        localIdentityId: string,
        label: string
      ): Promise<{ registered?: boolean; error?: string; peer_id?: string }> {
        const identity = await createIdentityFor(counterpartyFortress, label);
        const initiated = parse(
          await initiate.handler({ identity_id: localIdentityId })
        );
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
        return parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
      }

      const firstForA = await mintAndRegisterPeer(identityA.identity_id, "a-peer-000");
      expect(firstForA.registered).toBe(true);
      for (let i = 1; i < MAX_FEDERATION_PEERS_PER_ORIGIN; i += 1) {
        const out = await mintAndRegisterPeer(identityA.identity_id, `a-peer-${i}`);
        expect(out.registered).toBe(true);
      }

      // The (quota+1)-th registration for A is REFUSED.
      const overflowForA = await mintAndRegisterPeer(identityA.identity_id, "a-overflow");
      expect(overflowForA.registered).toBeUndefined();
      expect(overflowForA.error).toContain("registration quota");

      // A's first peer is still listed — refusing never evicted it.
      const listedAfterA = parse(await register.handler({ action: "list" }));
      expect(
        listedAfterA.peers.some((p: { peer_id: string }) => p.peer_id === firstForA.peer_id)
      ).toBe(true);

      // B is a COMPLETELY DIFFERENT local identity: A's flood must not
      // have touched B's headroom.
      const forB = await mintAndRegisterPeer(identityB.identity_id, "b-peer-000");
      expect(forB.registered).toBe(true);
    },
    60_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct identities (each within its own quota), the registry evicts the oldest INACTIVE peer to admit a new one — a legitimate registration still succeeds, and an ACTIVE peer survives",
    async () => {
      const registrar = makeAgent();
      // Dedicated identities for the two peers whose fate is asserted below
      // (kept SEPARATE from the round-robin filler identities so their
      // one pre-existing registration never collides with a round-robin
      // remainder pushing them over their own per-origin quota).
      const inactiveOrigin = await createIdentityFor(registrar, "origin-inactive");
      const firstActiveOrigin = await createIdentityFor(registrar, "origin-first-active");
      const probeIdentity = await createIdentityFor(registrar, "origin-probe");
      // Round-robin fillers for the remaining 498 registrations. 11 origins
      // keeps each one's share (ceil(498/11) = 46) comfortably under
      // MAX_FEDERATION_PEERS_PER_ORIGIN (50), regardless of how the 498
      // remainder distributes across them.
      const fillerIdentities = [];
      for (let i = 0; i < 11; i += 1) {
        fillerIdentities.push(await createIdentityFor(registrar, `spread-${i}`));
      }

      const { tools: registrarTools, handshakeResults, handshakeResultOrigins } =
        createHandshakeTools(
          registrar.config,
          registrar.identityManager,
          registrar.masterKey,
          registrar.auditLog
        );
      const { tools: federationTools } = createFederationTools(
        registrar.auditLog,
        handshakeResults,
        registrar.identityManager,
        handshakeResultOrigins
      );
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      // Registers ONE new peer end-to-end AS `localIdentityId`. The
      // counterparty's OWN handshake tools take `counterpartyShrValidityMs`
      // — deliberately short for exactly ONE peer below, so it (and ONLY
      // it) becomes an INACTIVE peer shortly after registration, without
      // any timing dependency on how long the rest of this test takes (the
      // registrar's own SHR validity, and every OTHER counterparty's, stay
      // at the real 1-hour default). `result.expires_at` on the registrar's
      // side derives from the COUNTERPARTY's SHR (handshake/protocol.ts:
      // `their_shr.body.expires_at`), which is exactly what
      // FederationRegistry uses to compute `peer.active`.
      async function mintAndRegisterPeer(
        localIdentityId: string,
        label: string,
        counterpartyShrValidityMs?: number
      ): Promise<{ registered?: boolean; error?: string; peer_id?: string; active?: boolean }> {
        const counterpartyFortress = makeAgent();
        const identity = await createIdentityFor(counterpartyFortress, label);
        const { tools: counterpartyTools } = createHandshakeTools(
          counterpartyFortress.config,
          counterpartyFortress.identityManager,
          counterpartyFortress.masterKey,
          counterpartyFortress.auditLog,
          counterpartyShrValidityMs !== undefined
            ? { shrValidityMs: counterpartyShrValidityMs }
            : undefined
        );
        const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
        const initiated = parse(
          await initiate.handler({ identity_id: localIdentityId })
        );
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
        return parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
      }

      // The ONE peer that will become inactive: a 500ms-validity
      // counterparty SHR, registered first.
      const SHORT_VALIDITY_MS = 500;
      const inactivePeer = await mintAndRegisterPeer(
        inactiveOrigin.identity_id,
        "inactive-peer",
        SHORT_VALIDITY_MS
      );
      expect(inactivePeer.registered).toBe(true);

      // The very first ACTIVE peer registered — this one must SURVIVE.
      const firstActivePeer = await mintAndRegisterPeer(
        firstActiveOrigin.identity_id,
        "first-active-peer"
      );
      expect(firstActivePeer.registered).toBe(true);

      // Fill the rest of the global cap (498 more), spread round-robin
      // across the filler identities so no single one exceeds its own
      // per-origin quota.
      let counter = 0;
      const totalToFill = MAX_FEDERATION_PEERS - 2;
      for (let i = 0; i < totalToFill; i += 1) {
        const identity = fillerIdentities[i % fillerIdentities.length]!;
        const out = await mintAndRegisterPeer(identity.identity_id, `filler-${counter}`);
        expect(out.registered).toBe(true);
        counter += 1;
      }

      // Registry is now at the GLOBAL cap (500). Let the short-validity
      // peer actually expire before probing further.
      await sleep(SHORT_VALIDITY_MS + 500);

      // The probe identity (fresh, well under its own quota) registers a
      // NEW peer — the registry is at global capacity, but ONE existing
      // peer (the deliberately-short-lived one) is now INACTIVE, so this
      // is admitted by evicting THAT one, not refused, and not by evicting
      // an active peer.
      const newPeer = await mintAndRegisterPeer(probeIdentity.identity_id, "legitimate-new-peer");
      expect(newPeer.registered).toBe(true);

      const finalList = parse(await register.handler({ action: "list" }));
      expect(
        finalList.peers.some((p: { peer_id: string }) => p.peer_id === inactivePeer.peer_id)
      ).toBe(false);
      expect(
        finalList.peers.some((p: { peer_id: string }) => p.peer_id === firstActivePeer.peer_id)
      ).toBe(true);
      expect(
        finalList.peers.some((p: { peer_id: string }) => p.peer_id === newPeer.peer_id)
      ).toBe(true);
    },
    180_000
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

  it(
    "MUTATION-PROOF TARGET (filter-before-truncate): a flood of RECENT low-severity findings does not hide an OLDER matching high-severity finding from a severity-filtered query",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      // A small maxScannedRecords makes the OLD bug ("sort by modified_at,
      // slice to the scan window, THEN filter") trivially reproducible: the
      // old finding would be pushed out of a 5-record newest-first window
      // by ANY flood bigger than 5. The fix filters the INDEX (all
      // entries) BEFORE ever touching the scan-window-sized decrypt bound,
      // so it must survive regardless of scan window size.
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-inventory-test",
        maxScannedRecords: 5,
      });

      const OLD_TIME = new Date("2026-01-01T00:00:00.000Z").toISOString();
      await store.saveFinding(
        mkFinding("old-critical", { severity: "alert", observed_at: OLD_TIME })
      );

      // Flood with NEWER, low-severity findings — well past maxScannedRecords.
      const FLOOD = 20;
      for (let i = 0; i < FLOOD; i += 1) {
        await store.saveFinding(
          mkFinding(`recent-info-${i}`, {
            severity: "info",
            observed_at: new Date(Date.parse(OLD_TIME) + (i + 1) * 60_000).toISOString(),
          })
        );
        // Distinct modified_at per write (matches the ordering test above).
        await new Promise((resolve) => setTimeout(resolve, 2));
      }

      const criticalOnly = await store.listFindings({ severity: "alert" });
      expect(criticalOnly.map((f) => f.finding_id)).toEqual(["old-critical"]);
    },
    30_000
  );

  it(
    "an 8-day-baseline-style `since` query (anomaly-trigger's own call shape) is NOT truncated below its span by a flood past the old hardcoded scan window",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      // Deliberately no maxScannedRecords override — this exercises the
      // REAL production ceiling (pinned to anomaly-trigger's QUERY_LIMIT,
      // 5000), and the OLD hardcoded scan window this class re-introduced
      // was 500 — so a flood between 500 and 5000, all within the query's
      // `since` window, is exactly the case that used to silently starve
      // anomaly-trigger's baseline.
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-inventory-test",
      });

      const sinceIso = new Date("2026-01-01T00:00:00.000Z").toISOString();
      await store.saveFinding(
        mkFinding("in-window-old", {
          severity: "info",
          observed_at: new Date(Date.parse(sinceIso) + 1_000).toISOString(),
        })
      );

      // 600 > the OLD hardcoded 500-record scan window this class
      // re-introduced, all newer than `in-window-old` but still >= since.
      const FLOOD = 600;
      for (let i = 0; i < FLOOD; i += 1) {
        await store.saveFinding(
          mkFinding(`in-window-flood-${i}`, {
            severity: "info",
            observed_at: new Date(Date.parse(sinceIso) + (i + 2) * 60_000).toISOString(),
          })
        );
      }

      // Mirrors sentinel/sentinels/anomaly-trigger.ts's own call: `since` +
      // a limit large enough to cover the whole baseline span.
      const found = await store.listFindings({ since: sinceIso, limit: 5_000 });
      expect(found.length).toBe(FLOOD + 1);
      expect(found.some((f) => f.finding_id === "in-window-old")).toBe(true);
    },
    60_000
  );
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
      const firstForCaller0 = await runtime.invokeIfTrap(
        FAKE_TOOL,
        { probe: "first" },
        "agent:caller-0"
      );
      const firstStats = runtime
        .stats()
        .find((s) => s.trap_id === TRAP_ID)!
        .activations.filter((a) => a.caller_identity === "agent:caller-0")
        .at(-1)!;
      const firstFindingIdForCaller0 = firstStats.finding_id;
      expect(firstForCaller0).toEqual({
        handled: true,
        response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
      });

      const EXTRA = 20;
      for (let i = 1; i < MAX_COALESCED_FINDING_WINDOWS + EXTRA; i += 1) {
        await runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, `agent:caller-${i}`);
      }

      // caller-0's TRACKER entry must have been evicted by now (oldest-first
      // policy, well over MAX_COALESCED_FINDING_WINDOWS distinct callers
      // seen since) — but the DURABLE record must NOT have been affected:
      // register Z-HNY-02 RECHECK's second bypass was exactly "tracker
      // eviction mints a fresh durable finding within the same window."
      // The deterministic (trap, caller, time-bucket) finding_id means a
      // re-invocation of caller-0, still comfortably inside
      // FOLLOW_UP_WINDOW_MS, recovers ground truth from the STORE (not the
      // evicted tracker entry) and CONTINUES the same durable row —
      // repeat_count increments to 2, the finding_id is UNCHANGED, and no
      // second durable row is created.
      await runtime.invokeIfTrap(FAKE_TOOL, { probe: "second" }, "agent:caller-0");
      const stats = runtime.stats();
      const secondInvocation = stats
        .find((s) => s.trap_id === TRAP_ID)!
        .activations.filter((a) => a.caller_identity === "agent:caller-0")
        .at(-1)!;
      expect(secondInvocation.finding_id).toBe(firstFindingIdForCaller0);
      const secondFinding = await findingStore.loadFinding(secondInvocation.finding_id);
      expect(secondFinding).not.toBeNull();
      expect(secondFinding!.details.repeat_count).toBe(2);

      const allForCaller0 = (await findingStore.listFindings({ limit: 5_000 })).filter(
        (f) => f.details.caller_identity === "agent:caller-0"
      );
      expect(allForCaller0.length).toBe(1);
    },
    60_000
  );

  it(
    "MUTATION-PROOF TARGET (atomicity): concurrent overlapping invocations for the SAME (trap, caller) converge onto exactly ONE durable finding, never two",
    async () => {
      // register Z-HNY-02 RECHECK's first bypass: the original check-then-
      // set coalescing let two overlapping calls both observe "no existing
      // window" before either had written one, so each minted its own
      // finding_id — two durable rows for what should coalesce into one.
      // The fix (a deterministic finding_id + `runExclusive` serializing
      // the whole read-decide-persist sequence per windowKey) must survive
      // real concurrency, not just sequential calls — this test fires a
      // batch of invocations for ONE caller via Promise.all, not a loop.
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

      const CONCURRENT = 30;
      await Promise.all(
        Array.from({ length: CONCURRENT }, (_, i) =>
          runtime.invokeIfTrap(FAKE_TOOL, { probe: i }, "agent:concurrent-caller")
        )
      );

      const forCaller = (await findingStore.listFindings({ limit: 5_000 })).filter(
        (f) => f.details.caller_identity === "agent:concurrent-caller"
      );
      expect(forCaller.length).toBe(1);
      expect(forCaller[0]!.details.repeat_count).toBe(CONCURRENT);
    },
    30_000
  );

  it(
    "durable finding count stays bounded (never O(invocations)) under a high-volume flood across many traps and callers within one window",
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
      const TRAP_COUNT = 3;
      for (let t = 0; t < TRAP_COUNT; t += 1) {
        // Each trap needs its OWN trap_id AND fake_tool_name —
        // invokeIfTrap resolves the trap by matching
        // `trigger.fake_tool_name === toolName`, so reusing the same name
        // across traps would route every call to whichever trap happens to
        // be first, silently collapsing all 3 traps into 1 for this test's
        // purposes. Built directly (not spread from mkToolSpec()) so the
        // `kind: "tool_call"` discriminant stays narrowed.
        registry.deploy({
          trap_id: `${TRAP_ID}-${t}`,
          trap_class: "tool_call",
          trigger: {
            kind: "tool_call",
            fake_tool_name: `${FAKE_TOOL}-${t}`,
            fake_tool_description: "Read the administrative password.",
            fake_tool_schema: { type: "object", properties: {} },
            catalog_visibility: "all_wrapped_agents",
            fake_response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
          },
          finding_severity: "alert",
          english_text: "Deploy a fake admin_password_reader tool.",
          explanation_paragraph: "inventory test fixture",
          compiled_at: new Date().toISOString(),
        });
      }
      const runtime = new ToolCallTrapRuntime({
        registry,
        findingStore,
        auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS,
      });

      const CALLER_COUNT = 20;
      const INVOCATIONS_PER_CALLER_PER_TRAP = 15;
      for (let t = 0; t < TRAP_COUNT; t += 1) {
        const spec = registry.list()[t]!;
        const toolName =
          spec.trigger.kind === "tool_call" ? spec.trigger.fake_tool_name : "";
        for (let c = 0; c < CALLER_COUNT; c += 1) {
          for (let i = 0; i < INVOCATIONS_PER_CALLER_PER_TRAP; i += 1) {
            await runtime.invokeIfTrap(toolName, { probe: i }, `agent:flood-caller-${c}`);
          }
        }
      }

      // O(traps x callers), NOT O(invocations): TRAP_COUNT x CALLER_COUNT
      // distinct durable rows regardless of how many times each pair was
      // invoked (300 invocations per (trap,caller) here would have been
      // 300 rows pre-coalescing; this asserts exactly TRAP_COUNT x
      // CALLER_COUNT).
      const allFindings = await findingStore.listFindings({ limit: 5_000 });
      const honeypotFindings = allFindings.filter((f) =>
        f.sentinel_id.startsWith("honeypot:")
      );
      expect(honeypotFindings.length).toBe(TRAP_COUNT * CALLER_COUNT);
      for (const finding of honeypotFindings) {
        expect(finding.details.repeat_count).toBe(INVOCATIONS_PER_CALLER_PER_TRAP);
      }
    },
    60_000
  );
});
