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
 *   6. awaited critical audit before eviction/reclamation (cross-cutting;
 *      MUST-FIX 6, fix-round-2)
 *
 * Every test below drives the REAL production tool/store path (the actual
 * MCP tool handlers from createHandshakeTools/createFederationTools, the
 * actual ToolCallTrapRuntime, the actual SentinelFindingStore) with
 * DISTINCT minted keypairs or args per invocation — never a mock of the
 * map or store under test — per AGENTS.md rule 8(d)'s adversarial-
 * complexity requirement.
 *
 * PER-ORIGIN QUOTAS ARE SESSION-SCOPED, NOT IDENTITY-SCOPED (fix-round-2,
 * MUST-FIX 1 spine RECHECK): `identity_create`/`identity_list` are Tier-3
 * always-allow (principal-policy/loader.ts), so an untrusted agent mints
 * local Sanctuary identities freely. Every test below that exercises a
 * per-origin quota therefore drives the REAL tool handler's SECOND
 * argument — `callerIdentity`, the server-set agent-session principal
 * router.ts threads in from `options.currentAgentId()` — as the origin,
 * never `identity_id`. Several tests deliberately MINT MANY DISTINCT LOCAL
 * IDENTITIES under ONE session string to prove that multiplicity doesn't
 * multiply origins — this is the exact mint-many-identities bypass the
 * fix-round-1 cut of this branch was vulnerable to (its own multi-identity
 * test proved the lockout was still reachable).
 */

import { describe, it, expect, vi } from "vitest";
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
  AGENT_UNKNOWN_ORIGIN,
} from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import {
  MAX_FEDERATION_PEERS,
  MAX_FEDERATION_PEERS_PER_ORIGIN,
} from "../../src/federation/registry.js";
import { ON_EVICT_AUDIT_TIMEOUT_MS } from "../../src/core/bounded-map.js";
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
import {
  SentinelFindingStore,
  SentinelFindingStoreRefusedError,
  SENTINEL_FINDING_NAMESPACE,
} from "../../src/sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";
import { AnomalyTriggerWatcher } from "../../src/sentinel/sentinels/anomaly-trigger.js";
import type { SentinelContext } from "../../src/sentinel/types.js";

// ── Shared harness (mirrors test/handshake/handshake-forgery-remediation.test.ts) ──

function makeAgent(storage: MemoryStorage = new MemoryStorage()) {
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

/** Storage wrapper that fails every `_audit` namespace write once
 * `failAuditWrites` is flipped true — used by section 6's mutation-proof
 * tests to prove a rejected critical audit write ABORTS an eviction /
 * reclamation rather than proceeding to delete with no durable trail. */
class ToggleableFaultingAuditStorage extends MemoryStorage {
  failAuditWrites = false;
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit" && this.failAuditWrites) {
      throw new Error("simulated audit disk unavailable");
    }
    return super.write(namespace, key, data);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 1. Handshake sessions (handshake/tools.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("1. handshake sessions: capped + swept + bounded + per-session fair", () => {
  it(
    "MUTATION-PROOF TARGET (per-session, MUST-FIX 1 spine): minting MANY local identities within ONE agent session does not multiply origins — refuses at the session's own quota, and a DISTINCT session is unaffected",
    async () => {
      const agent = makeAgent();
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      const SESSION_A = "agent:session-a";
      const SESSION_B = "agent:session-b";

      // MINT a distinct local identity for EVERY call — the exact bypass
      // fix-round-1 was vulnerable to: identity_create is Tier-3
      // always-allow, so an attacker who could multiply origins by minting
      // identities would defeat a per-identity quota. Every one of these
      // calls carries the SAME agent session.
      const identities = [];
      for (let i = 0; i < MAX_HANDSHAKE_SESSIONS_PER_ORIGIN; i += 1) {
        identities.push(await createIdentityFor(agent, `minted-${i}`));
      }
      const firstForA = parse(
        await initiate.handler({ identity_id: identities[0]!.identity_id }, SESSION_A)
      );
      const firstSessionIdForA = firstForA.session_id as string;
      for (let i = 1; i < identities.length; i += 1) {
        const out = parse(
          await initiate.handler({ identity_id: identities[i]!.identity_id }, SESSION_A)
        );
        expect(out.error).toBeUndefined();
      }

      // The (quota+1)-th session for session A is refused even against a
      // BRAND NEW, never-before-used minted identity — proving the quota
      // tracks the SESSION, not identity_id.
      const overflowIdentity = await createIdentityFor(agent, "minted-overflow");
      const overflowForA = parse(
        await initiate.handler({ identity_id: overflowIdentity.identity_id }, SESSION_A)
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

      // A COMPLETELY DIFFERENT SESSION — reusing one of A's own minted
      // identities, to prove it is the SESSION that is accounted, not the
      // identity — is entirely unaffected by A's flood.
      const forB = parse(
        await initiate.handler({ identity_id: identities[0]!.identity_id }, SESSION_B)
      );
      expect(forB.error).toBeUndefined();
      expect(forB.session_id).toBeDefined();
    },
    30_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct AGENT SESSIONS (each within its own quota), the store still evicts the oldest session to admit a new one",
    async () => {
      const agent = makeAgent();
      const identity = await createIdentityFor(agent, "shared-identity");
      // At least ceil(MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN) + 1
      // distinct SESSIONS are needed so the flood can reach the GLOBAL cap
      // without any single session ever exceeding its own quota (which
      // would refuse before the global cap is ever reached). One shared
      // local identity is enough — origin no longer depends on identity_id.
      const sessionCount =
        Math.ceil(MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN) + 1;
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      const first = parse(
        await initiate.handler({ identity_id: identity.identity_id }, "agent:spread-0")
      );
      const firstSessionId = first.session_id as string;

      // Round-robin across sessions so no single one exceeds its per-origin
      // quota, while collectively exceeding the GLOBAL cap by a small
      // margin — proves the ORIGINAL entry was evicted to make room under
      // genuine multi-session pressure.
      const EXTRA = 20;
      for (let i = 1; i < MAX_HANDSHAKE_SESSIONS + EXTRA; i += 1) {
        const session = `agent:spread-${i % sessionCount}`;
        const out = parse(
          await initiate.handler({ identity_id: identity.identity_id }, session)
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

  it("a call with no callerIdentity (bypassing the router) falls into the shared AGENT_UNKNOWN_ORIGIN bucket, which is itself quota-bounded — not an unbounded escape hatch", async () => {
    const agent = makeAgent();
    const identity = await createIdentityFor(agent, "unknown-origin-identity");
    const { tools } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;

    // No second argument passed — mirrors a direct handler call that never
    // goes through router.ts's callerIdentity computation.
    const first = parse(await initiate.handler({ identity_id: identity.identity_id }));
    expect(first.error).toBeUndefined();

    for (let i = 1; i < MAX_HANDSHAKE_SESSIONS_PER_ORIGIN; i += 1) {
      const out = parse(await initiate.handler({ identity_id: identity.identity_id }));
      expect(out.error).toBeUndefined();
    }
    // The shared unknown-origin bucket hits the SAME per-origin quota as
    // any named session — refused, not unbounded.
    const overflow = parse(await initiate.handler({ identity_id: identity.identity_id }));
    expect(overflow.error).toContain("too many in-flight handshake sessions");

    // Explicitly passing the constant produces the identical refusal —
    // confirms this IS the AGENT_UNKNOWN_ORIGIN bucket, not a separate one.
    const explicit = parse(
      await initiate.handler({ identity_id: identity.identity_id }, AGENT_UNKNOWN_ORIGIN)
    );
    expect(explicit.error).toContain("too many in-flight handshake sessions");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 2. Handshake results (handshake/tools.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("2. handshake results: capped + per-session fair + expires_at-aware eviction + bounded listing", () => {
  it(
    "MUTATION-PROOF TARGET (per-session, MUST-FIX 1 spine): minting MANY local identities within ONE agent session does not multiply origins for handshakeResults either",
    async () => {
      const agent = makeAgent();
      const { tools, handshakeResults } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;

      const SESSION_A = "agent:session-a";
      const SESSION_B = "agent:session-b";

      const identities = [];
      for (let i = 0; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
        identities.push(await createIdentityFor(agent, `minted-result-${i}`));
      }
      // shrFor() defaults to the primary identity, which must exist first.
      const template = shrFor(agent);

      const firstSHRForA = mintCounterpartySHR(template);
      const firstResultForA = parse(
        await exchange.handler(
          { counterparty_shr: firstSHRForA, identity_id: identities[0]!.identity_id },
          SESSION_A
        )
      );
      expect(firstResultForA.verification.recorded).toBe(true);
      const firstIdForA = firstSHRForA.body.instance_id;
      expect(handshakeResults.get(firstIdForA)).toBeDefined();

      for (let i = 1; i < identities.length; i += 1) {
        const out = parse(
          await exchange.handler(
            {
              counterparty_shr: mintCounterpartySHR(template),
              identity_id: identities[i]!.identity_id,
            },
            SESSION_A
          )
        );
        expect(out.verification.recorded).toBe(true);
      }

      // The (quota+1)-th preview for session A — using a BRAND NEW minted
      // identity — is refused. Surfaced via verification.recorded/
      // record_error (FAIL-LOUD fix), never a silently-dropped "success".
      const overflowIdentity = await createIdentityFor(agent, "minted-result-overflow");
      const overflowForA = parse(
        await exchange.handler(
          {
            counterparty_shr: mintCounterpartySHR(template),
            identity_id: overflowIdentity.identity_id,
          },
          SESSION_A
        )
      );
      expect(overflowForA.verification.recorded).toBe(false);
      expect(overflowForA.verification.record_error).toContain(
        "too many handshake results"
      );
      expect(overflowForA.attestation).toBeDefined();

      // A's FIRST entry is still present — refusing never evicted it.
      expect(handshakeResults.get(firstIdForA)).toBeDefined();

      // A COMPLETELY DIFFERENT SESSION (reusing one of A's own minted
      // identities): A's flood must not have touched B's headroom.
      const forB = parse(
        await exchange.handler(
          {
            counterparty_shr: mintCounterpartySHR(template),
            identity_id: identities[0]!.identity_id,
          },
          SESSION_B
        )
      );
      expect(forB.verification.recorded).toBe(true);
    },
    30_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct AGENT SESSIONS (each within its own quota), the store still evicts the oldest unverified entry to admit a new one",
    async () => {
      const agent = makeAgent();
      const identity = await createIdentityFor(agent, "shared-identity");
      const sessionCount =
        Math.ceil(MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN) + 1;
      const { tools, handshakeResults } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      const firstSHR = mintCounterpartySHR(template);
      await exchange.handler(
        { counterparty_shr: firstSHR, identity_id: identity.identity_id },
        "agent:spread-0"
      );
      const firstId = firstSHR.body.instance_id;
      expect(handshakeResults.get(firstId)).toBeDefined();

      const EXTRA = 20;
      for (let i = 1; i < MAX_HANDSHAKE_RESULTS + EXTRA; i += 1) {
        const session = `agent:spread-${i % sessionCount}`;
        await exchange.handler(
          { counterparty_shr: mintCounterpartySHR(template), identity_id: identity.identity_id },
          session
        );
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
      // 1-hour default.
      const SHR_VALIDITY_MS = 30_000;
      const registrar = makeAgent();
      const registrarIdentity = await createIdentityFor(registrar, "registrar-identity");
      const { tools: registrarTools, handshakeResults } = createHandshakeTools(
        registrar.config,
        registrar.identityManager,
        registrar.masterKey,
        registrar.auditLog,
        { shrValidityMs: SHR_VALIDITY_MS }
      );
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;

      const fillerSessionCount = MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN;
      const probeSession = "agent:probe-session";

      // Runs a REAL 3-step handshake (initiate/respond/complete) between the
      // registrar (as `callerIdentity`'s session) and a freshly-minted
      // counterparty fortress, and returns the PARSED handshake_complete
      // response — callers assert success or refusal as appropriate (a
      // refused recordHandshakeResult is an EXPECTED outcome for the
      // overflow probes below, so this helper must not assert success
      // itself). The counterparty's OWN `respond` call gets a per-call
      // UNIQUE callerIdentity so its (separate, single-use) session store
      // never approaches its own quota.
      async function completeRealHandshake(
        callerIdentity: string,
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
          await initiate.handler({ identity_id: registrarIdentity.identity_id }, callerIdentity)
        );
        const responded = parse(
          await respond.handler(
            {
              challenge: initiated.challenge,
              identity_id: counterpartyIdentity.identity_id,
            },
            `agent:counterparty-${counterpartyLabel}`
          )
        );
        return parse(
          await complete.handler(
            {
              session_id: initiated.session_id,
              response: responded.response,
            },
            callerIdentity
          )
        );
      }

      // Fill handshakeResults to EXACTLY the global cap, spread across
      // `fillerSessionCount` distinct agent SESSIONS (one shared registrar
      // identity throughout — origin no longer depends on identity_id) so
      // no single one ever exceeds its own per-origin quota.
      let counter = 0;
      for (let s = 0; s < fillerSessionCount; s += 1) {
        const session = `agent:filler-session-${s}`;
        for (let i = 0; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
          const completed = await completeRealHandshake(session, `peer-${counter}`);
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
        return originalAppend(...args);
      }) as AuditLog["append"];
      // Eviction now audits via appendCritical (MUST-FIX 6, fix-round-2 —
      // awaited, durable, BEFORE the delete), not the low-risk `.append`
      // fire-and-forget it used before, so the spy targets that method.
      const originalAppendCritical = registrar.auditLog.appendCritical.bind(
        registrar.auditLog
      );
      registrar.auditLog.appendCritical = ((
        ...args: Parameters<AuditLog["appendCritical"]>
      ) => {
        const entry = args[0];
        // MUST-FIX 2, fix-round-5: the pre-delete critical write is now the
        // INTENT record (`_eviction_intent`), not `_evicted` — the
        // COMPLETION record moved to a fire-and-forget `append()` call in
        // `onEvicted` (see handshake/tools.ts), which fires only after the
        // authoritative delete and is therefore not intercepted here.
        if (entry.operation === "handshake_result_eviction_intent") {
          evictedAudited = entry.details as { expired?: boolean };
        }
        return originalAppendCritical(...args);
      }) as AuditLog["appendCritical"];

      // Every slot holds a verified, live, UNEXPIRED peer — the probe
      // session's own new handshake is REFUSED, not admitted by evicting
      // one of them (never blind-FIFO a live peer).
      const whileLive = await completeRealHandshake(
        probeSession,
        "overflow-while-live"
      );
      expect(whileLive.result).toBeUndefined();
      expect(whileLive.error).toContain("live, unexpired peer");
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      expect(saturatedAudited).toBeGreaterThan(0);

      // Wait past SHR_VALIDITY_MS: every filler entry's expires_at is now
      // in the past. A fresh handshake for the SAME probe session must now
      // SUCCEED — an expired verified entry rolls off to admit a new one,
      // instead of wedging the store for the server's lifetime.
      await sleep(SHR_VALIDITY_MS + 500);
      const afterExpiry = await completeRealHandshake(
        probeSession,
        "overflow-after-expiry"
      );
      expect(afterExpiry.result?.verified).toBe(true);
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      expect(evictedAudited).toBeDefined();
      expect(evictedAudited!.expired).toBe(true);
    },
    240_000
  );

  it(
    "MUTATION-PROOF TARGET (no reattribution on update, MUST-FIX 3): a SECOND session's unverified preview for the SAME counterparty does not reattribute that entry's origin away from the FIRST session that created it",
    async () => {
      const agent = makeAgent();
      await createIdentityFor(agent, "template-identity");
      const { tools, handshakeResults, handshakeResultOrigins } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);
      const counterpartySHR = mintCounterpartySHR(template);

      const SESSION_A = "agent:session-a-reattribution";
      const SESSION_B = "agent:session-b-reattribution";

      // Session A creates the FIRST (unverified preview) entry for this
      // counterparty.
      const first = parse(
        await exchange.handler({ counterparty_shr: counterpartySHR }, SESSION_A)
      );
      expect(first.verification.recorded).toBe(true);
      expect(handshakeResultOrigins.get(counterpartySHR.body.instance_id)).toBe(SESSION_A);
      expect(handshakeResults.get(counterpartySHR.body.instance_id)).toBeDefined();

      // Session B "updates" the SAME entry — the MEDIUM#3 downgrade guard
      // allows overwriting an entry that is still unverified/non-live.
      // Pre-fix, BoundedMap.set()'s update path re-attributed the origin
      // to whichever caller updated it LAST (a framing/evasion primitive
      // — see bounded-map.ts's `set()` doc: an attacker could inflate a
      // VICTIM origin's count by repeatedly "updating" a shared key onto
      // it, or evade their OWN quota by moving entries off their origin).
      // Post-fix, the origin stays fixed at SESSION_A regardless of who
      // updates the value afterward.
      const second = parse(
        await exchange.handler({ counterparty_shr: counterpartySHR }, SESSION_B)
      );
      expect(second.verification.recorded).toBe(true);
      expect(handshakeResultOrigins.get(counterpartySHR.body.instance_id)).toBe(SESSION_A);

      // Confirm this is not a stale read of a map that was never touched:
      // SESSION_B's own origin count is still zero (it never actually got
      // attributed anything), while SESSION_A's count is exactly 1 (the
      // one entry it created, never reassigned).
      let sessionACounted = 0;
      let sessionBCounted = 0;
      for (const origin of handshakeResultOrigins.values()) {
        if (origin === SESSION_A) sessionACounted += 1;
        if (origin === SESSION_B) sessionBCounted += 1;
      }
      expect(sessionACounted).toBe(1);
      expect(sessionBCounted).toBe(0);
    }
  );

  it(
    "MUTATION-PROOF TARGET (truthful `recorded`, MUST-FIX 7): handshake_exchange reports recorded:false when SHR verification fails — never defaults to true for an attempt that never wrote anything",
    async () => {
      const agent = makeAgent();
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      await createIdentityFor(agent, "template-identity");
      const template = shrFor(agent);

      const badSHR = mintCounterpartySHR(template);
      // Corrupt the signature so verifySHR's cryptographic check fails —
      // verificationResult.valid becomes false, and (pre-fix) `recorded`
      // still defaulted to `true` here despite no write ever being
      // attempted.
      badSHR.signature = toBase64url(new Uint8Array(64));

      const out = parse(
        await exchange.handler({ counterparty_shr: badSHR }, "agent:truthful-recorded-session")
      );
      expect(out.verification.counterparty_valid).toBe(false);
      expect(out.verification.recorded).toBe(false);
    }
  );

  it(
    "MUTATION-PROOF TARGET (F1, fix-round-4): a real handshakeResults eviction whose onEvict audit write is slow — crossing the OLD (wrong) 10s timeout but well inside the CORRECTED bound — succeeds normally, never spuriously refuses, and correctly moves handshakeResultWriterOrigins from the evicted entry to the new one via the authoritative onEvicted hook",
    async () => {
      const agent = makeAgent();
      await createIdentityFor(agent, "template-identity");
      const { tools, handshakeResults, handshakeResultWriterOrigins } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      // Fill handshakeResults to its GLOBAL cap with cheap unverified
      // previews (handshake_exchange never needs a real round trip),
      // spread across enough distinct agent sessions that no ONE session's
      // own MAX_HANDSHAKE_RESULTS_PER_ORIGIN quota is ever hit — every
      // entry stays evictable (never "currently live": unverified).
      const sessionsNeeded = Math.ceil(
        MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN
      );
      let filled = 0;
      let survivorId: string | undefined;
      let survivorSession: string | undefined;
      outer: for (let s = 0; s < sessionsNeeded; s += 1) {
        const session = `agent:filler-f1-${s}`;
        for (let i = 0; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
          if (filled >= MAX_HANDSHAKE_RESULTS) break outer;
          const shr = mintCounterpartySHR(template);
          const out = parse(await exchange.handler({ counterparty_shr: shr }, session));
          expect(out.verification.recorded).toBe(true);
          if (filled === 0) {
            survivorId = shr.body.instance_id;
            survivorSession = session;
          }
          filled += 1;
        }
      }
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      // The FIRST-inserted entry is what `selectEviction`'s oldest-first
      // scan (Map insertion order) will pick once the map is at capacity.
      expect(handshakeResultWriterOrigins.get(survivorId!)).toBe(survivorSession);

      // Intercept appendCritical to hold the EVICTION's own audit write
      // pending under manual control, then drive elapsed time with fake
      // timers rather than a real multi-second wait (same pattern as
      // test/core/bounded-map.test.ts).
      vi.useFakeTimers();
      try {
        let resolveAudit!: () => void;
        let evictionAuditCalls = 0;
        const originalAppendCritical = agent.auditLog.appendCritical.bind(agent.auditLog);
        agent.auditLog.appendCritical = ((
          ...args: Parameters<typeof originalAppendCritical>
        ) => {
          const entry = args[0];
          // MUST-FIX 2, fix-round-5: intercept the INTENT write
          // (`_eviction_intent`) — the pre-delete critical audit this test
          // is deliberately holding pending. See the sibling comment above
          // (section 3) for why `_evicted` itself is no longer written via
          // appendCritical.
          if (entry.operation === "handshake_result_eviction_intent") {
            evictionAuditCalls += 1;
            return new Promise<void>((resolve) => {
              resolveAudit = () => {
                originalAppendCritical(...args).then(resolve, resolve);
              };
            });
          }
          return originalAppendCritical(...args);
        }) as typeof originalAppendCritical;

        const newSession = "agent:probe-f1";
        const newSHR = mintCounterpartySHR(template);
        const resultPromise = exchange.handler({ counterparty_shr: newSHR }, newSession);

        // 25s: past the OLD (wrong) 10s derivation, comfortably inside the
        // CORRECTED one (AUDIT_WRITE_LOCK_TIMEOUT_MS +
        // DEFAULT_AUDIT_WRITE_LOCK_HOLD_DEADLINE_MS + margin = 40s) — a
        // write genuinely this slow must still succeed, not refuse.
        await vi.advanceTimersByTimeAsync(25_000);
        resolveAudit();
        const out = parse(await resultPromise);

        expect(evictionAuditCalls).toBe(1);
        // THE MUTATION-PROOF ASSERTION (F1): no spurious refusal for a
        // legitimately slow write. Reverting ON_EVICT_AUDIT_TIMEOUT_MS to
        // its old (wrong) 10s derivation makes this false — the probe's
        // own recording would fail with `audit_unavailable`.
        expect(out.verification.recorded).toBe(true);

        // The evicted entry is truly gone, and its writer-origin
        // attribution went with it — via the AUTHORITATIVE `onEvicted`
        // hook (bounded-map.ts), driven by bounded-map's own post-delete
        // call, never by `onEvict`'s (now audit-only) continuation.
        expect(handshakeResults.get(survivorId!)).toBeUndefined();
        expect(handshakeResultWriterOrigins.get(survivorId!)).toBeUndefined();
        expect(handshakeResultWriterOrigins.get(newSHR.body.instance_id)).toBe(newSession);
      } finally {
        vi.useRealTimers();
      }
    },
    240_000
  );

  it(
    "MUTATION-PROOF TARGET (no phantom eviction-success audit, MUST-FIX 2, fix-round-5): a REFUSED/timed-out eviction never produces a `handshake_result_evicted` completion record for the surviving entry, even after the pending intent write eventually resolves",
    async () => {
      const agent = makeAgent();
      await createIdentityFor(agent, "template-identity");
      const { tools, handshakeResults, handshakeResultWriterOrigins } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const exchange = tools.find((t) => t.name === "handshake_exchange")!;
      const template = shrFor(agent);

      // Fill to the global cap with cheap unverified previews, exactly as
      // the F1 test above — every entry stays evictable.
      const sessionsNeeded = Math.ceil(
        MAX_HANDSHAKE_RESULTS / MAX_HANDSHAKE_RESULTS_PER_ORIGIN
      );
      let filled = 0;
      let survivorId: string | undefined;
      outer: for (let s = 0; s < sessionsNeeded; s += 1) {
        const session = `agent:filler-f1phantom-${s}`;
        for (let i = 0; i < MAX_HANDSHAKE_RESULTS_PER_ORIGIN; i += 1) {
          if (filled >= MAX_HANDSHAKE_RESULTS) break outer;
          const shr = mintCounterpartySHR(template);
          const out = parse(await exchange.handler({ counterparty_shr: shr }, session));
          expect(out.verification.recorded).toBe(true);
          if (filled === 0) survivorId = shr.body.instance_id;
          filled += 1;
        }
      }
      expect(handshakeResults.size).toBe(MAX_HANDSHAKE_RESULTS);
      const survivorWriter = handshakeResultWriterOrigins.get(survivorId!);
      expect(survivorWriter).toBeDefined();

      vi.useFakeTimers();
      try {
        // Hold the INTENT write pending under manual control — this time,
        // NEVER resolve it before the admission timeout elapses (unlike the
        // F1 test above, which resolves at 25s, inside the corrected
        // bound). Spy on BOTH audit channels for the COMPLETION operation
        // name (`handshake_result_evicted`, no `_intent` suffix) — the
        // pre-fix-round-5 shape wrote that name via `appendCritical` (the
        // phantom record itself); the fixed shape writes it, if at all,
        // via the low-risk fire-and-forget `append()` from `onEvicted`.
        // Checking both channels makes this proof independent of WHICH
        // channel a regression happens to use.
        let evictionIntentCalls = 0;
        let resolveIntent!: () => void;
        let completionAuditedWhileSurvivorExists = false;
        const originalAppendCritical = agent.auditLog.appendCritical.bind(agent.auditLog);
        agent.auditLog.appendCritical = ((
          ...args: Parameters<typeof originalAppendCritical>
        ) => {
          const entry = args[0];
          if (entry.operation === "handshake_result_eviction_intent") {
            evictionIntentCalls += 1;
            return new Promise<void>((resolve) => {
              resolveIntent = () => {
                originalAppendCritical(...args).then(resolve, resolve);
              };
            });
          }
          if (
            entry.operation === "handshake_result_evicted" &&
            (entry.details as { counterparty_id?: string } | undefined)?.counterparty_id ===
              survivorId &&
            handshakeResults.get(survivorId!) !== undefined
          ) {
            completionAuditedWhileSurvivorExists = true;
          }
          return originalAppendCritical(...args);
        }) as typeof originalAppendCritical;

        const originalAppend = agent.auditLog.append.bind(agent.auditLog);
        agent.auditLog.append = ((...args: Parameters<typeof originalAppend>) => {
          if (
            args[1] === "handshake_result_evicted" &&
            (args[3] as { counterparty_id?: string } | undefined)?.counterparty_id ===
              survivorId &&
            handshakeResults.get(survivorId!) !== undefined
          ) {
            completionAuditedWhileSurvivorExists = true;
          }
          return originalAppend(...args);
        }) as typeof originalAppend;

        const newSession = "agent:probe-f1-phantom";
        const newSHR = mintCounterpartySHR(template);
        const resultPromise = exchange.handler({ counterparty_shr: newSHR }, newSession);

        // Advance PAST the corrected admission timeout (bounded-map.ts's
        // ON_EVICT_AUDIT_TIMEOUT_MS) — set() must give up waiting and
        // refuse this admission, leaving the victim (survivorId) intact.
        await vi.advanceTimersByTimeAsync(ON_EVICT_AUDIT_TIMEOUT_MS + 1_000);
        const out = parse(await resultPromise);

        expect(evictionIntentCalls).toBe(1);
        // The probe's own recording failed — the eviction was refused, not
        // completed (audit_unavailable, matching bounded-map.ts's
        // `withTimeout` contract).
        expect(out.verification.recorded).toBe(false);
        // The survivor is genuinely still present: NOT evicted.
        expect(handshakeResults.get(survivorId!)).toBeDefined();
        expect(handshakeResultWriterOrigins.get(survivorId!)).toBe(survivorWriter);

        // THE MUTATION-PROOF ASSERTION: no completion record for the
        // survivor yet, because `onEvicted` (the only place that writes
        // one) never fired for a refused eviction.
        expect(completionAuditedWhileSurvivorExists).toBe(false);

        // Now let the detached intent write finally resolve (models the
        // exact audit-queue-contention scenario MUST-FIX 2 describes: a
        // write that eventually lands successfully, long after set() gave
        // up). Reverting the fix-round-5 split (writing the completion
        // audit directly inside `onEvict`, before the delete, as fix-round-4
        // did) makes this assertion FALSE: the old shape would have already
        // written a "success" `handshake_result_evicted` record for
        // survivorId the moment the intent write above resolved, well
        // before any real delete ever happened.
        resolveIntent();
        await vi.runAllTimersAsync();
        expect(completionAuditedWhileSurvivorExists).toBe(false);
        expect(handshakeResults.get(survivorId!)).toBeDefined();
      } finally {
        vi.useRealTimers();
      }
    },
    240_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 3. Federation peers (federation/registry.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("3. federation peers: capped + per-session fair + refuse-on-all-active + bounded listing", () => {
  it(
    "MUTATION-PROOF TARGET (per-session, MUST-FIX 1 spine): completing handshakes under MANY minted local identities from ONE agent session cannot lock out a DIFFERENT session's legitimate registration",
    async () => {
      // register LD2-04 RECHECK: the fix-round-1 cut let one FLOODING
      // IDENTITY exhaust its own quota, but an attacker session that mints
      // enough distinct identities (Tier-3 always-allow) could still fill
      // the whole registry across "different" identities that are really
      // the same attacker. Binding the quota to the SESSION (MUST-FIX 1)
      // closes that: minting identities never creates new origins.
      const registrar = makeAgent();
      const registrarIdentity = await createIdentityFor(registrar, "registrar-identity");
      const counterpartyFortress = makeAgent();

      const { tools: registrarTools, handshakeResults, handshakeResultWriterOrigins } =
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
        handshakeResultWriterOrigins
      );

      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      // Registers ONE new peer end-to-end under `callerIdentity`'s session:
      // mints a fresh counterparty identity (cheap: no KDF), completes the
      // real nonce-bearing 4-step handshake, then registers it as a
      // federation peer. The counterparty's OWN `respond` call gets a
      // per-call unique session string so its (shared across this test)
      // sessions map never approaches its own quota. Returns the parsed
      // register response (callers assert success or refusal as
      // appropriate — refusal is an EXPECTED outcome for the overflow
      // probes below).
      async function mintAndRegisterPeer(
        callerIdentity: string,
        label: string
      ): Promise<{ registered?: boolean; error?: string; peer_id?: string }> {
        const identity = await createIdentityFor(counterpartyFortress, label);
        const { tools: counterpartyTools } = createHandshakeTools(
          counterpartyFortress.config,
          counterpartyFortress.identityManager,
          counterpartyFortress.masterKey,
          counterpartyFortress.auditLog
        );
        const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
        const initiated = parse(
          await initiate.handler({ identity_id: registrarIdentity.identity_id }, callerIdentity)
        );
        const responded = parse(
          await respond.handler(
            {
              challenge: initiated.challenge,
              identity_id: identity.identity_id,
            },
            `agent:counterparty-${label}`
          )
        );
        await complete.handler(
          {
            session_id: initiated.session_id,
            response: responded.response,
          },
          callerIdentity
        );
        return parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
      }

      const SESSION_A = "agent:session-a";
      const SESSION_B = "agent:session-b";

      const firstForA = await mintAndRegisterPeer(SESSION_A, "a-peer-000");
      expect(firstForA.registered).toBe(true);
      for (let i = 1; i < MAX_FEDERATION_PEERS_PER_ORIGIN; i += 1) {
        const out = await mintAndRegisterPeer(SESSION_A, `a-peer-${i}`);
        expect(out.registered).toBe(true);
      }

      // The (quota+1)-th registration for session A is REFUSED.
      const overflowForA = await mintAndRegisterPeer(SESSION_A, "a-overflow");
      expect(overflowForA.registered).toBeUndefined();
      expect(overflowForA.error).toContain("registration quota");

      // A's first peer is still listed — refusing never evicted it.
      const listedAfterA = parse(await register.handler({ action: "list" }));
      expect(
        listedAfterA.peers.some((p: { peer_id: string }) => p.peer_id === firstForA.peer_id)
      ).toBe(true);

      // B is a COMPLETELY DIFFERENT session: A's flood must not have
      // touched B's headroom.
      const forB = await mintAndRegisterPeer(SESSION_B, "b-peer-000");
      expect(forB.registered).toBe(true);
    },
    60_000
  );

  it(
    "under GLOBAL-cap pressure spread across many distinct AGENT SESSIONS (each within its own quota), the registry evicts the oldest INACTIVE peer to admit a new one — a legitimate registration still succeeds, and an ACTIVE peer survives",
    async () => {
      const registrar = makeAgent();
      const registrarIdentity = await createIdentityFor(registrar, "registrar-identity");
      const inactiveSession = "agent:session-inactive";
      const firstActiveSession = "agent:session-first-active";
      const probeSession = "agent:session-probe";
      // 11 filler sessions keeps each one's share (ceil(498/11) = 46)
      // comfortably under MAX_FEDERATION_PEERS_PER_ORIGIN (50), regardless
      // of how the 498 remainder distributes across them.
      const fillerSessionCount = 11;

      const { tools: registrarTools, handshakeResults, handshakeResultWriterOrigins } =
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
        handshakeResultWriterOrigins
      );
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      // Registers ONE new peer end-to-end under `callerIdentity`'s session.
      // The counterparty's OWN handshake tools take
      // `counterpartyShrValidityMs` — deliberately short for exactly ONE
      // peer below, so it (and ONLY it) becomes an INACTIVE peer shortly
      // after registration, without any timing dependency on how long the
      // rest of this test takes. A FRESH counterparty fortress+tools
      // instance per call means the counterparty's own session accounting
      // never accumulates across calls.
      async function mintAndRegisterPeer(
        callerIdentity: string,
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
          await initiate.handler({ identity_id: registrarIdentity.identity_id }, callerIdentity)
        );
        const responded = parse(
          await respond.handler({
            challenge: initiated.challenge,
            identity_id: identity.identity_id,
          })
        );
        await complete.handler(
          {
            session_id: initiated.session_id,
            response: responded.response,
          },
          callerIdentity
        );
        return parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
      }

      // The ONE peer that will become inactive: a 500ms-validity
      // counterparty SHR, registered first.
      const SHORT_VALIDITY_MS = 500;
      const inactivePeer = await mintAndRegisterPeer(
        inactiveSession,
        "inactive-peer",
        SHORT_VALIDITY_MS
      );
      expect(inactivePeer.registered).toBe(true);

      // The very first ACTIVE peer registered — this one must SURVIVE.
      const firstActivePeer = await mintAndRegisterPeer(
        firstActiveSession,
        "first-active-peer"
      );
      expect(firstActivePeer.registered).toBe(true);

      // Fill the rest of the global cap (498 more), spread round-robin
      // across the filler sessions so no single one exceeds its own
      // per-origin quota.
      let counter = 0;
      const totalToFill = MAX_FEDERATION_PEERS - 2;
      for (let i = 0; i < totalToFill; i += 1) {
        const session = `agent:filler-session-${i % fillerSessionCount}`;
        const out = await mintAndRegisterPeer(session, `filler-${counter}`);
        expect(out.registered).toBe(true);
        counter += 1;
      }

      // Registry is now at the GLOBAL cap (500). Let the short-validity
      // peer actually expire before probing further.
      await sleep(SHORT_VALIDITY_MS + 500);

      // The probe session (fresh, well under its own quota) registers a
      // NEW peer — the registry is at global capacity, but ONE existing
      // peer (the deliberately-short-lived one) is now INACTIVE, so this
      // is admitted by evicting THAT one, not refused, and not by evicting
      // an active peer.
      const newPeer = await mintAndRegisterPeer(probeSession, "legitimate-new-peer");
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

  it(
    "MUTATION-PROOF TARGET (required origin, MUST-FIX 2): a peer_id missing from handshakeResultWriterOrigins is NOT a quota-skip — it falls into the shared AGENT_UNKNOWN_ORIGIN bucket, which is itself quota-bounded",
    async () => {
      // Simulates the MUST-FIX 2 defect directly: a handshake result whose
      // origin attribution is somehow absent (a future producer bug, or
      // exactly what fix-round-1's OPTIONAL handshakeResultOrigins param
      // produced when a caller omitted it entirely — an empty map means
      // every peerId lookup misses). REQUIRED (not optional) means
      // federation/tools.ts's register handler must never treat a miss as
      // "skip the quota" — it falls back to the shared AGENT_UNKNOWN_ORIGIN
      // bucket instead, which is itself bounded. fix-round-3: federation now
      // reads `handshakeResultWriterOrigins` (see that map's doc,
      // handshake/tools.ts) rather than `handshakeResultOrigins`, so this
      // test simulates the same "missing attribution" shape against THAT
      // map.
      const registrar = makeAgent();
      const registrarIdentity = await createIdentityFor(registrar, "registrar-identity");
      const counterpartyFortress = makeAgent();

      const { tools: registrarTools, handshakeResults, handshakeResultWriterOrigins } =
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
        handshakeResultWriterOrigins
      );
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      async function completeHandshakeForOrigin(
        callerIdentity: string,
        label: string
      ): Promise<string> {
        const identity = await createIdentityFor(counterpartyFortress, label);
        const { tools: counterpartyTools } = createHandshakeTools(
          counterpartyFortress.config,
          counterpartyFortress.identityManager,
          counterpartyFortress.masterKey,
          counterpartyFortress.auditLog
        );
        const respond = counterpartyTools.find((t) => t.name === "handshake_respond")!;
        const initiated = parse(
          await initiate.handler({ identity_id: registrarIdentity.identity_id }, callerIdentity)
        );
        const responded = parse(
          await respond.handler(
            { challenge: initiated.challenge, identity_id: identity.identity_id },
            `agent:counterparty-${label}`
          )
        );
        await complete.handler(
          { session_id: initiated.session_id, response: responded.response },
          callerIdentity
        );
        return identity.identity_id;
      }

      // Fill the shared AGENT_UNKNOWN_ORIGIN bucket via "unattributed"
      // registrations: complete a real handshake (each under a DIFFERENT
      // session, proving this is about origin ATTRIBUTION, not session
      // reuse), then delete its origin entry before registering — modeling
      // the missing-attribution case.
      for (let i = 0; i < MAX_FEDERATION_PEERS_PER_ORIGIN; i += 1) {
        const peerId = await completeHandshakeForOrigin(`agent:owner-${i}`, `unattributed-${i}`);
        // Deliberate test-only reach into the ReadonlyMap's underlying
        // mutable store (BoundedMap's `origins` sibling map — see
        // originsView()'s doc) to simulate a producer that completed a
        // handshake but failed to attribute an origin for it. The public
        // API surface exercised below (register.handler) is unchanged —
        // only the origin INPUT this simulates is missing.
        (handshakeResultWriterOrigins as Map<string, string>).delete(peerId);
        const out = parse(await register.handler({ action: "register", peer_id: peerId }));
        expect(out.registered).toBe(true);
      }

      // The shared bucket is now at quota. One more "unattributed"
      // registration is REFUSED — proving the fallback bucket is real
      // accounting, not an unbounded escape hatch.
      const overflowPeerId = await completeHandshakeForOrigin(
        "agent:owner-overflow",
        "unattributed-overflow"
      );
      (handshakeResultWriterOrigins as Map<string, string>).delete(overflowPeerId);
      const overflow = parse(
        await register.handler({ action: "register", peer_id: overflowPeerId })
      );
      expect(overflow.registered).toBeUndefined();
      expect(overflow.error).toContain("registration quota");
    },
    60_000
  );

  it(
    "MUTATION-PROOF TARGET (writer origin, not first-writer origin, MUST-FIX 2 fix-round-3): a victim's REAL verified registration is charged to the VICTIM's own quota, not an attacker's exhausted quota, even though the attacker previewed the SAME counterparty FIRST",
    async () => {
      // The fix-round-2 defect this closes: `handshakeResults`'s own
      // BoundedMap `origins` (exposed as `handshakeResultOrigins`) is
      // IMMUTABLE at first insert BY DESIGN (MUST-FIX 3, fix-round-2 — see
      // the "no reattribution on update" test above), which is correct for
      // THAT map's own quota, but is the WRONG answer for "whose
      // registration is this" once a LATER session's real, verified write
      // supersedes an EARLIER session's cheap unverified preview for the
      // SAME counterparty_id. An attacker who previews a victim's
      // counterparty first — no real handshake required, just a one-shot
      // `handshake_exchange` — would otherwise permanently pin that
      // counterparty_id's federation-charge origin to themselves; once the
      // ATTACKER's own registration quota is separately exhausted (via
      // unrelated registrations), the VICTIM's later real registration for
      // that SAME counterparty would be refused too, even though the
      // victim never touched their own quota. `handshakeResultWriterOrigins`
      // (fix-round-3) tracks the CURRENT writer instead, so federation
      // charges the victim correctly regardless of the attacker's quota
      // state.
      const registrar = makeAgent();
      const registrarIdentity = await createIdentityFor(registrar, "registrar-identity");
      const counterpartyFortress = makeAgent();
      const sharedCounterparty = await createIdentityFor(
        counterpartyFortress,
        "shared-counterparty"
      );

      const {
        tools: registrarTools,
        handshakeResults,
        handshakeResultOrigins,
        handshakeResultWriterOrigins,
      } = createHandshakeTools(
        registrar.config,
        registrar.identityManager,
        registrar.masterKey,
        registrar.auditLog
      );
      const { tools: federationTools, registry } = createFederationTools(
        registrar.auditLog,
        handshakeResults,
        registrar.identityManager,
        handshakeResultWriterOrigins
      );
      const exchange = registrarTools.find((t) => t.name === "handshake_exchange")!;
      const initiate = registrarTools.find((t) => t.name === "handshake_initiate")!;
      const complete = registrarTools.find((t) => t.name === "handshake_complete")!;
      const register = federationTools.find((t) => t.name === "federation_peers")!;

      const SESSION_ATTACKER = "agent:mustfix2-attacker";
      const SESSION_VICTIM = "agent:mustfix2-victim";

      // Registers ONE new, UNRELATED peer end-to-end under `callerIdentity`'s
      // session — mirrors `mintAndRegisterPeer` in the MUST-FIX 1 spine test
      // above, used here only to fill SESSION_ATTACKER's OWN registration
      // quota with peers that have nothing to do with the shared
      // counterparty this test is actually about.
      async function mintAndRegisterUnrelatedPeer(
        callerIdentity: string,
        label: string
      ): Promise<void> {
        const identity = await createIdentityFor(counterpartyFortress, label);
        // Respond happens on a SEPARATE handshake-tools instance bound to
        // counterpartyFortress's own identity manager, matching the
        // section-3 helper pattern.
        const { tools: counterpartyTools } = createHandshakeTools(
          counterpartyFortress.config,
          counterpartyFortress.identityManager,
          counterpartyFortress.masterKey,
          counterpartyFortress.auditLog
        );
        const counterpartyRespond = counterpartyTools.find(
          (t) => t.name === "handshake_respond"
        )!;
        const initiated = parse(
          await initiate.handler({ identity_id: registrarIdentity.identity_id }, callerIdentity)
        );
        const responded = parse(
          await counterpartyRespond.handler(
            { challenge: initiated.challenge, identity_id: identity.identity_id },
            `agent:counterparty-${label}`
          )
        );
        await complete.handler(
          { session_id: initiated.session_id, response: responded.response },
          callerIdentity
        );
        const out = parse(
          await register.handler({ action: "register", peer_id: identity.identity_id })
        );
        expect(out.registered).toBe(true);
      }

      // Exhaust SESSION_ATTACKER's OWN federation registration quota FIRST,
      // entirely with unrelated peers — proves the fix below is not merely
      // "the attacker's quota happened to have room."
      for (let i = 0; i < MAX_FEDERATION_PEERS_PER_ORIGIN; i += 1) {
        await mintAndRegisterUnrelatedPeer(SESSION_ATTACKER, `unrelated-${i}`);
      }
      expect(registry.peerOriginSize(SESSION_ATTACKER)).toBe(MAX_FEDERATION_PEERS_PER_ORIGIN);

      // ATTACKER previews the SHARED counterparty FIRST — cheap, unverified,
      // no real handshake. This is the write that claims the ALLOCATION
      // origin (handshakeResultOrigins) forever, per MUST-FIX 3's
      // no-reattribution rule. Generated for `sharedCounterparty`
      // EXPLICITLY by identity_id (not the `shrFor` helper's default-
      // identity shortcut) — `counterpartyFortress` now also holds every
      // "unrelated" identity minted above, so relying on whichever
      // identity happens to be the manager's default would be ambiguous.
      const counterpartyShrResult = generateSHR(sharedCounterparty.identity_id, {
        config: counterpartyFortress.config,
        identityManager: counterpartyFortress.identityManager,
        masterKey: counterpartyFortress.masterKey,
      });
      if (typeof counterpartyShrResult === "string") {
        throw new Error(counterpartyShrResult);
      }
      const counterpartySHR = counterpartyShrResult;
      const previewed = parse(
        await exchange.handler(
          { counterparty_shr: counterpartySHR },
          SESSION_ATTACKER
        )
      );
      expect(previewed.verification.recorded).toBe(true);
      expect(handshakeResultOrigins.get(sharedCounterparty.identity_id)).toBe(
        SESSION_ATTACKER
      );
      expect(handshakeResultWriterOrigins.get(sharedCounterparty.identity_id)).toBe(
        SESSION_ATTACKER
      );

      // VICTIM completes a REAL 4-step verified handshake with the SAME
      // counterparty — this is an UPDATE to the existing handshakeResults
      // entry, so the ALLOCATION origin stays SESSION_ATTACKER (unchanged,
      // by design — MUST-FIX 3), but the WRITER origin must move to
      // SESSION_VICTIM.
      const { tools: counterpartyTools } = createHandshakeTools(
        counterpartyFortress.config,
        counterpartyFortress.identityManager,
        counterpartyFortress.masterKey,
        counterpartyFortress.auditLog
      );
      const counterpartyRespond = counterpartyTools.find(
        (t) => t.name === "handshake_respond"
      )!;
      const initiated = parse(
        await initiate.handler(
          { identity_id: registrarIdentity.identity_id },
          SESSION_VICTIM
        )
      );
      const responded = parse(
        await counterpartyRespond.handler(
          {
            challenge: initiated.challenge,
            identity_id: sharedCounterparty.identity_id,
          },
          "agent:counterparty-shared"
        )
      );
      await complete.handler(
        { session_id: initiated.session_id, response: responded.response },
        SESSION_VICTIM
      );

      // The allocation origin (handshakeResultOrigins) is UNCHANGED —
      // fix-round-2's guarantee still holds. The writer origin
      // (handshakeResultWriterOrigins) HAS moved to the victim.
      expect(handshakeResultOrigins.get(sharedCounterparty.identity_id)).toBe(
        SESSION_ATTACKER
      );
      expect(handshakeResultWriterOrigins.get(sharedCounterparty.identity_id)).toBe(
        SESSION_VICTIM
      );

      // THE FIX: registering this peer succeeds — charged to the VICTIM's
      // own (fresh) quota — even though the ATTACKER's origin is fully
      // exhausted. Pre-fix (charging to handshakeResultOrigins), this
      // registration would have been refused with "registration quota"
      // because the attacker's origin, not the victim's, was checked.
      const registered = parse(
        await register.handler({
          action: "register",
          peer_id: sharedCounterparty.identity_id,
        })
      );
      expect(registered.registered).toBe(true);
      expect(registry.peerOriginSize(SESSION_VICTIM)).toBe(1);
      // The attacker's own count is untouched by the victim's registration.
      expect(registry.peerOriginSize(SESSION_ATTACKER)).toBe(
        MAX_FEDERATION_PEERS_PER_ORIGIN
      );
    },
    120_000
  );
});

// ──────────────────────────────────────────────────────────────────────────
// 4. Sentinel durable findings (sentinel/sentinel-finding-store.ts)
// ──────────────────────────────────────────────────────────────────────────

describe("4. sentinel durable findings: capped, per-origin fair, never blind-FIFO, bounded list + prune", () => {
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
    "MUTATION-PROOF TARGET (flood-survival, MUST-FIX 4): a pre-existing CRITICAL finding survives a flood past MAX_TRACKED_FINDINGS — the flood is REFUSED, not silently overshot",
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
        // Isolate the CAPACITY refusal from the per-origin one (tested
        // separately below) — every finding here shares no agent_id, so
        // without this override they would all land in the same
        // "unattributed" bucket and hit ITS quota first.
        maxFindingsPerOrigin: 1000,
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
      // is expired, so evictOldestExpired can reclaim nothing — every one
      // of these writes must be REFUSED (MUST-FIX 4), loudly (via the
      // saturation audit), never a blind overshoot.
      const FLOOD = 10;
      let refusedCount = 0;
      for (let i = 0; i < FLOOD; i += 1) {
        try {
          await store.saveFinding(mkFinding(`flood-${i}`));
        } catch (err) {
          expect(err).toBeInstanceOf(SentinelFindingStoreRefusedError);
          expect((err as SentinelFindingStoreRefusedError).reason).toBe("capacity");
          refusedCount += 1;
        }
      }

      expect(refusedCount).toBe(FLOOD);
      expect(saturatedAudited).toBeGreaterThan(0);
      const survived = await store.loadFinding("critical-000");
      expect(survived).not.toBeNull();
      expect(survived!.severity).toBe("alert");

      // The store's tracked count NEVER exceeds the cap — the class this
      // rule closes, one layer up from the first place it was closed.
      const allMeta = await store.listFindingMetadata({});
      expect(allMeta.length).toBe(CAP);
    },
    30_000
  );

  it(
    "MUTATION-PROOF TARGET (per-origin, MUST-FIX 4): a flood from ONE origin is refused at its own quota without touching a DIFFERENT origin's headroom",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const ORIGIN_QUOTA = 5;
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-inventory-test",
        auditLog,
        maxFindingsPerOrigin: ORIGIN_QUOTA,
        // Large enough that only the per-origin quota can fire in this test.
        maxTrackedFindings: 1000,
      });

      for (let i = 0; i < ORIGIN_QUOTA; i += 1) {
        await store.saveFinding(mkFinding(`origin-a-${i}`, { agent_id: "origin-a" }));
      }

      await expect(
        store.saveFinding(mkFinding("origin-a-overflow", { agent_id: "origin-a" }))
      ).rejects.toMatchObject({
        reason: "origin_quota",
      });

      // A DIFFERENT origin is completely unaffected.
      await expect(
        store.saveFinding(mkFinding("origin-b-000", { agent_id: "origin-b" }))
      ).resolves.toBeTypeOf("string");

      // origin-a's existing findings are all still there — refusing never
      // evicted them.
      for (let i = 0; i < ORIGIN_QUOTA; i += 1) {
        expect(await store.loadFinding(`origin-a-${i}`)).not.toBeNull();
      }
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
      await store.saveFinding(mkFinding(`expired-${i}`, { agent_id: `agent-${i}` }));
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

  it(
    "MUTATION-PROOF TARGET (MUST-FIX 3, fix-round-4): a record renewed by a concurrent saveFinding call DURING pruneExpired's scan is not deleted — the versioned per-finding-id lock closes the race the bare pre-fix pruneExpired had no guard against at all",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-prune-race-test",
        retentionDays: 1,
        now: () => new Date(nowMs),
      });

      await store.saveFinding(mkFinding("racer"));
      // Past the 1-day retention window — genuinely expired at this point.
      nowMs += 2 * 24 * 60 * 60 * 1000;

      // Model a real overlapping `saveFinding` renewal landing in the gap
      // between `pruneExpired`'s coarse initial read (used only to decide
      // "does this candidate look expired") and its lock-protected
      // re-verify: intercept the storage read for this record's key and,
      // AFTER capturing the (still-expired) bytes `pruneExpired`'s own
      // read will see, perform the renewal before returning — so the
      // underlying storage already reflects the renewal by the time
      // `pruneExpired`'s initial read resolves, exactly the interleaving a
      // concurrent legitimate caller could produce.
      let renewed = false;
      const originalRead = storage.read.bind(storage);
      storage.read = (async (namespace: string, key: string) => {
        const result = await originalRead(namespace, key);
        if (!renewed && key === "finding.racer") {
          renewed = true;
          await store.saveFinding(
            mkFinding("racer", { summary: "renewed mid-scan" }),
            { knownExisting: true }
          );
        }
        return result;
      }) as typeof storage.read;

      const result = await store.pruneExpired();

      // THE MUTATION-PROOF ASSERTION: nothing was pruned — the renewed
      // record survived. Reverting `pruneExpired` to its pre-fix shape
      // (delete straight off the initial read, no lock, no re-verify)
      // makes this assertion fail: `pruned` would be 1 and the renewal
      // would be lost.
      expect(result.pruned).toBe(0);

      const survivor = await store.loadFinding("racer");
      expect(survivor).not.toBeNull();
      expect(survivor!.summary).toBe("renewed mid-scan");
    }
  );

  it(
    "MUTATION-PROOF TARGET (MUST-FIX 3, fix-round-4): two concurrent pruneExpired() sweeps racing to reclaim the SAME set of expired records never double-act — the per-finding-id lock serializes the second sweep's re-verify onto storage state the first sweep already deleted",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-prune-double-race-test",
        retentionDays: 1,
        now: () => new Date(nowMs),
      });

      const COUNT = 5;
      for (let i = 0; i < COUNT; i += 1) {
        await store.saveFinding(mkFinding(`double-${i}`));
      }
      nowMs += 2 * 24 * 60 * 60 * 1000;

      // Two overlapping sweeps over the SAME expired set. Without the
      // per-finding-id lock, both could read the same record as expired
      // and both call `storage.delete()` on it — harmless for MemoryStorage
      // (idempotent delete) but the REAL risk this guards is a `pruned`
      // double-count and a lost-renewal race on a record either sweep
      // could concurrently be asked to spare; with the lock, the second
      // sweep's lock-protected re-verify always observes whatever the
      // first sweep already did.
      const [first, second] = await Promise.all([
        store.pruneExpired(),
        store.pruneExpired(),
      ]);

      expect(first.pruned + second.pruned).toBe(COUNT);
      for (let i = 0; i < COUNT; i += 1) {
        expect(await store.loadFinding(`double-${i}`)).toBeNull();
      }
    }
  );

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
          agent_id: `agent-${i}`,
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
        mkFinding("old-critical", { severity: "alert", observed_at: OLD_TIME, agent_id: "agent-old" })
      );

      // Flood with NEWER, low-severity findings — well past maxScannedRecords.
      const FLOOD = 20;
      for (let i = 0; i < FLOOD; i += 1) {
        await store.saveFinding(
          mkFinding(`recent-info-${i}`, {
            severity: "info",
            observed_at: new Date(Date.parse(OLD_TIME) + (i + 1) * 60_000).toISOString(),
            agent_id: `agent-recent-${i}`,
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
    "MUTATION-PROOF TARGET (metadata scan, MUST-FIX 5): listFindingMetadata is NOT truncated by any decrypt-bound window — a flood far past the old hardcoded/decrypt-bound scan size still returns every matching record",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-inventory-test",
        maxTrackedFindings: 10_000,
        maxFindingsPerOrigin: 10_000,
      });

      const sinceIso = new Date("2026-01-01T00:00:00.000Z").toISOString();
      await store.saveFinding(
        mkFinding("in-window-old", {
          severity: "info",
          observed_at: new Date(Date.parse(sinceIso) + 1_000).toISOString(),
          agent_id: "agent-old",
        })
      );

      // 600 > the OLD hardcoded 500-record scan window this class
      // re-introduced, and also > listFindings's own MAX_SCANNED_RECORDS
      // decrypt bound region this consumer used to be capped by. Spread
      // across many distinct agent_ids so no single origin's quota
      // interferes with this test's actual concern (decrypt/scan
      // truncation, not per-origin fairness).
      const FLOOD = 600;
      for (let i = 0; i < FLOOD; i += 1) {
        await store.saveFinding(
          mkFinding(`in-window-flood-${i}`, {
            severity: "info",
            observed_at: new Date(Date.parse(sinceIso) + (i + 2) * 60_000).toISOString(),
            agent_id: `agent-flood-${i % 20}`,
          })
        );
      }

      // Mirrors sentinel/sentinels/anomaly-trigger.ts's own call shape
      // (MUST-FIX 5: it now calls listFindingMetadata, not listFindings).
      const found = await store.listFindingMetadata({ since: sinceIso });
      expect(found.length).toBe(FLOOD + 1);
      expect(found.some((f) => f.finding_id === "in-window-old")).toBe(true);
    },
    60_000
  );

  it("cold restart: a fresh store instance backfills its index from storage and sees every record a PRIOR instance wrote", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const fortressId = "fortress-restart-test";
    const store1 = new SentinelFindingStore({ storage, masterKey, fortressId });
    const N = 25;
    for (let i = 0; i < N; i += 1) {
      await store1.saveFinding(mkFinding(`restart-${i}`, { agent_id: `agent-${i % 5}` }));
    }

    // Fresh instance, same storage/fortress — simulates a process restart.
    const store2 = new SentinelFindingStore({ storage, masterKey, fortressId });
    const metadata = await store2.listFindingMetadata({});
    expect(metadata.length).toBe(N);
    const ids = metadata.map((m) => m.finding_id).sort();
    expect(ids).toEqual(Array.from({ length: N }, (_, i) => `restart-${i}`).sort());
  });

  it(
    "two INDEPENDENT store instances over the SAME storage do not see each other's writes once their own index has built — exactly why index.ts now shares ONE instance across production consumers (MUST-FIX 5)",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const fortressId = "fortress-dual-instance-test";
      const store1 = new SentinelFindingStore({ storage, masterKey, fortressId });
      const store2 = new SentinelFindingStore({ storage, masterKey, fortressId });

      // Force store2's index to build BEFORE store1 writes anything.
      await store2.listFindingMetadata({});

      await store1.saveFinding(mkFinding("only-in-store1"));

      // store2's OWN index has no knowledge of store1's write — this is
      // the exact defect class MUST-FIX 5 closes at the wiring layer
      // (index.ts / dashboard/v1_1/wiring.ts sharing ONE instance), not
      // something a single store class can fix for itself.
      const fromStore2 = await store2.listFindingMetadata({});
      expect(fromStore2.some((m) => m.finding_id === "only-in-store1")).toBe(false);

      // store1 sees its own write, of course.
      const fromStore1 = await store1.listFindingMetadata({});
      expect(fromStore1.some((m) => m.finding_id === "only-in-store1")).toBe(true);

      // A FRESH instance (a genuine cold start, per the test above) sees
      // it — confirms this is specifically about two LIVE instances
      // diverging, not about durability.
      const store3 = new SentinelFindingStore({ storage, masterKey, fortressId });
      const fromStore3 = await store3.listFindingMetadata({});
      expect(fromStore3.some((m) => m.finding_id === "only-in-store1")).toBe(true);
    }
  );

  it(
    "MUST-FIX 5b: anomaly-trigger's 8-day rolling baseline is NOT corrupted by a >5000 flood in the CURRENT window — every older baseline window keeps its true count",
    async () => {
      // Regression shape: the OLD listFindings({since, limit: 5000}) call
      // sorted matches newest-first and decrypt-bounded to 5000 — so a
      // >5000 flood entirely within window 0 (the most recent 24h) would
      // consume the WHOLE decrypt budget, silently truncating away every
      // OLDER baseline window's findings. Under that bug, Trigger B's
      // "populated >= BASELINE_WINDOWS" warmup gate would see windows 1-7
      // as EMPTY and never fire, despite a genuine, massive count spike.
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const fortressId = "fortress-baseline-flood-test";
      const now = new Date("2026-06-01T12:00:00.000Z");
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId,
        maxTrackedFindings: 10_000,
        maxFindingsPerOrigin: 10_000,
      });

      const DAY_MS = 24 * 60 * 60 * 1000;
      const BASELINE_WINDOWS = 7;
      const BASELINE_COUNT_PER_WINDOW = 10;
      const FLOOD_COUNT = 5_500; // > the old 5000 decrypt-bound

      let seq = 0;
      async function writeAt(windowIndex: number, count: number): Promise<void> {
        for (let i = 0; i < count; i += 1) {
          const observedAt = new Date(
            now.getTime() - windowIndex * DAY_MS - i * 1_000
          ).toISOString();
          await store.saveFinding(
            mkFinding(`baseline-${seq}`, {
              sentinel_id: "flood-sentinel",
              severity: "info",
              observed_at: observedAt,
              agent_id: `agent-${seq % 40}`,
            })
          );
          seq += 1;
        }
      }

      // Baseline windows 1..7: a small, known, populated count each.
      for (let w = 1; w <= BASELINE_WINDOWS; w += 1) {
        await writeAt(w, BASELINE_COUNT_PER_WINDOW);
      }
      // Current window (0): the flood, far past the old decrypt bound.
      await writeAt(0, FLOOD_COUNT);

      const watcher = new AnomalyTriggerWatcher();
      const context: SentinelContext = {
        fortressId,
        auditLog: { query: async () => ({ entries: [], total: 0 }) } as unknown as SentinelContext["auditLog"],
        now: () => now,
        findingStore: store,
      };
      await watcher.subscribe(context);
      const findings = await watcher.evaluate();

      const countSpike = findings.find(
        (f) => (f.details as { trigger?: string }).trigger === "count_spike"
      );
      // Under the pre-fix truncation bug this finding is never emitted
      // (the baseline windows read as unpopulated) — its presence here IS
      // the regression proof.
      expect(countSpike).toBeDefined();
      expect(countSpike!.severity).toBe("alert");
      expect((countSpike!.details as { current_count: number }).current_count).toBe(
        FLOOD_COUNT
      );
      // The baseline mean reflects the TRUE per-window count (10), not
      // zero/undercounted — proving windows 1-7 were not silently
      // truncated away by window 0's flood.
      const baselineMean = (countSpike!.details as { baseline_mean: number }).baseline_mean;
      expect(baselineMean).toBeCloseTo(BASELINE_COUNT_PER_WINDOW, 0);
    },
    120_000
  );

  it(
    "MUTATION-PROOF TARGET (cross-ID admission TOCTOU, MUST-FIX 1 fix-round-5): concurrent saveFinding calls for DISTINCT new finding_ids at the cap never overshoot MAX_TRACKED_FINDINGS or MAX_FINDINGS_PER_ORIGIN — the store-level admission lock, not just the per-finding-id lock, serializes them",
    async () => {
      // Reproduces the class exactly: runtime-trap-handler.ts mints a fresh
      // randomUUID() per invocation, so an attacker who trips a trap
      // repeatedly, concurrently, produces many DISTINCT new finding_ids —
      // each takes a DIFFERENT `findingLocks` entry, so the per-id lock
      // alone cannot serialize them against each other. Only a store-level
      // admission lock closes the race where two concurrent writes both
      // read the same pre-write quota/capacity headroom.
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const CAP = 10;
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-concurrent-admission-test",
        auditLog,
        maxTrackedFindings: CAP,
        // Isolate the GLOBAL-capacity race from the per-origin one — every
        // concurrent writer here shares no agent_id, so without this
        // override they would all race the "unattributed" origin's OWN
        // quota instead of (or in addition to) the global cap.
        maxFindingsPerOrigin: 1000,
      });

      // Fill to exactly ONE below the cap with distinct, non-expired,
      // sequential writes (uncontended — this just establishes the
      // starting state, not part of the race being tested).
      for (let i = 0; i < CAP - 1; i += 1) {
        await store.saveFinding(mkFinding(`seed-${i}`));
      }

      // Now fire MANY concurrent writes for DISTINCT new finding_ids —
      // enough that, pre-fix, every one of them could read "1 slot free"
      // before any of them had actually written. Nothing in the store is
      // expired, so nothing is reclaimable: AT MOST ONE of these should
      // ever succeed; every other one must be genuinely REFUSED
      // (`capacity`), never silently admitted past the cap.
      const RACERS = 20;
      const outcomes = await Promise.allSettled(
        Array.from({ length: RACERS }, (_, i) => store.saveFinding(mkFinding(`racer-${i}`)))
      );

      const succeeded = outcomes.filter((o) => o.status === "fulfilled").length;
      const refused = outcomes.filter(
        (o) =>
          o.status === "rejected" &&
          o.reason instanceof SentinelFindingStoreRefusedError &&
          o.reason.reason === "capacity"
      ).length;

      // THE MUTATION-PROOF ASSERTION: exactly one racer was admitted (the
      // one slot of headroom), every other racer was genuinely refused, and
      // — the property that actually matters — the store's real size NEVER
      // exceeds the cap. Removing the store-level admission lock
      // (`runAdmissionExclusive` in `saveFinding`, restoring the
      // pre-fix-round-5 shape where `enforceTrackedFindingsCeiling` ran
      // unlocked ahead of the per-id write) makes `succeeded` land above 1
      // and `finalCount` exceed `CAP` under this concurrency, because
      // multiple racers observe the same one-slot-free snapshot before any
      // of them commits.
      expect(succeeded).toBe(1);
      expect(refused).toBe(RACERS - 1);
      expect(outcomes.length).toBe(succeeded + refused);

      const finalCount = (await store.listFindingMetadata()).length;
      expect(finalCount).toBe(CAP);
    },
    30_000
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

// ──────────────────────────────────────────────────────────────────────────
// 6. Awaited critical audit before eviction/reclamation (cross-cutting,
//    MUST-FIX 6, fix-round-2)
// ──────────────────────────────────────────────────────────────────────────

describe("6. awaited critical audit before eviction/reclamation aborts on audit failure", () => {
  it(
    "MUTATION-PROOF TARGET (BoundedMap eviction abort): a rejected critical audit write during GLOBAL-cap eviction aborts the eviction — the oldest session is NOT deleted, and the new insert is refused",
    async () => {
      const storage = new ToggleableFaultingAuditStorage();
      const agent = makeAgent(storage);
      const identity = await createIdentityFor(agent, "audit-fail-identity");
      const { tools } = createHandshakeTools(
        agent.config,
        agent.identityManager,
        agent.masterKey,
        agent.auditLog
      );
      const initiate = tools.find((t) => t.name === "handshake_initiate")!;
      const status = tools.find((t) => t.name === "handshake_status")!;

      // Fill the GLOBAL cap spread across enough distinct sessions that no
      // single session's own quota refuses first.
      const sessionCount = Math.ceil(
        MAX_HANDSHAKE_SESSIONS / MAX_HANDSHAKE_SESSIONS_PER_ORIGIN
      );
      const first = parse(
        await initiate.handler(
          { identity_id: identity.identity_id },
          "agent:audit-fail-spread-0"
        )
      );
      const firstSessionId = first.session_id as string;
      for (let i = 1; i < MAX_HANDSHAKE_SESSIONS; i += 1) {
        const session = `agent:audit-fail-spread-${i % sessionCount}`;
        const out = parse(
          await initiate.handler({ identity_id: identity.identity_id }, session)
        );
        expect(out.error).toBeUndefined();
      }

      // NOW the map is at the global cap. Flip audit writes to fail BEFORE
      // triggering the eviction — this proves the ABORT path, not just
      // "audit happened to fail during setup".
      storage.failAuditWrites = true;

      const overflow = parse(
        await initiate.handler(
          { identity_id: identity.identity_id },
          "agent:audit-fail-new-session"
        )
      );
      // The eviction's critical audit write rejected -> BoundedMap.set()
      // ABORTS: the incoming insert is refused (same as a capacity
      // refusal), and the entry `selectEviction` had picked (the oldest
      // session) is NEVER deleted.
      expect(overflow.session_id).toBeUndefined();
      expect(overflow.error).toBeDefined();

      storage.failAuditWrites = false;
      const stillThere = parse(await status.handler({ session_id: firstSessionId }));
      expect(stillThere.error).toBeUndefined();
      expect(stillThere.session_id).toBe(firstSessionId);
    },
    60_000
  );

  it(
    "MUTATION-PROOF TARGET (sentinel reclamation abort): a rejected critical audit write during expired-record reclamation aborts the reclamation — the expired record is NOT deleted, and the triggering write is refused",
    async () => {
      const storage = new ToggleableFaultingAuditStorage();
      const masterKey = generateRandomKey();
      let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
      const auditLog = new AuditLog(storage, masterKey);
      const CAP = 3;
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-audit-fail-test",
        retentionDays: 1,
        now: () => new Date(nowMs),
        auditLog,
        maxTrackedFindings: CAP,
        maxFindingsPerOrigin: 1000,
      });

      // Fill the cap with findings that will all be EXPIRED shortly.
      for (let i = 0; i < CAP; i += 1) {
        await store.saveFinding(mkFinding(`expiring-${i}`, { agent_id: `agent-${i}` }));
      }
      // Advance past the 1-day retention window so every record above is
      // now reclaimable.
      nowMs += 2 * 24 * 60 * 60 * 1000;

      storage.failAuditWrites = true;
      await expect(store.saveFinding(mkFinding("overflow"))).rejects.toMatchObject({
        reason: "capacity",
      });
      storage.failAuditWrites = false;

      // The expired record was NEVER deleted — the audit failure aborted
      // reclamation before the delete.
      expect(await store.loadFinding("expiring-0")).not.toBeNull();
    },
    30_000
  );

  it(
    "MUTATION-PROOF TARGET (no false success, MUST-FIX 4 fix-round-3): a storage.delete() failure AFTER a successful reclamation-intent audit produces an explicit failure record, never a durable 'success' claim for a reclamation that never happened",
    async () => {
      class FailingDeleteStorage extends MemoryStorage {
        failFindingDeletes = false;
        async delete(
          namespace: string,
          key: string,
          secureOverwrite?: boolean
        ): Promise<boolean> {
          if (namespace === SENTINEL_FINDING_NAMESPACE && this.failFindingDeletes) {
            throw new Error("simulated finding delete failure");
          }
          return super.delete(namespace, key, secureOverwrite);
        }
      }
      const storage = new FailingDeleteStorage();
      const masterKey = generateRandomKey();
      let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
      const auditLog = new AuditLog(storage, masterKey);
      const CAP = 1;
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-false-success-test",
        retentionDays: 1,
        now: () => new Date(nowMs),
        auditLog,
        maxTrackedFindings: CAP,
        maxFindingsPerOrigin: 1000,
      });

      // Capture every audited op so we can assert on the EXACT sequence,
      // not just the thrown error.
      const auditedOps: { operation: string; result: string }[] = [];
      const originalAppend = auditLog.append.bind(auditLog);
      auditLog.append = ((...args: Parameters<AuditLog["append"]>) => {
        const [, operation, , , result] = args;
        auditedOps.push({ operation, result: result ?? "success" });
        return originalAppend(...args);
      }) as AuditLog["append"];
      const originalAppendCritical = auditLog.appendCritical.bind(auditLog);
      auditLog.appendCritical = ((...args: Parameters<AuditLog["appendCritical"]>) => {
        const entry = args[0];
        auditedOps.push({ operation: entry.operation, result: entry.result });
        return originalAppendCritical(...args);
      }) as AuditLog["appendCritical"];

      await store.saveFinding(mkFinding("expiring-0"));
      nowMs += 2 * 24 * 60 * 60 * 1000;

      // The intent audit (appendCritical, to a storage namespace that is
      // NOT gated by `failFindingDeletes`) succeeds normally; only the
      // FINDING delete itself fails.
      storage.failFindingDeletes = true;
      await expect(store.saveFinding(mkFinding("overflow"))).rejects.toMatchObject({
        reason: "capacity",
      });
      storage.failFindingDeletes = false;

      // The record was never actually deleted (the failed delete never
      // completed) — same observable state as the audit-rejection test
      // above, reached via a DIFFERENT failure point.
      expect(await store.loadFinding("expiring-0")).not.toBeNull();

      // THE FIX: the audit trail contains the INTENT (success) followed by
      // an explicit FAILURE record — never a lone
      // `finding_store_expired_record_reclaimed` / success claim with no
      // corresponding delete. Pre-fix, the single pre-delete audit entry
      // WAS `finding_store_expired_record_reclaimed` / success, written
      // before the (here, failing) delete was even attempted — exactly the
      // false-success shape this closes.
      const reclaimOps = auditedOps.filter((o) => o.operation.startsWith("finding_store_expired_record"));
      expect(reclaimOps).toContainEqual({
        operation: "finding_store_expired_record_reclaim_started",
        result: "success",
      });
      expect(reclaimOps).toContainEqual({
        operation: "finding_store_expired_record_reclaim_failed",
        result: "failure",
      });
      // Never a success claim for the RECLAIM COMPLETION when the delete
      // itself never ran.
      expect(reclaimOps).not.toContainEqual({
        operation: "finding_store_expired_record_reclaimed",
        result: "success",
      });
    },
    30_000
  );

  it(
    "MUTATION-PROOF TARGET (no concurrent-refresh deletion, MUST-FIX 4 fix-round-3): a record RENEWED by a concurrent write during the reclamation-intent audit await survives, and the scan reclaims a DIFFERENT genuinely-expired record instead",
    async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      let nowMs = Date.parse("2026-01-01T00:00:00.000Z");
      const auditLog = new AuditLog(storage, masterKey);
      const CAP = 2;
      const store = new SentinelFindingStore({
        storage,
        masterKey,
        fortressId: "fortress-concurrent-refresh-test",
        retentionDays: 1,
        now: () => new Date(nowMs),
        auditLog,
        maxTrackedFindings: CAP,
        maxFindingsPerOrigin: 1000,
      });

      await store.saveFinding(mkFinding("expiring-a"));
      await store.saveFinding(mkFinding("expiring-b"));
      // Both now past their 1-day retention window.
      nowMs += 2 * 24 * 60 * 60 * 1000;

      // Intercept the FIRST reclamation-intent audit (whichever of the two
      // candidates the oldest-first scan reaches first) and, DURING that
      // awaited critical write, perform a CONCURRENT renewal of that SAME
      // finding_id — modeling a legitimate `saveFinding` update racing the
      // reclamation scan's audit await (the real async gap this closes).
      let renewedFindingId: string | undefined;
      const originalAppendCritical = auditLog.appendCritical.bind(auditLog);
      auditLog.appendCritical = (async (
        ...args: Parameters<AuditLog["appendCritical"]>
      ) => {
        const entry = args[0];
        if (
          renewedFindingId === undefined &&
          entry.operation === "finding_store_expired_record_reclaim_started"
        ) {
          renewedFindingId = (entry.details as { finding_id?: string }).finding_id;
          // Renew: a fresh write for the SAME finding_id, computed at the
          // CURRENT (still-advanced) `nowMs`, so its retention_until lands
          // safely in the future relative to the reclamation's `cutoff`
          // (also computed from the same `nowMs`).
          await store.saveFinding(
            mkFinding(renewedFindingId!, { summary: "renewed concurrently" }),
            { knownExisting: true }
          );
        }
        return originalAppendCritical(...args);
      }) as AuditLog["appendCritical"];

      // Triggers reclamation: the FIRST candidate gets renewed mid-audit
      // (abandoned, not deleted); the scan continues to the SECOND
      // candidate, which is genuinely still expired and gets reclaimed
      // normally, making room for this write.
      const retentionUntil = await store.saveFinding(mkFinding("overflow"));
      expect(retentionUntil).toBeDefined();
      expect(renewedFindingId).toBeDefined();

      // The renewed record survived, WITH its renewal content intact —
      // never deleted despite having been the reclamation scan's first
      // candidate.
      const survivor = await store.loadFinding(renewedFindingId!);
      expect(survivor).not.toBeNull();
      expect(survivor!.summary).toBe("renewed concurrently");

      // The OTHER candidate (not renewed) was genuinely reclaimed.
      const otherId = renewedFindingId === "expiring-a" ? "expiring-b" : "expiring-a";
      expect(await store.loadFinding(otherId)).toBeNull();

      // The overflow write itself succeeded (room was made by reclaiming
      // the OTHER record, not the renewed one).
      expect(await store.loadFinding("overflow")).not.toBeNull();
    },
    30_000
  );

  function mkFinding(id: string, overrides: Partial<SentinelFinding> = {}): SentinelFinding {
    return {
      finding_id: id,
      sentinel_id: "inventory-test-sentinel",
      severity: "alert",
      summary: `finding ${id}`,
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: "fortress-inventory-test",
      ...overrides,
    };
  }
});
