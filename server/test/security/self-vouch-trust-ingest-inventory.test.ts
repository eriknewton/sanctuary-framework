/**
 * Self-Vouch Trust-Ingest Inventory — Class-Level Regression Suite
 * (register §Z RECHECK / LD2-02, LD2-02b, A11)
 *
 * "A locally-held key confers remote/peer trust" (self-vouch trust
 * laundering) is a RECURRING class in this codebase. Prior fixes each
 * patched ONE consumer:
 *   - REP-01 capped reputation weighting (tiers.ts resolveTierByDid).
 *   - LD2-02 found federation registration had NO local-custody check on
 *     the SAME shared handshakeResults map REP-01 only partially covered.
 *   - LD2-02b found the operator dashboard's handshake panel was a SECOND
 *     unprotected consumer of that same map.
 *   - A11 found the reputation STORAGE chokepoint (trustedSovereigntyTier)
 *     still trusted a local (imported:false) record's declared tier
 *     verbatim, so a pre-fix laundered record or a direct
 *     ReputationStore.record() caller could still carry privileged weight.
 *
 * This file is the class-binding artifact: it enumerates EVERY trust-ingest
 * point reachable from a locally-held counterparty key and asserts each one
 * refuses or caps it, driven through the real production object graph (real
 * IdentityManager, real handshake tools, real federation tools, a real
 * DashboardApprovalChannel HTTP surface, a real ReputationStore — no
 * manufactured fixtures standing in for the production wiring).
 *
 * THE INVARIANT: no trust or scoring decision may credit a DID whose signing
 * key this fortress holds. Every ingest point is listed here and must refuse
 * or cap it. When a new trust consumer is added, it earns its place in this
 * file before it earns "shipped."
 *
 * Covered ingest points:
 *   (a) The handshake producer chokepoint — recordHandshakeResult in
 *       handshake/tools.ts — refuses to WRITE a self-vouched entry from
 *       handshake_respond (earliest, tool-level), handshake_complete,
 *       handshake_status (verifyCompletion), and handshake_exchange.
 *   (b) federation_peers register() finds no completed handshake for a
 *       self-vouched pair (the producer kept the shared map clean), AND
 *       independently refuses a locally-held peer_did even if a poisoned
 *       entry reached the map by some other path (defense-in-depth).
 *   (c) The operator dashboard's handshake panel (/api/handshakes) never
 *       renders a locally-held counterparty as verified — it inherits the
 *       fix for free from the shared producer chokepoint (the "shared
 *       substrate" lesson: fix once at the producer, every reader inherits
 *       it), with zero code change to dashboard.ts.
 *   (d) reputation trustedSovereigntyTier / loadAllForTierScoring clamp a
 *       locally-signed privileged tier UNCONDITIONALLY (A11): a direct
 *       ReputationStore.record() caller that supplies a privileged tier, and
 *       a pre-existing imported:false legacy record written straight to the
 *       storage backend, both read back clamped to self-attested.
 *   (e) The REP-01 resolveTierByDid local-DID caps still hold (regression
 *       guard against re-widening them while touching this class).
 */

import { afterEach, describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools, IdentityManager } from "../../src/cognitive/tools.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import { generateSHR } from "../../src/shr/generator.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { defaultConfig } from "../../src/config.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import {
  ReputationStore,
  trustedSovereigntyTier,
  type Attestation,
  type StoredAttestation,
} from "../../src/reputation/reputation-store.js";
import { resolveTierByDid } from "../../src/reputation/tiers.js";
import { encrypt } from "../../src/core/encryption.js";
import {
  sign,
  legacyPublicKeyToDid,
  publicKeyToDid,
  localDidEncodings,
  requireLocalDidEncodings,
  isLocallyHeldPublicKey,
  type StoredIdentity,
} from "../../src/core/identity.js";
import { stringToBytes, toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { StorageBackend } from "../../src/storage/interface.js";

// ── Fortress harness: ONE IdentityManager, real production classes ────────

function makeFortress() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager, tools: l1Tools } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return {
    storage,
    masterKey,
    stateStore,
    auditLog,
    config,
    identityManager,
    l1Tools,
  };
}

async function addIdentity(
  fortress: ReturnType<typeof makeFortress>,
  label: string
): Promise<StoredIdentity> {
  const encKey = derivePurposeKey(fortress.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(label, encKey, "recovery-key");
  await fortress.identityManager.save(storedIdentity);
  return storedIdentity;
}

/**
 * MUST-FIX 1 (register §Z RECHECK / two-family gate CRITICAL) fixture: a
 * local identity persisted under the LEGACY base64url `did:key` encoding
 * (legacyPublicKeyToDid) instead of the canonical base58btc form
 * (publicKeyToDid). `legacyPublicKeyToDid` exists precisely because
 * persisted/imported identities can carry this old encoding — this
 * reproduces that shape by overriding `.did` after creation (the public key
 * and identity_id, which SHR generation actually signs with / keys off of,
 * are untouched). Any local-identity guard that compares `.did` STRINGS
 * against a freshly-derived CANONICAL DID (as isLocallyHeldDid /
 * peerDid-string-compare did pre-fix) fails to recognize this identity as
 * local; a guard that compares decoded PUBLIC-KEY BYTES recognizes it
 * regardless of which DID encoding it happens to be stored under.
 */
async function addLegacyDidIdentity(
  fortress: ReturnType<typeof makeFortress>,
  label: string
): Promise<StoredIdentity> {
  const encKey = derivePurposeKey(fortress.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(label, encKey, "recovery-key");
  const legacyIdentity: StoredIdentity = {
    ...storedIdentity,
    did: legacyPublicKeyToDid(fromBase64url(storedIdentity.public_key)),
  };
  await fortress.identityManager.save(legacyIdentity);
  return legacyIdentity;
}

function shrFor(
  fortress: ReturnType<typeof makeFortress>,
  identityId?: string
): SignedSHR {
  const shr = generateSHR(identityId, {
    config: fortress.config,
    identityManager: fortress.identityManager,
    masterKey: fortress.masterKey,
  });
  if (typeof shr === "string") throw new Error(shr);
  return shr;
}

function parse(result: { content: { text: string }[] }): Record<string, any> {
  return JSON.parse(result.content[0]!.text);
}

const MINIMAL_POLICY = {
  version: 1,
  tier1_always_approve: [],
  tier3_auto_allow: [],
  anomaly_thresholds: {
    new_namespace: true,
    unfamiliar_counterparty_window_days: 7,
    frequency_spike_multiplier: 5,
  },
  approval_channel: { type: "stderr", timeout_seconds: 30 },
} as never;

// ── (a) Handshake producer chokepoint ──────────────────────────────────────

describe("(a) handshake producer chokepoint: recordHandshakeResult", () => {
  it("handshake_respond refuses a challenge from a locally-held identity (earliest rejection)", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const { tools } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;
    const respond = tools.find((t) => t.name === "handshake_respond")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );
    const responded = parse(
      await respond.handler({
        challenge: initiated.challenge,
        identity_id: b.identity_id,
      })
    );

    expect(responded.error).toContain("same fortress");
  });

  it("handshake_complete refuses to RECORD a self-vouched pair even when the response is produced out-of-band (recordHandshakeResult chokepoint, not just the respond-side gate)", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const { tools, handshakeResults } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;
    const complete = tools.find((t) => t.name === "handshake_complete")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );

    // Build a valid response signed by B via the PURE protocol function,
    // bypassing handshake_respond's tool-level early check entirely. This
    // proves the RECORDING chokepoint itself refuses the self-vouch, not
    // just the earlier tool-level gate.
    const { respondToHandshake } = await import(
      "../../src/handshake/protocol.js"
    );
    const shrB = shrFor(fortress, b.identity_id);
    const respondResult = respondToHandshake(
      initiated.challenge,
      shrB,
      fortress.identityManager,
      fortress.masterKey,
      b.identity_id
    );
    if ("error" in respondResult) throw new Error(respondResult.error);

    const out = parse(
      await complete.handler({
        session_id: initiated.session_id,
        response: respondResult.response,
      })
    );

    expect(out.error).toContain("same fortress");
    // The producer chokepoint: no entry ever exists in the shared map, so
    // no downstream consumer (federation, dashboard, reputation) can ever
    // read one back as verified.
    expect(handshakeResults.size).toBe(0);
  });

  it("handshake_status (verifyCompletion) refuses to RECORD when the counterparty DID becomes locally held between respond and verify", async () => {
    // Two separate fortresses so the RESPONDER's early tool-level check
    // (handshake_respond) legitimately passes — the responder does not yet
    // hold the initiator's key at respond time. Custody of the initiator's
    // identity is then imported into the responder's fortress BEFORE
    // verifying the completion, proving isLocallyHeldDid is computed FRESH
    // via identityManager.list() on every call, not cached at boot.
    const initiatorFortress = makeFortress();
    const a = await addIdentity(initiatorFortress, "identity-a");
    const { tools: initTools } = createHandshakeTools(
      initiatorFortress.config,
      initiatorFortress.identityManager,
      initiatorFortress.masterKey,
      initiatorFortress.auditLog
    );

    const responderFortress = makeFortress();
    const b = await addIdentity(responderFortress, "identity-b");
    const { tools: respTools, handshakeResults: responderResults } =
      createHandshakeTools(
        responderFortress.config,
        responderFortress.identityManager,
        responderFortress.masterKey,
        responderFortress.auditLog
      );

    const initiate = initTools.find((t) => t.name === "handshake_initiate")!;
    const complete = initTools.find((t) => t.name === "handshake_complete")!;
    const respond = respTools.find((t) => t.name === "handshake_respond")!;
    const status = respTools.find((t) => t.name === "handshake_status")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );
    const responded = parse(
      await respond.handler({
        challenge: initiated.challenge,
        identity_id: b.identity_id,
      })
    );
    expect(responded.error).toBeUndefined();

    const completed = parse(
      await complete.handler({
        session_id: initiated.session_id,
        response: responded.response,
      })
    );
    expect(completed.result.verified).toBe(true);

    // Simulate the responder's fortress gaining custody of A's identity
    // (key import / backup restore) after respond but before verify.
    await responderFortress.identityManager.save(a);

    const verified = parse(
      await status.handler({
        session_id: responded.session_id,
        completion: completed.completion,
      })
    );

    expect(verified.result.verified).toBe(false);
    expect(verified.result.errors.join(" ")).toContain("same fortress");
    expect(responderResults.size).toBe(0);
  });

  it("handshake_exchange never records a self-vouched preview entry", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const { tools, handshakeResults } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const exchange = tools.find((t) => t.name === "handshake_exchange")!;

    const shrB = shrFor(fortress, b.identity_id);
    const out = parse(
      await exchange.handler({
        identity_id: a.identity_id,
        counterparty_shr: shrB,
      })
    );

    // Structurally fine (distinct, self-consistent key) — the refusal is
    // about RECORDING it as a trust-ingest entry, not about SHR validity.
    expect(out.verification.counterparty_valid).toBe(true);
    expect(handshakeResults.size).toBe(0);
  });
});

// ── (b) Federation registration ─────────────────────────────────────────

describe("(b) federation_peers register(): local-custody refusal", () => {
  it("finds no completed handshake for a self-vouched pair (the producer kept the map clean)", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const { tools: hsTools, handshakeResults } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = hsTools.find((t) => t.name === "handshake_initiate")!;
    const complete = hsTools.find((t) => t.name === "handshake_complete")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );
    const { respondToHandshake } = await import(
      "../../src/handshake/protocol.js"
    );
    const shrB = shrFor(fortress, b.identity_id);
    const respondResult = respondToHandshake(
      initiated.challenge,
      shrB,
      fortress.identityManager,
      fortress.masterKey,
      b.identity_id
    );
    if ("error" in respondResult) throw new Error(respondResult.error);
    await complete.handler({
      session_id: initiated.session_id,
      response: respondResult.response,
    });
    expect(handshakeResults.size).toBe(0);

    const { tools: fedTools } = createFederationTools(
      fortress.auditLog,
      handshakeResults,
      fortress.identityManager
    );
    const register = fedTools.find((t) => t.name === "federation_peers")!;
    const out = parse(
      await register.handler({
        action: "register",
        peer_id: shrB.body.instance_id,
      })
    );

    expect(out.registered).toBeUndefined();
    expect(out.error).toContain("No completed handshake");
    expect(handshakeResults.get(shrB.body.instance_id)).toBeUndefined();
  });

  it("also refuses independently when a self-vouched entry reaches the map by some other path (defense-in-depth register-time check)", async () => {
    const fortress = makeFortress();
    const b = await addIdentity(fortress, "identity-b");
    const shrB = shrFor(fortress, b.identity_id);

    // Bypass the producer entirely: hand-construct a verified,
    // liveness-proven HandshakeResult for B and insert it DIRECTLY,
    // simulating a future producer that forgets to route through
    // recordHandshakeResult. Federation's OWN register-time check
    // (identityManager.list()) must catch this independently.
    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shrB.body.instance_id, {
      counterparty_id: shrB.body.instance_id,
      counterparty_shr: shrB,
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    const { tools: fedTools } = createFederationTools(
      fortress.auditLog,
      handshakeResults,
      fortress.identityManager
    );
    const register = fedTools.find((t) => t.name === "federation_peers")!;
    const out = parse(
      await register.handler({
        action: "register",
        peer_id: shrB.body.instance_id,
      })
    );

    expect(out.registered).toBeUndefined();
    expect(out.error).toContain("holds keys for");
  });
});

// ── (c) Operator dashboard handshake panel ──────────────────────────────

describe("(c) operator dashboard handshake panel: shared-substrate inheritance", () => {
  let dashboard: DashboardApprovalChannel | null = null;

  afterEach(async () => {
    await dashboard?.stop();
    dashboard = null;
  });

  it("/api/handshakes never renders a locally-held counterparty — inherited for free from the producer chokepoint, no dashboard.ts change", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const { tools: hsTools, handshakeResults } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = hsTools.find((t) => t.name === "handshake_initiate")!;
    const complete = hsTools.find((t) => t.name === "handshake_complete")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );
    const { respondToHandshake } = await import(
      "../../src/handshake/protocol.js"
    );
    const shrB = shrFor(fortress, b.identity_id);
    const respondResult = respondToHandshake(
      initiated.challenge,
      shrB,
      fortress.identityManager,
      fortress.masterKey,
      b.identity_id
    );
    if ("error" in respondResult) throw new Error(respondResult.error);
    await complete.handler({
      session_id: initiated.session_id,
      response: respondResult.response,
    });
    expect(handshakeResults.size).toBe(0);

    const port = await getFreePort();
    const authToken = "self-vouch-inventory-dashboard-token";
    dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auth_token: authToken,
      auto_open: false,
    });
    // The SAME handshakeResults map instance the real handshake tools
    // populate — this is what proves the dashboard panel is a downstream
    // reader of the shared substrate, not a separately-fixed consumer.
    dashboard.setDependencies({
      policy: MINIMAL_POLICY,
      baseline: { load: async () => {}, save: async () => {} } as never,
      auditLog: fortress.auditLog,
      identityManager: fortress.identityManager,
      handshakeResults,
    });
    await dashboard.start();

    const res = await fetch(`http://127.0.0.1:${port}/api/handshakes`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      handshakes: Array<{ counterparty_id: string; trust_tier: string }>;
      count: number;
      tier_distribution: { verified_sovereign: number };
    };

    expect(body.count).toBe(0);
    expect(
      body.handshakes.find((h) => h.counterparty_id === shrB.body.instance_id)
    ).toBeUndefined();
    expect(body.tier_distribution.verified_sovereign).toBe(0);
  });
});

// ── (d) Reputation storage clamp ────────────────────────────────────────

describe("(d) reputation storage clamp: trustedSovereigntyTier (A11, unconditional)", () => {
  it("clamps a direct ReputationStore.record() caller that supplies a privileged tier, bypassing reputation_record/bridge_attest", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new ReputationStore(storage, masterKey);
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "direct-sdk-caller",
      encKey,
      "recovery-key"
    );

    // A caller using the ReputationStore class directly — not through the
    // reputation_record / bridge_attest MCP tools, which cap the tier via
    // resolveTierByDid before it ever reaches record() — supplies a
    // privileged tier explicitly. The storage chokepoint must still clamp
    // it: every record() write is signed with a locally-held key by
    // construction, so it can never legitimately outrank self-attested.
    const recorded = await store.record(
      "direct-1",
      "did:key:cp",
      { type: "transaction", result: "completed" },
      "commerce",
      storedIdentity,
      encKey,
      undefined,
      "verified-sovereign"
    );
    expect(recorded.imported).toBe(false);

    const scoring = await store.loadAllForTierScoring({});
    expect(scoring).toHaveLength(1);
    expect(trustedSovereigntyTier(scoring[0]!)).toBe("self-attested");
    expect(scoring[0]!.attestation.data.sovereignty_tier).toBe("self-attested");

    const summary = await store.summarizeForSHR();
    expect(summary.tier_distribution["verified-sovereign"]).toBe(0);
    expect(summary.tier_distribution["self-attested"]).toBe(1);
  });

  it("clamps a pre-existing imported:false record written straight to the storage backend (old shape, pre-A11 laundered record)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new ReputationStore(storage, masterKey);
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "pre-fix-signer",
      encKey,
      "recovery-key"
    );

    await writeStoredAttestationDirectly(storage, masterKey, storedIdentity, encKey, {
      attestationId: "pre-a11-laundered",
      sovereigntyTier: "verified-sovereign",
      imported: false,
    });

    const scoring = await store.loadAllForTierScoring({});
    expect(scoring).toHaveLength(1);
    expect(scoring[0]!.imported).toBe(false);
    // FAIL-BEFORE A11: trustedSovereigntyTier returned "verified-sovereign"
    // for this record because imported === false bypassed the clamp.
    // PASS-AFTER: the clamp is unconditional.
    expect(trustedSovereigntyTier(scoring[0]!)).toBe("self-attested");
  });
});

// ── (e) resolveTierByDid local-DID caps (REP-01) ────────────────────────

describe("(e) resolveTierByDid local-DID caps still hold (REP-01 regression guard)", () => {
  it("caps a verified handshake for a locally-held DID at self-attested, and still credits a genuinely remote DID", () => {
    const encKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
    const local = createIdentity("local-signer", encKey, "recovery-key");
    const remote = createIdentity("remote-peer", encKey, "recovery-key");

    const shrFor = (
      identity: ReturnType<typeof createIdentity>,
      instanceId: string
    ): SignedSHR => ({
      body: {
        shr_version: "1.0",
        implementation: {
          sanctuary_version: "0.4.0",
          node_version: "20.0.0",
          generated_by: "sanctuary-mcp-server",
        },
        instance_id: instanceId,
        generated_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        layers: {
          l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
          l2: { status: "active", isolation_type: "local-process", attestation_available: true },
          l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
          l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
        },
        capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
        degradations: [],
      },
      signed_by: identity.storedIdentity.public_key,
      signature_scheme: "ed25519-v1",
      signature: toBase64url(new Uint8Array(64)),
    });

    const map = new Map<string, HandshakeResult>();
    map.set("local-instance", {
      counterparty_id: "local-instance",
      counterparty_shr: shrFor(local, "local-instance"),
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });
    map.set("remote-instance", {
      counterparty_id: "remote-instance",
      counterparty_shr: shrFor(remote, "remote-instance"),
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    // Locally held: capped, never credited above self-attested.
    expect(
      resolveTierByDid(
        local.publicIdentity.did,
        map,
        true,
        new Set([local.publicIdentity.did])
      ).sovereignty_tier
    ).toBe("self-attested");

    // Genuinely remote: still credited (no over-block from the guard).
    expect(
      resolveTierByDid(
        remote.publicIdentity.did,
        map,
        true,
        new Set([local.publicIdentity.did])
      ).sovereignty_tier
    ).toBe("verified-sovereign");
  });
});

// ── (f) MUST-FIX 1: legacy DID encoding does not evade the guard ───────────
//
// register §Z RECHECK / two-family gate CRITICAL: isLocallyHeldDid /
// peerDid-string-compare pre-fix derived the counterparty's DID CANONICALLY
// (publicKeyToDid) and compared it against each held identity's STORED
// `.did` string. legacyPublicKeyToDid exists precisely because a persisted
// or imported identity can carry the OLD base64url DID encoding — a
// legacy-encoded local identity's `.did` therefore never matched the
// canonical derivation, so the guard failed to recognize it as local and
// its self-vouch was NOT blocked. The fix compares DECODED PUBLIC-KEY BYTES
// instead (core/identity.ts isLocallyHeldPublicKey), which is invariant to
// which DID encoding the identity happens to be stored under.

describe("(f) MUST-FIX 1: a legacy-DID-encoded local identity is still recognized as local", () => {
  it("handshake_respond refuses a challenge from a legacy-DID-encoded locally-held identity", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addLegacyDidIdentity(fortress, "identity-b-legacy-did");
    // Sanity: b really is stored under the legacy (non-canonical) encoding —
    // different from what the canonical derivation would produce for the
    // SAME key.
    expect(b.did).not.toEqual(publicKeyToDid(fromBase64url(b.public_key)));

    const { tools } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;
    const respond = tools.find((t) => t.name === "handshake_respond")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );
    // A challenges B (the legacy-DID identity) — B is locally held either way.
    const respondedToLegacy = parse(
      await respond.handler({
        challenge: initiated.challenge,
        identity_id: b.identity_id,
      })
    );
    expect(respondedToLegacy.error).toContain("same fortress");

    // And the reverse direction: B (legacy-DID) initiates, A responds and
    // must recognize B's signing key as locally held despite B's `.did`
    // being the legacy string.
    const initiatedByLegacy = parse(
      await initiate.handler({ identity_id: b.identity_id })
    );
    const respondedByA = parse(
      await respond.handler({
        challenge: initiatedByLegacy.challenge,
        identity_id: a.identity_id,
      })
    );
    expect(respondedByA.error).toContain("same fortress");
  });

  it("handshake_complete refuses to RECORD a self-vouched pair for a legacy-DID identity (recordHandshakeResult chokepoint)", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addLegacyDidIdentity(fortress, "identity-b-legacy-did");
    const { tools, handshakeResults } = createHandshakeTools(
      fortress.config,
      fortress.identityManager,
      fortress.masterKey,
      fortress.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;
    const complete = tools.find((t) => t.name === "handshake_complete")!;

    const initiated = parse(
      await initiate.handler({ identity_id: a.identity_id })
    );

    // Bypass handshake_respond's own earliest-rejection tool-level gate via
    // the pure protocol function, isolating the RECORDING chokepoint itself
    // (mirrors the (a) group's equivalent test).
    const { respondToHandshake } = await import(
      "../../src/handshake/protocol.js"
    );
    const shrB = shrFor(fortress, b.identity_id);
    const respondResult = respondToHandshake(
      initiated.challenge,
      shrB,
      fortress.identityManager,
      fortress.masterKey,
      b.identity_id
    );
    if ("error" in respondResult) throw new Error(respondResult.error);

    const completed = parse(
      await complete.handler({
        session_id: initiated.session_id,
        response: respondResult.response,
      })
    );
    expect(completed.error).toContain("same fortress");
    expect(handshakeResults.get(b.identity_id)).toBeUndefined();
  });

  it("federation_peers register() independently refuses a legacy-DID-encoded locally-held peer_did reaching the map by some other path", async () => {
    const fortress = makeFortress();
    const b = await addLegacyDidIdentity(fortress, "identity-b-legacy-did");
    const shrB = shrFor(fortress, b.identity_id);

    // Bypass the producer entirely (as the (b) group's equivalent test
    // does): hand-insert a verified, liveness-proven HandshakeResult so
    // federation's OWN register-time check is what is under test.
    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shrB.body.instance_id, {
      counterparty_id: shrB.body.instance_id,
      counterparty_shr: shrB,
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    const { tools: fedTools } = createFederationTools(
      fortress.auditLog,
      handshakeResults,
      fortress.identityManager
    );
    const register = fedTools.find((t) => t.name === "federation_peers")!;
    const out = parse(
      await register.handler({
        action: "register",
        peer_id: shrB.body.instance_id,
      })
    );

    expect(out.registered).toBeUndefined();
    expect(out.error).toContain("Cannot register a federation peer this fortress holds keys for");
  });

  it("resolveTierByDid: a local-set built from only one DID encoding misses a canonically-looked-up local key; localDidEncodings closes it", () => {
    // resolveTierByDid's own contract is "is this DID one of ours" — general
    // purpose, not specific to today's two callers. This demonstrates the
    // latent gap directly: the internal handshake-map loop ALWAYS derives a
    // DID CANONICALLY from a stored signing key (publicKeyToDid), so the one
    // direction that can actually be fooled is a canonically-looked-up DID
    // matched against a local-identity set built from only that identity's
    // (possibly legacy-encoded) `.did` field — exactly what
    // `new Set([identity.did])` produces if that identity was persisted
    // under the legacy encoding. Today's two production callers (bridge/
    // tools.ts, reputation/tools.ts) happen to pass identity.did as BOTH the
    // lookup DID and the set's sole member, so they were never exploitable
    // by this specific path — but hardening the function's general contract
    // (rather than relying on that coincidence) is the fix MUST-FIX 1 asks
    // for, and this proves it holds.
    const encKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
    const local = createIdentity("local-signer", encKey, "recovery-key");
    const localKeyBytes = fromBase64url(local.storedIdentity.public_key);
    const canonicalDid = publicKeyToDid(localKeyBytes);
    const legacyDid = legacyPublicKeyToDid(localKeyBytes);
    expect(legacyDid).not.toEqual(canonicalDid);
    expect(canonicalDid).toEqual(local.publicIdentity.did);

    // A handshake-map entry for the SAME local key — as if a poisoned entry
    // had reached the map by some path other than the producer chokepoint
    // (recordHandshakeResult already prevents this at the producer; this
    // isolates resolveTierByDid's OWN defense-in-depth cap).
    const map = new Map<string, HandshakeResult>();
    map.set("poisoned-instance", {
      counterparty_id: "poisoned-instance",
      counterparty_shr: {
        body: {
          shr_version: "1.0",
          implementation: {
            sanctuary_version: "0.4.0",
            node_version: "20.0.0",
            generated_by: "sanctuary-mcp-server",
          },
          instance_id: "poisoned-instance",
          generated_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
          layers: {
            l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
            l2: { status: "active", isolation_type: "local-process", attestation_available: true },
            l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
            l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
          },
          capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
          degradations: [],
        } as unknown as SignedSHR["body"],
        signed_by: local.storedIdentity.public_key,
        signature_scheme: "ed25519-v1",
        signature: toBase64url(new Uint8Array(64)),
      },
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    // OLD (pre-fix) shape: a set built from only the LEGACY-encoded `.did` a
    // local identity might be persisted under MISSES a CANONICAL lookup —
    // falls through to the handshake-map loop, which matches by signing key
    // and over-credits the poisoned entry's declared verified-sovereign tier.
    const legacyOnlySet = new Set([legacyDid]);
    expect(
      resolveTierByDid(canonicalDid, map, true, legacyOnlySet).sovereignty_tier
    ).toBe("verified-sovereign"); // FAIL-BEFORE: demonstrates the gap

    // NEW (fixed) shape: localDidEncodings derives BOTH forms from the raw
    // key bytes, so the canonical lookup is recognized as local and capped —
    // regardless of which single encoding the identity happens to be stored
    // under.
    const bothFormsSet = new Set(
      localDidEncodings(local.storedIdentity.public_key)
    );
    expect(
      resolveTierByDid(canonicalDid, map, true, bothFormsSet).sovereignty_tier
    ).toBe("self-attested"); // PASS-AFTER
  });
});

// ── (g) MUST-FIX 1 (register §Z RECHECK fix-round-2, CRITICAL): an
//    undecodable/garbage stored public_key must never silently vanish from
//    a local-identity trust set ─────────────────────────────────────────
//
// REACHABILITY FINDING (recorded here, and restated in BUILD_RESULT.md):
// the literal end-to-end shape the finding describes — an identity self-
// vouches by producing a verifiable SHR while its OWN stored `public_key`
// is garbage — is NOT reachable through the handshake/federation guards,
// because `shr/generator.ts` sets `signed_by: identity.public_key` VERBATIM
// (the stored field, not a re-derivation from the private key), and
// `shr/verifier.ts` verifies the signature against THAT SAME field. A
// garbage `public_key` therefore makes that identity's OWN SHR
// unverifiable — the handshake never reaches `verified: true` in the first
// place, independent of this fix. The gap IS real and reachable one layer
// down: `resolveTierByDid`'s local-DID check (bridge/tools.ts,
// reputation/tools.ts) is DID-STRING based, and `identity.did` is an
// independently-supplied import field with NO binding check against
// `public_key` — so a decode failure on the local signer's OWN
// `public_key` collapsing the local set to `[]` (pre-fix) could let a
// colliding local `did` fall through to the handshake-map loop and borrow
// a genuinely-verified remote counterparty's declared tier in THAT tool
// call's OWN response. `trustedSovereigntyTier` (A11, already shipped)
// unconditionally re-clamps every STORED attestation at read/scoring time
// regardless of what was written, so this could never become a durable,
// SCORED trust gain — the exposure this fix closes is a misleading tier
// value in a single write call's own response, not a scored self-vouch.
// The fix (validate at ingest; hard-fail the "held identity" set-builder on
// a decode failure) is still the correct, unconditional posture per
// AGENTS.md rule 3 ("cannot determine locality" must never mean "not
// local") — it should not depend on the SHR-binding and A11 coincidences
// holding forever. Severity is downgraded from "live self-vouch bypass" to
// "fail-open write-time gap, neutralized for scoring by an independent
// control, closed here as the correct posture regardless."

describe("(g) MUST-FIX 1: an undecodable stored public_key never defeats a local-identity guard", () => {
  it("identity_import refuses an identity whose public_key does not decode to a well-formed 32-byte Ed25519 key (ingest chokepoint, root fix)", async () => {
    const fortress = makeFortress();
    const encKey = derivePurposeKey(fortress.masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "garbage-key-identity",
      encKey,
      "recovery-key"
    );
    // "AAAA" is valid base64url charset but decodes to 3 bytes, not the 32
    // an Ed25519 public key requires — the shape `assertEd25519PublicKey`
    // exists to reject.
    const garbageIdentity = { ...storedIdentity, public_key: "AAAA" };

    const importTool = fortress.l1Tools.find(
      (t) => t.name === "identity_import"
    )!;

    // REACHABILITY-FIRST: this call MUST fail before the fix (bare
    // requireNonEmptyString accepted any non-empty string) and MUST fail
    // after it (requireEd25519PublicKeyBase64url rejects a non-decodable
    // key) — both sides land on "refused," which is exactly the point:
    // mutation-proof (a) in BUILD_RESULT.md reverts the ingest check and
    // shows this same call SUCCEED instead.
    await expect(
      importTool.handler({ identity: garbageIdentity })
    ).rejects.toThrow(/Ed25519 public key/i);

    expect(fortress.identityManager.list()).toHaveLength(0);
  });

  it("IdentityManager.load() refuses to load a persisted identity whose public_key does not decode (defense-in-depth for state written before or bypassing ingest validation)", async () => {
    const fortress = makeFortress();
    const encKey = derivePurposeKey(fortress.masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity(
      "garbage-key-identity",
      encKey,
      "recovery-key"
    );
    const garbageIdentity: StoredIdentity = {
      ...storedIdentity,
      public_key: "AAAA",
    };
    // `IdentityManager.save()` itself does not run the identity_import
    // ingest check (only the MCP tool layer does) — this reproduces a
    // record already on disk from before this fix existed, or written by
    // any other path that bypasses the tool.
    await fortress.identityManager.save(garbageIdentity);

    const reloaded = new IdentityManager(fortress.storage, fortress.masterKey);
    const loadResult = await reloaded.load();

    expect(loadResult.total).toBe(1);
    expect(loadResult.loaded).toBe(0);
    expect(loadResult.failed).toBe(1);
    expect(reloaded.list()).toHaveLength(0);
  });

  it("isLocallyHeldPublicKey throws (integrity error) rather than silently skipping a held identity whose public_key cannot be decoded (defense-in-depth)", () => {
    const encKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
    const { storedIdentity } = createIdentity(
      "attacker-controlled-signer",
      encKey,
      "recovery-key"
    );
    const candidateKeyBytes = fromBase64url(storedIdentity.public_key);

    // Pre-fix: a held identity's undecodable public_key was silently
    // `continue`d past, so this returned `false` even for a candidate that
    // genuinely belongs to a held identity — the exact fail-open shape.
    // Post-fix: a held identity's own key material failing to decode is an
    // integrity error the caller must not paper over as "not local."
    expect(() =>
      isLocallyHeldPublicKey(candidateKeyBytes, [{ public_key: "AAAA" }])
    ).toThrow();

    // A genuinely undecodable CANDIDATE (untrusted signer material, not our
    // own held identity) stays a safe "not local" — never a hard failure.
    expect(
      isLocallyHeldPublicKey(undefined, [
        { public_key: storedIdentity.public_key },
      ])
    ).toBe(false);
  });

  it("requireLocalDidEncodings throws for an undecodable key instead of returning an empty set; localDidEncodings keeps its soft contract for untrusted candidates", () => {
    expect(() => requireLocalDidEncodings("AAAA")).toThrow();
    // The untrusted-candidate sibling is UNCHANGED — still soft, by design
    // (core/identity.ts's doc comment on both functions).
    expect(localDidEncodings("AAAA")).toEqual([]);
  });

  it("resolveTierByDid: an empty local set produced by a decode failure lets a colliding local DID borrow a genuinely-verified remote counterparty's tier; requireLocalDidEncodings closes it by refusing instead of building the set", () => {
    const encKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
    const local = createIdentity("local-signer", encKey, "recovery-key");
    const localDid = local.publicIdentity.did;

    // A handshake-map entry for the SAME local key, reproducing "a poisoned
    // entry reached the map by some other path" in isolation — this test
    // is exclusively about resolveTierByDid's own local-set defense, not
    // the producer chokepoint (already covered in groups (a)/(b)).
    const map = new Map<string, HandshakeResult>();
    map.set("poisoned-instance", {
      counterparty_id: "poisoned-instance",
      counterparty_shr: {
        body: {
          shr_version: "1.0",
          implementation: {
            sanctuary_version: "0.4.0",
            node_version: "20.0.0",
            generated_by: "sanctuary-mcp-server",
          },
          instance_id: "poisoned-instance",
          generated_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
          layers: {
            l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
            l2: { status: "active", isolation_type: "local-process", attestation_available: true },
            l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
            l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
          },
          capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
          degradations: [],
        } as unknown as SignedSHR["body"],
        signed_by: local.storedIdentity.public_key,
        signature_scheme: "ed25519-v1",
        signature: toBase64url(new Uint8Array(64)),
      },
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    // OLD (pre-fix) shape: `localDidEncodings` on a held identity's own
    // undecodable public_key silently returns [] — the empty set can never
    // refuse ANYTHING, so the local DID lookup falls through to the
    // handshake-map loop, which matches by signing key and over-credits the
    // poisoned entry's declared verified-sovereign tier in the caller's own
    // (bridge_attest / reputation_record) response.
    const gapFromDecodeFailure = new Set(localDidEncodings("AAAA"));
    expect(gapFromDecodeFailure.size).toBe(0);
    expect(
      resolveTierByDid(localDid, map, true, gapFromDecodeFailure)
        .sovereignty_tier
    ).toBe("verified-sovereign"); // FAIL-BEFORE: demonstrates the gap

    // NEW (fixed) shape: the production callers (bridge/tools.ts,
    // reputation/tools.ts) now build this set with requireLocalDidEncodings,
    // which refuses instead of silently producing the gap — resolveTierByDid
    // is never even reached with an incomplete set.
    expect(() => requireLocalDidEncodings("AAAA")).toThrow(); // PASS-AFTER: refused, not gapped
  });
});

// ── Helper: write a StoredAttestation straight into the encrypted
//    _reputation namespace, bypassing ReputationStore.record() entirely —
//    reproduces a record persisted by an older or bypassing write path. ──

async function writeStoredAttestationDirectly(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identity: StoredIdentity,
  encryptionKey: Uint8Array,
  opts: {
    attestationId: string;
    sovereigntyTier: "verified-sovereign" | "verified-degraded" | "self-attested" | "unverified";
    imported: boolean;
  }
): Promise<void> {
  const now = new Date().toISOString();
  const data: Attestation["data"] = {
    interaction_id: opts.attestationId,
    participant_did: identity.did,
    counterparty_did: "did:key:cp",
    outcome_type: "transaction",
    outcome_result: "completed",
    metrics: { rate: 1.0 },
    context: "commerce",
    timestamp: now,
    sovereignty_tier: opts.sovereigntyTier,
  };
  const attestation: Attestation = {
    attestation_id: opts.attestationId,
    schema: "sanctuary-interaction-v1",
    data,
    signature: toBase64url(
      sign(stringToBytes(JSON.stringify(data)), identity.encrypted_private_key, encryptionKey)
    ),
    signer: identity.did,
  };
  const stored: StoredAttestation = {
    attestation,
    recorded_at: now,
    imported: opts.imported,
  };
  const reputationKey = derivePurposeKey(masterKey, "l4-reputation");
  const encrypted = encrypt(stringToBytes(JSON.stringify(stored)), reputationKey);
  await storage.write(
    "_reputation",
    opts.attestationId,
    stringToBytes(JSON.stringify(encrypted))
  );
}
