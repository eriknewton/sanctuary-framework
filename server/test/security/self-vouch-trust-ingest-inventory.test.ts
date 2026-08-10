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
import { createL1Tools } from "../../src/cognitive/tools.js";
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
import { sign, type StoredIdentity } from "../../src/core/identity.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
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
  const { identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { storage, masterKey, stateStore, auditLog, config, identityManager };
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
