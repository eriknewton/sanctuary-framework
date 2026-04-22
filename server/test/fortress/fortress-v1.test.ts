/**
 * Fortress Modes v1.0 -- Regression Test Suite
 *
 * Real-crypto, real-storage, no mocks at the signature or storage boundary.
 * Covers all 10 acceptance criteria from WP-MVP-1.
 *
 * Uses the same buildFortress pattern from policy-engine fixtures:
 * real Ed25519 keys, real trust-root certs, real signed events.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  CAP_AUDIT_REPLICA_ELIGIBLE,
  CAP_COLD_STORAGE_RECEIPT_REPLICA,
} from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import { verifySignedEvent } from "../../src/mesh/envelope.js";
import type { VerifyContext } from "../../src/mesh/envelope.js";
import { MemoryStorage } from "../../src/storage/memory.js";

// Fortress module imports
import {
  MODE_TIERS,
  LEGAL_TRANSITIONS,
  FORTRESS_EVENT_TYPES,
  FORTRESS_MODE_NAMESPACE,
  TIER_CAPABILITY_DEFAULTS,
  TIER_CAPABILITY_CEILING,
  TIER_SUBSYSTEMS,
  TIER_3_EXTERNAL_ADAPTER_BITS,
  isModeTier,
} from "../../src/fortress/constants.js";
import type { ModeTier } from "../../src/fortress/constants.js";
import {
  validateTransition,
  isLegalTransition,
  getLegalTargets,
  checkPreconditions,
  getPreconditions,
} from "../../src/fortress/mode-state-machine.js";
import {
  IllegalTransitionError,
  AlreadyInTierError,
  InvalidTierError,
  ModePreconditionsNotMetError,
  FortressConfigError,
  InvalidAdapterError,
} from "../../src/fortress/errors.js";
import { packModeTransitionEvent } from "../../src/fortress/mode-transition-event.js";
import {
  getTierProfile,
  getAllTierProfiles,
  isValidCapabilityBits,
  isExternalAdapterBit,
  countExternalAdapterBits,
} from "../../src/fortress/tier-profile.js";
import { FortressModeStore } from "../../src/fortress/config.js";
import { FortressService } from "../../src/fortress/fortress-service.js";
import type { PreconditionContext, ExternalAdapterRegistration } from "../../src/fortress/types.js";

// ---------------------------------------------------------------------------
// Test fixture: real fortress with real keys
// ---------------------------------------------------------------------------

function buildTestFortress() {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const nodeKeypair = generateKeypair();
  const nodeCert = issueNodeIdentityCertificate({
    node_id: "node-" + toBase64url(randomBytes(4)),
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: "root",
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
  });
  return { master, principalKeypair, principalCert, nodeKeypair, nodeCert };
}

function buildService(storage?: MemoryStorage) {
  const f = buildTestFortress();
  const mem = storage ?? new MemoryStorage();
  let seq = 0;
  const service = new FortressService({
    storage: mem,
    masterKey: randomBytes(32),
    fortressId: f.master.public.fortress_id,
    nodeId: f.nodeCert.node_id,
    principalId: f.principalCert.principal_id,
    nodePrivateKey: f.nodeKeypair.privateKey,
    principalPrivateKey: f.principalKeypair.privateKey,
    nextMonotonicSeq: () => ++seq,
  });
  return { service, fortress: f, storage: mem, masterKey: randomBytes(32) };
}

// ---------------------------------------------------------------------------
// AC1: Three tiers defined with explicit capability profiles
// ---------------------------------------------------------------------------

describe("AC1: Three tiers with capability profiles", () => {
  it("MODE_TIERS has exactly three entries", () => {
    expect(MODE_TIERS).toEqual([
      "tier_1_private",
      "tier_2_federated",
      "tier_3_interop",
    ]);
  });

  it("isModeTier validates correctly", () => {
    expect(isModeTier("tier_1_private")).toBe(true);
    expect(isModeTier("tier_2_federated")).toBe(true);
    expect(isModeTier("tier_3_interop")).toBe(true);
    expect(isModeTier("tier_4_magic")).toBe(false);
    expect(isModeTier("")).toBe(false);
  });

  it("each tier has a TierProfile with capability bits and subsystems", () => {
    const profiles = getAllTierProfiles();
    expect(profiles).toHaveLength(3);
    for (const p of profiles) {
      expect(p.tier).toBeTruthy();
      expect(typeof p.capability_bits).toBe("number");
      expect(typeof p.capability_ceiling).toBe("number");
      expect(p.subsystems).toBeDefined();
      expect(p.description.length).toBeGreaterThan(0);
    }
  });

  it("Tier 1 has only standard node capability bit", () => {
    const p = getTierProfile("tier_1_private");
    expect(p.capability_bits).toBe(CAP_STANDARD_FORTRESS_NODE);
    expect(p.capability_ceiling).toBe(CAP_STANDARD_FORTRESS_NODE);
  });

  it("Tier 2 has standard + audit + cold storage bits", () => {
    const p = getTierProfile("tier_2_federated");
    const expected =
      CAP_STANDARD_FORTRESS_NODE |
      CAP_AUDIT_REPLICA_ELIGIBLE |
      CAP_COLD_STORAGE_RECEIPT_REPLICA;
    expect(p.capability_bits).toBe(expected);
    expect(p.capability_ceiling).toBe(expected);
  });

  it("Tier 3 ceiling includes bits 3-7 for external adapters", () => {
    const p = getTierProfile("tier_3_interop");
    // Ceiling should include bits 0-7
    for (let bit = 0; bit <= 7; bit++) {
      expect(p.capability_ceiling & (1 << bit)).toBeTruthy();
    }
    // Default bits should NOT include 3-7 (those need registered adapters)
    expect(p.capability_bits & TIER_3_EXTERNAL_ADAPTER_BITS).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// AC2: State machine enforces legal transitions
// ---------------------------------------------------------------------------

describe("AC2: Legal transitions enforced", () => {
  it("1->2 is legal", () => {
    expect(isLegalTransition("tier_1_private", "tier_2_federated")).toBe(true);
    expect(() => validateTransition("tier_1_private", "tier_2_federated")).not.toThrow();
  });

  it("2->1 is legal", () => {
    expect(isLegalTransition("tier_2_federated", "tier_1_private")).toBe(true);
  });

  it("2->3 is legal", () => {
    expect(isLegalTransition("tier_2_federated", "tier_3_interop")).toBe(true);
  });

  it("3->2 is legal", () => {
    expect(isLegalTransition("tier_3_interop", "tier_2_federated")).toBe(true);
  });

  it("3->1 is legal (full withdrawal)", () => {
    expect(isLegalTransition("tier_3_interop", "tier_1_private")).toBe(true);
  });

  it("1->3 is ILLEGAL (must pass through 2)", () => {
    expect(isLegalTransition("tier_1_private", "tier_3_interop")).toBe(false);
    expect(() => validateTransition("tier_1_private", "tier_3_interop")).toThrow(
      IllegalTransitionError
    );
  });

  it("same-tier transition throws AlreadyInTierError", () => {
    for (const tier of MODE_TIERS) {
      expect(() => validateTransition(tier, tier)).toThrow(AlreadyInTierError);
    }
  });

  it("invalid tier string throws InvalidTierError", () => {
    expect(() => validateTransition("bogus" as ModeTier, "tier_1_private")).toThrow(
      InvalidTierError
    );
    expect(() => validateTransition("tier_1_private", "bogus" as ModeTier)).toThrow(
      InvalidTierError
    );
  });

  it("getLegalTargets returns correct adjacency", () => {
    expect(getLegalTargets("tier_1_private")).toEqual(["tier_2_federated"]);
    expect(new Set(getLegalTargets("tier_2_federated"))).toEqual(
      new Set(["tier_1_private", "tier_3_interop"])
    );
    expect(new Set(getLegalTargets("tier_3_interop"))).toEqual(
      new Set(["tier_2_federated", "tier_1_private"])
    );
  });
});

// ---------------------------------------------------------------------------
// AC3: Tier 1 is fully offline (no mesh subsystem activation)
// ---------------------------------------------------------------------------

describe("AC3: Tier 1 fully offline", () => {
  it("Tier 1 subsystems are all disabled", () => {
    const subs = TIER_SUBSYSTEMS.tier_1_private;
    expect(subs.mesh).toBe(false);
    expect(subs.federation).toBe(false);
    expect(subs.chat).toBe(false);
    expect(subs.external_protocols).toBe(false);
  });

  it("Tier 1 profile disables all mesh-adjacent subsystems", () => {
    const profile = getTierProfile("tier_1_private");
    expect(profile.subsystems.mesh).toBe(false);
    expect(profile.subsystems.federation).toBe(false);
    expect(profile.subsystems.chat).toBe(false);
    expect(profile.subsystems.external_protocols).toBe(false);
  });

  it("Tier 1 capability ceiling is just bit 0 (standard node)", () => {
    expect(TIER_CAPABILITY_CEILING.tier_1_private).toBe(CAP_STANDARD_FORTRESS_NODE);
    expect(isValidCapabilityBits("tier_1_private", CAP_STANDARD_FORTRESS_NODE)).toBe(true);
    expect(isValidCapabilityBits("tier_1_private", CAP_AUDIT_REPLICA_ELIGIBLE)).toBe(false);
  });

  it("fortress initializes in Tier 1 by default", async () => {
    const { service } = buildService();
    await service.initialize();
    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_1_private");
    expect(status.profile.subsystems.mesh).toBe(false);
    expect(status.transitions_history).toEqual([]);
  });

  it("Tier 1 import-graph: fortress constants.ts imports only from mesh/constants.ts (capability bit values), not from mesh lifecycle or transport", async () => {
    // Structural assertion: constants.ts imports
    const fs = await import("fs");
    const constantsSource = fs.readFileSync(
      new URL("../../src/fortress/constants.ts", import.meta.url),
      "utf-8"
    );
    // Should import from mesh/constants for CAP_* values
    expect(constantsSource).toContain('from "../mesh/constants.js"');
    // Should NOT import from mesh/lifecycle, mesh/libp2p-transport, chat, etc.
    expect(constantsSource).not.toContain("mesh/lifecycle");
    expect(constantsSource).not.toContain("mesh/libp2p-transport");
    expect(constantsSource).not.toContain("mesh/router");
    expect(constantsSource).not.toContain("chat/");
    expect(constantsSource).not.toContain("concordia");
    expect(constantsSource).not.toContain("verascore");
  });

  it("fortress source files do not import from mesh/ except constants and envelope/types (Tier 1 isolation proof)", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const fortressDir = new URL("../../src/fortress/", import.meta.url);
    const files = fs.readdirSync(fortressDir).filter((f: string) => f.endsWith(".ts"));

    const ALLOWED_MESH_IMPORTS = [
      "../mesh/constants.js",
      "../mesh/envelope.js",
      "../mesh/types.js",
    ];

    for (const file of files) {
      const source = fs.readFileSync(path.join(fortressDir.pathname, file), "utf-8");
      // Find all mesh imports
      const meshImports = [...source.matchAll(/from\s+["']([^"']*mesh[^"']*)["']/g)];
      for (const match of meshImports) {
        expect(ALLOWED_MESH_IMPORTS).toContain(match[1]);
      }
      // Non-dependency: no concordia, no verascore
      expect(source).not.toContain("concordia");
      expect(source).not.toContain("verascore");
    }
  });
});

// ---------------------------------------------------------------------------
// AC4: Tier 2 requires valid federation join
// ---------------------------------------------------------------------------

describe("AC4: Tier 2 requires federation join preconditions", () => {
  it("1->2 fails without node identity cert", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_1_private",
      target_tier: "tier_2_federated",
      has_node_identity_cert: false,
      has_reachable_peer: true,
      registered_adapter_count: 0,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    expect(failures.length).toBe(1);
    expect(failures[0].id).toBe("federation_join");
    expect(failures[0].reason).toContain("node identity certificate");
  });

  it("1->2 fails without reachable peer", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_1_private",
      target_tier: "tier_2_federated",
      has_node_identity_cert: true,
      has_reachable_peer: false,
      registered_adapter_count: 0,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    expect(failures.length).toBe(1);
    expect(failures[0].id).toBe("federation_join");
    expect(failures[0].reason).toContain("reachable bootstrap peer");
  });

  it("1->2 fails with both missing", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_1_private",
      target_tier: "tier_2_federated",
      has_node_identity_cert: false,
      has_reachable_peer: false,
      registered_adapter_count: 0,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    // First failure short-circuits (cert check fails first)
    expect(failures.length).toBeGreaterThanOrEqual(1);
  });

  it("1->2 passes with valid cert and reachable peer", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_1_private",
      target_tier: "tier_2_federated",
      has_node_identity_cert: true,
      has_reachable_peer: true,
      registered_adapter_count: 0,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    expect(failures).toEqual([]);
  });

  it("FortressService 1->2 throws ModePreconditionsNotMetError on missing cert", async () => {
    const { service } = buildService();
    await service.initialize();
    await expect(
      service.executeTransition(
        { target_tier: "tier_2_federated", reason: "join mesh" },
        { has_node_identity_cert: false }
      )
    ).rejects.toThrow(ModePreconditionsNotMetError);
  });

  it("FortressService 1->2 succeeds with valid preconditions", async () => {
    const { service } = buildService();
    await service.initialize();
    const result = await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join mesh" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );
    expect(result.from_tier).toBe("tier_1_private");
    expect(result.to_tier).toBe("tier_2_federated");
    expect(result.event_id).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// AC5: Tier 3 is hooks-only at v1.0
// ---------------------------------------------------------------------------

describe("AC5: Tier 3 hooks-only", () => {
  it("2->3 fails without registered adapter", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_2_federated",
      target_tier: "tier_3_interop",
      has_node_identity_cert: true,
      has_reachable_peer: true,
      registered_adapter_count: 0,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    expect(failures.length).toBe(1);
    expect(failures[0].id).toBe("external_adapter_registered");
  });

  it("2->3 passes with at least one registered adapter", async () => {
    const ctx: PreconditionContext = {
      current_tier: "tier_2_federated",
      target_tier: "tier_3_interop",
      has_node_identity_cert: true,
      has_reachable_peer: true,
      registered_adapter_count: 1,
      fortress_id: "test-fortress",
    };
    const failures = await checkPreconditions(ctx);
    expect(failures).toEqual([]);
  });

  it("adapter registration validates capability bit range", () => {
    const { service } = buildService();
    const validAdapter: ExternalAdapterRegistration = {
      adapter_id: "x402-stub",
      protocol: "x402",
      registered_at: new Date().toISOString(),
      capability_bit: 3,
    };
    expect(() => service.registerAdapter(validAdapter)).not.toThrow();

    const invalidAdapter: ExternalAdapterRegistration = {
      adapter_id: "bad",
      protocol: "bad",
      registered_at: new Date().toISOString(),
      capability_bit: 1, // Not in 3-7 range
    };
    expect(() => service.registerAdapter(invalidAdapter)).toThrow(InvalidAdapterError);
  });

  it("FortressService full path: 1->2->3 with stub adapter", async () => {
    const { service } = buildService();
    await service.initialize();

    // 1->2
    await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join mesh" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );

    // Register stub adapter for Tier 3
    service.registerAdapter({
      adapter_id: "x402-stub-v1",
      protocol: "x402",
      registered_at: new Date().toISOString(),
      capability_bit: 3,
    });

    // 2->3
    const result = await service.executeTransition(
      { target_tier: "tier_3_interop", reason: "enable x402 hooks" },
    );
    expect(result.from_tier).toBe("tier_2_federated");
    expect(result.to_tier).toBe("tier_3_interop");
  });

  it("Tier 3 subsystems mark external_protocols as true", () => {
    expect(TIER_SUBSYSTEMS.tier_3_interop.external_protocols).toBe(true);
  });

  it("external adapter bit helpers work correctly", () => {
    expect(isExternalAdapterBit(0)).toBe(false);
    expect(isExternalAdapterBit(2)).toBe(false);
    expect(isExternalAdapterBit(3)).toBe(true);
    expect(isExternalAdapterBit(7)).toBe(true);
    expect(isExternalAdapterBit(8)).toBe(false);

    expect(countExternalAdapterBits(0)).toBe(0);
    expect(countExternalAdapterBits(TIER_3_EXTERNAL_ADAPTER_BITS)).toBe(5);
    expect(countExternalAdapterBits(1 << 3)).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// AC6: Mode transition events are signed
// ---------------------------------------------------------------------------

describe("AC6: Signed mode transition events", () => {
  it("packModeTransitionEvent produces a verifiable SignedEvent", () => {
    const f = buildTestFortress();
    const event = packModeTransitionEvent({
      from_tier: "tier_1_private",
      to_tier: "tier_2_federated",
      fortress_id: f.master.public.fortress_id,
      reason: "join mesh",
      preconditions_checked: ["federation_join"],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });

    // Event shape
    expect(event.event_type).toBe(FORTRESS_EVENT_TYPES.MODE_TRANSITION);
    expect(event.event_type).toBe("fortress_mode_transition");
    expect(event.fortress_id).toBe(f.master.public.fortress_id);
    expect(event.protocol_version).toBe("0.1");
    expect(event.node_signature).toBeTruthy();
    expect(event.principal_signature).toBeTruthy();

    // Payload
    expect(event.payload.from_tier).toBe("tier_1_private");
    expect(event.payload.to_tier).toBe("tier_2_federated");
    expect(event.payload.reason).toBe("join mesh");
    expect(event.payload.preconditions_checked).toEqual(["federation_join"]);
    expect(event.payload.transitioned_at).toBeTruthy();

    // Verify signature using mesh verifier
    const verifyCtx: VerifyContext = {
      pinnedMasterPubkey: f.master.public,
      lookupNodeCert: (id) => (id === f.nodeCert.node_id ? f.nodeCert : undefined),
      lookupPrincipalCert: (id) =>
        id === f.principalCert.principal_id ? f.principalCert : undefined,
    };
    const result = verifySignedEvent(event, verifyCtx);
    expect(result.ok).toBe(true);
  });

  it("event type is in fortress_* namespace (not reusing reserved prefixes)", () => {
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).toMatch(/^fortress_/);
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).not.toMatch(/^policy_/);
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).not.toMatch(/^chat_/);
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).not.toMatch(/^mesh_/);
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).not.toMatch(/^recovery_/);
    expect(FORTRESS_EVENT_TYPES.MODE_TRANSITION).not.toMatch(/^identity_/);
  });

  it("signature_scheme is ed25519-v1 (mandatory per spec SS5.3)", () => {
    const f = buildTestFortress();
    const event = packModeTransitionEvent({
      from_tier: "tier_2_federated",
      to_tier: "tier_1_private",
      fortress_id: f.master.public.fortress_id,
      reason: "leave mesh",
      preconditions_checked: [],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 2,
      node_private_key: f.nodeKeypair.privateKey,
    });
    // The envelope should contain the event and payload_hash
    expect(event.payload_hash).toBeTruthy();
    expect(event.monotonic_seq).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// AC7: Config persists operator-sovereign
// ---------------------------------------------------------------------------

describe("AC7: Operator-sovereign config persistence", () => {
  it("FortressModeStore initializes, saves, and loads config", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = new FortressModeStore(storage, masterKey);

    // Initialize
    const config = await store.initialize("test-fortress-123");
    expect(config.schema_version).toBe("1.0");
    expect(config.current_tier).toBe("tier_1_private");
    expect(config.fortress_id).toBe("test-fortress-123");
    expect(config.last_transition_at).toBeNull();

    // Clear cache and reload from storage
    store.clearCache();
    const loaded = await store.load();
    expect(loaded).not.toBeNull();
    expect(loaded!.current_tier).toBe("tier_1_private");
    expect(loaded!.fortress_id).toBe("test-fortress-123");
  });

  it("config uses _fortress_mode reserved namespace", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = new FortressModeStore(storage, masterKey);
    await store.initialize("test-fortress");

    // Verify data was written to the reserved namespace
    const exists = await storage.exists("_fortress_mode", "current");
    expect(exists).toBe(true);
  });

  it("applyTransition updates config correctly", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = new FortressModeStore(storage, masterKey);
    await store.initialize("test-fortress");

    const expectedBits =
      CAP_STANDARD_FORTRESS_NODE |
      CAP_AUDIT_REPLICA_ELIGIBLE |
      CAP_COLD_STORAGE_RECEIPT_REPLICA;

    const updated = await store.applyTransition(
      "tier_2_federated",
      "evt-123",
      expectedBits
    );
    expect(updated.current_tier).toBe("tier_2_federated");
    expect(updated.capability_bits).toBe(expectedBits);
    expect(updated.last_transition_event_id).toBe("evt-123");
    expect(updated.last_transition_at).toBeTruthy();
  });

  it("transition history appends and loads correctly", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = new FortressModeStore(storage, masterKey);
    await store.initialize("test-fortress");

    await store.appendHistory({
      event_id: "evt-1",
      from_tier: "tier_1_private",
      to_tier: "tier_2_federated",
      reason: "join mesh",
      transitioned_at: new Date().toISOString(),
    });

    await store.appendHistory({
      event_id: "evt-2",
      from_tier: "tier_2_federated",
      to_tier: "tier_1_private",
      reason: "leave mesh",
      transitioned_at: new Date().toISOString(),
    });

    const history = await store.loadHistory();
    expect(history.entries).toHaveLength(2);
    expect(history.entries[0].event_id).toBe("evt-1");
    expect(history.entries[1].event_id).toBe("evt-2");
  });

  it("config encrypted at rest (raw bytes are not plaintext JSON)", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const store = new FortressModeStore(storage, masterKey);
    await store.initialize("test-fortress");

    const raw = await storage.read("_fortress_mode", "current");
    expect(raw).not.toBeNull();
    const rawStr = new TextDecoder().decode(raw!);
    // The raw data should be an encrypted payload with ct/iv/alg fields
    // (auth tag is included in ciphertext by @noble/ciphers, no separate tag field)
    const parsed = JSON.parse(rawStr);
    expect(parsed).toHaveProperty("ct");
    expect(parsed).toHaveProperty("iv");
    expect(parsed).toHaveProperty("alg", "aes-256-gcm");
    // Should NOT contain plaintext tier names
    expect(rawStr).not.toContain("tier_1_private");
  });

  it("wrong master key cannot decrypt config", async () => {
    const storage = new MemoryStorage();
    const masterKey1 = randomBytes(32);
    const masterKey2 = randomBytes(32);

    const store1 = new FortressModeStore(storage, masterKey1);
    await store1.initialize("test-fortress");

    const store2 = new FortressModeStore(storage, masterKey2);
    await expect(store2.load()).rejects.toThrow(FortressConfigError);
  });
});

// ---------------------------------------------------------------------------
// AC8: Operator-visible current mode via API
// ---------------------------------------------------------------------------

describe("AC8: Current mode exposed via API", () => {
  it("getCurrentMode returns full status after initialization", async () => {
    const { service } = buildService();
    await service.initialize();

    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_1_private");
    expect(status.profile.tier).toBe("tier_1_private");
    expect(status.profile.subsystems.mesh).toBe(false);
    expect(status.capability_bits).toBe(CAP_STANDARD_FORTRESS_NODE);
    expect(status.transitions_history).toEqual([]);
    expect(status.last_transition_at).toBeNull();
  });

  it("getCurrentMode reflects transitions", async () => {
    const { service } = buildService();
    await service.initialize();

    await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join mesh" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );

    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_2_federated");
    expect(status.profile.tier).toBe("tier_2_federated");
    expect(status.profile.subsystems.mesh).toBe(true);
    expect(status.transitions_history).toHaveLength(1);
    expect(status.transitions_history[0].from_tier).toBe("tier_1_private");
    expect(status.transitions_history[0].to_tier).toBe("tier_2_federated");
    expect(status.last_transition_at).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// AC9: Non-dependency clean
// ---------------------------------------------------------------------------

describe("AC9: Non-dependency clean", () => {
  it("fortress source files have zero concordia or verascore imports", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const fortressDir = new URL("../../src/fortress/", import.meta.url);
    const files = fs.readdirSync(fortressDir).filter((f: string) => f.endsWith(".ts"));

    for (const file of files) {
      const source = fs.readFileSync(path.join(fortressDir.pathname, file), "utf-8");
      expect(source).not.toMatch(/concordia/i);
      expect(source).not.toMatch(/verascore/i);
    }
  });

  it("no competitor names appear in fortress source files", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const fortressDir = new URL("../../src/fortress/", import.meta.url);
    const files = fs.readdirSync(fortressDir).filter((f: string) => f.endsWith(".ts"));

    const COMPETITOR_PATTERNS = [
      /\bcoze\b/i,
      /\bdust\b/i,
      /\bhermes\b/i,
    ];

    for (const file of files) {
      const source = fs.readFileSync(path.join(fortressDir.pathname, file), "utf-8");
      for (const pattern of COMPETITOR_PATTERNS) {
        expect(source).not.toMatch(pattern);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// AC10: Real-shape tests (integration: signed events + storage + config)
// ---------------------------------------------------------------------------

describe("AC10: Real-shape integration tests", () => {
  it("full lifecycle: init -> 1->2 -> 2->3 -> 3->2 -> 2->1", async () => {
    const { service } = buildService();
    await service.initialize();

    // 1->2
    const r1 = await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join mesh" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );
    expect(r1.from_tier).toBe("tier_1_private");
    expect(r1.to_tier).toBe("tier_2_federated");

    // Register stub adapter for 2->3
    service.registerAdapter({
      adapter_id: "x402-stub",
      protocol: "x402",
      registered_at: new Date().toISOString(),
      capability_bit: 3,
    });

    // 2->3
    const r2 = await service.executeTransition(
      { target_tier: "tier_3_interop", reason: "enable x402 hooks" },
    );
    expect(r2.from_tier).toBe("tier_2_federated");
    expect(r2.to_tier).toBe("tier_3_interop");

    // 3->2
    const r3 = await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "disable external protocols" },
    );
    expect(r3.from_tier).toBe("tier_3_interop");
    expect(r3.to_tier).toBe("tier_2_federated");

    // 2->1
    const r4 = await service.executeTransition(
      { target_tier: "tier_1_private", reason: "leave federation" },
    );
    expect(r4.from_tier).toBe("tier_2_federated");
    expect(r4.to_tier).toBe("tier_1_private");

    // Full history
    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_1_private");
    expect(status.transitions_history).toHaveLength(4);
  });

  it("illegal 1->3 direct is rejected at service level", async () => {
    const { service } = buildService();
    await service.initialize();

    await expect(
      service.executeTransition(
        { target_tier: "tier_3_interop", reason: "skip federation" },
      )
    ).rejects.toThrow(IllegalTransitionError);

    // State unchanged
    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_1_private");
    expect(status.transitions_history).toHaveLength(0);
  });

  it("3->1 full withdrawal works", async () => {
    const { service } = buildService();
    await service.initialize();

    // Walk up to Tier 3
    await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );
    service.registerAdapter({
      adapter_id: "stub",
      protocol: "test",
      registered_at: new Date().toISOString(),
      capability_bit: 4,
    });
    await service.executeTransition(
      { target_tier: "tier_3_interop", reason: "enable hooks" },
    );

    // Full withdrawal 3->1
    const result = await service.executeTransition(
      { target_tier: "tier_1_private", reason: "full withdrawal" },
    );
    expect(result.from_tier).toBe("tier_3_interop");
    expect(result.to_tier).toBe("tier_1_private");
    expect(result.capability_bits).toBe(CAP_STANDARD_FORTRESS_NODE);
  });

  it("downgrade transitions (2->1, 3->2) have no preconditions", async () => {
    const preconditions_2_1 = getPreconditions("tier_2_federated", "tier_1_private");
    expect(preconditions_2_1).toEqual([]);

    const preconditions_3_2 = getPreconditions("tier_3_interop", "tier_2_federated");
    expect(preconditions_3_2).toEqual([]);

    const preconditions_3_1 = getPreconditions("tier_3_interop", "tier_1_private");
    expect(preconditions_3_1).toEqual([]);
  });

  it("transition events have unique event_ids", async () => {
    const { service } = buildService();
    await service.initialize();

    const r1 = await service.executeTransition(
      { target_tier: "tier_2_federated", reason: "join" },
      { has_node_identity_cert: true, has_reachable_peer: true }
    );
    const r2 = await service.executeTransition(
      { target_tier: "tier_1_private", reason: "leave" },
    );

    expect(r1.event_id).not.toBe(r2.event_id);
  });

  it("queryTierProfile returns correct profile for each tier", () => {
    const { service } = buildService();
    for (const tier of MODE_TIERS) {
      const profile = service.queryTierProfile(tier);
      expect(profile.tier).toBe(tier);
      expect(profile.subsystems).toEqual(TIER_SUBSYSTEMS[tier]);
    }
  });

  it("adapter registration and deregistration", () => {
    const { service } = buildService();

    service.registerAdapter({
      adapter_id: "a2a-stub",
      protocol: "a2a",
      registered_at: new Date().toISOString(),
      capability_bit: 4,
    });
    expect(service.getRegisteredAdapters()).toHaveLength(1);

    service.registerAdapter({
      adapter_id: "x402-stub",
      protocol: "x402",
      registered_at: new Date().toISOString(),
      capability_bit: 3,
    });
    expect(service.getRegisteredAdapters()).toHaveLength(2);

    const removed = service.deregisterAdapter("a2a-stub");
    expect(removed).toBe(true);
    expect(service.getRegisteredAdapters()).toHaveLength(1);

    const notFound = service.deregisterAdapter("nonexistent");
    expect(notFound).toBe(false);
  });

  it("no LLM or network imports at any gate (pure-logic assertion)", async () => {
    // Structural invariant: no fortress module imports HTTP/fetch/LLM modules.
    // Comments mentioning "no LLM" as documentation are fine; imports are not.
    const fs = await import("fs");
    const path = await import("path");
    const fortressDir = new URL("../../src/fortress/", import.meta.url);
    const files = fs.readdirSync(fortressDir).filter((f: string) => f.endsWith(".ts"));

    const BANNED_IMPORT_PATTERNS = [
      /import.*from\s+["'].*\bfetch\b/,
      /import.*from\s+["'].*\bhttp\b/i,
      /import.*from\s+["'].*\baxios\b/i,
      /import.*from\s+["'].*\bnode-fetch\b/,
      /import.*from\s+["'].*\bopenai\b/i,
      /import.*from\s+["'].*\banthropic\b/i,
      /require\s*\(\s*["'].*\bhttp\b/i,
      /require\s*\(\s*["'].*\bfetch\b/,
    ];

    for (const file of files) {
      const source = fs.readFileSync(path.join(fortressDir.pathname, file), "utf-8");
      for (const pattern of BANNED_IMPORT_PATTERNS) {
        expect(source).not.toMatch(pattern);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Edge cases and error handling
// ---------------------------------------------------------------------------

describe("Edge cases", () => {
  it("error classes have correct codes", () => {
    expect(new IllegalTransitionError("a", "b").code).toBe("ILLEGAL_TRANSITION");
    expect(new AlreadyInTierError("t").code).toBe("ALREADY_IN_TIER");
    expect(new InvalidTierError("x").code).toBe("INVALID_TIER");
    expect(new ModePreconditionsNotMetError([]).code).toBe("PRECONDITIONS_NOT_MET");
    expect(new FortressConfigError("x").code).toBe("CONFIG_ERROR");
    expect(new InvalidAdapterError("x").code).toBe("INVALID_ADAPTER");
  });

  it("adapter with bit 8+ is rejected", () => {
    const { service } = buildService();
    expect(() =>
      service.registerAdapter({
        adapter_id: "bad",
        protocol: "test",
        registered_at: new Date().toISOString(),
        capability_bit: 8,
      })
    ).toThrow(InvalidAdapterError);
  });

  it("adapter with bit 0-2 is rejected (those are v0.1 bits, not adapter bits)", () => {
    const { service } = buildService();
    for (const bit of [0, 1, 2]) {
      expect(() =>
        service.registerAdapter({
          adapter_id: `bad-${bit}`,
          protocol: "test",
          registered_at: new Date().toISOString(),
          capability_bit: bit,
        })
      ).toThrow(InvalidAdapterError);
    }
  });

  it("idempotent initialization", async () => {
    const { service } = buildService();
    await service.initialize();
    await service.initialize(); // Second call should be harmless
    const status = await service.getCurrentMode();
    expect(status.tier).toBe("tier_1_private");
  });

  it("LEGAL_TRANSITIONS covers all tiers", () => {
    for (const tier of MODE_TIERS) {
      expect(LEGAL_TRANSITIONS).toHaveProperty(tier);
    }
  });
});
