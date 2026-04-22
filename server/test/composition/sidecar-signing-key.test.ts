/**
 * Sanctuary Composition v1.0 -- Sidecar Signing Key HKDF + Rotation Suite
 *
 * WP-MVP-10 Follow-up #1 hardening item 3.
 *
 * Acceptance:
 *  (a) Sidecar key is byte-equal to
 *      hkdfDeriveEd25519(master, 'sanctuary-composition-v1.0-sidecar-signing-key').
 *  (b) Sidecar key changes deterministically on master rotation.
 *  (c) Old composition events verify under the preserved historical pubkey.
 *  (d) New composition events verify under the new master-derived key.
 *
 * Additional invariant tests covering the Federation Protocol v0.1 §2.2
 * derivation shape (32-byte output, deterministic, info-string matches
 * the spec §10.3 composition_* namespace reservation, recovery cascade
 * re-anchors on rotation).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import {
  HKDF_COMPOSITION_SIDECAR_SIGNING_INFO,
  CompositionService,
  SIDECAR_SIGNATURE_SCHEME,
  SIGNATURE_SCHEME_V1,
  deriveSidecarSigningKey,
  rederiveSidecarSigningKeyOnRotation,
} from "../../src/composition/index.js";

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

function randomMasterSecret(): Uint8Array {
  return ed25519.utils.randomPrivateKey();
}

function stringToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

// -----------------------------------------------------------------------
// Constant invariants
// -----------------------------------------------------------------------

describe("HKDF_COMPOSITION_SIDECAR_SIGNING_INFO constant", () => {
  it("is the Decision A default info string", () => {
    expect(HKDF_COMPOSITION_SIDECAR_SIGNING_INFO).toBe(
      "sanctuary-composition-v1.0-sidecar-signing-key"
    );
  });

  it("starts with the composition_* v1.0 namespace prefix", () => {
    // Spec §10.3 allocates the composition_* event-type namespace; the
    // HKDF info-string uses the dashed form of the same prefix for
    // human-readable key material scoping.
    expect(HKDF_COMPOSITION_SIDECAR_SIGNING_INFO.startsWith("sanctuary-composition-v1.0-")).toBe(true);
  });

  it("admits v1.x principal-scope templating without breaking v1.0", () => {
    // Multi-principal invariant holdout: the info string's prefix admits
    // a v1.x patron-scope extension like
    //   "sanctuary-composition-v1.0-{principal_id}-sidecar-signing-key"
    // without changing the prefix v1.0 uses.
    const v1xTemplate = `sanctuary-composition-v1.0-principal_alpha-sidecar-signing-key`;
    expect(v1xTemplate.startsWith("sanctuary-composition-v1.0-")).toBe(true);
    expect(v1xTemplate).not.toBe(HKDF_COMPOSITION_SIDECAR_SIGNING_INFO);
  });
});

// -----------------------------------------------------------------------
// Raw derivation: byte-equal to the canonical HKDF recipe
// -----------------------------------------------------------------------

describe("deriveSidecarSigningKey byte-equivalence", () => {
  it("produces a 32-byte private key and a 32-byte public key", () => {
    const master = randomMasterSecret();
    const { privateKey, publicKey } = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: "f-0001",
    });
    expect(privateKey.byteLength).toBe(32);
    expect(publicKey.byteLength).toBe(32);
  });

  it("private key is byte-equal to HKDF(sha256, master, salt=fortress_id, info=HKDF_COMPOSITION_SIDECAR_SIGNING_INFO, 32)", () => {
    const master = randomMasterSecret();
    const fortressId = "f-canonical-hkdf";
    const expected = hkdf(
      sha256,
      master,
      stringToBytes(fortressId),
      stringToBytes(HKDF_COMPOSITION_SIDECAR_SIGNING_INFO),
      32
    );
    const { privateKey } = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: fortressId,
    });
    expect(bytesEqual(privateKey, expected)).toBe(true);
  });

  it("public key matches ed25519.getPublicKey(privateKey)", () => {
    const master = randomMasterSecret();
    const pair = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: "f-pubkey-check",
    });
    expect(bytesEqual(pair.publicKey, ed25519.getPublicKey(pair.privateKey))).toBe(true);
  });

  it("is deterministic — same (master, fortress_id) yields the same keypair", () => {
    const master = randomMasterSecret();
    const fortressId = "f-determinism";
    const a = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: fortressId,
    });
    const b = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: fortressId,
    });
    expect(bytesEqual(a.privateKey, b.privateKey)).toBe(true);
    expect(bytesEqual(a.publicKey, b.publicKey)).toBe(true);
  });

  it("changes when the master changes (other inputs fixed)", () => {
    const fortressId = "f-master-change";
    const a = deriveSidecarSigningKey({
      fortress_master_secret: randomMasterSecret(),
      fortress_id: fortressId,
    });
    const b = deriveSidecarSigningKey({
      fortress_master_secret: randomMasterSecret(),
      fortress_id: fortressId,
    });
    expect(bytesEqual(a.privateKey, b.privateKey)).toBe(false);
    expect(bytesEqual(a.publicKey, b.publicKey)).toBe(false);
  });

  it("changes when the fortress_id changes (master fixed)", () => {
    const master = randomMasterSecret();
    const a = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: "f-alpha",
    });
    const b = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: "f-beta",
    });
    expect(bytesEqual(a.privateKey, b.privateKey)).toBe(false);
    expect(bytesEqual(a.publicKey, b.publicKey)).toBe(false);
  });

  it("rejects empty master secret", () => {
    expect(() =>
      deriveSidecarSigningKey({
        fortress_master_secret: new Uint8Array(0),
        fortress_id: "f-1",
      })
    ).toThrow(RangeError);
  });

  it("rejects empty fortress_id", () => {
    expect(() =>
      deriveSidecarSigningKey({
        fortress_master_secret: randomMasterSecret(),
        fortress_id: "",
      })
    ).toThrow(RangeError);
  });

  it("rederiveSidecarSigningKeyOnRotation is equivalent to deriveSidecarSigningKey", () => {
    const newMaster = randomMasterSecret();
    const fortressId = "f-rotation-alias";
    const viaRotation = rederiveSidecarSigningKeyOnRotation({
      new_fortress_master_secret: newMaster,
      fortress_id: fortressId,
    });
    const viaDerive = deriveSidecarSigningKey({
      fortress_master_secret: newMaster,
      fortress_id: fortressId,
    });
    expect(bytesEqual(viaRotation.privateKey, viaDerive.privateKey)).toBe(true);
    expect(bytesEqual(viaRotation.publicKey, viaDerive.publicKey)).toBe(true);
  });
});

// -----------------------------------------------------------------------
// CompositionService: master rotation + audit-continuity
// -----------------------------------------------------------------------

describe("CompositionService sidecar-key rotation cascade", () => {
  it("returns null for getSidecarSigningKey when no fortress context installed", () => {
    const svc = new CompositionService();
    expect(svc.getSidecarSigningKey()).toBeNull();
  });

  it("caches and returns the derived keypair once fortress context is installed", () => {
    const master = randomMasterSecret();
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: master,
      fortress_id: "f-cache-check",
    });
    const first = svc.getSidecarSigningKey();
    const second = svc.getSidecarSigningKey();
    expect(first).not.toBeNull();
    // Cache returns the exact same object reference.
    expect(first).toBe(second);
    const canonical = deriveSidecarSigningKey({
      fortress_master_secret: master,
      fortress_id: "f-cache-check",
    });
    expect(bytesEqual(first!.privateKey, canonical.privateKey)).toBe(true);
    expect(bytesEqual(first!.publicKey, canonical.publicKey)).toBe(true);
  });

  it("setFortressContext installs a fresh master and invalidates the cache", () => {
    const masterA = randomMasterSecret();
    const masterB = randomMasterSecret();
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: masterA,
      fortress_id: "f-setctx",
    });
    const a = svc.getSidecarSigningKey()!;
    svc.setFortressContext({
      fortress_master_secret: masterB,
      fortress_id: "f-setctx",
    });
    const b = svc.getSidecarSigningKey()!;
    expect(bytesEqual(a.privateKey, b.privateKey)).toBe(false);
  });

  it("rotateFortressMaster derives a new keypair + preserves old pubkey historically", () => {
    const masterA = randomMasterSecret();
    const masterB = randomMasterSecret();
    const fortressId = "f-rotation";
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: masterA,
      fortress_id: fortressId,
    });
    const keyA = svc.getSidecarSigningKey()!;
    expect(svc.getHistoricalSidecarPubkeys()).toEqual([]);

    svc.rotateFortressMaster(masterB, "old-master-fp-a");
    const keyB = svc.getSidecarSigningKey()!;

    // New key is different.
    expect(bytesEqual(keyA.privateKey, keyB.privateKey)).toBe(false);
    expect(bytesEqual(keyA.publicKey, keyB.publicKey)).toBe(false);

    // Old public key is preserved in the historical list.
    const historical = svc.getHistoricalSidecarPubkeys();
    expect(historical).toHaveLength(1);
    expect(bytesEqual(historical[0].publicKey, keyA.publicKey)).toBe(true);
    expect(historical[0].anchoringMasterFingerprint).toBe("old-master-fp-a");
    expect(typeof historical[0].retiredAt).toBe("string");
    expect(Date.parse(historical[0].retiredAt)).not.toBeNaN();
  });

  it("audit-continuity: old events verify under historical pubkey, new events under new key", () => {
    const masterA = randomMasterSecret();
    const masterB = randomMasterSecret();
    const fortressId = "f-continuity";
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: masterA,
      fortress_id: fortressId,
    });

    // Sign event A under master A's derived key.
    const keyA = svc.getSidecarSigningKey()!;
    const eventA = stringToBytes(
      JSON.stringify({
        composition_event_type: "composition_verascore_published",
        signal_id: "sig-A",
        signature_scheme: SIDECAR_SIGNATURE_SCHEME,
      })
    );
    const sigA = ed25519.sign(eventA, keyA.privateKey);

    // Rotate.
    svc.rotateFortressMaster(masterB, "master-A-fp");
    const keyB = svc.getSidecarSigningKey()!;

    // Sign event B under master B's derived key.
    const eventB = stringToBytes(
      JSON.stringify({
        composition_event_type: "composition_verascore_published",
        signal_id: "sig-B",
        signature_scheme: SIDECAR_SIGNATURE_SCHEME,
      })
    );
    const sigB = ed25519.sign(eventB, keyB.privateKey);

    // Event A verifies under historical pubkey (= keyA.publicKey).
    const historical = svc.getHistoricalSidecarPubkeys();
    expect(historical).toHaveLength(1);
    expect(ed25519.verify(sigA, eventA, historical[0].publicKey)).toBe(true);

    // Event B verifies under the current (keyB) pubkey.
    expect(ed25519.verify(sigB, eventB, keyB.publicKey)).toBe(true);

    // Cross-verification must fail (proves the keys are genuinely different).
    expect(ed25519.verify(sigA, eventA, keyB.publicKey)).toBe(false);
    expect(ed25519.verify(sigB, eventB, historical[0].publicKey)).toBe(false);
  });

  it("signature_scheme remains ed25519-v1 across rotations (crypto-agility hinge)", () => {
    // The HKDF derivation change does not alter signature_scheme. Every
    // composition event signed under a derived key still carries the
    // v1.0 scheme. v1.1 will introduce hybrid signing under a new
    // scheme identifier; that migration is orthogonal to this PR.
    expect(SIDECAR_SIGNATURE_SCHEME).toBe(SIGNATURE_SCHEME_V1);
    expect(SIDECAR_SIGNATURE_SCHEME).toBe("ed25519-v1");
  });

  it("clearAll clears the historical list and the cached keypair", () => {
    const master = randomMasterSecret();
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: master,
      fortress_id: "f-clear",
    });
    svc.getSidecarSigningKey();
    svc.rotateFortressMaster(randomMasterSecret(), "fp-1");
    expect(svc.getHistoricalSidecarPubkeys()).toHaveLength(1);
    svc.clearAll();
    expect(svc.getHistoricalSidecarPubkeys()).toEqual([]);
  });

  it("rederivation after rotation is deterministic vs. the canonical HKDF recipe", () => {
    // Acceptance criterion 5: master rotation correctly re-derives the
    // sidecar key. Assert byte-equivalence to the canonical derivation
    // using the new master secret.
    const masterB = randomMasterSecret();
    const fortressId = "f-postrot-canonical";
    const svc = new CompositionService(undefined, undefined, {
      fortress_master_secret: randomMasterSecret(),
      fortress_id: fortressId,
    });
    svc.rotateFortressMaster(masterB, "old-fp");
    const derived = svc.getSidecarSigningKey()!;
    const canonical = deriveSidecarSigningKey({
      fortress_master_secret: masterB,
      fortress_id: fortressId,
    });
    expect(bytesEqual(derived.privateKey, canonical.privateKey)).toBe(true);
    expect(bytesEqual(derived.publicKey, canonical.publicKey)).toBe(true);
  });
});
