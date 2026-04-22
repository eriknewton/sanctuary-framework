/**
 * Sanctuary Composition v1.0 -- Production-Caller Surface Tightening Tests
 *
 * WP-MVP-10 Follow-up #2a acceptance suite.
 *
 * A1: publishVerascoreSignal signingKey becomes optional and defaults to the
 *     HKDF-derived sidecar signing key; throws MissingSidecarSigningKeyError
 *     when omitted without fortress context.
 * A2: new canonical entry point emitForCommitment that always uses
 *     getSidecarSigningKey() and refuses to run without fortress context.
 * A3: JSDoc-only deprecation on the free-function publishVerascoreSignal
 *     export; behavioral contract unchanged (sanity check).
 *
 * All tests are platform-agnostic (no Keychain, no filesystem, no sidecar
 * spawn). Safe for the Linux CI baseline floor.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  CompositionService,
  SIDECAR_SIGNATURE_SCHEME,
  SIGNATURE_SCHEME_V1,
  CONCORDIA_RECEIPT_SCHEMA_URN,
  CompositionDisabledError,
  CompositionError,
  MissingSidecarSigningKeyError,
  publishVerascoreSignal as freeFunctionPublishVerascoreSignal,
  resolveCompositionConfig,
  type ConcordiaReceipt,
  type EmitForCommitmentResult,
  type VerascoreSignal,
} from "../../src/composition/index.js";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function randomMaster(): Uint8Array {
  return ed25519.utils.randomPrivateKey();
}

function makeReceipt(overrides: Partial<ConcordiaReceipt> = {}): ConcordiaReceipt {
  return {
    receipt_id: "rcpt-2a",
    schema_urn: CONCORDIA_RECEIPT_SCHEMA_URN,
    source_event_id: "evt-2a",
    source_event_type: "commitment_boundary",
    agent_id: "agent-a",
    counterparty_id: "agent-b",
    commitment_class: "delegation",
    references: [],
    signature: "sig-placeholder",
    signature_scheme: SIGNATURE_SCHEME_V1,
    packed_at: new Date().toISOString(),
    ...overrides,
  };
}

function base64urlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

function canonicalBytesForSignal(signal: VerascoreSignal): Uint8Array {
  const signableData = { ...signal, signature: undefined };
  const canonical = JSON.stringify(signableData, Object.keys(signableData).sort());
  return new TextEncoder().encode(canonical);
}

function enabledService(withFortressContext: boolean): CompositionService {
  const config = { composition_enabled: true };
  if (!withFortressContext) {
    return new CompositionService(config);
  }
  return new CompositionService(config, undefined, {
    fortress_master_secret: randomMaster(),
    fortress_id: "f-2a",
  });
}

// -----------------------------------------------------------------------
// A1: publishVerascoreSignal signingKey is optional
// -----------------------------------------------------------------------

describe("A1: CompositionService.publishVerascoreSignal with optional signingKey", () => {
  it("defaults to the HKDF-derived sidecar signing key when signingKey is omitted", () => {
    const svc = enabledService(true);
    const receipt = makeReceipt();
    const signal = svc.publishVerascoreSignal(receipt, "f-2a");

    expect(signal.scope).toBe("private");
    expect(signal.signature_scheme).toBe(SIDECAR_SIGNATURE_SCHEME);
    expect(signal.signature).toBeTruthy();

    const derived = svc.getSidecarSigningKey();
    expect(derived).not.toBeNull();
    const canonical = canonicalBytesForSignal(signal);
    const sigBytes = base64urlToBytes(signal.signature);
    expect(ed25519.verify(sigBytes, canonical, derived!.publicKey)).toBe(true);
  });

  it("omitting signingKey produces a signature that verifies under the HKDF-derived public key across arbitrary fortress contexts", () => {
    // Exercises determinism of the default-key path: any two services with
    // the same fortress context produce signatures that verify under the
    // shared HKDF-derived pubkey.
    const master = randomMaster();
    const fortressId = "f-cross-check";
    const svcA = new CompositionService(
      { composition_enabled: true },
      undefined,
      { fortress_master_secret: master, fortress_id: fortressId }
    );
    const svcB = new CompositionService(
      { composition_enabled: true },
      undefined,
      { fortress_master_secret: master, fortress_id: fortressId }
    );
    const receipt = makeReceipt({ receipt_id: "rcpt-cross-check" });
    const signalA = svcA.publishVerascoreSignal(receipt, fortressId);
    const keyB = svcB.getSidecarSigningKey()!;

    const canonicalA = canonicalBytesForSignal(signalA);
    const sigABytes = base64urlToBytes(signalA.signature);
    // svcA-derived signature verifies against svcB's independently-derived
    // public key, proving both sides land on the same HKDF output.
    expect(ed25519.verify(sigABytes, canonicalA, keyB.publicKey)).toBe(true);
  });

  it("throws MissingSidecarSigningKeyError when signingKey is omitted and no fortress context was installed", () => {
    const svc = enabledService(false);
    const receipt = makeReceipt();
    expect(() => svc.publishVerascoreSignal(receipt, "f-no-ctx")).toThrow(
      MissingSidecarSigningKeyError
    );
  });

  it("MissingSidecarSigningKeyError carries callSite=publishVerascoreSignal and the composition-error code", () => {
    const svc = enabledService(false);
    try {
      svc.publishVerascoreSignal(makeReceipt(), "f-no-ctx");
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MissingSidecarSigningKeyError);
      expect(err).toBeInstanceOf(CompositionError);
      const typed = err as MissingSidecarSigningKeyError;
      expect(typed.callSite).toBe("publishVerascoreSignal");
      expect(typed.code).toBe("MISSING_SIDECAR_SIGNING_KEY");
      expect(typed.message).toContain("publishVerascoreSignal");
      expect(typed.message).toContain("FortressContextInput");
    }
  });

  it("accepts an explicit signingKey unchanged (PR #47 backward compatibility)", () => {
    // The v1.0 ergonomic escape hatch: tests can still construct a service
    // without fortress context and pass an explicit signing key. This
    // contract is what PR #47's existing suite relies on.
    const svc = new CompositionService({ composition_enabled: true });
    const explicit = ed25519.utils.randomPrivateKey();
    const receipt = makeReceipt({ receipt_id: "rcpt-explicit" });
    const signal = svc.publishVerascoreSignal(receipt, "f-explicit", explicit);

    expect(signal.signature).toBeTruthy();
    const expectedPub = ed25519.getPublicKey(explicit);
    const canonical = canonicalBytesForSignal(signal);
    const sigBytes = base64urlToBytes(signal.signature);
    expect(ed25519.verify(sigBytes, canonical, expectedPub)).toBe(true);
  });
});

// -----------------------------------------------------------------------
// A2: emitForCommitment canonical entry point
// -----------------------------------------------------------------------

describe("A2: CompositionService.emitForCommitment", () => {
  it("produces a signed signal whose signature verifies against the HKDF-derived public key", () => {
    const svc = enabledService(true);
    const receipt = makeReceipt({ receipt_id: "rcpt-emit-1" });
    const result: EmitForCommitmentResult = svc.emitForCommitment({
      receipt,
      fortressId: "f-2a",
    });

    const derived = svc.getSidecarSigningKey();
    expect(derived).not.toBeNull();
    const canonical = canonicalBytesForSignal(result.signal);
    const sigBytes = base64urlToBytes(result.signal.signature);
    expect(ed25519.verify(sigBytes, canonical, derived!.publicKey)).toBe(true);
  });

  it("emitted signal carries signature_scheme=ed25519-v1 (hard gate 3 invariant)", () => {
    const svc = enabledService(true);
    const result = svc.emitForCommitment({
      receipt: makeReceipt({ receipt_id: "rcpt-emit-scheme" }),
      fortressId: "f-2a",
    });
    expect(result.signal.signature_scheme).toBe("ed25519-v1");
    expect(result.signal.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(result.signal.signature_scheme).toBe(SIDECAR_SIGNATURE_SCHEME);
  });

  it("throws MissingSidecarSigningKeyError when no fortress context was installed, with callSite=emitForCommitment", () => {
    const svc = enabledService(false);
    try {
      svc.emitForCommitment({
        receipt: makeReceipt({ receipt_id: "rcpt-emit-no-ctx" }),
        fortressId: "f-no-ctx",
      });
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(MissingSidecarSigningKeyError);
      const typed = err as MissingSidecarSigningKeyError;
      expect(typed.callSite).toBe("emitForCommitment");
      expect(typed.message).toContain("emitForCommitment");
      expect(typed.message).toContain("FortressContextInput");
    }
  });

  it("result.audit_event_ids is empty at v1.0 (reserved for Follow-up #2b)", () => {
    const svc = enabledService(true);
    const result = svc.emitForCommitment({
      receipt: makeReceipt({ receipt_id: "rcpt-emit-audit" }),
      fortressId: "f-2a",
    });
    expect(result.audit_event_ids).toEqual([]);
    expect(Array.isArray(result.audit_event_ids)).toBe(true);
  });

  it("result.signal has the VerascoreSignal shape (fortress_id, agent_id, behavioral_metrics, scope default)", () => {
    const svc = enabledService(true);
    const result = svc.emitForCommitment({
      receipt: makeReceipt({ receipt_id: "rcpt-emit-shape", agent_id: "agent-shape" }),
      fortressId: "f-shape",
    });
    expect(result.signal.signal_type).toBe("commitment_close");
    expect(result.signal.fortress_id).toBe("f-shape");
    expect(result.signal.agent_id).toBe("agent-shape");
    expect(result.signal.scope).toBe("private");
    expect(Object.keys(result.signal.behavioral_metrics).sort()).toEqual(
      ["commitment_class", "counterparty_count", "references_count"]
    );
  });

  it("principal_id in the input is accepted but does not appear in the emitted signal at v1.0", () => {
    // Multi-principal-data-model v1.x holdout: accepting the field keeps
    // the v1.0 schema stable for v1.x populating callers. The v1.0 emitter
    // ignores it and the signal shape must NOT introduce a principal_id
    // field (that would be a schema break at v1.0).
    const svc = enabledService(true);
    const result = svc.emitForCommitment({
      receipt: makeReceipt({ receipt_id: "rcpt-emit-principal" }),
      fortressId: "f-2a",
      principal_id: "principal-alpha",
    });
    expect(result.signal).not.toHaveProperty("principal_id");
    expect(JSON.stringify(result.signal)).not.toContain("principal-alpha");
  });

  it("throws CompositionDisabledError when composition is off", () => {
    const svc = new CompositionService({ composition_enabled: false }, undefined, {
      fortress_master_secret: randomMaster(),
      fortress_id: "f-2a",
    });
    expect(() =>
      svc.emitForCommitment({
        receipt: makeReceipt(),
        fortressId: "f-2a",
      })
    ).toThrow(CompositionDisabledError);
  });

  it("honors scope=public when explicitPublicOptIn=true", () => {
    const svc = enabledService(true);
    const result = svc.emitForCommitment({
      receipt: makeReceipt({ receipt_id: "rcpt-emit-public" }),
      fortressId: "f-2a",
      scope: "public",
      explicitPublicOptIn: true,
    });
    expect(result.signal.scope).toBe("public");
  });
});

// -----------------------------------------------------------------------
// A3: free-function publishVerascoreSignal remains functional
// -----------------------------------------------------------------------

describe("A3: free-function publishVerascoreSignal sanity check (JSDoc-only deprecation)", () => {
  it("still accepts an explicit signing key and produces a verifiable signature", () => {
    // The deprecation is documentary. Behavior, signature, and importability
    // are unchanged. Fresh imports of the free function must still work
    // byte-for-byte as before PR #50.
    const config = resolveCompositionConfig({ composition_enabled: true });
    const privKey = ed25519.utils.randomPrivateKey();
    const receipt = makeReceipt({ receipt_id: "rcpt-freefn" });

    const signal = freeFunctionPublishVerascoreSignal(config, {
      receipt,
      fortressId: "f-freefn",
      signingKey: privKey,
    });

    expect(signal.signal_type).toBe("commitment_close");
    expect(signal.signature).toBeTruthy();
    expect(signal.signature_scheme).toBe(SIGNATURE_SCHEME_V1);

    const canonical = canonicalBytesForSignal(signal);
    const sigBytes = base64urlToBytes(signal.signature);
    expect(ed25519.verify(sigBytes, canonical, ed25519.getPublicKey(privKey))).toBe(true);
  });
});
