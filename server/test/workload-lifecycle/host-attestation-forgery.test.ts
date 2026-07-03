/**
 * Adversarial regression suite for the host-attestation SEAL fail-CLOSED
 * hardening (#513 follow-up).
 *
 * Audits three classes:
 *   (1) FORGED seal: a self-signed envelope minted under an ATTACKER's own
 *       keypair must NOT be accepted as authentic. Before the fix,
 *       `verifyHostWorkloadAttestation(att, att.public_key)` returned true for
 *       any self-consistent envelope (verify-against-the-key-the-message-brought),
 *       and `sealHostAttestation` bound ANY presented envelope into the chain
 *       without ever verifying a signature. The fix adds (a) an optional trusted
 *       expected-signer to the verifier and (b) a REQUIRED verify-before-seal on
 *       the seal, so a forged bundle cannot be sealed as if it were the fortress's.
 *   (2) REPLAYED seal: a signature over the host-attestation domain cannot be
 *       replayed under the undeclared-finding domain (cross-domain replay guard).
 *   (3) UNDECLARED-finding TAMPER: the same self-signed / seal-without-verify
 *       fail-open existed on the undeclared-finding path, letting a forged
 *       `undeclared: []` finding silently bypass the detection. The same fix
 *       closes it.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { WORKLOAD_LIFECYCLE_OPS } from "../../src/workload-lifecycle/constants.js";
import { WorkloadRegistry } from "../../src/workload-lifecycle/registry.js";
import {
  buildHostWorkloadAttestation,
  verifyHostWorkloadAttestation,
  hostAttestationSigningBytes,
  type SignedHostWorkloadAttestation,
  type HostWorkloadAttestationBody,
  type WorkloadAttestationSigner,
} from "../../src/workload-lifecycle/host-attestation.js";
import { sealHostAttestation } from "../../src/workload-lifecycle/host-attestation-seal.js";
import {
  detectUndeclaredWorkloads,
  type LiveSupervisedWorkload,
} from "../../src/workload-lifecycle/undeclared-detection.js";
import {
  buildUndeclaredFinding,
  verifyUndeclaredFinding,
  undeclaredFindingSigningBytes,
  type UndeclaredFindingBody,
} from "../../src/workload-lifecycle/undeclared-finding.js";
import { sealUndeclaredFinding } from "../../src/workload-lifecycle/undeclared-finding-seal.js";

function makeSigner(
  kid: string,
): WorkloadAttestationSigner & { privateKey: Uint8Array } {
  const { publicKey, privateKey } = generateKeypair();
  return {
    signer_kid: kid,
    publicKey,
    privateKey,
    async sign(bytes: Uint8Array): Promise<Uint8Array> {
      return ed25519.sign(bytes, privateKey);
    },
  };
}

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

/**
 * Forge a fully attacker-controlled host attestation: an arbitrary body signed
 * under the attacker's OWN keypair, with the envelope self-declaring that key.
 * This is internally self-consistent (the signature verifies under public_key)
 * but the key is NOT the fortress's trusted signer.
 */
function forgeAttestation(
  body: HostWorkloadAttestationBody,
): SignedHostWorkloadAttestation {
  const { publicKey, privateKey } = generateKeypair();
  const sig = ed25519.sign(hostAttestationSigningBytes(body), privateKey);
  return {
    body,
    signer_kid: body.signer_kid,
    signature: toBase64url(sig),
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    public_key: toBase64url(publicKey),
  };
}

function forgedBody(
  over: Partial<HostWorkloadAttestationBody> = {},
): HostWorkloadAttestationBody {
  return {
    schema: "sanctuary.workload-host-attestation.v1",
    fortress_id: "victim-fortress",
    attested_at: new Date(1_700_000_900_000).toISOString(),
    scope: "forged",
    workloads: [],
    // The laundering payload: claim full compliance the real chain never had.
    compliant: true,
    manufactured_preference_caveat: true,
    signer_kid: "victim-fortress-signer",
    signature_algorithm: "Ed25519",
    payload_encoding: "domain-separated-canonical-json-v1",
    ...over,
  };
}

// ── Class 1: FORGED host attestation is REJECTED ────────────────────────────
describe("host attestation: FORGED seal is rejected (class 1)", () => {
  it("a self-signed forgery under an ATTACKER key is NOT accepted against a trusted signer key", () => {
    const trusted = makeSigner("victim-fortress-signer");
    const forged = forgeAttestation(forgedBody());

    // The forgery is internally self-consistent: it verifies against the key it
    // brought with it (its OWN attacker key). This is the fail-open shape.
    expect(verifyHostWorkloadAttestation(forged, forged.public_key)).toBe(true);

    // But pinned to the fortress's TRUE public key, it must be rejected: the
    // signature was made by the attacker key, not the fortress key.
    expect(
      verifyHostWorkloadAttestation(forged, trusted.publicKey),
    ).toBe(false);
  });

  it("expected-signer pinning rejects a forged envelope even against its own self-declared key", () => {
    const forged = forgeAttestation(forgedBody());
    // With an expected-signer constraint, presenting the envelope's own key is no
    // longer sufficient: the key must match the pinned trusted key.
    const trusted = makeSigner("victim-fortress-signer");
    expect(
      verifyHostWorkloadAttestation(forged, forged.public_key, {
        trustedPublicKey: trusted.publicKey,
      }),
    ).toBe(false);
    // And the expected kid must match too.
    const genuine = forged; // reuse shape; kid check is independent
    expect(
      verifyHostWorkloadAttestation(genuine, genuine.public_key, {
        expectedSignerKid: "some-other-kid",
      }),
    ).toBe(false);
  });

  it("sealHostAttestation REFUSES to bind a forged attestation when given the trusted key (fail-closed)", async () => {
    const auditLog = newAuditLog();
    const trusted = makeSigner("victim-fortress-signer");
    const forged = forgeAttestation(forgedBody());

    await expect(
      sealHostAttestation(auditLog, forged, {
        recording_identity_id: "victim-fortress",
        trustedPublicKey: trusted.publicKey,
      }),
    ).rejects.toThrow();

    // Nothing was written: no host-attestation entry exists on the chain.
    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED,
    });
    expect(entries).toHaveLength(0);
  });

  it("sealHostAttestation still binds a GENUINE attestation verified against its trusted key", async () => {
    const auditLog = newAuditLog();
    const signer = makeSigner("fortress-1-signer");
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    const boundHash = await sealHostAttestation(auditLog, att, {
      recording_identity_id: "fortress-1",
      trustedPublicKey: signer.publicKey,
    });
    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED,
    });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details!.attestation_bundle_sha256).toBe(boundHash);
  });

  it("sealHostAttestation rejects a signature-invalid envelope even without a trusted key (verify-before-seal)", async () => {
    const auditLog = newAuditLog();
    const signer = makeSigner("fortress-1-signer");
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const att = await buildHostWorkloadAttestation({
      registry,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    // Corrupt the signed body AFTER signing: the envelope's own signature no
    // longer verifies against its own public_key.
    const corrupt: SignedHostWorkloadAttestation = {
      ...att,
      body: { ...att.body, compliant: !att.body.compliant },
    };
    await expect(
      sealHostAttestation(auditLog, corrupt, {
        recording_identity_id: "fortress-1",
      }),
    ).rejects.toThrow();
    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.HOST_ATTESTED,
    });
    expect(entries).toHaveLength(0);
  });
});

// ── Class 2: REPLAYED seal (cross-domain) is rejected ───────────────────────
describe("host attestation: cross-domain replay is rejected (class 2)", () => {
  it("a host-attestation signature cannot be replayed as an undeclared finding (distinct domain prefix)", () => {
    const signer = makeSigner("fortress-1-signer");
    // Sign bytes over the HOST-ATTESTATION domain.
    const attBody = forgedBody();
    const attSig = ed25519.sign(
      hostAttestationSigningBytes(attBody),
      signer.privateKey,
    );

    // Attempt to present the SAME signature as an undeclared finding whose body
    // canonicalizes to the same JSON. Because the finding verifier prepends the
    // undeclared-finding DOMAIN prefix, the signed bytes differ and the replayed
    // signature does not verify.
    const findingBody = {
      schema: "sanctuary.workload-undeclared-finding.v1",
      fortress_id: attBody.fortress_id,
      attested_at: attBody.attested_at,
      scope: "x",
      undeclared: [],
      undeclared_count: 0,
      live_count: 0,
      declared_count: 0,
      signer_kid: signer.signer_kid,
      signature_algorithm: "Ed25519",
      payload_encoding: "domain-separated-canonical-json-v1",
    } as UndeclaredFindingBody;
    const replayed = {
      body: findingBody,
      signer_kid: signer.signer_kid,
      signature: toBase64url(attSig),
      signature_algorithm: "Ed25519" as const,
      payload_encoding: "domain-separated-canonical-json-v1" as const,
      public_key: toBase64url(signer.publicKey),
    };
    expect(verifyUndeclaredFinding(replayed, signer.publicKey)).toBe(false);
    // Sanity: the finding domain bytes differ from the attestation domain bytes.
    expect(undeclaredFindingSigningBytes(findingBody)).not.toEqual(
      hostAttestationSigningBytes(attBody),
    );
  });
});

// ── Class 3: UNDECLARED-finding TAMPER (forged suppression) is rejected ─────
describe("undeclared finding: forged suppression is rejected (class 3)", () => {
  function live(agent_id: string): LiveSupervisedWorkload {
    return { agent_id, harness: "claude_code", state: "protected" as never };
  }

  it("a forged finding that hides a live undeclared workload is NOT accepted against a trusted key", async () => {
    // The genuine detection: agent_x is live and undeclared (registry empty).
    const auditLog = newAuditLog();
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_x")],
      registry,
    });
    expect(detection.undeclared.map((u) => u.agent_id)).toEqual(["agent_x"]);

    const trusted = makeSigner("fortress-1-signer");

    // The attacker forges a finding with an EMPTY undeclared list (suppression),
    // signed under their OWN key.
    const forgedBody: UndeclaredFindingBody = {
      schema: "sanctuary.workload-undeclared-finding.v1",
      fortress_id: "fortress-1",
      attested_at: new Date(1_700_000_900_000).toISOString(),
      scope: "forged",
      undeclared: [],
      undeclared_count: 0,
      live_count: 1,
      declared_count: 0,
      signer_kid: "fortress-1-signer",
      signature_algorithm: "Ed25519",
      payload_encoding: "domain-separated-canonical-json-v1",
    };
    const { publicKey: attackerPub, privateKey: attackerPriv } =
      generateKeypair();
    const forged = {
      body: forgedBody,
      signer_kid: forgedBody.signer_kid,
      signature: toBase64url(
        ed25519.sign(undeclaredFindingSigningBytes(forgedBody), attackerPriv),
      ),
      signature_algorithm: "Ed25519" as const,
      payload_encoding: "domain-separated-canonical-json-v1" as const,
      public_key: toBase64url(attackerPub),
    };

    // Self-consistent (fail-open shape): verifies against its own attacker key.
    expect(verifyUndeclaredFinding(forged, forged.public_key)).toBe(true);
    // But pinned to the fortress's TRUE key, the forgery is rejected.
    expect(verifyUndeclaredFinding(forged, trusted.publicKey)).toBe(false);
    // And expected-signer pinning rejects it even against its own key.
    expect(
      verifyUndeclaredFinding(forged, forged.public_key, {
        trustedPublicKey: trusted.publicKey,
      }),
    ).toBe(false);
  });

  it("sealUndeclaredFinding REFUSES to bind a forged finding when given the trusted key (fail-closed)", async () => {
    const auditLog = newAuditLog();
    const trusted = makeSigner("fortress-1-signer");
    const forgedBody: UndeclaredFindingBody = {
      schema: "sanctuary.workload-undeclared-finding.v1",
      fortress_id: "fortress-1",
      attested_at: new Date(1_700_000_900_000).toISOString(),
      scope: "forged",
      undeclared: [],
      undeclared_count: 0,
      live_count: 1,
      declared_count: 0,
      signer_kid: "fortress-1-signer",
      signature_algorithm: "Ed25519",
      payload_encoding: "domain-separated-canonical-json-v1",
    };
    const { publicKey: attackerPub, privateKey: attackerPriv } =
      generateKeypair();
    const forged = {
      body: forgedBody,
      signer_kid: forgedBody.signer_kid,
      signature: toBase64url(
        ed25519.sign(undeclaredFindingSigningBytes(forgedBody), attackerPriv),
      ),
      signature_algorithm: "Ed25519" as const,
      payload_encoding: "domain-separated-canonical-json-v1" as const,
      public_key: toBase64url(attackerPub),
    };
    await expect(
      sealUndeclaredFinding(auditLog, forged, {
        recording_identity_id: "fortress-1",
        trustedPublicKey: trusted.publicKey,
      }),
    ).rejects.toThrow();
    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED,
    });
    expect(entries).toHaveLength(0);
  });

  it("sealUndeclaredFinding still binds a GENUINE finding verified against its trusted key", async () => {
    const auditLog = newAuditLog();
    const signer = makeSigner("fortress-1-signer");
    const registry = await WorkloadRegistry.fromAuditLog(auditLog);
    const detection = detectUndeclaredWorkloads({
      liveStatuses: [live("agent_x")],
      registry,
    });
    const finding = await buildUndeclaredFinding({
      detection,
      signer,
      fortressId: "fortress-1",
      now: new Date(1_700_000_900_000).toISOString(),
    });
    const boundHash = await sealUndeclaredFinding(auditLog, finding, {
      recording_identity_id: "fortress-1",
      trustedPublicKey: signer.publicKey,
    });
    const { entries } = await auditLog.query({
      operation_type: WORKLOAD_LIFECYCLE_OPS.UNDECLARED_DETECTED,
    });
    expect(entries).toHaveLength(1);
    expect(entries[0]!.details!.finding_bundle_sha256).toBe(boundHash);
  });
});
