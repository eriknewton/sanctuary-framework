/**
 * Sanctuary Federation Protocol v0.1 — Error Hierarchy
 *
 * Every failure mode that a v0.1 emitter/verifier/validator can produce is a named
 * subclass of MeshError. Error names are stable and may be matched by tests and
 * operator-facing surfaces.
 *
 * Security invariant (CLAUDE.md §5): never silently degrade to a less-secure behavior
 * on error. If signature verification fails, the message MUST be rejected — and that
 * rejection MUST surface as a named error, not a null-return.
 */

export class MeshError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MeshError";
  }
}

// ── Envelope / signature errors ─────────────────────────────────────────

export class MeshEnvelopeError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshEnvelopeError";
  }
}

export class MeshReservedExtensionKeyError extends MeshEnvelopeError {
  constructor(key: string) {
    super(
      `v0.1 emitters MUST NOT populate reserved extension_envelope key: ${key}`
    );
    this.name = "MeshReservedExtensionKeyError";
  }
}

export class MeshReservedEventTypeError extends MeshEnvelopeError {
  constructor(eventType: string) {
    super(
      `v0.1 emitters MUST NOT emit reserved-namespace event_type: ${eventType}`
    );
    this.name = "MeshReservedEventTypeError";
  }
}

export class MeshSignatureError extends MeshEnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = "MeshSignatureError";
  }
}

// ── Certificate / chain errors ──────────────────────────────────────────

export class MeshCertificateError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshCertificateError";
  }
}

export class MeshReservedCapabilityBitError extends MeshCertificateError {
  constructor(caps: number) {
    super(
      `v0.1 certificate issuance MUST NOT set reserved capability bits (given capabilities=0x${caps.toString(16)})`
    );
    this.name = "MeshReservedCapabilityBitError";
  }
}

export class MeshChainError extends MeshCertificateError {
  constructor(message: string) {
    super(message);
    this.name = "MeshChainError";
  }
}

// ── Audit-batch / rollback errors ───────────────────────────────────────

export class MeshAuditBatchError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshAuditBatchError";
  }
}

export class MeshRollbackDetectedError extends MeshAuditBatchError {
  constructor(emitterNode: string, details: string) {
    super(
      `rollback detected on emitter_node=${emitterNode}: ${details}. This is a hard alarm; see spec §8.3.`
    );
    this.name = "MeshRollbackDetectedError";
  }
}

export class MeshChainDiscontinuityError extends MeshAuditBatchError {
  constructor(emitterNode: string, batchSeq: number, details: string) {
    super(
      `audit-batch chain discontinuity on emitter_node=${emitterNode} batch_seq=${batchSeq}: ${details}`
    );
    this.name = "MeshChainDiscontinuityError";
  }
}

// ── Config / state errors ───────────────────────────────────────────────

export class MeshConfigError extends MeshError {
  constructor(message: string) {
    super(message);
    this.name = "MeshConfigError";
  }
}
