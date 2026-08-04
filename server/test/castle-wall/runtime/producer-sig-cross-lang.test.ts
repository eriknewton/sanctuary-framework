/**
 * Producer-signature CROSS-LANGUAGE byte-compat test (Slice L1 + Slice P
 * activation).
 *
 * The signature in the shared fixture was produced by the RUST daemon
 * (`ed25519-dalek` `ProducerSigner::sign_event`) and the verifying key was
 * published by the Rust daemon. Here the TS consumer/reader verifier
 * (`@noble/curves` via `verifyProducerSignature`) re-derives the signing bytes
 * and verifies that exact Rust signature against that exact Rust-published key.
 * A GREEN result proves the two languages hash and verify byte-identical input —
 * which is what makes the Slice P activation real: a real daemon-signed event
 * re-verifies in-process.
 *
 * The companion Rust test
 * (`castle-wall-daemon/tests/integration_producer_sig_cross_lang.rs`) verifies
 * the SAME fixture from the Rust side, so a layout drift in either language
 * fails in both suites.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuditConsumer,
  type AuditSink,
  type CriticalEventEnvelope,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import { buildAuditEvent } from "../../../src/castle-wall/audit/builder.js";
import type { CastleWallAuditEvent } from "../../../src/castle-wall/audit/events.js";
import type { AuditDrainEvent } from "../../../src/castle-wall/ipc/messages.js";
import { buildCriticalEnvelopeFromDrainEvent } from "../../../src/castle-wall/runtime/linux-audit-drain.js";
import {
  producerSigningBytes,
  toBase64url,
  verifyProducerSignature,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";

interface CrossLangVector {
  pubkey_b64url: string;
  canonical: string;
  captured_at_unix_ms: number;
  seq: number;
  key_id: string;
  sig_b64url: string;
}

function loadVector(): CrossLangVector {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(
    here,
    "..",
    "fixtures",
    "producer-sig-cross-lang-vector.json",
  );
  return JSON.parse(readFileSync(fixturePath, "utf8")) as CrossLangVector;
}

class RecordingSink implements AuditSink {
  entries: Array<{
    operation: string;
    details?: Record<string, unknown>;
    result: "success" | "failure";
  }> = [];
  append(
    _layer: "l1",
    operation: string,
    _identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success",
  ): void {
    this.entries.push({ operation, details, result });
  }
  async flush(): Promise<void> {}
}

function signedBodyHash(eventCanonicalJson: string): string {
  return createHash("sha256").update(eventCanonicalJson, "utf8").digest("hex");
}

function currentChainHash(consumer: AuditConsumer): string | null {
  const state = consumer.getWalChainState() as {
    lastEventChainHash?: string | null;
    lastEventCanonicalHash?: string | null;
  };
  return state.lastEventChainHash ?? state.lastEventCanonicalHash ?? null;
}

function signProducerBody(input: {
  canonical: string;
  capturedAtUnixMs: number;
  seq: number;
  privateKey: Uint8Array;
}): string {
  return toBase64url(
    ed25519.sign(
      producerSigningBytes(
        input.canonical,
        input.capturedAtUnixMs,
        input.seq,
      ),
      input.privateKey,
    ),
  );
}

function rustWalBody(input: {
  seq: number;
  priorSha256Hex: string | null;
  timestamp: string;
}): string {
  return canonicalize({
    timestamp: input.timestamp,
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "signed-agent",
    result: "blocked",
    details: {
      agent_id: "signed-agent",
      dest_host: "api.example.test",
      dest_ip: "203.0.113.10",
      dest_port: 443,
      dest_protocol: "tcp",
      seq: input.seq,
      prior_sha256_hex: input.priorSha256Hex,
    },
  });
}

function rustDrainEnvelope(input: {
  canonical: string;
  seq: number;
  priorSha256Hex: string | null;
  capturedAtUnixMs: number;
  privateKey: Uint8Array;
}): CriticalEventEnvelope {
  const drained: AuditDrainEvent = {
    seq: input.seq,
    captured_at_unix_ms: input.capturedAtUnixMs,
    prior_sha256_hex: input.priorSha256Hex,
    event_canonical_json: input.canonical,
    critical: true,
    producer_signature_b64url: signProducerBody(input),
    producer_key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  };
  const built = buildCriticalEnvelopeFromDrainEvent(drained, async () => {});
  if (built.kind === "error") {
    throw new Error(built.reason);
  }
  return built.envelope;
}

function macOSAvailabilityBody(input: {
  seq: number;
  priorSha256Hex: string | null;
  timestamp: string;
}): string {
  return canonicalize({
    timestamp: input.timestamp,
    layer: "l1",
    operation: "enforcement_availability_report",
    identity_id: "fortress-test",
    result: "success",
    details: {
      seq: input.seq,
      prior_sha256_hex: input.priorSha256Hex,
      enforcement: {
        protocol_version: 1,
        source: "macos_extension",
        lease_state: "live",
        lease_reason: "ok",
        manifest_state: "applied",
        manifest_signature_b64url: "manifest-sig",
        provider_bound: true,
        producer_claimed_at: input.timestamp,
      },
    },
  });
}

function macOSAvailabilityEnvelope(input: {
  canonical: string;
  seq: number;
  priorSha256Hex: string | null;
  capturedAtUnixMs: number;
  privateKey: Uint8Array;
}): CriticalEventEnvelope {
  const event: CastleWallAuditEvent = buildAuditEvent({
    timestamp: new Date(input.capturedAtUnixMs).toISOString(),
    fortress_id: "fortress-test",
    event_type: "filter_started",
    details: {
      seq: input.seq,
      prior_sha256_hex: input.priorSha256Hex,
    },
  });
  return {
    event,
    ack: async () => {},
    producer: {
      eventCanonicalJson: input.canonical,
      capturedAtUnixMs: input.capturedAtUnixMs,
      seq: input.seq,
      signatureB64url: signProducerBody(input),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
    producerSubjectBinding: { kind: "signed_identity_id" },
  };
}

describe("castle-wall producer-signature : Rust→TS cross-language vector", () => {
  it("the TS verifier accepts a genuine Rust-daemon-signed event", () => {
    const v = loadVector();
    // The fixture's key id must match the v1 constant the verifier expects.
    expect(v.key_id).toBe(CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1);
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: v.canonical,
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      v.pubkey_b64url,
    );
    expect(verdict).toEqual({ ok: true });
  });

  it("a one-byte change to the Rust-signed body fails (no re-encode drift)", () => {
    const v = loadVector();
    const verdict = verifyProducerSignature(
      {
        // Tamper the canonical body: the Rust signature must no longer verify,
        // proving the signature binds the EXACT bytes (not a re-canonicalized
        // object the two languages might normalize differently).
        eventCanonicalJson: v.canonical.replace("egress_blocked", "egress_allowed"),
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      v.pubkey_b64url,
    );
    expect(verdict.ok).toBe(false);
  });

  it("the Rust signature does not verify against a different key (forgery floor)", () => {
    const v = loadVector();
    // Flip a char near the START of the pubkey so the decoded 32 bytes genuinely
    // differ (a last-char flip can be padding-only and decode to the same bytes).
    const c = v.pubkey_b64url[1] === "A" ? "B" : "A";
    const tweaked = v.pubkey_b64url[0] + c + v.pubkey_b64url.slice(2);
    const verdict = verifyProducerSignature(
      {
        eventCanonicalJson: v.canonical,
        capturedAtUnixMs: v.captured_at_unix_ms,
        seq: v.seq,
        signatureB64url: v.sig_b64url,
        keyId: v.key_id,
      },
      tweaked,
    );
    expect(verdict.ok).toBe(false);
  });
});

describe("castle-wall audit chain basis : producer-body vectors", () => {
  it("Rust WAL-body writer: consumer head after event 1 equals producer prior for event 2", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const now = 1_780_000_000_000;
    const consumer = new AuditConsumer(new RecordingSink(), undefined, {
      pinnedProducerKeyB64url: publicKeyB64url,
      now: () => now,
    });

    const body1 = rustWalBody({
      seq: 0,
      priorSha256Hex: null,
      timestamp: "2026-08-04T12:00:00.000Z",
    });
    const event2Prior = signedBodyHash(body1);
    const body2 = rustWalBody({
      seq: 1,
      priorSha256Hex: event2Prior,
      timestamp: "2026-08-04T12:00:01.000Z",
    });

    await consumer.ingestCritical(
      rustDrainEnvelope({
        canonical: body1,
        seq: 0,
        priorSha256Hex: null,
        capturedAtUnixMs: now - 1000,
        privateKey,
      }),
    );

    expect(currentChainHash(consumer)).toBe(event2Prior);
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({
          canonical: body2,
          seq: 1,
          priorSha256Hex: event2Prior,
          capturedAtUnixMs: now - 500,
          privateKey,
        }),
      ),
    ).resolves.toBeUndefined();
  });

  it("macOS availability-report writer: consumer head after event 1 equals producer prior for event 2", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const now = 1_780_000_000_000;
    const consumer = new AuditConsumer(new RecordingSink(), undefined, {
      pinnedProducerKeyB64url: publicKeyB64url,
      now: () => now,
    });

    const body1 = macOSAvailabilityBody({
      seq: 0,
      priorSha256Hex: null,
      timestamp: "2026-08-04T12:00:00.000Z",
    });
    const event2Prior = signedBodyHash(body1);
    const body2 = macOSAvailabilityBody({
      seq: 1,
      priorSha256Hex: event2Prior,
      timestamp: "2026-08-04T12:00:01.000Z",
    });

    await consumer.ingestCritical(
      macOSAvailabilityEnvelope({
        canonical: body1,
        seq: 0,
        priorSha256Hex: null,
        capturedAtUnixMs: now - 1000,
        privateKey,
      }),
    );

    expect(currentChainHash(consumer)).toBe(event2Prior);
    await expect(
      consumer.ingestCritical(
        macOSAvailabilityEnvelope({
          canonical: body2,
          seq: 1,
          priorSha256Hex: event2Prior,
          capturedAtUnixMs: now - 500,
          privateKey,
        }),
      ),
    ).resolves.toBeUndefined();
  });

  // DEBT(PR-B): add the macOS flow-decision producer vector after the Swift
  // producer switches that path from raw-event hashing to signed-body hashing.
});
