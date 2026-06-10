/**
 * Federation PR-A3 — V1SessionService unit tests.
 *
 * Every security property of the RFC v7 session ceremony is asserted at the
 * unit level with an injected clock: challenge expiry, single-use
 * consumption, token expiry/tamper, session-generation rotation, and the
 * pending-challenge cap. The attestation suite covers the PR-A3 REPLACEMENT
 * of PR-A1's bearer-token validator with a durable Ed25519 operator
 * attestation — including the explicit replace-not-extend invariant: a caller
 * presenting what the temporary token validator would have accepted is now
 * rejected, because the token path is gone, not stacked.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

import {
  V1SessionService,
  V1_CAPABILITY_STATUS_READ,
  type V1SessionAuthBridge,
} from "../../src/v1/session-service.js";
import {
  buildChallengeMessage,
  OPERATOR_ED25519_ATTESTATION_REF,
  LOOPBACK_OPERATOR_ATTESTATION_REF,
  AUTH_DISABLED_ATTESTATION_REF,
} from "../../src/v1/ceremony.js";
import { signOperatorAttestation } from "../../src/v1/operator-attestation.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";

// One operator identity for the whole suite — the daemon resolves this key.
const OPERATOR_PRIV = randomBytes(32);
const OPERATOR_PUB = ed25519.getPublicKey(OPERATOR_PRIV);

function makeAuth(overrides?: Partial<V1SessionAuthBridge>): V1SessionAuthBridge {
  return {
    resolveOperatorPublicKey: () => OPERATOR_PUB,
    isLoopbackAutoAuthEnabled: () => false,
    ...overrides,
  };
}

function makeClient() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** A durable operator attestation bound to `clientPubkey` at `issuedAtMs`. */
function durableAttestation(clientPubkey: Uint8Array, issuedAtMs: number) {
  return signOperatorAttestation({
    operatorPublicKey: OPERATOR_PUB,
    operatorPrivateKey: OPERATOR_PRIV,
    clientPubkey,
    issuedAtMs,
  });
}

function initBody(publicKey: Uint8Array, attestation?: unknown) {
  return {
    client_pubkey: toBase64url(publicKey),
    ...(attestation !== undefined ? { operator_attestation: attestation } : {}),
  };
}

function signChallenge(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  challengeB64: string,
  ref: string,
): string {
  const message = buildChallengeMessage(publicKey, fromBase64url(challengeB64), ref);
  return toBase64url(ed25519.sign(message, privateKey));
}

/** Full ceremony over the durable operator-attestation path → session token. */
function openSession(service: V1SessionService, nowMs = Date.now()): string {
  const { privateKey, publicKey } = makeClient();
  const init = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
  expect(init.ok).toBe(true);
  if (!init.ok) throw new Error("unreachable");
  expect(init.attestation_ref).toBe(OPERATOR_ED25519_ATTESTATION_REF);
  const complete = service.complete({
    challenge_id: init.challenge_id,
    client_signature: signChallenge(privateKey, publicKey, init.challenge, init.attestation_ref),
  });
  expect(complete.ok).toBe(true);
  if (!complete.ok) throw new Error("unreachable");
  return complete.session_token;
}

describe("V1SessionService ceremony", () => {
  it("happy path issues a token whose claims validate with status_read", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const token = openSession(service);
    const claims = service.validateToken(token);
    expect(claims).not.toBeNull();
    expect(claims!.capabilities).toContain(V1_CAPABILITY_STATUS_READ);
    expect(claims!.attestation_ref).toBe(OPERATOR_ED25519_ATTESTATION_REF);
  });

  it("rejects a replayed challenge_id (single-use, success path)", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
    if (!init.ok) throw new Error("init failed");
    const signature = signChallenge(privateKey, publicKey, init.challenge, init.attestation_ref);
    const first = service.complete({ challenge_id: init.challenge_id, client_signature: signature });
    expect(first.ok).toBe(true);
    const replay = service.complete({ challenge_id: init.challenge_id, client_signature: signature });
    expect(replay.ok).toBe(false);
  });

  it("consumes the challenge on a FAILED attempt too (no signature brute-force)", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
    if (!init.ok) throw new Error("init failed");
    const bad = service.complete({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(randomBytes(64)),
    });
    expect(bad.ok).toBe(false);
    const good = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signChallenge(privateKey, publicKey, init.challenge, init.attestation_ref),
    });
    expect(good.ok).toBe(false);
  });

  it("rejects an expired challenge", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
    if (!init.ok) throw new Error("init failed");
    nowMs += 61_000; // past the 60s challenge TTL
    const result = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signChallenge(privateKey, publicKey, init.challenge, init.attestation_ref),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a signature from a different keypair over the right message", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const honest = makeClient();
    const attacker = makeClient();
    const init = service.init(initBody(honest.publicKey, durableAttestation(honest.publicKey, nowMs)), false);
    if (!init.ok) throw new Error("init failed");
    const message = buildChallengeMessage(
      honest.publicKey,
      fromBase64url(init.challenge),
      init.attestation_ref,
    );
    const result = service.complete({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, attacker.privateKey)),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects unknown challenge ids and malformed bodies", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    expect(service.complete({ challenge_id: "nope", client_signature: "x" }).ok).toBe(false);
    expect(service.complete(null).ok).toBe(false);
    expect(service.complete("string").ok).toBe(false);
    expect(service.complete({}).ok).toBe(false);
    expect(service.init(null, true).ok).toBe(false);
    expect(service.init({}, true).ok).toBe(false);
    expect(service.init({ client_pubkey: 42 }, true).ok).toBe(false);
    const { publicKey } = makeClient();
    expect(
      service.init(
        { client_pubkey: toBase64url(randomBytes(16)), operator_attestation: durableAttestation(publicKey, Date.now()) },
        true,
      ).ok,
    ).toBe(false); // wrong-length pubkey
  });
});

describe("V1SessionService durable operator attestation (PR-A3)", () => {
  it("accepts a valid durable attestation bound to the client key (non-loopback)", () => {
    let nowMs = 2_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { publicKey } = makeClient();
    const init = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
    expect(init.ok).toBe(true);
    if (init.ok) expect(init.attestation_ref).toBe(OPERATOR_ED25519_ATTESTATION_REF);
  });

  it("REPLACE-NOT-EXTEND: a bearer-token attestation (what the temporary validator accepted) is now rejected", () => {
    // PR-A1's `local_operator` token-possession attestation — over loopback,
    // with auto-auth OFF, this WOULD have opened a session under the old
    // validator. The durable validator no longer accepts it: the token path
    // is gone, so a leaked bearer token cannot mint a /v1 session.
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();
    expect(
      service.init(
        initBody(publicKey, { type: "local_operator", token: "operator-token-for-tests" }),
        false,
      ).ok,
    ).toBe(false);
    // And over loopback (auto-auth off) it is still rejected — no token path.
    expect(
      service.init(
        initBody(publicKey, { type: "local_operator", token: "operator-token-for-tests" }),
        true,
      ).ok,
    ).toBe(false);
  });

  it("rejects an attestation bound to a DIFFERENT client key (no cross-session replay)", () => {
    let nowMs = 2_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const a = makeClient();
    const b = makeClient();
    // Attestation minted for client a, presented with client b's key.
    const stolen = durableAttestation(a.publicKey, nowMs);
    expect(service.init(initBody(b.publicKey, stolen), false).ok).toBe(false);
  });

  it("rejects an attestation signed by a NON-operator key", () => {
    let nowMs = 2_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { publicKey } = makeClient();
    const impostorPriv = randomBytes(32);
    const impostorPub = ed25519.getPublicKey(impostorPriv);
    const forged = signOperatorAttestation({
      operatorPublicKey: impostorPub,
      operatorPrivateKey: impostorPriv,
      clientPubkey: publicKey,
      issuedAtMs: nowMs,
    });
    expect(service.init(initBody(publicKey, forged), false).ok).toBe(false);
  });

  it("rejects a stale attestation (past the freshness window)", () => {
    let nowMs = 10_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { publicKey } = makeClient();
    const stale = durableAttestation(publicKey, nowMs - 6 * 60_000); // 6 min old, > 5 min window
    expect(service.init(initBody(publicKey, stale), false).ok).toBe(false);
    // A fresh one at the same clock is accepted.
    expect(service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false).ok).toBe(true);
  });

  it("denies the durable path when no operator identity is configured", () => {
    let nowMs = 2_000_000;
    const service = new V1SessionService({
      auth: makeAuth({ resolveOperatorPublicKey: () => null }),
      now: () => nowMs,
    });
    const { publicKey } = makeClient();
    // Even a structurally valid attestation cannot verify against a null key.
    expect(service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false).ok).toBe(false);
  });
});

describe("V1SessionService loopback fallbacks (network-position only)", () => {
  it("loopback auto-auth: tokenless same-box init opens, network init does not", () => {
    const off = new V1SessionService({ auth: makeAuth() });
    const on = new V1SessionService({ auth: makeAuth({ isLoopbackAutoAuthEnabled: () => true }) });
    const { publicKey } = makeClient();
    // auto-auth off: loopback alone does not open a tokenless session.
    expect(off.init(initBody(publicKey), true).ok).toBe(false);
    // auto-auth on: same-box opens with no attestation...
    const onInit = on.init(initBody(publicKey), true);
    expect(onInit.ok).toBe(true);
    if (onInit.ok) expect(onInit.attestation_ref).toBe(LOOPBACK_OPERATOR_ATTESTATION_REF);
    // ...but a network caller presenting nothing never does.
    expect(on.init(initBody(publicKey), false).ok).toBe(false);
  });

  it("auth-disabled daemon (no operator key): loopback may open, network may not", () => {
    const service = new V1SessionService({
      auth: makeAuth({ resolveOperatorPublicKey: () => null }),
    });
    const { publicKey } = makeClient();
    const loop = service.init(initBody(publicKey), true);
    expect(loop.ok).toBe(true);
    if (loop.ok) expect(loop.attestation_ref).toBe(AUTH_DISABLED_ATTESTATION_REF);
    expect(service.init(initBody(publicKey), false).ok).toBe(false);
  });

  it("denies an unknown attestation type from a network caller", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();
    expect(
      service.init(initBody(publicKey, { type: "something_else", token: "x" }), false).ok,
    ).toBe(false);
  });
});

describe("V1SessionService tokens", () => {
  it("rejects an expired session token", () => {
    let nowMs = 5_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const token = openSession(service, nowMs);
    expect(service.validateToken(token)).not.toBeNull();
    nowMs += 31 * 60_000; // past the 30min token TTL
    expect(service.validateToken(token)).toBeNull();
  });

  it("rejects a tampered token (GCM authentication)", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const token = openSession(service);
    const raw = fromBase64url(token);
    raw[raw.length - 1]! ^= 0x01; // flip one ciphertext bit
    expect(service.validateToken(toBase64url(raw))).toBeNull();
  });

  it("rejects garbage and truncated tokens", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    expect(service.validateToken("")).toBeNull();
    expect(service.validateToken("not-a-token")).toBeNull();
    expect(service.validateToken(toBase64url(randomBytes(8)))).toBeNull();
    expect(service.validateToken(toBase64url(randomBytes(64)))).toBeNull();
  });

  it("rejects tokens minted before rotateSessions()", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const token = openSession(service);
    expect(service.validateToken(token)).not.toBeNull();
    service.rotateSessions();
    expect(service.validateToken(token)).toBeNull();
    const fresh = openSession(service);
    expect(service.validateToken(fresh)).not.toBeNull();
  });

  it("a token from one service instance does not validate on another (process-local keys)", () => {
    const a = new V1SessionService({ auth: makeAuth() });
    const b = new V1SessionService({ auth: makeAuth() });
    const token = openSession(a);
    expect(b.validateToken(token)).toBeNull();
  });
});

describe("V1SessionService resource bounds", () => {
  it("refuses new ceremonies past the pending-challenge cap (fail closed)", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({ auth: makeAuth(), now: () => nowMs });
    const { publicKey } = makeClient();
    let denied = false;
    for (let i = 0; i < 300; i++) {
      const result = service.init(initBody(publicKey, durableAttestation(publicKey, nowMs)), false);
      if (!result.ok) {
        denied = true;
        expect(i).toBeGreaterThanOrEqual(256);
        break;
      }
    }
    expect(denied).toBe(true);
  });
});
