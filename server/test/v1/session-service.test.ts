/**
 * Federation PR-A1 — V1SessionService unit tests.
 *
 * Every security property of the RFC v7 session ceremony is asserted at
 * the unit level with an injected clock: challenge expiry, single-use
 * consumption, attestation gating (token match, loopback auto-auth,
 * auth-disabled loopback-only), token expiry, token tampering, session
 * generation rotation, and the pending-challenge cap. Each test fails if
 * the corresponding check is removed from the implementation.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "node:crypto";

import {
  V1SessionService,
  V1_CAPABILITY_STATUS_READ,
  constantShapeTokenEqual,
  type V1SessionAuthBridge,
} from "../../src/v1/session-service.js";
import {
  buildChallengeMessage,
  LOCAL_OPERATOR_ATTESTATION_REF,
} from "../../src/v1/ceremony.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";

const AUTH_TOKEN = "operator-token-for-tests";

function makeAuth(overrides?: Partial<V1SessionAuthBridge>): V1SessionAuthBridge {
  return {
    getAuthToken: () => AUTH_TOKEN,
    isLoopbackAutoAuthEnabled: () => false,
    ...overrides,
  };
}

function makeClient() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Build a session-init body. `token` defaults to the valid operator
 * token; pass null to OMIT the token field entirely (tokenless caller).
 */
function initBody(publicKey: Uint8Array, token: string | null = AUTH_TOKEN) {
  return {
    client_pubkey: toBase64url(publicKey),
    operator_attestation: {
      type: "local_operator",
      ...(token !== null ? { token } : {}),
    },
  };
}

function signChallenge(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  challengeB64: string,
): string {
  const message = buildChallengeMessage(
    publicKey,
    fromBase64url(challengeB64),
    LOCAL_OPERATOR_ATTESTATION_REF,
  );
  return toBase64url(ed25519.sign(message, privateKey));
}

/** Run the full ceremony and return the session token. */
function openSession(service: V1SessionService, loopback = false): string {
  const { privateKey, publicKey } = makeClient();
  const init = service.init(initBody(publicKey), loopback);
  expect(init.ok).toBe(true);
  if (!init.ok) throw new Error("unreachable");
  const complete = service.complete({
    challenge_id: init.challenge_id,
    client_signature: signChallenge(privateKey, publicKey, init.challenge),
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
    expect(claims!.attestation_ref).toBe(LOCAL_OPERATOR_ATTESTATION_REF);
  });

  it("rejects a replayed challenge_id (single-use, success path)", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey), false);
    if (!init.ok) throw new Error("init failed");
    const signature = signChallenge(privateKey, publicKey, init.challenge);
    const first = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signature,
    });
    expect(first.ok).toBe(true);
    // Replay of the IDENTICAL completed ceremony must be denied.
    const replay = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signature,
    });
    expect(replay.ok).toBe(false);
  });

  it("consumes the challenge on a FAILED attempt too (no signature brute-force)", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey), false);
    if (!init.ok) throw new Error("init failed");
    const bad = service.complete({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(randomBytes(64)),
    });
    expect(bad.ok).toBe(false);
    // A subsequent VALID signature against the same challenge is denied:
    // the failed attempt burned it.
    const good = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signChallenge(privateKey, publicKey, init.challenge),
    });
    expect(good.ok).toBe(false);
  });

  it("rejects an expired challenge", () => {
    let nowMs = 1_000_000;
    const service = new V1SessionService({
      auth: makeAuth(),
      now: () => nowMs,
    });
    const { privateKey, publicKey } = makeClient();
    const init = service.init(initBody(publicKey), false);
    if (!init.ok) throw new Error("init failed");
    nowMs += 61_000; // past the 60s challenge TTL
    const result = service.complete({
      challenge_id: init.challenge_id,
      client_signature: signChallenge(privateKey, publicKey, init.challenge),
    });
    expect(result.ok).toBe(false);
  });

  it("rejects a signature from a different keypair over the right message", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const honest = makeClient();
    const attacker = makeClient();
    const init = service.init(initBody(honest.publicKey), false);
    if (!init.ok) throw new Error("init failed");
    // Attacker signs the canonical message for the honest pubkey with
    // their own key (key-binding check).
    const message = buildChallengeMessage(
      honest.publicKey,
      fromBase64url(init.challenge),
      LOCAL_OPERATOR_ATTESTATION_REF,
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
    // Wrong-length pubkey.
    expect(
      service.init(
        { client_pubkey: toBase64url(randomBytes(16)), operator_attestation: { type: "local_operator", token: AUTH_TOKEN } },
        true,
      ).ok,
    ).toBe(false);
  });
});

describe("V1SessionService attestation gating", () => {
  it("denies init with a wrong operator token (non-loopback)", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();
    expect(service.init(initBody(publicKey, "wrong-token"), false).ok).toBe(false);
  });

  it("denies init with NO token from non-loopback even when auto-auth is on", () => {
    const service = new V1SessionService({
      auth: makeAuth({ isLoopbackAutoAuthEnabled: () => true }),
    });
    const { publicKey } = makeClient();
    expect(service.init(initBody(publicKey, null), false).ok).toBe(false);
  });

  it("allows tokenless loopback init only when loopback auto-auth is enabled", () => {
    const off = new V1SessionService({ auth: makeAuth() });
    const on = new V1SessionService({
      auth: makeAuth({ isLoopbackAutoAuthEnabled: () => true }),
    });
    const { publicKey } = makeClient();
    expect(off.init(initBody(publicKey, null), true).ok).toBe(false);
    expect(on.init(initBody(publicKey, null), true).ok).toBe(true);
  });

  it("auth-disabled daemon: loopback may open sessions, network may not", () => {
    const service = new V1SessionService({
      auth: makeAuth({ getAuthToken: () => undefined }),
    });
    const { publicKey } = makeClient();
    expect(service.init(initBody(publicKey, null), true).ok).toBe(true);
    expect(service.init(initBody(publicKey, null), false).ok).toBe(false);
  });

  it("constant-shape token compare: wrong tokens of ANY length rejected, correct accepted", () => {
    // Codex review finding 1: the compare must do identical work for
    // every candidate. Functionally: an equal-length wrong token and a
    // different-length wrong token are both rejected, and the correct
    // token is accepted, through the fixed-size-digest comparison path.
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();

    const equalLengthWrong = "X".repeat(AUTH_TOKEN.length);
    expect(equalLengthWrong).toHaveLength(AUTH_TOKEN.length);
    expect(service.init(initBody(publicKey, equalLengthWrong), false).ok).toBe(false);

    expect(service.init(initBody(publicKey, "short"), false).ok).toBe(false);
    expect(
      service.init(initBody(publicKey, AUTH_TOKEN + "-and-then-some"), false).ok,
    ).toBe(false);

    expect(service.init(initBody(publicKey, AUTH_TOKEN), false).ok).toBe(true);
  });

  it("constantShapeTokenEqual compares fixed-size digests (no length branch, no throw)", () => {
    // timingSafeEqual throws on unequal-length inputs; the helper never
    // does, because BOTH sides are first compressed to 32-byte HMAC
    // digests — the identical work regardless of candidate length.
    expect(constantShapeTokenEqual("a", "a-much-longer-configured-token")).toBe(false);
    expect(constantShapeTokenEqual("a-much-longer-presented-token", "a")).toBe(false);
    expect(constantShapeTokenEqual("", "configured")).toBe(false);
    expect(constantShapeTokenEqual("same-length-A", "same-length-B")).toBe(false);
    expect(constantShapeTokenEqual("exact-match", "exact-match")).toBe(true);
  });

  it("denies unknown attestation types", () => {
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();
    expect(
      service.init(
        {
          client_pubkey: toBase64url(publicKey),
          operator_attestation: { type: "ed25519_operator", token: AUTH_TOKEN },
        },
        true,
      ).ok,
    ).toBe(false);
  });
});

describe("V1SessionService tokens", () => {
  it("rejects an expired session token", () => {
    let nowMs = 5_000_000;
    const service = new V1SessionService({
      auth: makeAuth(),
      now: () => nowMs,
    });
    const token = openSession(service);
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
    // New ceremonies mint valid tokens under the new generation.
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
    const service = new V1SessionService({ auth: makeAuth() });
    const { publicKey } = makeClient();
    let denied = false;
    for (let i = 0; i < 300; i++) {
      const result = service.init(initBody(publicKey), false);
      if (!result.ok) {
        denied = true;
        expect(i).toBeGreaterThanOrEqual(256);
        break;
      }
    }
    expect(denied).toBe(true);
  });
});
