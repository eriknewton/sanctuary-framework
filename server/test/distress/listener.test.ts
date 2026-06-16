/**
 * HABEAS PORT — local distress listener + inbox + delivery tests.
 *
 * Security properties under test:
 *   - Sender authentication: only a frame whose nonce-bound HMAC verifies with
 *     the operator-uid-only secret is accepted; wrong/absent/foreign-secret
 *     HMACs are rejected and never reach the inbox (any local process can
 *     connect, so loopback is not trust).
 *   - Mutual auth / anti port-squat: the listener proves it holds the secret in
 *     its challenge; the emitter refuses to send the envelope to a peer that
 *     cannot.
 *   - Anti-replay: a frame is nonce-bound (single connection) and an accepted
 *     event_id is not accepted twice.
 *   - No information leak: the listener's reply is a bare status, never inbox
 *     content; reading the inbox is dashboard-auth'd, not listener-served.
 *   - Bounded + closed shape: oversized frames rejected, extra envelope keys
 *     rejected, inbox ring capped.
 *   - Additive: round-trip emitter→listener delivery lands in the inbox; a
 *     delivery to a closed port fails best-effort (no throw).
 *   - Port conflict is loud, never a crash.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { connect } from "node:net";
import { mkdtemp, rm, writeFile, chmod, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DistressListener,
  computeFrameHmac,
  computeChallengeProof,
  DISTRESS_FRAME_MAX_BYTES,
  type DistressChallenge,
} from "../../src/distress/listener.js";
import { DistressInbox, DISTRESS_INBOX_MAX } from "../../src/distress/inbox.js";
import { deliverDistressLocally } from "../../src/distress/local-delivery.js";
import {
  loadOrCreateLocalListenerSecret,
  DistressLocalSecretError,
  DISTRESS_LOCAL_SECRET_FILENAME,
} from "../../src/distress/local-secret.js";
import type { DistressEnvelope } from "../../src/distress/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { canonicalJson, sha256 } from "../../src/agent-native/safety-base.js";

function hashFor(env: DistressEnvelope): string {
  return sha256(canonicalJson(env));
}

function makeEnvelope(overrides: Partial<DistressEnvelope> = {}): DistressEnvelope {
  return {
    schema: "sanctuary.distress.v1",
    event_id: "distress:abc123",
    emitted_at: new Date().toISOString(),
    actor: "agent-test",
    reason: "policy_constraint",
    severity: "urgent",
    sequence_in_window: 1,
    ...overrides,
  };
}

async function buildHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const inbox = new DistressInbox(storage, masterKey);
  await inbox.load();
  const secret = generateRandomKey();
  const listener = new DistressListener({
    inbox,
    auditLog,
    localSecret: secret,
    identityId: "fortress:test",
    host: "127.0.0.1",
    port: 0,
  });
  await listener.start();
  const addr = listener.address();
  if (!addr) throw new Error("listener did not bind");
  return { storage, masterKey, auditLog, inbox, secret, listener, port: addr.port };
}

interface Ack {
  ok?: boolean;
  reason?: string;
  event_id?: string;
}

const CLIENT_NONCE = "clientnoncetestclientnoncetest00";

/**
 * Drive the full handshake against the listener: send a client hello, read the
 * challenge line, hand it to `buildFrame` (which returns the JSON frame body to
 * send, or null to abandon), send it, and resolve the ack. Also exposes the raw
 * challenge for assertions.
 */
function exchange(
  port: number,
  buildFrame: (challenge: DistressChallenge) => string | null,
  clientNonce: string = CLIENT_NONCE,
): Promise<{ ack: Ack; challenge: DistressChallenge | null }> {
  return new Promise((resolve, reject) => {
    let buf = "";
    let sawChallenge = false;
    let challenge: DistressChallenge | null = null;
    const socket = connect({ host: "127.0.0.1", port }, () => {
      socket.write(
        JSON.stringify({
          protocol: "sanctuary.distress.local.v1",
          client_nonce: clientNonce,
        }) + "\n",
      );
    });
    socket.on("data", (c: Buffer) => {
      buf += c.toString("utf8");
      if (!sawChallenge) {
        const nl = buf.indexOf("\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        sawChallenge = true;
        try {
          challenge = JSON.parse(line) as DistressChallenge;
        } catch {
          socket.destroy();
          resolve({ ack: {}, challenge: null });
          return;
        }
        const body = buildFrame(challenge);
        if (body === null) {
          socket.destroy();
          resolve({ ack: {}, challenge });
          return;
        }
        socket.end(body);
      }
    });
    socket.on("end", () => {
      try {
        resolve({ ack: JSON.parse(buf) as Ack, challenge });
      } catch {
        resolve({ ack: {}, challenge });
      }
    });
    socket.on("error", reject);
  });
}

/** Build a valid nonce-bound frame for an envelope + secret. */
function validFrame(env: DistressEnvelope, secret: Uint8Array, nonce: string): string {
  return JSON.stringify({
    envelope: env,
    envelope_hash: hashFor(env),
    hmac: computeFrameHmac(env, nonce, secret),
  });
}

describe("DistressListener — challenge + sender authentication", () => {
  let h: Awaited<ReturnType<typeof buildHarness>>;
  beforeEach(async () => {
    h = await buildHarness();
  });
  afterEach(async () => {
    await h.listener.stop();
  });

  it("sends a challenge proving it holds the secret, bound to the client nonce", async () => {
    const { challenge } = await exchange(h.port, () => null);
    expect(challenge).not.toBeNull();
    expect(challenge!.protocol).toBe("sanctuary.distress.local.v1");
    expect(challenge!.proof).toBe(
      computeChallengeProof(CLIENT_NONCE, challenge!.nonce, h.secret),
    );
  });

  it("a challenge for client-nonce A does not verify under client-nonce B (anti-harvest)", async () => {
    const { challenge } = await exchange(h.port, () => null, "client-nonce-A");
    expect(challenge).not.toBeNull();
    // The proof is bound to "client-nonce-A"; an emitter that sent a different
    // client nonce would reject this exact proof.
    expect(challenge!.proof).not.toBe(
      computeChallengeProof("client-nonce-B", challenge!.nonce, h.secret),
    );
  });

  it("accepts a correctly nonce-bound frame and stores it", async () => {
    const env = makeEnvelope();
    const { ack } = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(ack.ok).toBe(true);
    const entries = await h.inbox.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.envelope.event_id).toBe(env.event_id);
    expect(entries[0]!.authenticated).toBe(true);
  });

  it("REJECTS a frame signed with a DIFFERENT secret (spoofing peer)", async () => {
    const env = makeEnvelope();
    const attacker = generateRandomKey();
    const { ack } = await exchange(h.port, (ch) => validFrame(env, attacker, ch.nonce));
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("bad_signature");
    expect(await h.inbox.count()).toBe(0);
  });

  it("REJECTS a frame whose HMAC is bound to a different nonce (no replay)", async () => {
    const env = makeEnvelope();
    const { ack } = await exchange(h.port, () =>
      // Sign against a nonce the listener never issued.
      validFrame(env, h.secret, "deadbeefdeadbeefdeadbeefdeadbeef"),
    );
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("bad_signature");
    expect(await h.inbox.count()).toBe(0);
  });
});

describe("DistressListener — anti-replay across connections", () => {
  let h: Awaited<ReturnType<typeof buildHarness>>;
  beforeEach(async () => {
    h = await buildHarness();
  });
  afterEach(async () => {
    await h.listener.stop();
  });

  it("rejects a second delivery of an already-accepted event_id", async () => {
    const env = makeEnvelope({ event_id: "distress:once" });
    const first = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(first.ack.ok).toBe(true);
    // Re-sign with the SECOND connection's fresh nonce (so it is a real,
    // correctly-signed frame) — it must still be rejected as a replay by
    // event_id.
    const second = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(second.ack.ok).toBe(false);
    expect(second.ack.reason).toBe("replay");
    expect(await h.inbox.count()).toBe(1);
  });
});

describe("DistressListener — bounded + closed shape", () => {
  let h: Awaited<ReturnType<typeof buildHarness>>;
  beforeEach(async () => {
    h = await buildHarness();
  });
  afterEach(async () => {
    await h.listener.stop();
  });

  it("rejects an oversized frame", async () => {
    const big = "x".repeat(DISTRESS_FRAME_MAX_BYTES + 10);
    const { ack } = await exchange(h.port, () => big);
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("too_large");
    expect(await h.inbox.count()).toBe(0);
  });

  it("rejects malformed JSON", async () => {
    const { ack } = await exchange(h.port, () => "{not json");
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("malformed");
  });

  it("rejects an out-of-vocabulary reason even when correctly signed", async () => {
    const env = makeEnvelope({ reason: "exfiltrate" as DistressEnvelope["reason"] });
    const { ack } = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("bad_envelope");
    expect(await h.inbox.count()).toBe(0);
  });

  it("rejects an envelope carrying EXTRA keys even with a valid HMAC", async () => {
    const env = makeEnvelope();
    const { ack } = await exchange(h.port, (ch) => {
      const tampered = { ...env, exfil: "stolen-data" } as DistressEnvelope;
      return JSON.stringify({
        envelope: tampered,
        envelope_hash: sha256(canonicalJson(tampered)),
        hmac: computeFrameHmac(tampered, ch.nonce, h.secret),
      });
    });
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("bad_envelope");
    expect(await h.inbox.count()).toBe(0);
  });

  it("rejects an over-long detail (closed-shape bound)", async () => {
    const env = makeEnvelope({ detail: "y".repeat(281) });
    const { ack } = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("bad_envelope");
  });

  it("rejects a frame whose advertised hash disagrees with the signed bytes", async () => {
    const env = makeEnvelope();
    const { ack } = await exchange(h.port, (ch) =>
      JSON.stringify({
        envelope: env,
        envelope_hash: "sha256:" + "0".repeat(64),
        hmac: computeFrameHmac(env, ch.nonce, h.secret),
      }),
    );
    expect(ack.ok).toBe(false);
    expect(ack.reason).toBe("malformed");
  });

  it("never echoes inbox content in the ack (no information leak)", async () => {
    const env = makeEnvelope({ detail: "secret operator detail" });
    const { ack } = await exchange(h.port, (ch) => validFrame(env, h.secret, ch.nonce));
    expect(ack.ok).toBe(true);
    expect(JSON.stringify(ack)).not.toContain("secret operator detail");
    expect(Object.keys(ack).sort()).toEqual(["event_id", "ok"]);
  });
});

describe("DistressInbox — bounded ring", () => {
  it("caps the inbox at DISTRESS_INBOX_MAX, dropping oldest first", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const inbox = new DistressInbox(storage, masterKey);
    await inbox.load();
    for (let i = 0; i < DISTRESS_INBOX_MAX + 5; i++) {
      await inbox.append({
        envelope: makeEnvelope({ event_id: `distress:${i}` }),
        envelope_hash: "sha256:" + "a".repeat(64),
        received_at: new Date().toISOString(),
        authenticated: true,
      });
    }
    expect(await inbox.count()).toBe(DISTRESS_INBOX_MAX);
    const list = await inbox.list(5);
    expect(list[0]!.envelope.event_id).toBe(`distress:${DISTRESS_INBOX_MAX + 4}`);
    const all = await inbox.list(DISTRESS_INBOX_MAX);
    expect(all.find((e) => e.envelope.event_id === "distress:0")).toBeUndefined();
  });

  it("persists across instances (encrypted at rest)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const a = new DistressInbox(storage, masterKey);
    await a.append({
      envelope: makeEnvelope({ event_id: "distress:persist" }),
      envelope_hash: "sha256:" + "b".repeat(64),
      received_at: new Date().toISOString(),
      authenticated: true,
    });
    const b = new DistressInbox(storage, masterKey);
    const list = await b.list();
    expect(list).toHaveLength(1);
    expect(list[0]!.envelope.event_id).toBe("distress:persist");
  });
});

describe("local delivery (emitter side, mutual auth)", () => {
  let h: Awaited<ReturnType<typeof buildHarness>>;
  beforeEach(async () => {
    h = await buildHarness();
  });
  afterEach(async () => {
    await h.listener.stop();
  });

  it("round-trips: deliver lands in the inbox", async () => {
    const env = makeEnvelope({ event_id: "distress:rt" });
    const result = await deliverDistressLocally({
      envelope: env,
      envelopeHash: hashFor(env),
      localSecret: h.secret,
      host: "127.0.0.1",
      port: h.port,
    });
    expect(result.delivered).toBe(true);
    const list = await h.inbox.list();
    expect(list[0]!.envelope.event_id).toBe("distress:rt");
  });

  it("a wrong-secret deliver is refused (emitter rejects the listener proof)", async () => {
    // The emitter holds the wrong secret: it cannot verify the listener's
    // proof, so it refuses to send the envelope at all (no leak), reason
    // listener_unauthenticated.
    const env = makeEnvelope();
    const result = await deliverDistressLocally({
      envelope: env,
      envelopeHash: hashFor(env),
      localSecret: generateRandomKey(),
      host: "127.0.0.1",
      port: h.port,
    });
    expect(result.delivered).toBe(false);
    expect(result.reason).toBe("listener_unauthenticated");
    expect(await h.inbox.count()).toBe(0);
  });

  it("refuses to deliver to a port-squatter that cannot prove the secret", async () => {
    // Stand up a rogue 'listener' that speaks the protocol shape but signs the
    // challenge with the wrong secret. The emitter must NOT send the envelope.
    const { createServer } = await import("node:net");
    const rogueSecret = generateRandomKey();
    let envelopeReceived = false;
    const rogue = createServer({ allowHalfOpen: true }, (socket) => {
      let helloSeen = false;
      let buf = "";
      socket.on("data", (c: Buffer) => {
        buf += c.toString("utf8");
        if (!helloSeen) {
          const nl = buf.indexOf("\n");
          if (nl === -1) return;
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          helloSeen = true;
          const hello = JSON.parse(line) as { client_nonce: string };
          const nonce = "roguenonce";
          socket.write(
            JSON.stringify({
              protocol: "sanctuary.distress.local.v1",
              nonce,
              // Signed with the WRONG secret — the emitter must reject it.
              proof: computeChallengeProof(hello.client_nonce, nonce, rogueSecret),
            }) + "\n",
          );
          return;
        }
        envelopeReceived = true;
      });
      socket.on("end", () => socket.end(JSON.stringify({ ok: true })));
      socket.on("error", () => {});
    });
    await new Promise<void>((r) => rogue.listen(0, "127.0.0.1", () => r()));
    const addr = rogue.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;

    const env = makeEnvelope();
    const result = await deliverDistressLocally({
      envelope: env,
      envelopeHash: hashFor(env),
      localSecret: h.secret, // the REAL secret
      host: "127.0.0.1",
      port,
      timeoutMs: 1000,
    });
    expect(result.delivered).toBe(false);
    expect(result.reason).toBe("listener_unauthenticated");
    expect(envelopeReceived).toBe(false); // the squatter never got the envelope
    await new Promise<void>((r) => rogue.close(() => r()));
  });

  it("delivery to a closed port fails best-effort, never throws", async () => {
    await h.listener.stop();
    const env = makeEnvelope();
    const result = await deliverDistressLocally({
      envelope: env,
      envelopeHash: hashFor(env),
      localSecret: h.secret,
      host: "127.0.0.1",
      port: h.port,
      timeoutMs: 500,
    });
    expect(result.delivered).toBe(false);
  });
});

describe("port conflict is loud, never a crash", () => {
  it("a second listener on the same fixed port resolves with a warning", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const inbox = new DistressInbox(storage, masterKey);
    const secret = generateRandomKey();
    const first = new DistressListener({
      inbox,
      auditLog,
      localSecret: secret,
      identityId: "fortress:test",
      host: "127.0.0.1",
      port: 0,
    });
    await first.start();
    const port = first.address()!.port;

    const warnings: string[] = [];
    const second = new DistressListener({
      inbox,
      auditLog,
      localSecret: secret,
      identityId: "fortress:test",
      host: "127.0.0.1",
      port,
      warn: (line) => warnings.push(line),
    });
    await expect(second.start()).resolves.toBeUndefined();
    expect(warnings.some((w) => w.includes("could NOT bind"))).toBe(true);
    expect(second.address()).toBeNull();

    await first.stop();
    await second.stop();
  });
});

describe("local secret file", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "habeas-secret-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("mints a 0600 secret on first use and reads the same one back", async () => {
    const a = await loadOrCreateLocalListenerSecret(dir);
    expect(a.length).toBe(32);
    const file = join(dir, "policy", "egress", DISTRESS_LOCAL_SECRET_FILENAME);
    const st = await stat(file);
    expect(st.mode & 0o077).toBe(0);
    const b = await loadOrCreateLocalListenerSecret(dir);
    expect(Buffer.from(b).equals(Buffer.from(a))).toBe(true);
  });

  it("rejects a group/world-readable secret (fail closed)", async () => {
    await loadOrCreateLocalListenerSecret(dir);
    const file = join(dir, "policy", "egress", DISTRESS_LOCAL_SECRET_FILENAME);
    await chmod(file, 0o644);
    await expect(loadOrCreateLocalListenerSecret(dir)).rejects.toBeInstanceOf(
      DistressLocalSecretError,
    );
  });

  it("rejects a malformed secret file", async () => {
    const egress = join(dir, "policy", "egress");
    await rm(egress, { recursive: true, force: true });
    await (await import("node:fs/promises")).mkdir(egress, { recursive: true, mode: 0o700 });
    const file = join(egress, DISTRESS_LOCAL_SECRET_FILENAME);
    await writeFile(file, "not-hex", { mode: 0o600 });
    await expect(loadOrCreateLocalListenerSecret(dir)).rejects.toBeInstanceOf(
      DistressLocalSecretError,
    );
  });
});
