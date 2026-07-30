/**
 * Slice P — producer-key PROVISIONING activates the L1/R audit-authenticity
 * close on Linux without regressing the macOS / no-key channel basis.
 *
 * Slice L1 made the Linux daemon sign each enforcement event; Slice R made the
 * readers re-verify that signature against a pinned key. This suite exercises
 * the key-loading binding with mocked signed events; it does not prove live
 * Linux capability. Slice P wires the SINGLE-SOURCE loader
 * (`loadFortressProducerKey` → `<storage>/policy/egress/audit-producer.pub`) into
 * BOTH the consumer (lifecycle) and the readers (posture/dashboard), so:
 *
 *   (1) a mock-signed event re-verifies GREEN because the key is loaded;
 *   (2) a forged in-process entry renders NON-green BECAUSE the key is loaded
 *       (the key-loaded harness is not key-null);
 *   (3) macOS / no-key stays channel-basis green (unknown-never-green preserved);
 *   (4) key-published-but-unreadable fails HONESTLY (degraded), never channel-green;
 *   (5) explicit rotation does not break verification.
 *
 * The pubkey file is written the EXACT way the Rust daemon publishes it: 32 raw
 * verifying-key bytes at the canonical relative path.
 */

import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type { CastleWallMessage } from "../../../src/castle-wall/ipc/messages.js";
import type { IpcTransport } from "../../../src/castle-wall/runtime/ipc-client.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import {
  loadFortressProducerKey,
  resolveProducerPubKeyPath,
  producerKeyDaemonLaunchArgs,
  producerSigningBytes,
  CASTLE_WALL_PRODUCER_PUBKEY_RELPATH,
  CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import { startCastleWall } from "../../../src/castle-wall/runtime/lifecycle.js";
import { buildCastleWallPosture } from "../../../src/principal-policy/posture.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
} from "../../../src/castle-wall/constants.js";

const FORTRESS = "fortress:test";
const SUBJECT = `${FORTRESS}/uid-503`;
const NOW = 1_750_000_000_000;
const FRESH_TS = NOW - 1000;
const LINUX_PRODUCER_KEY_LOAD = { platform: "linux" as const };
const UNDETERMINED_AVAILABILITY = {
  status: "undetermined" as const,
  reason: "availability_not_queried",
  observed_at: null,
  freshness_window_ms: 30_000,
  active_connection_count: 0,
};

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Write the daemon-published pubkey file: 32 raw verifying-key bytes. */
async function publishPubKey(storage: string, pubBytes: Uint8Array): Promise<void> {
  const dir = join(storage, "policy", "egress");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "audit-producer.pub"), Buffer.from(pubBytes));
}

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

function walBody(seq: number): string {
  return JSON.stringify({
    timestamp: new Date(FRESH_TS).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    identity_id: SUBJECT,
    result: "blocked",
    details: { agent_id: SUBJECT, dest_host: "evil.example" },
  });
}

async function appendGenuineSigned(
  log: AuditLog,
  priv: Uint8Array,
  seq: number,
): Promise<void> {
  const canonical = walBody(seq);
  const sig = ed25519.sign(producerSigningBytes(canonical, FRESH_TS, seq), priv);
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: SUBJECT,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq,
      agent_id: SUBJECT,
      dest_host: "evil.example",
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/** A forged in-process entry: claims producer_signed, no valid signature. */
async function appendForgedMarkerOnly(log: AuditLog): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: SUBJECT,
    result: "success",
    timestamp: new Date(FRESH_TS).toISOString(),
    details: {
      seq: 0,
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: walBody(0),
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: FRESH_TS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  });
}

/** In-process mock daemon transport (mirrors lifecycle.test.ts). */
function buildMockTransport(): {
  transport: IpcTransport;
  daemonSend: (msg: CastleWallMessage) => Promise<void>;
} {
  let listener: ((bytes: Uint8Array) => void) | null = null;
  let buffer = new Uint8Array(0);
  return {
    transport: {
      send: async (bytes: Uint8Array) => {
        const merged = new Uint8Array(buffer.length + bytes.length);
        merged.set(buffer, 0);
        merged.set(bytes, buffer.length);
        buffer = merged;
        while (true) {
          const step = parseFrame(buffer);
          if (step.kind === "complete") {
            buffer = new Uint8Array(buffer.subarray(step.consumedBytes));
          } else if (step.kind === "need_more") {
            break;
          } else {
            throw new Error(`framing error: ${step.reason}`);
          }
        }
      },
      onData: (l) => {
        listener = l;
        return () => {
          listener = null;
        };
      },
      close: async () => {
        listener = null;
      },
    },
    daemonSend: async (msg) => {
      // The lifecycle resolves the producer key (an async tick) BEFORE the IPC
      // client registers `onData`, so wait for the listener to attach rather
      // than dropping the challenge on a race.
      for (let i = 0; i < 200 && !listener; i++) {
        await new Promise((r) => setTimeout(r, 1));
      }
      if (!listener) throw new Error("transport listener never registered");
      listener(
        frame(
          JSON.stringify({
            jsonrpc: "2.0",
            method: `castle-wall.${msg.type}`,
            params: msg,
          }),
        ),
      );
    },
  };
}

let tmp: string;
let identityEncKey: Uint8Array;
beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "slice-p-"));
  identityEncKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
});
afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
});

function startArgs(extra: Record<string, unknown>) {
  const { storedIdentity } = createIdentity(
    "slice-p-test",
    identityEncKey,
    "passphrase",
  );
  return {
    key: {
      fortressId: "f",
      signingKeyId: storedIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: identityEncKey,
    },
    auditSink: { append: () => {}, flush: async () => {} },
    handshakeTimeoutMs: 1_000,
    ...extra,
  };
}

/** Start the lifecycle to a running handle, completing the handshake. */
async function startToRunning(extra: Record<string, unknown>) {
  const { transport, daemonSend } = buildMockTransport();
  const startP = startCastleWall({
    transport,
    ...startArgs(extra),
  } as never);
  await daemonSend({ type: "handshake_challenge", nonce_b64url: "AAEC" });
  return startP;
}

/**
 * Start WITHOUT a handshake responder — for the fail-closed case, where the
 * lifecycle must reject during key RESOLUTION (before any handshake), so no
 * challenge is sent and no transport listener is awaited.
 */
function startNoHandshake(extra: Record<string, unknown>) {
  const { transport } = buildMockTransport();
  return startCastleWall({ transport, ...startArgs(extra) } as never);
}

describe("Slice P — single-source loader (the path consumer + reader share)", () => {
  it("resolves the canonical relative path", () => {
    expect(resolveProducerPubKeyPath("/X")).toBe(
      join("/X", CASTLE_WALL_PRODUCER_PUBKEY_RELPATH),
    );
    expect(CASTLE_WALL_PRODUCER_PUBKEY_RELPATH).toBe(
      "policy/egress/audit-producer.pub",
    );
    expect(CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH).toBe(
      "/Library/Application Support/Sanctuary/castle-audit-producer.pub",
    );
  });

  it("status=present for a 32-byte published key", async () => {
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await publishPubKey(tmp, pub);
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    expect(load.status).toBe("present");
    if (load.status === "present") {
      expect(load.keyB64url).toBe(toBase64url(pub));
    }
  });

  it("status=absent when no key file exists (the ONLY channel-basis path)", async () => {
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    expect(load.status).toBe("absent");
  });

  it("status=unreadable for a present-but-wrong-length key (NOT absent)", async () => {
    const dir = join(tmp, "policy", "egress");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "audit-producer.pub"), Buffer.from([1, 2, 3]));
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    expect(load.status).toBe("unreadable");
  });

  it("on darwin prefers the host-wide audit-producer key published by the root helper", async () => {
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const hostDir = join(tmp, "host-wide");
    const hostPath = join(hostDir, "castle-audit-producer.pub");
    await mkdir(hostDir, { recursive: true });
    await writeFile(hostPath, Buffer.from(pub));

    const load = await loadFortressProducerKey(tmp, {
      platform: "darwin",
      macosProducerPubKeyPath: hostPath,
    });

    expect(load.status).toBe("present");
    if (load.status === "present") {
      expect(load.keyB64url).toBe(toBase64url(pub));
    }
  });

  it("on darwin falls back to the fortress key only when the host-wide key is absent", async () => {
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await publishPubKey(tmp, pub);

    const load = await loadFortressProducerKey(tmp, {
      platform: "darwin",
      macosProducerPubKeyPath: join(tmp, "missing", "castle-audit-producer.pub"),
    });

    expect(load.status).toBe("present");
    if (load.status === "present") {
      expect(load.keyB64url).toBe(toBase64url(pub));
    }
  });

  it("daemon-launch args BIND the daemon publish path to the TS read path (codex HIGH #2)", () => {
    // The whole activation hinges on the daemon publishing the pubkey where the
    // TS server reads it. Deriving both from one storage root makes them equal
    // by construction: the `--producer-pub-key` arg MUST equal the read path.
    const args = producerKeyDaemonLaunchArgs("/srv/fortress");
    const pubIdx = args.indexOf("--producer-pub-key");
    expect(pubIdx).toBeGreaterThanOrEqual(0);
    expect(args[pubIdx + 1]).toBe(resolveProducerPubKeyPath("/srv/fortress"));
    // And the policy-dir parents the published pub key.
    const dirIdx = args.indexOf("--policy-dir");
    expect(args[dirIdx + 1]).toBe(join("/srv/fortress", "policy", "egress"));
  });
});

describe("Slice P — consumer activation (startCastleWall via fortressStoragePath)", () => {
  it("ACTIVATES: key present → consumer ENFORCES producer signatures", async () => {
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await publishPubKey(tmp, pub);
    const handle = await startToRunning({
      fortressStoragePath: tmp,
      producerKeyLoadOptions: LINUX_PRODUCER_KEY_LOAD,
    });
    expect(handle.state()).toBe("running");
    // The load-bearing assertion: the consumer resolved the published key and is
    // enforcing per-producer signatures (the L1 close is ACTIVE), not key-null.
    expect(handle.audit().isProducerSignatureEnforced()).toBe(true);
    await handle.stop();
  });

  it("FAILS CLOSED when a key is expected but unreadable (never channel basis)", async () => {
    const dir = join(tmp, "policy", "egress");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "audit-producer.pub"), Buffer.from([9, 9, 9]));
    await expect(
      startNoHandshake({
        fortressStoragePath: tmp,
        producerKeyLoadOptions: LINUX_PRODUCER_KEY_LOAD,
      }),
    ).rejects.toThrow(/expected but unreadable/);
  });

  it("absent key → consumer stays on the channel basis (macOS / pre-provision floor)", async () => {
    // No key file published → absent → channel basis, NOT a refusal.
    const handle = await startToRunning({
      fortressStoragePath: tmp,
      producerKeyLoadOptions: LINUX_PRODUCER_KEY_LOAD,
    });
    expect(handle.state()).toBe("running");
    expect(handle.audit().isProducerSignatureEnforced()).toBe(false);
    await handle.stop();
  });

  it("DIVERGENCE-PROOF: passing BOTH a storage path AND an explicit key is rejected", async () => {
    // codex MEDIUM #3: two sources of truth for one key would let a caller pin
    // the consumer to a different basis than the reader. Refuse the ambiguity.
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await publishPubKey(tmp, pub);
    const pubB64 = toBase64url(
      ed25519.getPublicKey(ed25519.utils.randomPrivateKey()),
    );
    await expect(
      startNoHandshake({
        fortressStoragePath: tmp,
        producerKeyLoadOptions: LINUX_PRODUCER_KEY_LOAD,
        pinnedProducerKeyB64url: pubB64,
      }),
    ).rejects.toThrow(/not both/);
  });

  it("storage path is AUTHORITATIVE: an explicit null does NOT downgrade a present key", async () => {
    // A caller passing null alongside a storage path that HAS a key must still
    // get the present key (the consumer can never be weaker than the reader).
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await publishPubKey(tmp, pub);
    const handle = await startToRunning({
      fortressStoragePath: tmp,
      producerKeyLoadOptions: LINUX_PRODUCER_KEY_LOAD,
      pinnedProducerKeyB64url: null,
    });
    expect(handle.state()).toBe("running");
    expect(handle.audit().isProducerSignatureEnforced()).toBe(true);
    await handle.stop();
  });

  it("path-less explicit key is still honored (tests / self-resolving callers)", async () => {
    const pubB64 = toBase64url(
      ed25519.getPublicKey(ed25519.utils.randomPrivateKey()),
    );
    const handle = await startToRunning({ pinnedProducerKeyB64url: pubB64 });
    expect(handle.state()).toBe("running");
    expect(handle.audit().isProducerSignatureEnforced()).toBe(true);
    await handle.stop();
  });
});

describe("Slice P — reader activation end-to-end (provisioned key on disk)", () => {
  it("(1) a mock-signed event re-verifies GREEN once the key is loaded", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    expect(load.status).toBe("present");
    const keyB64 = load.status === "present" ? load.keyB64url : null;

    const log = newLog();
    await appendGenuineSigned(log, priv, 1);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: keyB64,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("producer_signed");
  });

  it("(2) a forged in-process entry is NON-green BECAUSE the key is loaded (not key-null)", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    const keyB64 = load.status === "present" ? load.keyB64url : null;

    const log = newLog();
    await appendForgedMarkerOnly(log);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: keyB64,
    });
    // The forged entry claims producer_signed but carries no valid signature;
    // with the key loaded it fails re-verify and does NOT arm.
    expect(posture.arm_state).not.toBe("armed");
  });

  it("(3) Linux / no-key path: a channel-basis event still arms (floor preserved)", async () => {
    // No key file published → absent → channel basis.
    const load = await loadFortressProducerKey(tmp, {
      platform: "linux",
      macosProducerPubKeyPath: join(tmp, "missing", "castle-audit-producer.pub"),
    });
    expect(load.status).toBe("absent");
    const log = newLog();
    // A genuine signed entry still arms on the channel basis when no key is set
    // (the reader does not require re-verification without a pinned key).
    await appendGenuineSigned(log, ed25519.utils.randomPrivateKey(), 1);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: null,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("channel_authenticated");

    const cappedByAvailability = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: null,
      enforcementAvailability: UNDETERMINED_AVAILABILITY,
    });
    expect(cappedByAvailability.arm_state).toBe("unknown");
    expect(cappedByAvailability.producer_authenticity).toBe("not_applicable");
  });

  it("(4) key published-but-unreadable → reader fails HONESTLY (degraded, never channel-green)", async () => {
    const log = newLog();
    // Even with a genuine-looking signed entry present, the expected-but-unreadable
    // signal forces a non-armed degraded posture (never green on the channel basis).
    await appendGenuineSigned(log, ed25519.utils.randomPrivateKey(), 1);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: null,
      producerKeyExpectedButUnavailable: true,
    });
    expect(posture.arm_state).toBe("degraded");
    expect(posture.evidence_basis).toBe("producer_key_unavailable");
    expect(posture.producer_authenticity).toBe("not_applicable");
  });

  it("(5) explicit rotation: a NEW published key verifies events signed by the NEW key", async () => {
    // Rotate: publish a second keypair (explicit overwrite at provisioning time).
    const newPriv = ed25519.utils.randomPrivateKey();
    const newPub = ed25519.getPublicKey(newPriv);
    await publishPubKey(tmp, newPub);
    const load = await loadFortressProducerKey(tmp, LINUX_PRODUCER_KEY_LOAD);
    const keyB64 = load.status === "present" ? load.keyB64url : null;

    const log = newLog();
    await appendGenuineSigned(log, newPriv, 7);
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: SUBJECT,
      auditLog: log,
      originMachine: "m",
      platform: "linux",
      now: NOW,
      pinnedProducerKeyB64url: keyB64,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("producer_signed");
  });
});
