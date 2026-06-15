/**
 * C4 (tamper-proof half) — end-to-end Linux producer-signed activation.
 *
 * Slice L1/R/P built the producer-signing daemon + the re-verifying consumer +
 * the single-source key loader, but nothing in PRODUCTION launched the daemon
 * with the key flags, bound a transport, or ran the drain pull-loop that feeds
 * signed events into the consumer. This suite exercises that now-built path
 * (`linux-daemon.ts` launcher + `linux-audit-drain.ts` pull-loop +
 * `linux-activation-gate.ts` opt-in/fail-closed gate) end-to-end against a mock
 * systemd + a mock daemon that serves real `audit_drain_response` frames.
 *
 * The four pre-declared acceptance cases (spec P-4):
 *   (a) a real daemon-signed event re-verifies GREEN because the key is now
 *       loaded via the launcher (consumer ACCEPTS the producer signature);
 *   (b) a forged in-process entry renders NON-green BECAUSE the key is loaded
 *       (consumer REJECTS it — not key-null);
 *   (c) macOS / no-key path stays on the channel basis (no regression);
 *   (d) fail-closed when the daemon won't start or the key is unreadable
 *       (activation THROWS → not-armed, never green, never channel fallback).
 *
 * DRILL-ACCEPTANCE NOTE: this is test/smoke coverage. The production-arm
 * capability claim still requires a CAPTURED DRILL on real Linux hardware.
 */

import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type {
  AuditDrainEvent,
  CastleWallMessage,
} from "../../../src/castle-wall/ipc/messages.js";
import type { IpcTransport } from "../../../src/castle-wall/runtime/ipc-client.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";
import {
  renderProducerKeyDropIn,
  launchLinuxCastleWallDaemon,
  type SystemctlRunner,
  type LauncherFs,
} from "../../../src/castle-wall/runtime/linux-daemon.js";
import {
  buildCriticalEnvelopeFromDrainEvent,
  drainOnce,
} from "../../../src/castle-wall/runtime/linux-audit-drain.js";
import {
  maybeActivateLinuxProducerSignedCastleWall,
  isLinuxProducerSignedActivationRequested,
  LINUX_PRODUCER_SIGNED_ACTIVATION_ENV,
} from "../../../src/castle-wall/runtime/linux-activation-gate.js";
import { RuntimeLinuxActivationError } from "../../../src/castle-wall/runtime/errors.js";

// The audit consumer's freshness gate compares the signed `captured_at_unix_ms`
// against the REAL `Date.now()` (no clock injection through the lifecycle path),
// so signed events must carry a timestamp fresh relative to wall-clock — exactly
// as a real daemon signing with its own clock would. Compute per-call so the
// suite stays deterministic even under a slow CI runner.
function freshNow(): number {
  return Date.now() - 1000;
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Write the daemon-published pubkey file exactly as the Rust daemon does. */
async function publishPubKey(storage: string, pubBytes: Uint8Array): Promise<void> {
  const dir = join(storage, "policy", "egress");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "audit-producer.pub"), Buffer.from(pubBytes));
}

/** The daemon's signed WAL body (canonical JSON) for one enforcement event. */
function walBody(freshTs: number): string {
  return JSON.stringify({
    timestamp: new Date(freshTs).toISOString(),
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "fortress:test",
    fortress_id: "fortress:test",
    result: "blocked",
    details: { agent_id: "agent-1", dest_host: "evil.example" },
  });
}

/** A genuine daemon-signed drain event (signed with the daemon's priv key). */
function signedDrainEvent(
  priv: Uint8Array,
  seq: number,
  priorHash: string | null
): AuditDrainEvent {
  const freshTs = freshNow();
  const canonical = walBody(freshTs);
  const sig = ed25519.sign(producerSigningBytes(canonical, freshTs, seq), priv);
  return {
    seq,
    captured_at_unix_ms: freshTs,
    prior_sha256_hex: priorHash,
    event_canonical_json: canonical,
    critical: true,
    producer_signature_b64url: toBase64url(sig),
    producer_key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  };
}

/** A forged drain event: claims producer_signed but carries NO valid signature. */
function forgedDrainEvent(seq: number, priorHash: string | null): AuditDrainEvent {
  const freshTs = freshNow();
  const canonical = walBody(freshTs);
  return {
    seq,
    captured_at_unix_ms: freshTs,
    prior_sha256_hex: priorHash,
    event_canonical_json: canonical,
    critical: true,
    // No signature, but the key-id is present (the forger mimics the marker).
    producer_signature_b64url: null,
    producer_key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  };
}

/**
 * In-process mock Linux daemon: completes the handshake and serves a scripted
 * queue of drain events in response to `audit_drain_request`, then `more_pending`
 * goes false. Records the acks it receives so tests assert WAL truncation.
 */
function buildMockDaemon(drainQueue: AuditDrainEvent[]): {
  transport: IpcTransport;
  sendChallenge: () => Promise<void>;
  acks: number[];
} {
  let listener: ((bytes: Uint8Array) => void) | null = null;
  let buffer = new Uint8Array(0);
  const acks: number[] = [];
  let served = false;

  const emit = (msg: CastleWallMessage): void => {
    if (!listener) throw new Error("mock daemon: no listener attached");
    listener(
      frame(
        JSON.stringify({
          jsonrpc: "2.0",
          method: `castle-wall.${msg.type}`,
          params: msg,
        })
      )
    );
  };

  const handleEnvelope = (body: string): void => {
    const env = JSON.parse(body) as { params?: CastleWallMessage };
    const msg = env.params;
    if (!msg || typeof msg !== "object") return;
    if (msg.type === "audit_drain_request") {
      // Serve the whole queue in one batch, then more_pending=false.
      const events = served ? [] : drainQueue;
      served = true;
      emit({
        type: "audit_drain_response",
        request_id: msg.request_id,
        events,
        next_after_seq: events.length > 0 ? events[events.length - 1]!.seq : (msg.after_seq ?? null),
        more_pending: false,
        wal_overflow_count: 0,
      });
    } else if (msg.type === "audit_drain_ack") {
      acks.push(msg.last_acked_seq);
    }
    // handshake_response + lock/unlock are accepted silently.
  };

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
            const body = step.body;
            buffer = new Uint8Array(buffer.subarray(step.consumedBytes));
            handleEnvelope(body);
          } else if (step.kind === "need_more") {
            break;
          } else {
            throw new Error(`mock daemon framing error: ${step.reason}`);
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
    sendChallenge: async () => {
      for (let i = 0; i < 500 && !listener; i++) {
        await new Promise((r) => setTimeout(r, 1));
      }
      if (!listener) throw new Error("mock daemon: listener never attached");
      emit({ type: "handshake_challenge", nonce_b64url: "AAEC" });
    },
    acks,
  };
}

/** A systemctl runner that reports the unit active (the happy path). */
function activeSystemctl(): { runner: SystemctlRunner; calls: string[][] } {
  const calls: string[][] = [];
  return {
    runner: {
      run: async (args) => {
        calls.push(args);
        if (args[0] === "is-active") {
          return { code: 0, stdout: "active\n", stderr: "" };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
    },
    calls,
  };
}

/** A systemctl runner whose unit FAILS to start (is-active returns failed). */
function failingSystemctl(): SystemctlRunner {
  return {
    run: async (args) => {
      if (args[0] === "is-active") {
        return { code: 3, stdout: "failed\n", stderr: "" };
      }
      if (args[0] === "restart") {
        return { code: 1, stdout: "", stderr: "Job for sanctuary-castle-wall.service failed" };
      }
      return { code: 0, stdout: "", stderr: "" };
    },
  };
}

/** An in-memory LauncherFs so the launcher never touches the host /etc. */
function memoryFs(): { fs: LauncherFs; files: Map<string, string> } {
  const files = new Map<string, string>();
  return {
    fs: {
      mkdir: async () => {},
      writeFile: async (path, contents) => {
        files.set(path, contents);
      },
      chmod: async () => {},
    },
    files,
  };
}

let tmp: string;
let identityEncKey: Uint8Array;

beforeEach(async () => {
  tmp = await mkdtemp(join(tmpdir(), "c4-linux-"));
  identityEncKey = derivePurposeKey(generateRandomKey(), "identity-encryption");
  delete process.env[LINUX_PRODUCER_SIGNED_ACTIVATION_ENV];
});

afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
  delete process.env[LINUX_PRODUCER_SIGNED_ACTIVATION_ENV];
});

function keyMaterial() {
  const { storedIdentity } = createIdentity("c4-linux", identityEncKey, "passphrase");
  return {
    fortressId: "fortress:test",
    signingKeyId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    encryptionKey: identityEncKey,
  };
}

describe("C4 — opt-in gate (off by default, never surprise default-on)", () => {
  it("is OFF by default (no env flag → not requested)", () => {
    expect(isLinuxProducerSignedActivationRequested({ env: {} })).toBe(false);
  });

  it("requires the explicit capability flag = '1'", () => {
    expect(
      isLinuxProducerSignedActivationRequested({
        env: { [LINUX_PRODUCER_SIGNED_ACTIVATION_ENV]: "1" },
      })
    ).toBe(true);
    expect(
      isLinuxProducerSignedActivationRequested({
        env: { [LINUX_PRODUCER_SIGNED_ACTIVATION_ENV]: "true" },
      })
    ).toBe(false);
  });

  it("gate returns not_opted_in (no activation) when the flag is absent", async () => {
    const outcome = await maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: new AuditLog(new MemoryStorage(), generateRandomKey()),
      platform: "linux",
      env: {},
    });
    expect(outcome.activated).toBe(false);
    if (!outcome.activated) expect(outcome.reason).toBe("not_opted_in");
  });
});

describe("C4 — P-1 launcher: systemd drop-in renders + verifies active", () => {
  it("renders a drop-in that clears + re-states ExecStart with the key flags", () => {
    const conf = renderProducerKeyDropIn({
      fortressId: "fortress:test",
      fortressStoragePath: "/srv/fortress",
    });
    // Must clear the inherited ExecStart (blank) before re-stating it.
    expect(conf).toContain("ExecStart=\n");
    // Must splice the producer-key flags pointing at the TS read path.
    expect(conf).toContain("--producer-pub-key /srv/fortress/policy/egress/audit-producer.pub");
    expect(conf).toContain("--producer-key /srv/fortress/policy/egress/audit-producer.key");
    expect(conf).toContain("--policy-dir /srv/fortress/policy/egress");
    expect(conf).toContain("--fortress-id fortress:test");
    // Must grant the hardened daemon write access to the egress dir.
    expect(conf).toContain("ReadWritePaths=/srv/fortress/policy/egress");
  });

  it("installs the drop-in, reloads, restarts, and VERIFIES is-active", async () => {
    const { runner, calls } = activeSystemctl();
    const { fs, files } = memoryFs();
    const result = await launchLinuxCastleWallDaemon({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      systemctl: runner,
      fs,
      dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
    });
    expect(result.active).toBe(true);
    expect(files.size).toBe(1);
    // The orchestration order: daemon-reload → restart → is-active.
    expect(calls.map((c) => c[0])).toEqual(["daemon-reload", "restart", "is-active"]);
  });
});

describe("C4 — P-2 drain mapping: drain event → critical envelope with producer", () => {
  it("populates envelope.producer from the wire signature fields", () => {
    const priv = ed25519.utils.randomPrivateKey();
    const drained = signedDrainEvent(priv, 1, null);
    const built = buildCriticalEnvelopeFromDrainEvent(drained, async () => {});
    expect(built.kind).toBe("ok");
    if (built.kind !== "ok") return;
    expect(built.envelope.event.event_type).toBe("egress_blocked");
    expect(built.envelope.event.details.seq).toBe(1);
    expect(built.envelope.producer?.signatureB64url).toBe(drained.producer_signature_b64url);
    expect(built.envelope.producer?.eventCanonicalJson).toBe(drained.event_canonical_json);
    expect(built.envelope.producer?.seq).toBe(1);
    expect(built.envelope.producer?.capturedAtUnixMs).toBe(drained.captured_at_unix_ms);
  });
});

describe("C4 — P-4 end-to-end (a)-(d), deterministic", () => {
  it("(a) a real daemon-signed event re-verifies GREEN once the key is loaded via the launcher", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);

    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = buildMockDaemon([signedDrainEvent(priv, 1, null)]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    const outcomeP = maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: auditLog,
      platform: "linux",
      explicitOptIn: true,
      systemctl: runner,
      fs,
      dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
      connectTransport: async () => mock.transport,
      startDrainLoop: false, // drive drain manually for determinism
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;
    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;

    // The consumer resolved the published key and is ENFORCING (not key-null).
    expect(outcome.activation.lifecycle.audit().isProducerSignatureEnforced()).toBe(true);

    // Drive ONE drain cycle: pull the signed event into the consumer.
    const res = await drainOnce(
      outcome.activation.lifecycle.client(),
      outcome.activation.lifecycle.audit(),
      null,
      256
    );
    expect(res.drained).toBe(1);
    const stats = outcome.activation.lifecycle.audit().getStats();
    expect(stats.producerSignatureAccepted).toBe(1);
    expect(stats.producerSignatureRejections).toBe(0);
    // The daemon was acked through seq 1 (WAL truncation point).
    expect(mock.acks).toContain(1);

    await outcome.activation.stop();
  });

  it("(b) a forged in-process entry is NON-green BECAUSE the key is loaded (rejected, not accepted)", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);

    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = buildMockDaemon([forgedDrainEvent(1, null)]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    const outcomeP = maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: auditLog,
      platform: "linux",
      explicitOptIn: true,
      systemctl: runner,
      fs,
      dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
      connectTransport: async () => mock.transport,
      startDrainLoop: false,
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;
    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;
    expect(outcome.activation.lifecycle.audit().isProducerSignatureEnforced()).toBe(true);

    // Drive the drain: the forged event must be REJECTED (not key-null pass).
    const res = await drainOnce(
      outcome.activation.lifecycle.client(),
      outcome.activation.lifecycle.audit(),
      null,
      256
    );
    const stats = outcome.activation.lifecycle.audit().getStats();
    expect(stats.producerSignatureRejections).toBe(1);
    expect(stats.producerSignatureAccepted).toBe(0);
    expect(stats.acceptedCriticalEvents).toBe(0);
    // The refusal is durably recorded → the loop acks past it (re-delivery is
    // pointless), so the cursor advanced and the daemon was acked through seq 1.
    expect(res.drained).toBe(1);
    expect(mock.acks).toContain(1);

    await outcome.activation.stop();
  });

  it("(c) macOS / no-key path: gate refuses on macOS (channel basis preserved, no regression)", async () => {
    // The producer-signed close is Linux-only. On macOS the gate must refuse to
    // run the systemd launcher; the caller keeps the macOS channel basis.
    const outcome = await maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: new AuditLog(new MemoryStorage(), generateRandomKey()),
      platform: "darwin",
      explicitOptIn: true, // even opted-in, macOS is gated out
    });
    expect(outcome.activated).toBe(false);
    if (!outcome.activated) expect(outcome.reason).toBe("not_linux");
  });

  it("(c2) Linux + absent key: consumer stays on the channel basis (pre-provision floor, not a failure)", async () => {
    // No pubkey published → loadFortressProducerKey = absent → channel basis.
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = buildMockDaemon([]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    const outcomeP = maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: auditLog,
      platform: "linux",
      explicitOptIn: true,
      systemctl: runner,
      fs,
      dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
      connectTransport: async () => mock.transport,
      startDrainLoop: false,
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;
    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;
    // Absent key → NOT enforcing (channel basis), but NOT a refusal: the daemon
    // is up and the lifecycle is running.
    expect(outcome.activation.lifecycle.audit().isProducerSignatureEnforced()).toBe(false);
    expect(outcome.activation.lifecycle.state()).toBe("running");
    await outcome.activation.stop();
  });

  it("(d) FAIL-CLOSED when the daemon will not start (not-armed, never green, never channel fallback)", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
    const { fs } = memoryFs();

    await expect(
      maybeActivateLinuxProducerSignedCastleWall({
        fortressId: "fortress:test",
        fortressStoragePath: tmp,
        key: keyMaterial(),
        auditSink: new AuditLog(new MemoryStorage(), generateRandomKey()),
        platform: "linux",
        explicitOptIn: true,
        systemctl: failingSystemctl(),
        fs,
        dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
        connectTransport: async () => buildMockDaemon([]).transport,
      })
    ).rejects.toThrow(RuntimeLinuxActivationError);
  });

  it("(d2) FAIL-CLOSED when a key is expected but UNREADABLE (never channel basis)", async () => {
    // Publish a malformed (wrong-length) key: loadFortressProducerKey =
    // unreadable → startCastleWall throws → activation surfaces not-armed.
    const dir = join(tmp, "policy", "egress");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "audit-producer.pub"), Buffer.from([1, 2, 3]));
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    await expect(
      maybeActivateLinuxProducerSignedCastleWall({
        fortressId: "fortress:test",
        fortressStoragePath: tmp,
        key: keyMaterial(),
        auditSink: new AuditLog(new MemoryStorage(), generateRandomKey()),
        platform: "linux",
        explicitOptIn: true,
        systemctl: runner,
        fs,
        dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
        // Provide a transport so we reach startCastleWall (which throws on unreadable).
        connectTransport: async () => buildMockDaemon([]).transport,
        startDrainLoop: false,
      })
    ).rejects.toThrow(/unreadable|not armed|fail-closed/i);
  });
});
