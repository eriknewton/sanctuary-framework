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
  AuditConsumer,
  type AuditSink,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import type { IpcClient } from "../../../src/castle-wall/runtime/ipc-client.js";
import type { AuditDrainResponse } from "../../../src/castle-wall/ipc/messages.js";
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

  // ── FIX 5 (codex MEDIUM): systemd unit injection guard ──────────────────
  it("QUOTES a storage path with whitespace (stays one ExecStart/ReadWritePaths token)", () => {
    const conf = renderProducerKeyDropIn({
      fortressId: "fortress:test",
      fortressStoragePath: "/srv/my fortress",
    });
    // A space in the path must be quoted everywhere it appears so systemd does
    // not split it into two tokens / two paths.
    expect(conf).toContain('--policy-dir "/srv/my fortress/policy/egress"');
    expect(conf).toContain('ReadWritePaths="/srv/my fortress/policy/egress"');
  });

  it("REJECTS a storage path containing a newline (injection guard)", () => {
    expect(() =>
      renderProducerKeyDropIn({
        fortressId: "fortress:test",
        fortressStoragePath: "/srv/x\nExecStart=/bin/sh -c evil",
      })
    ).toThrow(RuntimeLinuxActivationError);
    expect(() =>
      renderProducerKeyDropIn({
        fortressId: "fortress:test",
        fortressStoragePath: "/srv/x\nExecStart=/bin/sh -c evil",
      })
    ).toThrow(/control character/i);
  });

  it("REJECTS a fortress id containing a newline / control char (injection guard)", () => {
    expect(() =>
      renderProducerKeyDropIn({
        fortressId: "fortress\nUser=root",
        fortressStoragePath: "/srv/fortress",
      })
    ).toThrow(/control character/i);
  });

  it("REJECTS a RELATIVE storage path (must be absolute + normalized)", () => {
    expect(() =>
      renderProducerKeyDropIn({
        fortressId: "fortress:test",
        fortressStoragePath: "relative/fortress",
      })
    ).toThrow(/absolute path/i);
  });

  it("REJECTS a storage path with a .. traversal segment", () => {
    expect(() =>
      renderProducerKeyDropIn({
        fortressId: "fortress:test",
        fortressStoragePath: "/srv/../etc/fortress",
      })
    ).toThrow(/traversal/i);
  });

  it("REJECTS a control char in the (test-only) unit name and drop-in filename", async () => {
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();
    await expect(
      launchLinuxCastleWallDaemon({
        fortressId: "fortress:test",
        fortressStoragePath: tmp,
        systemctl: runner,
        fs,
        unit: "evil\nWantedBy=multi-user.target",
        dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
      })
    ).rejects.toThrow(/control character/i);
    await expect(
      launchLinuxCastleWallDaemon({
        fortressId: "fortress:test",
        fortressStoragePath: tmp,
        systemctl: runner,
        fs,
        dropInDir: "/etc/systemd/system/sanctuary-castle-wall.service.d",
        dropInFileName: "../escape.conf",
      })
    ).rejects.toThrow(/bare basename/i);
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

  it("(c2) Linux + opt-in + ABSENT key: FAIL-CLOSED (never channel basis, never armed) — codex CRITICAL FIX 1", async () => {
    // FIX 1: on the OPTED-IN Linux path a published producer key is REQUIRED. An
    // absent key after the daemon launches must THROW (not-armed), never report
    // `activated: true` on the (weaker) channel basis — that would be a fake-green
    // armed-but-not-enforcing state. (Absent-key WITHOUT opt-in legitimately stays
    // channel-basis; that case never reaches this gate at all.)
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = buildMockDaemon([]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    // No pubkey published → loadFortressProducerKey = absent → fail-closed throw.
    let thrown: unknown;
    try {
      await maybeActivateLinuxProducerSignedCastleWall({
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
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RuntimeLinuxActivationError);
    expect((thrown as RuntimeLinuxActivationError).reason).toBe("producer_key_absent");
    expect((thrown as Error).message).toMatch(/not armed/i);
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

describe("C4 — FIX 2 (codex CRITICAL): drain never acks past an UNPERSISTED event", () => {
  /** A sink that fails the FIRST enforcement-evidence append, then succeeds. */
  class PersistFailsOnceSink implements AuditSink {
    entries: Array<{ operation: string; details?: Record<string, unknown> }> = [];
    private failedOnce = false;
    append(
      _layer: "l1",
      operation: string,
      _identityId: string,
      details?: Record<string, unknown>,
    ): void {
      if (
        !this.failedOnce &&
        (operation === "egress_blocked" || operation === "egress_allowed")
      ) {
        this.failedOnce = true;
        throw new Error("audit disk unavailable (transient)");
      }
      this.entries.push({ operation, details });
    }
    async flush(): Promise<void> {}
  }

  /** A minimal fake IpcClient that serves a fixed batch once and records acks. */
  function fakeClient(events: AuditDrainEvent[]): {
    client: IpcClient;
    acks: number[];
  } {
    const acks: number[] = [];
    let served = false;
    const client = {
      async drainRequest(): Promise<AuditDrainResponse> {
        const batch = served ? [] : events;
        served = true;
        return {
          events: batch,
          next_after_seq:
            batch.length > 0 ? batch[batch.length - 1]!.seq : null,
          more_pending: false,
          wal_overflow_count: 0,
        } as AuditDrainResponse;
      },
      async sendDrainAck(seq: number): Promise<void> {
        acks.push(seq);
      },
    } as unknown as IpcClient;
    return { client, acks };
  }

  it("BREAKs the batch on a transient persist failure — never acks the next seq (no WAL truncation)", async () => {
    // No pinned key on the consumer → events accepted on the channel basis, so we
    // isolate the persistence-failure + ack behavior (not the signature gate).
    const sink = new PersistFailsOnceSink();
    const consumer = new AuditConsumer(sink);
    // seq 1 persist FAILS (PersistFailsOnceSink throws the first enforcement
    // append). The loop must BREAK before ever touching seq 2, so seq 2's exact
    // prior-hash is irrelevant — what matters is it is never acked.
    const { client, acks } = fakeClient([
      forgedDrainEvent(1, null),
      forgedDrainEvent(2, null),
    ]);

    const errors: Error[] = [];
    const res = await drainOnce(client, consumer, null, 256, (e) => errors.push(e));

    // seq 1 failed to persist → NOT acked; the loop BROKE so seq 2 was never
    // even ingested → also NOT acked. The daemon will re-deliver from seq 1.
    expect(acks).not.toContain(1);
    expect(acks).not.toContain(2);
    expect(acks).toHaveLength(0);
    expect(res.drained).toBe(0);
    expect(res.nextAfterSeq).toBeNull();
    // The transient failure surfaced via onError.
    expect(errors.some((e) => /transient/.test(e.message))).toBe(true);
    // And the consumer never accepted either enforcement event.
    expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
  });

  it("CONTINUES the batch when an event SETTLES (a refused forgery is acked, later events still flow)", async () => {
    // Contrast case: a forgery is durably refused + acked (it settled), so the
    // loop keeps going and a following genuine event is still pulled. This proves
    // the BREAK is scoped to UN-settled (transient) failures, not every throw.
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const { loadFortressProducerKey } = await import(
      "../../../src/castle-wall/runtime/producer-signature.js"
    );
    const load = await loadFortressProducerKey(tmp);
    expect(load.status).toBe("present");
    if (load.status !== "present") return;
    const consumer = new AuditConsumer(auditLog, undefined, {
      pinnedProducerKeyB64url: load.keyB64url,
    });
    // seq 1 forged (refused+acked → settles), seq 2 genuine (accepted+acked).
    const { client, acks } = fakeClient([
      forgedDrainEvent(1, null),
      signedDrainEvent(priv, 2, null),
    ]);
    const res = await drainOnce(client, consumer, null, 256, () => {});
    // Both settled → both acked; the loop did NOT break on the refused forgery.
    expect(acks).toContain(1);
    expect(acks).toContain(2);
    expect(res.drained).toBe(2);
    expect(consumer.getStats().producerSignatureRejections).toBe(1);
    expect(consumer.getStats().producerSignatureAccepted).toBe(1);
  });
});

describe("C4 — FIX 4 (codex HIGH): drain transport failure trips NOT-ARMED (never silently armed)", () => {
  it("a drain transport failure marks the activation unhealthy + records a durable not-armed signal", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    await publishPubKey(tmp, pub);

    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    // Spy on the audit sink so we can assert the durable not-armed record.
    const appended: string[] = [];
    const origAppend = auditLog.append.bind(auditLog);
    (auditLog as unknown as { append: AuditSink["append"] }).append = ((
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      appended.push(operation);
      return origAppend(layer, operation, id, details, result);
    }) as AuditSink["append"];

    const mock = buildMockDaemon([]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    // Deterministic timer: capture each scheduled cycle callback instead of
    // letting it auto-fire, so we control exactly when the (wedged) cycle runs.
    const scheduled: Array<() => void> = [];
    const unhealthyErrors: Error[] = [];

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
      drainOptions: {
        pollIntervalMs: 10_000,
        setTimer: (cb) => {
          scheduled.push(cb as () => void);
          return scheduled.length;
        },
        clearTimer: () => {},
      },
      onDrainUnhealthy: (e) => unhealthyErrors.push(e),
    });
    // The handshake completes via sendChallenge while activation is in-flight.
    await mock.sendChallenge();
    const outcome = await outcomeP;
    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;
    expect(outcome.activation.drainHealthy()).toBe(true); // healthy before any failure

    // Drain the first (healthy, empty) cycle so its scheduled follow-up exists.
    for (let i = 0; i < 50 && scheduled.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    expect(scheduled.length).toBeGreaterThanOrEqual(1);

    // Wedge the daemon link: every drainRequest now throws.
    const client = outcome.activation.lifecycle.client();
    (client as unknown as { drainRequest: () => Promise<never> }).drainRequest =
      async () => {
        throw new Error("daemon link dropped");
      };
    // Fire the next scheduled cycle: it hits the wedged link → onError →
    // markDrainUnhealthy. Await the loop's in-flight settle.
    scheduled[scheduled.length - 1]!();
    for (let i = 0; i < 50 && outcome.activation.drainHealthy(); i++) {
      await new Promise((r) => setTimeout(r, 1));
    }

    // The drain failure must have tripped the health transition + durable record.
    expect(outcome.activation.drainHealthy()).toBe(false);
    expect(unhealthyErrors.length).toBeGreaterThanOrEqual(1);
    expect(unhealthyErrors[0]!.message).toMatch(/daemon link dropped/);
    expect(appended).toContain("castle_wall_drain_failed");

    await outcome.activation.stop();
  });
});
