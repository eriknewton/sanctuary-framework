/**
 * C4 (tamper-proof half) - deterministic Linux producer-signed binding harness.
 *
 * This suite exercises the binding half of the Linux path against mock systemd
 * and a mock daemon transport. The signed event bodies come from the Rust audit
 * builder fixture, not from a live privileged Linux daemon drain. The Linux
 * manifest-publication half that stamps `agent_origin` does not exist yet, so
 * this test suite does not claim live Linux green or S5 drill success.
 *
 * The four pre-declared acceptance cases (spec P-4):
 *   (a) a Rust-builder event signed by the mock daemon key re-verifies GREEN in
 *       this harness when the claim subject matches;
 *   (b) a forged in-process entry renders NON-green BECAUSE the key is loaded
 *       (consumer REJECTS it — not key-null);
 *   (c) macOS / no-key path stays on the channel basis (no regression);
 *   (d) fail-closed when the daemon won't start or the key is unreadable
 *       (activation THROWS → not-armed, never green, never channel fallback).
 *
 * DRILL-ACCEPTANCE NOTE: this is test/smoke coverage only. No Linux capability
 * claim is made until the missing publication half is implemented and drilled on
 * real Linux hardware.
 */

import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

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
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { buildCastleWallPosture } from "../../../src/principal-policy/posture.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_DRAIN_FAULT_UNSIGNED,
} from "../../../src/castle-wall/constants.js";
import { verifiedCastleWallAuditAttribution } from "../../../src/castle-wall/audit-attribution.js";
import type { AuditEntry } from "../../../src/operational/audit-log.js";
import {
  renderProducerKeyDropIn,
  launchLinuxCastleWallDaemon,
  type SystemctlRunner,
  type LauncherFs,
} from "../../../src/castle-wall/runtime/linux-daemon.js";
import {
  buildCriticalEnvelopeFromDrainEvent,
  drainOnce,
  startLinuxAuditDrainLoop,
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

type LinuxDaemonAuditFixtureKey = "uid_503" | "uid_504" | "old_agent_name";
const daemonManifestPath = fileURLToPath(
  new URL("../../../../castle-wall-daemon/Cargo.toml", import.meta.url),
);
const RUST_POLICY_TEST_TIMEOUT_MS = 120_000;
const linuxDaemonAuditFixtures = JSON.parse(
  readFileSync(
    new URL(
      "../fixtures/linux-daemon-canonical-subject-audit-vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as Record<LinuxDaemonAuditFixtureKey, string> & {
  captured_by: string;
  captured_from: string;
  captured_at_note: string;
};

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

/** Captured daemon audit-builder canonical JSON for one enforcement event. */
function walBody(
  fixture: LinuxDaemonAuditFixtureKey = "uid_503",
): string {
  return linuxDaemonAuditFixtures[fixture];
}

/** A valid mock-signed drain event using the daemon-key test fixture. */
function signedDrainEvent(
  priv: Uint8Array,
  seq: number,
  priorHash: string | null,
  fixture: LinuxDaemonAuditFixtureKey = "uid_503",
): AuditDrainEvent {
  const freshTs = freshNow();
  const canonical = walBody(fixture);
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
function forgedDrainEvent(
  seq: number,
  priorHash: string | null,
  fixture: LinuxDaemonAuditFixtureKey = "uid_503",
): AuditDrainEvent {
  const freshTs = freshNow();
  const canonical = walBody(fixture);
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

async function activateAndDrainCapturedFixture(input: {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  fixture: LinuxDaemonAuditFixtureKey;
}): Promise<{
  auditLog: AuditLog;
  stop: () => Promise<void>;
  pinnedProducerKeyB64url: string;
}> {
  await publishPubKey(tmp, input.publicKey);
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  const mock = buildMockDaemon([
    signedDrainEvent(input.privateKey, 1, null, input.fixture),
  ]);
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
  if (!outcome.activated) throw new Error("linux activation did not arm");

  const drainResult = await drainOnce(
    outcome.activation.lifecycle.client(),
    outcome.activation.lifecycle.audit(),
    null,
    256,
  );
  expect(drainResult.drained).toBe(1);
  expect(mock.acks).toContain(1);

  return {
    auditLog,
    stop: () => outcome.activation.stop(),
    pinnedProducerKeyB64url: toBase64url(input.publicKey),
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
    expect(built.envelope.event.fortress_id).toBe("fortress:test");
    expect(built.envelope.event.details.seq).toBe(1);
    expect(built.envelope.producer?.signatureB64url).toBe(drained.producer_signature_b64url);
    expect(built.envelope.producer?.eventCanonicalJson).toBe(drained.event_canonical_json);
    expect(built.envelope.producer?.seq).toBe(1);
    expect(built.envelope.producer?.capturedAtUnixMs).toBe(drained.captured_at_unix_ms);
    expect(built.envelope.producerSubjectBinding).toEqual({
      kind: "signed_identity_id",
    });
  });
});

describe("C4 — P-4 end-to-end (a)-(d), deterministic", () => {
  it("(a) Rust policy refuses system uid origins before canonical subject audit emission", () => {
    const output = execFileSync(
      "cargo",
      [
        "test",
        "snapshot_refuses_uid_mode_agent_origin_below_system_uid_ceiling",
        "--manifest-path",
        daemonManifestPath,
      ],
      { encoding: "utf8", timeout: RUST_POLICY_TEST_TIMEOUT_MS },
    );

    expect(output).toContain(
      "snapshot_refuses_uid_mode_agent_origin_below_system_uid_ceiling",
    );
    expect(output).toContain("test result: ok.");
    expect(output).toContain("1 passed");
  }, RUST_POLICY_TEST_TIMEOUT_MS);

  it("(a) a mock-signed Rust-builder event re-verifies GREEN once the key is loaded via the launcher", async () => {
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

    const posture = await buildCastleWallPosture({
      protectionClaimSubject: "fortress:test/uid-503",
      auditLog,
      originMachine: "fortress:test",
      platform: "linux",
      now: Date.now(),
      pinnedProducerKeyB64url: toBase64url(pub),
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.producer_authenticity).toBe("producer_signed");
    expect(posture.verdict_counts.blocked).toBe(1);

    await outcome.activation.stop();
  });

  it("(a-c) subject-bound Linux evidence greens only for the correct confined uid and refuses both relabel directions", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const cases: Array<{
      fixture: LinuxDaemonAuditFixtureKey;
      signedSubject: string;
      wrongClaim: string;
    }> = [
      {
        fixture: "uid_503",
        signedSubject: "fortress:test/uid-503",
        wrongClaim: "fortress:test/uid-504",
      },
      {
        fixture: "uid_504",
        signedSubject: "fortress:test/uid-504",
        wrongClaim: "fortress:test/uid-503",
      },
    ];

    for (const relabelCase of cases) {
      const activated = await activateAndDrainCapturedFixture({
        privateKey: priv,
        publicKey: pub,
        fixture: relabelCase.fixture,
      });
      try {
        const correct = await buildCastleWallPosture({
          protectionClaimSubject: relabelCase.signedSubject,
          auditLog: activated.auditLog,
          originMachine: "fortress:test",
          platform: "linux",
          now: Date.now(),
          pinnedProducerKeyB64url: activated.pinnedProducerKeyB64url,
        });
        expect(correct.arm_state).toBe("armed");
        expect(correct.producer_authenticity).toBe("producer_signed");

        const wrong = await buildCastleWallPosture({
          protectionClaimSubject: relabelCase.wrongClaim,
          auditLog: activated.auditLog,
          originMachine: "fortress:test",
          platform: "linux",
          now: Date.now(),
          pinnedProducerKeyB64url: activated.pinnedProducerKeyB64url,
        });
        expect(wrong.arm_state).toBe("unknown");
        expect(wrong.evidence_basis).toBe("subject_unbound_evidence");
        expect(wrong.producer_authenticity).toBe("not_applicable");
        expect(wrong.verdict_counts.blocked).toBe(0);
      } finally {
        await activated.stop();
      }
    }
  });

  it("(d) old-format Linux agent-name signed evidence fails closed as pre-canonical and never greens", async () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const activated = await activateAndDrainCapturedFixture({
      privateKey: priv,
      publicKey: pub,
      fixture: "old_agent_name",
    });
    try {
      const posture = await buildCastleWallPosture({
        protectionClaimSubject: "fortress:test/uid-503",
        auditLog: activated.auditLog,
        originMachine: "fortress:test",
        platform: "linux",
        now: Date.now(),
        pinnedProducerKeyB64url: activated.pinnedProducerKeyB64url,
      });

      expect(posture.arm_state).toBe("unknown");
      expect(posture.evidence_basis).toBe("pre_canonical_linux_agent_name");
      expect(posture.producer_authenticity).toBe("not_applicable");
      expect(posture.verdict_counts.blocked).toBe(0);
    } finally {
      await activated.stop();
    }
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

    const diagnostics: Error[] = [];
    const faults: Error[] = [];
    const res = await drainOnce(
      client,
      consumer,
      null,
      256,
      (e) => diagnostics.push(e),
      (e) => faults.push(e)
    );

    // seq 1 failed to persist → NOT acked; the loop BROKE so seq 2 was never
    // even ingested → also NOT acked. The daemon will re-deliver from seq 1.
    expect(acks).not.toContain(1);
    expect(acks).not.toContain(2);
    expect(acks).toHaveLength(0);
    expect(res.drained).toBe(0);
    expect(res.nextAfterSeq).toBeNull();
    // codex HIGH split: a transient persist failure is an UNSETTLED FAULT (the
    // cursor never advanced), so it surfaces on `onDrainFault` — NOT on the
    // settled-diagnostics `onError`. This is what trips NOT-ARMED in opt-in mode.
    expect(faults.some((e) => /transient/.test(e.message))).toBe(true);
    expect(diagnostics).toHaveLength(0);
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
    const load = await loadFortressProducerKey(tmp, { platform: "linux" });
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
    // Fire the next scheduled cycle: it hits the wedged link → the cycle's
    // outer catch → onDrainFault → markDrainUnhealthy. drainHealthy() flips
    // SYNCHRONOUSLY; the durable record + teardown then settle asynchronously.
    scheduled[scheduled.length - 1]!();
    for (let i = 0; i < 50 && outcome.activation.drainHealthy(); i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    // Health flips the instant the fault is seen (the wall is not-armed NOW).
    expect(outcome.activation.drainHealthy()).toBe(false);

    // Round-3 HIGH: the NOT-ARMED record must be DURABLE before the transition
    // is complete. `whenDrainSettled()` resolves only after the append+flush
    // have been AWAITED (no fire-and-forget) and the loop stopped — so the
    // durable record is guaranteed present here, not raced.
    await outcome.activation.whenDrainSettled();

    expect(unhealthyErrors.length).toBeGreaterThanOrEqual(1);
    expect(unhealthyErrors[0]!.message).toMatch(/daemon link dropped/);
    expect(appended).toContain("castle_wall_drain_failed");

    await outcome.activation.stop();
  });
});

describe("C4 — round-3 HIGH: NOT-ARMED record durability + settled-refusal vs transport failure", () => {
  /**
   * Drive the activation's LIVE drain loop deterministically: capture each
   * scheduled cycle so the test fires cycles explicitly. Returns the activation
   * outcome + the scheduled-callback queue + the spied audit operations.
   */
  async function activateWithCapturedLoop(opts: {
    auditSink: AuditSink;
    drainQueue: AuditDrainEvent[];
    onDrainUnhealthy?: (err: Error, info: { recordDurable: boolean }) => void;
    onAuditUnavailable?: (fatal: RuntimeLinuxActivationError) => void;
  }): Promise<{
    activation: NonNullable<
      Awaited<ReturnType<typeof maybeActivateLinuxProducerSignedCastleWall>> extends infer R
        ? R extends { activated: true; activation: infer A }
          ? A
          : never
        : never
    >;
    scheduled: Array<() => void>;
  }> {
    const mock = buildMockDaemon(opts.drainQueue);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();
    const scheduled: Array<() => void> = [];

    const outcomeP = maybeActivateLinuxProducerSignedCastleWall({
      fortressId: "fortress:test",
      fortressStoragePath: tmp,
      key: keyMaterial(),
      auditSink: opts.auditSink,
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
      onDrainUnhealthy: opts.onDrainUnhealthy,
      onAuditUnavailable: opts.onAuditUnavailable,
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;
    if (!outcome.activated) throw new Error("expected activation");
    return { activation: outcome.activation, scheduled };
  }

  /** Spy wrapper that records the operations appended to a real AuditLog. */
  function spyAppend(log: AuditLog): string[] {
    const appended: string[] = [];
    const orig = log.append.bind(log);
    (log as unknown as { append: AuditSink["append"] }).append = ((
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      appended.push(operation);
      return orig(layer, operation, id, details, result);
    }) as AuditSink["append"];
    return appended;
  }

  /**
   * Spy that records the FULL appended entries (operation + details), so a test
   * can assert the details a specific record carried, not just its operation.
   */
  function spyAppendEntries(
    log: AuditLog,
  ): Array<{ operation: string; details?: Record<string, unknown> }> {
    const entries: Array<{ operation: string; details?: Record<string, unknown> }> = [];
    const orig = log.append.bind(log);
    (log as unknown as { append: AuditSink["append"] }).append = ((
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      entries.push({ operation, details });
      return orig(layer, operation, id, details, result);
    }) as AuditSink["append"];
    return entries;
  }

  it("(honesty) the NOT-ARMED castle_wall_drain_failed record uses an UNSIGNED fault basis (never producer_signed) and the read-side attributor fail-closed-rejects it", async () => {
    // The fault record is a consumer-emitted NOT-ARMED signal written when the
    // daemon link wedges. It carries NO producer signature, so it must NEVER
    // claim the `producer_signed` authenticity basis (the mislabel this fixes).
    // A published key lets activation pass the FIX-1 gate; the fault fires on a
    // wedged transport, not on any signature check, so the key value is moot.
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const entries = spyAppendEntries(auditLog);

    const { activation, scheduled } = await activateWithCapturedLoop({
      auditSink: auditLog,
      drainQueue: [],
    });

    // Wedge the daemon link so the next drain cycle faults → markDrainUnhealthy
    // → durable NOT-ARMED record.
    const client = activation.lifecycle.client();
    (client as unknown as { drainRequest: () => Promise<never> }).drainRequest =
      async () => {
        throw new Error("daemon link dropped");
      };
    for (let i = 0; i < 100 && scheduled.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    expect(scheduled.length).toBeGreaterThanOrEqual(1);
    scheduled[scheduled.length - 1]!();
    for (let i = 0; i < 100 && activation.drainHealthy(); i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled();
    expect(activation.drainHealthy()).toBe(false);

    const faultRecord = entries.find(
      (e) => e.operation === "castle_wall_drain_failed",
    );
    expect(faultRecord).toBeDefined();
    const details = faultRecord!.details ?? {};

    // HONESTY: the basis is the unsigned fault-specific string, NOT the
    // producer-signed basis a real verified signature would earn.
    expect(details.evidence_basis).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_DRAIN_FAULT_UNSIGNED,
    );
    expect(details.evidence_basis).not.toBe(
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    );
    expect(details.armed).toBe(false);

    // FAIL-CLOSED: even with a pinned producer key available, the read-side
    // attributor never treats this fault record as producer-attributed
    // evidence. It carries no `cw_evidence_basis=producer_signed` marker and no
    // signature, so verified attribution returns null — it can never be
    // projected as an armed/attributed agent.
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      layer: "l1",
      operation: "castle_wall_drain_failed",
      identity_id: "fortress:test",
      result: "failure",
      details,
    };
    expect(
      verifiedCastleWallAuditAttribution(entry, {
        pinnedProducerKeyB64url: "A".repeat(43),
      }),
    ).toBeNull();

    await activation.stop();
  });

  it("(b) a SETTLED producer-signature refusal does NOT stop the drain / does NOT trip NOT-ARMED", async () => {
    // The forger mints the marker but no valid signature. The live consumer
    // (key loaded) durably REJECTS + acks it — a SETTLED refusal. The drain must
    // stay HEALTHY: a refused forgery is the gate working, not a transport
    // failure. (codex HIGH: settled-refusal must not be a false NOT-ARMED.)
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const appended = spyAppend(auditLog);
    const unhealthy: Error[] = [];

    const { activation, scheduled } = await activateWithCapturedLoop({
      auditSink: auditLog,
      drainQueue: [forgedDrainEvent(1, null)],
      onDrainUnhealthy: (e) => unhealthy.push(e),
    });
    // The live consumer is enforcing (key loaded), so the forgery is rejected.
    expect(activation.lifecycle.audit().isProducerSignatureEnforced()).toBe(true);

    // Let the first cycle run (it drains + durably refuses + acks the forgery),
    // then settle.
    for (let i = 0; i < 100 && scheduled.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled();

    // Health is UNTOUCHED: a settled refusal is not a transport fault.
    expect(activation.drainHealthy()).toBe(true);
    expect(unhealthy).toHaveLength(0);
    // The refusal was durably recorded; NO not-armed record was written.
    expect(appended).toContain("producer_signature_rejected");
    expect(appended).not.toContain("castle_wall_drain_failed");
    // The consumer rejected (not accepted) the forgery.
    expect(activation.lifecycle.audit().getStats().producerSignatureRejections).toBe(1);
    expect(activation.lifecycle.audit().getStats().producerSignatureAccepted).toBe(0);

    // CONTRAST: a real transport failure on the SAME activation DOES trip
    // NOT-ARMED — proving the split is about settlement, not "any error".
    const client = activation.lifecycle.client();
    (client as unknown as { drainRequest: () => Promise<never> }).drainRequest =
      async () => {
        throw new Error("daemon link dropped");
      };
    expect(scheduled.length).toBeGreaterThanOrEqual(1);
    scheduled[scheduled.length - 1]!();
    for (let i = 0; i < 100 && activation.drainHealthy(); i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled();
    expect(activation.drainHealthy()).toBe(false);
    expect(unhealthy.length).toBeGreaterThanOrEqual(1);
    expect(appended).toContain("castle_wall_drain_failed");

    await activation.stop();
  });

  it("(a-i) the NOT-ARMED transition is NOT complete until the durable record is settled (append is AWAITED, not fire-and-forget)", async () => {
    // A sink whose `castle_wall_drain_failed` append BLOCKS on a gate we control.
    // If the transition awaited the record, `whenDrainSettled()` must NOT resolve
    // while the gate is closed, and MUST resolve once we open it. (Round-3 HIGH:
    // the old code did `void (async () => { append... })()` — fire-and-forget —
    // so a process exit / sink failure could leave drainHealthy()=false with NO
    // durable record.)
    // A published key so activation passes the FIX-1 gate (no events drained,
    // so the key value is irrelevant — only its presence).
    await publishPubKey(tmp, ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    let releaseRecord!: () => void;
    const recordGate = new Promise<void>((res) => {
      releaseRecord = res;
    });
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const orig = auditLog.append.bind(auditLog);
    let notArmedAppendStarted = false;
    (auditLog as unknown as { append: AuditSink["append"] }).append = (async (
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      if (operation === "castle_wall_drain_failed") {
        notArmedAppendStarted = true;
        await recordGate; // block until the test releases it
      }
      return orig(layer, operation, id, details, result);
    }) as AuditSink["append"];

    const { activation, scheduled } = await activateWithCapturedLoop({
      auditSink: auditLog,
      drainQueue: [],
    });
    for (let i = 0; i < 100 && scheduled.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled(); // the first (healthy, empty) cycle

    // Wedge the link → fault → markDrainUnhealthy → durable record append begins
    // (and BLOCKS on our gate).
    const client = activation.lifecycle.client();
    (client as unknown as { drainRequest: () => Promise<never> }).drainRequest =
      async () => {
        throw new Error("daemon link dropped");
      };
    scheduled[scheduled.length - 1]!();
    // Wait until the not-armed append has STARTED but is parked on the gate.
    for (let i = 0; i < 100 && !notArmedAppendStarted; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    expect(notArmedAppendStarted).toBe(true);
    // Health already reads false (the wall is not-armed the instant the fault is
    // seen)...
    expect(activation.drainHealthy()).toBe(false);

    // ...but the TRANSITION is not complete: `whenDrainSettled()` must still be
    // pending because the durable record append is awaited and parked.
    let settled = false;
    const settledP = activation.whenDrainSettled().then(() => {
      settled = true;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(settled).toBe(false); // proves the append is AWAITED, not fire-and-forget

    // Release the record; NOW the transition completes.
    releaseRecord();
    await settledP;
    expect(settled).toBe(true);

    await activation.stop();
  });

  it("(a-ii) a NOT-ARMED record that CANNOT be persisted takes the explicit audit-unavailable FATAL path (no silent drop, stays not-armed)", async () => {
    // The sink throws on the `castle_wall_drain_failed` append. The transition
    // must NOT silently drop the record: it surfaces an explicit
    // `RuntimeLinuxActivationError` (reason `drain_failed`) via `onAuditUnavailable`,
    // reports `recordDurable: false` to the health hook, and the wall STAYS
    // not-armed. Fail-closed + loud. (Round-3 HIGH: errors were previously
    // swallowed in a catch{}.)
    await publishPubKey(tmp, ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const orig = auditLog.append.bind(auditLog);
    (auditLog as unknown as { append: AuditSink["append"] }).append = (async (
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      if (operation === "castle_wall_drain_failed") {
        throw new Error("audit sink unavailable (disk full)");
      }
      return orig(layer, operation, id, details, result);
    }) as AuditSink["append"];

    const fatals: RuntimeLinuxActivationError[] = [];
    const unhealthyInfos: Array<{ recordDurable: boolean }> = [];
    const { activation, scheduled } = await activateWithCapturedLoop({
      auditSink: auditLog,
      drainQueue: [],
      onDrainUnhealthy: (_e, info) => unhealthyInfos.push(info),
      onAuditUnavailable: (f) => fatals.push(f),
    });
    for (let i = 0; i < 100 && scheduled.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled();

    // Wedge the link → fault → markDrainUnhealthy → the not-armed append THROWS.
    const client = activation.lifecycle.client();
    (client as unknown as { drainRequest: () => Promise<never> }).drainRequest =
      async () => {
        throw new Error("daemon link dropped");
      };
    scheduled[scheduled.length - 1]!();
    for (let i = 0; i < 100 && activation.drainHealthy(); i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await activation.whenDrainSettled();

    // The wall STAYS not-armed (never falls back to a silent green on a record
    // failure)...
    expect(activation.drainHealthy()).toBe(false);
    // ...the explicit FATAL fired (NOT a silently-swallowed error)...
    expect(fatals).toHaveLength(1);
    expect(fatals[0]).toBeInstanceOf(RuntimeLinuxActivationError);
    expect(fatals[0]!.reason).toBe("drain_failed");
    expect(fatals[0]!.message).toMatch(/audit unavailable/i);
    expect(fatals[0]!.message).toMatch(/disk full/);
    // ...and the health hook was told the record was NOT made durable.
    expect(unhealthyInfos).toHaveLength(1);
    expect(unhealthyInfos[0]!.recordDurable).toBe(false);

    await activation.stop();
  });
});

describe("C4 — round-4 HIGH: never report ARMED before the audit channel is PROVEN (initial-drain confirmation)", () => {
  /**
   * A mock daemon that completes the handshake normally but FAILS the first
   * `audit_drain_request` (its `transport.send` rejects for that frame). Models a
   * daemon that handshakes then wedges the drain channel — the case where a
   * handshake-only "armed" would be fake-green.
   */
  function handshakeOkDrainWedgedDaemon(): {
    transport: IpcTransport;
    sendChallenge: () => Promise<void>;
  } {
    let listener: ((bytes: Uint8Array) => void) | null = null;
    let buffer = new Uint8Array(0);
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
              const env = JSON.parse(body) as { params?: CastleWallMessage };
              const msg = env.params;
              if (msg && msg.type === "audit_drain_request") {
                // The drain channel is wedged: reject the send so the client's
                // `drainRequest` rejects immediately (deterministic — no waiting
                // on the request timeout).
                throw new Error("drain channel wedged (first request)");
              }
              // handshake_response / lock / unlock are accepted silently.
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
    };
  }

  it("FAILS CLOSED (not-armed) when the handshake succeeds but the FIRST drain round-trip does not complete", async () => {
    // The daemon handshakes (so `startCastleWall` succeeds and the key is loaded
    // + enforcing) but then wedges the drain channel. Without the initial-drain
    // confirmation the activation would return `activated: true` for the whole
    // request-timeout window with ZERO signed evidence flowing. The probe must
    // catch this and THROW NOT-ARMED instead.
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = handshakeOkDrainWedgedDaemon();
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
      // Continuous loop (default) + initial-drain confirmation (default) engaged.
    });
    await mock.sendChallenge();

    // The activation must REJECT (not resolve as armed): the audit channel was
    // never proven, so reporting armed would be fake-green.
    let thrown: unknown;
    try {
      await outcomeP;
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(RuntimeLinuxActivationError);
    expect((thrown as RuntimeLinuxActivationError).reason).toBe("drain_failed");
    expect((thrown as Error).message).toMatch(/not armed/i);
    expect((thrown as Error).message).toMatch(/unproven|round-trip/i);
  });

  it("ARMS when the initial drain completes a round-trip (empty batch counts — the channel is proven live)", async () => {
    // Contrast: a daemon that handshakes AND serves an (empty) first drain proves
    // the channel delivers, so the activation legitimately reports armed. This is
    // the positive side of the round-4 contract.
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const mock = buildMockDaemon([]); // serves an empty first drain, then more_pending=false
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
      drainOptions: {
        // Park the continuous loop's NEXT cycle so the test controls teardown;
        // the initial-drain PROBE still runs (it is not the scheduled loop).
        pollIntervalMs: 10_000,
        setTimer: () => 1,
        clearTimer: () => {},
      },
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;

    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;
    // Armed AND healthy: the channel was proven by the initial round-trip.
    expect(outcome.activation.drainHealthy()).toBe(true);
    expect(outcome.activation.lifecycle.audit().isProducerSignatureEnforced()).toBe(
      true
    );

    await outcome.activation.stop();
  });
});

describe("C4 — round-5 HIGH: initial-drain probe never skips an unsettled event when it stops mid-batch", () => {
  it("FAILS CLOSED when the probe partially settles then hits a transient persist fault mid-batch (loop never starts, no skip)", async () => {
    // codex round-5: if the probe drains [seq1(ok), seq2(persist-fault)], it must
    // NOT report armed and start the continuous loop resumed PAST seq2 (which
    // would skip the unsettled seq2). seq1 settles (durably persisted + acked);
    // seq2's enforcement append throws (transient) → drainOnce routes it to
    // onDrainFault and breaks WITHOUT advancing the cursor past seq2 → the probe's
    // markDrainUnhealthy trips → activation FAILS CLOSED (NOT-ARMED). The loop is
    // never started, so seq2 cannot be skipped; on a later re-activation the
    // daemon re-delivers from seq2.
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));

    // Two FORGED events in ONE batch. seq1's refusal record persists (settles +
    // acks → cursor advances to 1). seq2's `producer_signature_rejected` append
    // THROWS (transient persist fault) → ingestCritical throws BEFORE acking →
    // seq2 does NOT settle, the cursor stays at 1. Forgeries need no WAL-chain
    // anchor, which isolates the "probe stops mid-batch at an unsettled fault"
    // scenario cleanly.
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    const orig = auditLog.append.bind(auditLog);
    let refusalAppends = 0;
    const appended: string[] = [];
    (auditLog as unknown as { append: AuditSink["append"] }).append = (async (
      layer: "l1",
      operation: string,
      id: string,
      details?: Record<string, unknown>,
      result?: "success" | "failure",
    ) => {
      appended.push(operation);
      if (operation === "producer_signature_rejected") {
        refusalAppends += 1;
        if (refusalAppends === 2) {
          throw new Error("audit disk unavailable mid-batch (transient)");
        }
      }
      return orig(layer, operation, id, details, result);
    }) as AuditSink["append"];

    const mock = buildMockDaemon([forgedDrainEvent(1, null), forgedDrainEvent(2, null)]);
    const { runner } = activeSystemctl();
    const { fs } = memoryFs();

    const faults: Error[] = [];
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
      drainOptions: { onDrainFault: (e) => faults.push(e) },
    });
    await mock.sendChallenge();

    let thrown: unknown;
    try {
      await outcomeP;
    } catch (err) {
      thrown = err;
    }
    // FAIL-CLOSED: the activation threw NOT-ARMED rather than reporting armed.
    expect(thrown).toBeInstanceOf(RuntimeLinuxActivationError);
    expect((thrown as RuntimeLinuxActivationError).reason).toBe("drain_failed");
    // The mid-batch fault was observed during the probe.
    expect(faults.length).toBeGreaterThanOrEqual(1);
    // seq1's refusal WAS durably recorded + acked (it settled); seq2 did NOT
    // (the daemon was NOT acked through 2), so the daemon re-delivers from seq2.
    expect(appended).toContain("producer_signature_rejected");
    expect(mock.acks).toContain(1);
    expect(mock.acks).not.toContain(2);
  });

  it("after a clean probe the consumer's DURABLE settled floor is the resume cursor (lastAckedSeq), and a loop seeded from it requests strictly above it", async () => {
    // Part 1 (integration): a clean probe drains seq1 (genuine, accepted). The
    // consumer's durable lastAckedSeq advances to 1 — that is exactly the value
    // the activation seeds the continuous loop's cursor from (initialCursor =
    // getWalChainState().lastAckedSeq), so the resume point is the authoritative
    // settled high-water mark, never a probe-local cursor that could outrun it.
    const priv = ed25519.utils.randomPrivateKey();
    await publishPubKey(tmp, ed25519.getPublicKey(priv));
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
      drainOptions: { pollIntervalMs: 10_000, setTimer: () => 1, clearTimer: () => {} },
    });
    await mock.sendChallenge();
    const outcome = await outcomeP;
    expect(outcome.activated).toBe(true);
    if (!outcome.activated) return;
    // The durable settled floor the loop is seeded from.
    expect(outcome.activation.lifecycle.audit().getWalChainState().lastAckedSeq).toBe(1);
    await outcome.activation.stop();

    // Part 2 (unit): a loop seeded with initialCursor=1 issues its first drain
    // request strictly ABOVE seq1 (after_seq=1) — it does not re-pull from null/0
    // (no needless re-pull of the settled seq1) and does not jump ahead.
    const requested: Array<number | null> = [];
    const stubClient = {
      async drainRequest(afterSeq: number | null): Promise<AuditDrainResponse> {
        requested.push(afterSeq);
        return {
          events: [],
          next_after_seq: afterSeq,
          more_pending: false,
          wal_overflow_count: 0,
        } as AuditDrainResponse;
      },
      async sendDrainAck(): Promise<void> {},
    } as unknown as IpcClient;
    const loop = startLinuxAuditDrainLoop(
      stubClient,
      outcome.activation.lifecycle.audit(),
      { initialCursor: 1, pollIntervalMs: 10_000, setTimer: () => 1, clearTimer: () => {} }
    );
    // Let the loop's first (synchronous) cycle issue its request.
    for (let i = 0; i < 50 && requested.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 1));
    }
    await loop.stop();
    expect(requested).toContain(1);
    expect(requested).not.toContain(0);
    expect(requested).not.toContain(null);
  });
});

describe("PR-C — bounded retention for persistent Linux audit drain faults", () => {
  type ScheduledDrainCycle = { cb: () => void; ms: number };

  async function waitForScheduledCount(
    scheduled: ScheduledDrainCycle[],
    count: number,
  ): Promise<void> {
    for (let i = 0; i < 50 && scheduled.length < count; i++) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    expect(scheduled.length).toBeGreaterThanOrEqual(count);
  }

  it("PR-C fail-before: an unsettled event with more_pending=true falls through to the poll delay instead of hot-spinning", async () => {
    const requested: Array<number | null> = [];
    const scheduled: ScheduledDrainCycle[] = [];
    const faultingEvent = forgedDrainEvent(1, null);
    const client = {
      async drainRequest(afterSeq: number | null): Promise<AuditDrainResponse> {
        requested.push(afterSeq);
        return {
          events: requested.length <= 4 ? [faultingEvent] : [],
          next_after_seq: afterSeq,
          more_pending: requested.length <= 4,
          wal_overflow_count: 0,
        } as AuditDrainResponse;
      },
      async sendDrainAck(): Promise<void> {},
    } as unknown as IpcClient;
    const consumer = {
      async ingestCritical(): Promise<void> {
        throw new Error("audit disk unavailable (persistent)");
      },
    } as unknown as AuditConsumer;
    const faults: Error[] = [];

    const loop = startLinuxAuditDrainLoop(client, consumer, {
      pollIntervalMs: 1000,
      setTimer: (cb, ms) => {
        scheduled.push({ cb: cb as () => void, ms });
        return scheduled.length;
      },
      clearTimer: () => {},
      onDrainFault: (err) => faults.push(err),
    });

    await waitForScheduledCount(scheduled, 1);
    await loop.stop();

    expect(scheduled).toHaveLength(1);
    expect(scheduled[0]?.ms).toBe(1000);
    expect(requested).toEqual([null]);
    expect(faults).toHaveLength(1);
  });

  it("backs off exponentially, capped, when the same cursor keeps faulting", async () => {
    const requested: Array<number | null> = [];
    const scheduled: ScheduledDrainCycle[] = [];
    const faultingEvent = forgedDrainEvent(1, null);
    const client = {
      async drainRequest(afterSeq: number | null): Promise<AuditDrainResponse> {
        requested.push(afterSeq);
        return {
          events: [faultingEvent],
          next_after_seq: afterSeq,
          more_pending: false,
          wal_overflow_count: 0,
        } as AuditDrainResponse;
      },
      async sendDrainAck(): Promise<void> {},
    } as unknown as IpcClient;
    const consumer = {
      async ingestCritical(): Promise<void> {
        throw new Error("audit disk unavailable (persistent)");
      },
    } as unknown as AuditConsumer;

    const loop = startLinuxAuditDrainLoop(client, consumer, {
      pollIntervalMs: 10,
      maxFaultBackoffMs: 25,
      setTimer: (cb, ms) => {
        scheduled.push({ cb: cb as () => void, ms });
        return scheduled.length;
      },
      clearTimer: () => {},
      onDrainFault: () => {},
    });

    await waitForScheduledCount(scheduled, 1);
    scheduled[0]!.cb();
    await waitForScheduledCount(scheduled, 2);
    scheduled[1]!.cb();
    await waitForScheduledCount(scheduled, 3);
    await loop.stop();

    expect(requested).toEqual([null, null, null]);
    expect(scheduled.map((entry) => entry.ms)).toEqual([10, 20, 25]);
  });

});
