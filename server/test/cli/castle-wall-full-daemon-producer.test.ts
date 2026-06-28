/**
 * Castle Wall FULL-mode operator daemon - Slice M producer-key wiring.
 *
 * The FULL operator daemon (`runDaemon` WITHOUT `--safe-mode`) is the
 * console-login enforcement path: it holds the fortress key and reaches the
 * audit-producer signing service, so producer-signed flow verdicts are
 * re-verified. This contrasts with the safe-mode boot daemon, which comes up
 * from the boot token only.
 *
 * These tests prove the FULL path:
 *   - comes up in `daemonMode: "full"` (NOT safe-mode-from-boot-token).
 *   - threads the macOS audit-producer public-key path into the daemon when one
 *     is provided (ctx override / SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY), so
 *     the daemon engages per-producer re-verification.
 *   - leaves the producer-key path UNSET when none is provided, so the daemon
 *     falls back to its honest channel-authenticated floor default (never
 *     overclaims a per-producer basis the operator did not provision).
 *
 * The daemon start is captured via the `fullDaemonStart` injection so no real
 * socket/helper is stood up; the assertion is on the resolved
 * `MacOSCastleWallDaemonInput` the CLI wired.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { ed25519 } from "@noble/curves/ed25519";

import {
  runDaemon,
  runProvisionPin,
  type CastleWallCommandContext,
} from "../../src/cli/castle-wall.js";
import type { MacOSCastleWallDaemonInput } from "../../src/castle-wall/runtime/macos-daemon.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

/** Capture-and-stop sentinel so we never reach the SIGTERM-blocked wait. */
const STOP_AFTER_CAPTURE = new Error("captured");

describe("castle-wall FULL daemon : Slice M producer-key wiring", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  const PASSPHRASE = "test-full-daemon-passphrase";

  /**
   * A local-sign fortress whose master + pin both derive from the SAME
   * passphrase, so the FULL daemon (which resolves the master via the
   * passphrase) reads the exact key `provision-pin` pinned. (Using a recovery
   * key for the pin but a passphrase for the daemon would mint two different
   * masters and the daemon would refuse to arm a mismatched key.)
   */
  async function makeLocalFortress(): Promise<{ fortressPath: string }> {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-full-"));
    tempDirs.push(fortressPath);
    // Provision the local pin from the passphrase-derived master so the
    // daemon's "no pinned key" gate passes and local-sign decrypts the SAME
    // master against the passphrase.
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(0);
    return { fortressPath };
  }

  async function writeProducerKey(fortressPath: string): Promise<string> {
    const pub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const path = join(fortressPath, "audit-producer.pub");
    await writeFile(path, pub);
    return path;
  }

  it("comes up in FULL mode and threads the audit-producer key path (ctx override)", async () => {
    const { fortressPath } = await makeLocalFortress();
    const producerKeyPath = await writeProducerKey(fortressPath);
    let captured: MacOSCastleWallDaemonInput | undefined;

    const ctx: CastleWallCommandContext = {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
      },
      auditProducerPublicKeyPath: producerKeyPath,
      fullDaemonStart: async (input) => {
        captured = input;
        throw STOP_AFTER_CAPTURE;
      },
    };

    const code = await runDaemon([], ctx);
    // The capture-throw surfaces as a start failure (exit 1); the point is the
    // INPUT the FULL path wired up.
    expect(code).toBe(1);
    expect(captured).toBeDefined();
    // FULL mode - NOT safe-mode-from-boot-token.
    expect(captured!.daemonMode).toBe("full");
    // The audit-producer key path is threaded, so the daemon will load it and
    // engage per-producer re-verification.
    expect(captured!.auditProducerPublicKeyPath).toBe(producerKeyPath);
    // Local-sign path (hermetic; no helper).
    expect(captured!.localSign).toBe(true);
    expect(captured!.fortressPath).toBe(fortressPath);
  });

  it("threads the audit-producer key path from SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY", async () => {
    const { fortressPath } = await makeLocalFortress();
    const producerKeyPath = await writeProducerKey(fortressPath);
    let captured: MacOSCastleWallDaemonInput | undefined;

    const code = await runDaemon([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
        SANCTUARY_CASTLE_AUDIT_PRODUCER_PUBKEY: producerKeyPath,
      },
      fullDaemonStart: async (input) => {
        captured = input;
        throw STOP_AFTER_CAPTURE;
      },
    });
    expect(code).toBe(1);
    expect(captured!.daemonMode).toBe("full");
    expect(captured!.auditProducerPublicKeyPath).toBe(producerKeyPath);
  });

  it("leaves the producer-key path UNSET when none is provided (honest channel floor)", async () => {
    const { fortressPath } = await makeLocalFortress();
    let captured: MacOSCastleWallDaemonInput | undefined;

    const code = await runDaemon([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
      },
      fullDaemonStart: async (input) => {
        captured = input;
        throw STOP_AFTER_CAPTURE;
      },
    });
    expect(code).toBe(1);
    expect(captured!.daemonMode).toBe("full");
    // No override: the daemon uses its built-in default global path (which is
    // absent on a dev box), so the CLI threads nothing. The daemon's own
    // loadMacOSAuditProducerPublicKey then yields the channel floor.
    expect(captured!.auditProducerPublicKeyPath).toBeUndefined();
  });
});
