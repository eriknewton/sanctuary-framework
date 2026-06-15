import { afterEach, describe, expect, it } from "vitest";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runSafeModeDaemon,
  type CastleWallCommandContext,
} from "../../src/cli/castle-wall.js";
import type { MacOSCastleWallDaemonInput } from "../../src/castle-wall/runtime/macos-daemon.js";
import {
  deriveSafeModeAuditKey,
  generateBootToken,
  persistBootToken,
} from "../../src/castle-wall/boot/boot-token.js";

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

/** Sentinel thrown by the capturing fake so the run returns before the
 * never-resolving SIGINT/SIGTERM wait (we only need the wiring it was called with). */
const STOP_AFTER_CAPTURE = new Error("captured");

describe("castle-wall safe-mode daemon (F1 Option C)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "f1-safe-"));
    tempDirs.push(dir);
    return dir;
  }

  async function makeToken(): Promise<{ path: string; token: Uint8Array }> {
    const dir = await mkdtemp(join(tmpdir(), "f1-safe-tok-"));
    tempDirs.push(dir);
    const path = join(dir, "boot-token.bin");
    const token = generateBootToken();
    await persistBootToken(token, { path });
    return { path, token };
  }

  it("refuses on non-macOS", async () => {
    const err = new CaptureStream();
    const code = await runSafeModeDaemon([], { err, platform: "linux" });
    expect(code).toBe(1);
    expect(err.text()).toContain("macOS-only");
  });

  it("refuses local-sign in safe mode (it would need the master key)", async () => {
    const err = new CaptureStream();
    const code = await runSafeModeDaemon([], {
      err,
      platform: "darwin",
      env: { SANCTUARY_CASTLE_LOCAL_SIGN: "1" },
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("master key");
  });

  it("fails closed when the boot token is absent", async () => {
    const fortress = await makeFortress();
    const err = new CaptureStream();
    const code = await runSafeModeDaemon([], {
      err,
      platform: "darwin",
      env: { SANCTUARY_STORAGE_PATH: fortress },
      bootTokenPath: join(fortress, "no-token.bin"),
      signerClientPath: "/x/shim",
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("no boot token found");
  });

  it("fails closed when the boot token has insecure permissions", async () => {
    const fortress = await makeFortress();
    const tok = await makeToken();
    await chmod(tok.path, 0o644);
    const err = new CaptureStream();
    const code = await runSafeModeDaemon([], {
      err,
      platform: "darwin",
      env: { SANCTUARY_STORAGE_PATH: fortress },
      bootTokenPath: tok.path,
      signerClientPath: "/x/shim",
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("insecure permissions");
  });

  it("refuses without a signer helper (never local-signs)", async () => {
    const fortress = await makeFortress();
    const tok = await makeToken();
    const err = new CaptureStream();
    const code = await runSafeModeDaemon([], {
      err,
      platform: "darwin",
      env: { SANCTUARY_STORAGE_PATH: fortress },
      bootTokenPath: tok.path,
      // no signerClientPath, no signerClientInvoke
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("without a signer helper");
  });

  it("brings the daemon up with the boot-token audit key, helper signing, and no master key", async () => {
    const fortress = await makeFortress();
    const tok = await makeToken();
    const err = new CaptureStream();
    let captured: MacOSCastleWallDaemonInput | undefined;

    const ctx: CastleWallCommandContext = {
      err,
      platform: "darwin",
      env: { SANCTUARY_STORAGE_PATH: fortress },
      bootTokenPath: tok.path,
      signerClientPath: "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client",
      safeModeDaemonStart: async (input) => {
        captured = input;
        // Throw after capture so we never reach the SIGTERM-blocked wait.
        throw STOP_AFTER_CAPTURE;
      },
    };

    const code = await runSafeModeDaemon([], ctx);
    // The capture-throw is handled as a start failure (returns 1); the point of
    // this test is the INPUT the safe-mode path wired up.
    expect(code).toBe(1);
    expect(captured).toBeDefined();

    const expectedAuditKey = deriveSafeModeAuditKey(tok.token);
    // Audit provenance marks this as a safe-mode boot bring-up.
    expect(captured!.auditSource).toBe("launchd-boot-safe-mode");
    // Helper signing only — never the local-sign master-key path.
    expect(captured!.localSign).toBeUndefined();
    expect(captured!.signerClientPath).toContain("castle-wall-signer-client");
    // The key handed to the daemon is the boot-token-derived safe-mode audit
    // key, NOT anything derived from the fortress passphrase.
    expect(Buffer.from(captured!.masterKey).equals(Buffer.from(expectedAuditKey))).toBe(true);
    // Storage points at the operator fortress.
    expect(captured!.fortressPath).toBe(fortress);
    // #450 item 3: safe mode (root) re-owns the socket to the fortress OWNER so
    // the operator CLI dead-man lever can reach it. The temp fortress is owned
    // by the test runner, so the derived owner uid is the current uid.
    const selfUid = process.getuid?.();
    if (selfUid !== undefined) {
      expect(captured!.socketOwnerUid).toBe(selfUid);
    }
  });
});
