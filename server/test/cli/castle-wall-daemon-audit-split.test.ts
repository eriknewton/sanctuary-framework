/**
 * F2 Option A: `sanctuary castle-wall daemon` audit-store-split wiring.
 *
 * Proves the `runDaemon` posture change end-to-end (root-context detection
 * via the injected `getuid` seam, since a test process cannot become real
 * root):
 *   - non-root (default posture; the overwhelming majority of dev/CI/manual
 *     runs): behavior is UNCHANGED — the daemon's `auditLog` writes straight
 *     into the shared `_audit` chain, and no `_audit-daemon` namespace or
 *     split-boundary record is ever created.
 *   - root (`ctx.getuid` returns 0): the daemon runs the migration BEFORE
 *     arming, then its `auditLog` writes into the SEPARATE `_audit-daemon`
 *     chain, never `_audit`.
 *   - root + a genuinely tampered pre-split `_audit` chain: the daemon
 *     refuses to arm (exit 1) rather than sealing a broken chain — proven by
 *     `fullDaemonStart` never being invoked.
 *
 * A REAL root-owned `_audit-daemon` directory unreadable to a REAL,
 * different, non-root operator uid is a cross-uid filesystem-permission
 * property this single-process test cannot reproduce; that is exactly the
 * armed-box Mini1 re-drill's job (see the PR body).
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  runAuditStoreStatus,
  runDaemon,
  runProvisionPin,
  type CastleWallCommandContext,
} from "../../src/cli/castle-wall.js";
import type { MacOSCastleWallDaemonInput } from "../../src/castle-wall/runtime/macos-daemon.js";
import { AUDIT_DAEMON_NAMESPACE } from "../../src/operational/audit-store-split.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";

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

const STOP_AFTER_CAPTURE = new Error("captured");

describe("castle-wall daemon: F2 Option A audit-store split", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  const PASSPHRASE = "test-audit-split-daemon-passphrase";

  async function makeLocalFortress(): Promise<{ fortressPath: string }> {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-audit-split-"));
    tempDirs.push(fortressPath);
    await initializeTestCustody(fortressPath, { passphrase: PASSPHRASE });
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
      globalPinnedPublicKeyPath: join(fortressPath, "global-pin.bin"),
    });
    expect(code).toBe(0);
    return { fortressPath };
  }

  function baseCtx(fortressPath: string, capture: {
    input?: MacOSCastleWallDaemonInput;
  }): CastleWallCommandContext {
    return {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
      },
      fullDaemonStart: async (input) => {
        capture.input = input;
        throw STOP_AFTER_CAPTURE;
      },
    };
  }

  it("non-root: unchanged — writes straight into _audit, never provisions _audit-daemon", async () => {
    const { fortressPath } = await makeLocalFortress();
    const capture: { input?: MacOSCastleWallDaemonInput } = {};
    const ctx = baseCtx(fortressPath, capture);
    ctx.getuid = () => 501; // ordinary (non-root) operator uid

    const code = await runDaemon([], ctx);
    expect(code).toBe(1); // capture-throw surfaces as start failure
    expect(capture.input).toBeDefined();

    await capture.input!.auditLog.appendCritical({
      layer: "l1",
      operation: "probe",
      identity_id: "id-1",
      result: "success",
    });
    await capture.input!.auditLog.flush();

    const auditDir = join(fortressPath, "state", "_audit");
    const entries = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    expect(entries.length).toBeGreaterThan(0);

    // No daemon namespace, no split-boundary record.
    await expect(
      readdir(join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE)),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(join(fortressPath, "state", "_audit_migration", "boundary-v1.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("root: migrates first, then writes into _audit-daemon (never _audit)", async () => {
    const { fortressPath } = await makeLocalFortress();
    const capture: { input?: MacOSCastleWallDaemonInput } = {};
    const ctx = baseCtx(fortressPath, capture);
    ctx.getuid = () => 0;

    const code = await runDaemon([], ctx);
    expect(code).toBe(1);
    expect(capture.input).toBeDefined();

    // The boundary record now exists (migration ran on a fresh/empty chain,
    // so sealed_tip_sequence is 0 — still a real, MAC-authenticated record).
    const boundaryRaw = await readFile(
      join(fortressPath, "state", "_audit_migration", "boundary-v1.json"),
      "utf-8",
    );
    expect(JSON.parse(boundaryRaw).data.sealed_tip_sequence).toBe(0);

    // Its own genesis marker entry already landed (migration wrote it).
    const daemonEntriesBefore = (
      await readdir(join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE))
    ).filter((f) => f.startsWith("entry-"));
    expect(daemonEntriesBefore.length).toBe(1);

    // The wired-up auditLog writes into the daemon namespace, not the shared one.
    await capture.input!.auditLog.appendCritical({
      layer: "l1",
      operation: "probe",
      identity_id: "id-1",
      result: "success",
    });
    await capture.input!.auditLog.flush();

    const daemonEntriesAfter = (
      await readdir(join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE))
    ).filter((f) => f.startsWith("entry-"));
    expect(daemonEntriesAfter.length).toBe(2); // genesis marker + probe

    // The shared operator `_audit` namespace never received the probe entry
    // (it may not even exist yet on a fortress this fresh, since it starts
    // empty and only the migration's own READ touched it).
    const sharedEntries = await readdir(join(fortressPath, "state", "_audit")).catch(
      (err) => {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
        throw err;
      },
    );
    expect(sharedEntries.filter((f) => f.startsWith("entry-")).length).toBe(0);
  });

  it("root + a genuinely tampered pre-split _audit chain: refuses to arm (never reaches fullDaemonStart)", async () => {
    const { fortressPath } = await makeLocalFortress();

    // Seed one operator entry, then corrupt it, so the migration's own
    // (root-context) chain re-verification finds a REAL problem.
    const seedCapture: { input?: MacOSCastleWallDaemonInput } = {};
    const seedCtx = baseCtx(fortressPath, seedCapture);
    seedCtx.getuid = () => 501;
    await runDaemon([], seedCtx);
    await seedCapture.input!.auditLog.appendCritical({
      layer: "l1",
      operation: "seed",
      identity_id: "id-1",
      result: "success",
    });
    await seedCapture.input!.auditLog.flush();

    const auditDir = join(fortressPath, "state", "_audit");
    const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-"));
    expect(files.length).toBeGreaterThan(0);
    const filePath = join(auditDir, files[0]!);
    const raw = JSON.parse(await readFile(filePath, "utf-8"));
    raw.entry_hash = "0".repeat(64);
    await writeFile(filePath, JSON.stringify(raw));

    const capture: { input?: MacOSCastleWallDaemonInput } = {};
    const ctx = baseCtx(fortressPath, capture);
    ctx.getuid = () => 0;

    const code = await runDaemon([], ctx);
    expect(code).toBe(1);
    // The daemon never reached fullDaemonStart — it refused before arming.
    expect(capture.input).toBeUndefined();

    // No boundary was written over the tampered chain.
    await expect(
      readFile(join(fortressPath, "state", "_audit_migration", "boundary-v1.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("castle-wall audit-store-status (CLI)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  const PASSPHRASE = "test-audit-store-status-passphrase";

  async function makeLocalFortress(): Promise<{ fortressPath: string }> {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-audit-status-"));
    tempDirs.push(fortressPath);
    await initializeTestCustody(fortressPath, { passphrase: PASSPHRASE });
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
      globalPinnedPublicKeyPath: join(fortressPath, "global-pin.bin"),
    });
    expect(code).toBe(0);
    return { fortressPath };
  }

  it("fresh fortress: operator verified, daemon absent, always exits 0", async () => {
    const { fortressPath } = await makeLocalFortress();
    const out = new CaptureStream();
    const code = await runAuditStoreStatus(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text());
    expect(report.operator.status).toBe("verified");
    expect(report.daemon.status).toBe("absent");
  });

  it("after a root daemon run, reports both chains honestly (same-uid test process: both verified)", async () => {
    const { fortressPath } = await makeLocalFortress();
    const capture: { input?: MacOSCastleWallDaemonInput } = {};
    const rootCtx: CastleWallCommandContext = {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
      },
      fullDaemonStart: async (input) => {
        capture.input = input;
        throw STOP_AFTER_CAPTURE;
      },
    };
    rootCtx.getuid = () => 0;
    await runDaemon([], rootCtx);

    const out = new CaptureStream();
    const code = await runAuditStoreStatus(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text());
    expect(report.operator.status).toBe("verified");
    expect(report.daemon.status).toBe("verified");
  });

  it("daemon chain present but unreadable at this privilege: reports present_unreadable via the CLI, exit 0", async () => {
    const { fortressPath } = await makeLocalFortress();
    const capture: { input?: MacOSCastleWallDaemonInput } = {};
    const rootCtx: CastleWallCommandContext = {
      out: new CaptureStream(),
      err: new CaptureStream(),
      platform: "darwin",
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_PASSPHRASE: PASSPHRASE,
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
      },
      fullDaemonStart: async (input) => {
        capture.input = input;
        throw STOP_AFTER_CAPTURE;
      },
    };
    rootCtx.getuid = () => 0;
    await runDaemon([], rootCtx);

    const { chmod } = await import("node:fs/promises");
    const daemonDir = join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE);
    await chmod(daemonDir, 0o000);
    try {
      const out = new CaptureStream();
      const code = await runAuditStoreStatus(["--fortress", fortressPath], {
        out,
        err: new CaptureStream(),
        env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
      });
      expect(code).toBe(0);
      const report = JSON.parse(out.text());
      expect(report.operator.status).toBe("verified");
      expect(report.daemon.status).toBe("present_unreadable");
      expect(report.daemon.status).not.toBe("verified");
    } finally {
      await chmod(daemonDir, 0o755);
    }
  });
});
