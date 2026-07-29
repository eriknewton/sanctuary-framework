/**
 * F2 HIGH-1 (adversarial gate 2026-07-14): the Castle Wall audit readers must
 * be chain-aware after the writer-split. The root daemon's enforcement evidence
 * lives in `_audit-daemon`, so a reader that reads only `_audit` would print a
 * false-green over an incomplete chain.
 *
 * These prove:
 *   - `audit-dump` includes daemon-chain entries (tagged `_chain`) when the
 *     daemon chain is readable, and warns INCOMPLETE when it exists but is
 *     unreadable at this privilege.
 *   - `audit-verify` counts daemon evidence when readable (`complete: true`) and
 *     marks `complete: false` when the daemon chain is unreadable (a green /
 *     zero-count is NOT a success claim).
 *   - `audit-chain export` fails closed (no silent omission) on a fortress with
 *     a daemon chain unless `--operator-only` is passed.
 *
 * Single-process test: the daemon chain is created via `createDaemonAuditLog`
 * and made "unreadable" via chmod 0000 (a faithful proxy for the real root-owned
 * cross-uid case, which only the Mini1 re-drill can fully reproduce).
 */

import { chmod, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import {
  runAuditDump,
  runAuditVerify,
  runProvisionPin,
} from "../../src/cli/castle-wall.js";
import {
  parseExportArgs,
  runExport,
} from "../../src/cli/audit-chain-export.js";
import {
  createDaemonAuditLog,
  migrateFortressAuditStoreSplit,
  AUDIT_DAEMON_NAMESPACE,
} from "../../src/operational/audit-store-split.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _enc: BufferEncoding,
    cb: (e?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const PASSPHRASE = "test-audit-readers-chain-aware-passphrase";

describe("F2 HIGH-1: Castle Wall audit readers are chain-aware", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      // Restore perms so cleanup can recurse.
      await chmod(join(dir, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  /** Bootstrap a fortress, migrate it, and land N daemon enforcement events in
   * `_audit-daemon`. Returns the fortress path + storage + master key. */
  async function migratedFortressWithDaemonEvents(n: number) {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-readers-"));
    tempDirs.push(fortressPath);
    const code = await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(0);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const { masterKey } = await establishMaster({ storage, passphrase: PASSPHRASE });
    await migrateFortressAuditStoreSplit({ storage, masterKey });

    const daemonLog = createDaemonAuditLog(storage, masterKey);
    for (let i = 0; i < n; i++) {
      await daemonLog.appendCritical({
        layer: "l1",
        operation: i % 2 === 0 ? "egress_allowed" : "egress_blocked",
        identity_id: "castle-wall-daemon",
        result: "success",
        details: { host: `h${i}.example` },
      });
    }
    await daemonLog.flush();
    return { fortressPath, storage, masterKey };
  }

  const READER_ENV = (fortressPath: string) => ({
    SANCTUARY_STORAGE_PATH: fortressPath,
    SANCTUARY_PASSPHRASE: PASSPHRASE,
  });

  it("audit-dump includes daemon-chain entries (tagged _chain) when readable", async () => {
    const { fortressPath } = await migratedFortressWithDaemonEvents(3);
    const out = new CaptureStream();
    const code = await runAuditDump(["--fortress", fortressPath], {
      out,
      err: new CaptureStream(),
      env: READER_ENV(fortressPath),
    });
    expect(code).toBe(0);
    const lines = out.text().trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const daemonLines = lines.filter((l) => l._chain === "daemon");
    expect(daemonLines.length).toBe(3);
  });

  it("audit-dump warns INCOMPLETE (does not silently drop) when the daemon chain is unreadable", async () => {
    const { fortressPath } = await migratedFortressWithDaemonEvents(3);
    const daemonDir = join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE);
    await chmod(daemonDir, 0o000);
    try {
      const out = new CaptureStream();
      const err = new CaptureStream();
      const code = await runAuditDump(["--fortress", fortressPath], {
        out,
        err,
        env: READER_ENV(fortressPath),
      });
      expect(code).toBe(0);
      expect(err.text()).toMatch(/INCOMPLETE/);
      expect(err.text()).toMatch(/_audit-daemon/);
    } finally {
      await chmod(daemonDir, 0o700);
    }
  });

  it("audit-verify counts daemon evidence and reports complete:true when readable", async () => {
    const { fortressPath } = await migratedFortressWithDaemonEvents(4);
    const out = new CaptureStream();
    const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
      out,
      err: new CaptureStream(),
      env: READER_ENV(fortressPath),
    });
    expect(code).toBe(0);
    const report = JSON.parse(out.text());
    expect(report.complete).toBe(true);
    expect(report.daemon_chain).toBe("included");
    // All 4 daemon egress verdicts are examined (channel basis, no producer key).
    expect(report.enforcement_entries).toBe(4);
  });

  it("audit-verify marks complete:false and warns when the daemon chain is unreadable (green is NOT a success claim)", async () => {
    const { fortressPath } = await migratedFortressWithDaemonEvents(4);
    const daemonDir = join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE);
    await chmod(daemonDir, 0o000);
    try {
      const out = new CaptureStream();
      const code = await runAuditVerify(["--fortress", fortressPath, "--json"], {
        out,
        err: new CaptureStream(),
        env: READER_ENV(fortressPath),
      });
      expect(code).toBe(0);
      const report = JSON.parse(out.text());
      expect(report.complete).toBe(false);
      expect(report.daemon_chain).toBe("unreadable");
    } finally {
      await chmod(daemonDir, 0o700);
    }
  });

  it("audit-chain export fails closed on a fortress with a daemon chain unless --operator-only", async () => {
    const { fortressPath } = await migratedFortressWithDaemonEvents(2);
    // Without --operator-only: refuse.
    await expect(
      runExport(parseExportArgs(["--fortress", fortressPath], {})),
    ).rejects.toThrow(/INCOMPLETE|--operator-only|daemon/);
    // With --operator-only: succeeds (writes to a Writable we capture).
    const out = new CaptureStream();
    const opts = parseExportArgs(["--fortress", fortressPath, "--operator-only"], {});
    // runExport writes to process.stdout when no --output; redirect by asserting
    // it resolves. (The guard path is what HIGH-1 asserts; content is covered by
    // existing audit-chain-export tests.)
    await expect(runExport(opts)).resolves.toBeUndefined();
    void out;
  });

  it("audit-chain export on a non-migrated fortress behaves as before (no daemon chain, no flag needed)", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-readers-nomig-"));
    tempDirs.push(fortressPath);
    await runProvisionPin([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    // No _audit-daemon → export must NOT require --operator-only.
    await expect(
      runExport(parseExportArgs(["--fortress", fortressPath], {})),
    ).resolves.toBeUndefined();
    // Sanity: no daemon namespace exists.
    await expect(
      readdir(join(fortressPath, "state", AUDIT_DAEMON_NAMESPACE)),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
