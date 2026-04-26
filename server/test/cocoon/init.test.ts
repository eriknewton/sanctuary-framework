/**
 * sanctuary init — fortress isolation tests (v1.1.1 hotfix Findings S + T)
 *
 * Findings S + T together meant the tooling had no working primitive for
 * "stand up a side-by-side fresh fortress" on v1.1.0. The init command
 * is the new primitive for that workflow. These tests pin:
 *
 *   - resolveFortressPath honors --fortress flag, SANCTUARY_FORTRESS_PATH
 *     env var, and SANCTUARY_STORAGE_PATH env var in the documented
 *     precedence order.
 *   - runInit creates the fortress directory at the resolved path,
 *     persists the recovery-key hash, and writes recovery-key.txt with
 *     the full plaintext key.
 *   - runInit refuses to overwrite a non-empty directory unless --force.
 *   - parseInitArgs round-trips every flag.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import {
  parseInitArgs,
  printInitHelp,
  resolveFortressPath,
  runInit,
} from "../../src/cocoon/init.js";
import { RECOVERY_KEY_FILENAME } from "../../src/cocoon/recovery-key-disclosure.js";

describe("resolveFortressPath", () => {
  it("returns ~/.sanctuary when no flag or env var is set", () => {
    const path = resolveFortressPath({}, {}, "/tmp/test-home");
    expect(path).toBe("/tmp/test-home/.sanctuary");
  });

  it("honors the --fortress flag over env vars", () => {
    const path = resolveFortressPath(
      { fortress: "/tmp/explicit-fortress" },
      {
        SANCTUARY_FORTRESS_PATH: "/tmp/from-fortress-env",
        SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env",
      },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/explicit-fortress");
  });

  it("honors SANCTUARY_FORTRESS_PATH over SANCTUARY_STORAGE_PATH", () => {
    const path = resolveFortressPath(
      {},
      {
        SANCTUARY_FORTRESS_PATH: "/tmp/from-fortress-env",
        SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env",
      },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/from-fortress-env");
  });

  it("falls back to SANCTUARY_STORAGE_PATH when only that is set", () => {
    const path = resolveFortressPath(
      {},
      { SANCTUARY_STORAGE_PATH: "/tmp/from-storage-env" },
      "/tmp/test-home",
    );
    expect(path).toBe("/tmp/from-storage-env");
  });

  it("resolves relative paths against cwd", () => {
    const path = resolveFortressPath(
      { fortress: "./relative-fortress" },
      {},
      "/tmp/test-home",
    );
    expect(path.endsWith("/relative-fortress")).toBe(true);
    expect(path.startsWith("/")).toBe(true);
  });
});

describe("runInit", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-test-"));
  });

  afterEach(async () => {
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {}
  });

  it("creates the fortress at --fortress <path>, NOT ~/.sanctuary", async () => {
    const fortressPath = join(tmp, "isolated-fortress");
    const result = await runInit({
      fortress: fortressPath,
      noConfirm: true,
    });
    expect(result.fortressPath).toBe(fortressPath);

    // Recovery key file landed at the fortress path, not at HOME.
    expect(result.recoveryKeyDisclosurePath).toBe(
      join(fortressPath, RECOVERY_KEY_FILENAME),
    );
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(recoveryFile).toContain("Recovery key:");
    expect(recoveryFile).toContain(
      "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY",
    );

    // Crucially: ~/.sanctuary was NOT touched. We can't safely assert this
    // on a developer machine (it might already exist), but we CAN assert
    // the fortress isn't at the default location.
    expect(result.fortressPath).not.toBe(join(homedir(), ".sanctuary"));
  });

  it("persists recovery-key-hash so subsequent boots can verify the key", async () => {
    const fortressPath = join(tmp, "fortress-with-hash");
    await runInit({ fortress: fortressPath, noConfirm: true });

    // Hash file lives under <fortress>/state/_meta/recovery-key-hash.enc.
    const hashFile = join(
      fortressPath,
      "state",
      "_meta",
      "recovery-key-hash.enc",
    );
    const st = await stat(hashFile);
    expect(st.isFile()).toBe(true);
    expect(st.size).toBeGreaterThan(0);
  });

  it("creates the fortress directory with mode 0700", async () => {
    const fortressPath = join(tmp, "mode-test-fortress");
    await runInit({ fortress: fortressPath, noConfirm: true });
    const st = await stat(fortressPath);
    // Mask off file-type bits; only permission bits matter.
    expect(st.mode & 0o777).toBe(0o700);
  });

  it("refuses to overwrite a non-empty fortress directory without --force", async () => {
    const fortressPath = join(tmp, "non-empty-fortress");
    await mkdir(fortressPath, { recursive: true });
    await writeFile(join(fortressPath, "operator-data.txt"), "important", {
      mode: 0o600,
    });

    await expect(
      runInit({ fortress: fortressPath, noConfirm: true }),
    ).rejects.toThrow(/not empty/);

    // Original file still present.
    const operatorData = await readFile(
      join(fortressPath, "operator-data.txt"),
      "utf-8",
    );
    expect(operatorData).toBe("important");
  });

  it("succeeds against a non-empty directory when --force is set", async () => {
    const fortressPath = join(tmp, "forced-fortress");
    await mkdir(fortressPath, { recursive: true });
    await writeFile(join(fortressPath, "stale-marker.txt"), "old", {
      mode: 0o600,
    });

    const result = await runInit({
      fortress: fortressPath,
      force: true,
      noConfirm: true,
    });
    expect(result.fortressPath).toBe(fortressPath);

    // recovery-key.txt was written despite the pre-existing content.
    const recoveryFile = await readFile(
      result.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(recoveryFile).toContain("Recovery key:");
  });

  it("recovery-key.txt is single-issuance: re-init with --force does NOT overwrite", async () => {
    const fortressPath = join(tmp, "single-issuance-fortress");
    const first = await runInit({ fortress: fortressPath, noConfirm: true });
    const firstContent = await readFile(
      first.recoveryKeyDisclosurePath,
      "utf-8",
    );

    // Second init under --force should NOT overwrite recovery-key.txt
    // (the disclosure helper enforces single-issuance regardless of caller).
    await runInit({ fortress: fortressPath, force: true, noConfirm: true });
    const afterSecond = await readFile(
      first.recoveryKeyDisclosurePath,
      "utf-8",
    );
    expect(afterSecond).toBe(firstContent);
  });
});

describe("parseInitArgs", () => {
  it("recognizes --fortress, --force, --no-confirm, --help", () => {
    const opts = parseInitArgs([
      "--fortress",
      "/tmp/x",
      "--force",
      "--no-confirm",
    ]);
    expect(opts.fortress).toBe("/tmp/x");
    expect(opts.force).toBe(true);
    expect(opts.noConfirm).toBe(true);

    const helpOpts = parseInitArgs(["--help"]);
    expect(helpOpts.helpRequested).toBe(true);

    const shortHelp = parseInitArgs(["-h"]);
    expect(shortHelp.helpRequested).toBe(true);
  });

  it("printInitHelp does not throw", () => {
    expect(() => printInitHelp()).not.toThrow();
  });
});
