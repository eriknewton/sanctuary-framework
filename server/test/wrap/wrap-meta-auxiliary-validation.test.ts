/**
 * Wrap-meta auxiliary validation — D4 adversarial finding P1-2
 *
 * wrap-meta.json `auxiliary` entries were trusted blindly on unwrap: a
 * forged entry like {backupPath: "/anything/readable", originalPath:
 * "/anything/writable"} (or null fields) made --unwrap copy or unlink
 * arbitrary paths. Validation now runs on read (findLatestBackup) AND
 * before use (the unwrap path), enforcing after realpath resolution:
 *   - backupPath: null, or a string strictly inside the wrap backup dir;
 *   - originalPath: a string strictly inside a known agent config
 *     directory (for Hermes: ~/.hermes).
 * Anything else throws WrapMetaValidationError and the unwrap aborts with
 * nothing modified. P2-3 rides along here for the restore side: a
 * symlinked restore target is refused before any restore runs.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFile, mkdir, readFile, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  validateWrapMetaAuxiliary,
  findLatestBackup,
  WrapMetaValidationError,
} from "../../src/wrap/config-reader.js";
import { runWrap } from "../../src/wrap/cli.js";

describe("validateWrapMetaAuxiliary + unwrap abort (D4 P1-2)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let backupDir: string;
  let hermesDir: string;
  let errSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-meta-valid-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    backupDir = join(tmpHome, ".sanctuary", "backup");
    hermesDir = join(tmpHome, ".hermes");
    await mkdir(backupDir, { recursive: true });
    await mkdir(hermesDir, { recursive: true });
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
  });

  afterEach(async () => {
    errSpy.mockRestore();
    exitSpy.mockRestore();
    vi.restoreAllMocks();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function stderrOutput(): string {
    return errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
  }

  // ── Unit: the validator itself ────────────────────────────────────

  it("accepts a legitimate Hermes auxiliary entry and returns resolved paths", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    const backupPath = join(backupDir, "config-backup-x.yaml");
    await writeFile(backupPath, "mcp_servers: {}\n");

    const validated = await validateWrapMetaAuxiliary([
      { originalPath: yamlPath, backupPath },
    ]);
    expect(validated).toHaveLength(1);
    expect(validated[0]!.originalPath).toBe(yamlPath);
    expect(validated[0]!.backupPath!.endsWith("config-backup-x.yaml")).toBe(true);
  });

  it("accepts a null backupPath (wrap created the file fresh)", async () => {
    const validated = await validateWrapMetaAuxiliary([
      { originalPath: join(hermesDir, "config.yaml"), backupPath: null },
    ]);
    expect(validated[0]!.backupPath).toBeNull();
  });

  it("returns [] for an absent auxiliary list (metas from earlier releases)", async () => {
    expect(await validateWrapMetaAuxiliary(undefined)).toEqual([]);
  });

  it("rejects an originalPath outside every known agent config directory", async () => {
    const victim = join(tmpHome, "Documents");
    await mkdir(victim, { recursive: true });
    await expect(
      validateWrapMetaAuxiliary([
        { originalPath: join(victim, "secret.txt"), backupPath: null },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects an originalPath that traverses out of the config directory", async () => {
    await expect(
      validateWrapMetaAuxiliary([
        {
          originalPath: join(hermesDir, "..", "evil.yaml"),
          backupPath: null,
        },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects null and non-string originalPath fields", async () => {
    await expect(
      validateWrapMetaAuxiliary([{ originalPath: null, backupPath: null }])
    ).rejects.toThrow(WrapMetaValidationError);
    await expect(
      validateWrapMetaAuxiliary([{ originalPath: 42, backupPath: null }])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects a backupPath outside the wrap backup directory", async () => {
    const evilBackup = join(tmpHome, "evil-backup.yaml");
    await writeFile(evilBackup, "attacker: payload\n");
    await expect(
      validateWrapMetaAuxiliary([
        { originalPath: join(hermesDir, "config.yaml"), backupPath: evilBackup },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects a backupPath that traverses out of the backup directory", async () => {
    const escapee = join(tmpHome, ".sanctuary", "escapee.yaml");
    await writeFile(escapee, "attacker: payload\n");
    await expect(
      validateWrapMetaAuxiliary([
        {
          originalPath: join(hermesDir, "config.yaml"),
          backupPath: join(backupDir, "..", "escapee.yaml"),
        },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects a backupPath that is a symlink escaping the backup directory", async () => {
    const outside = join(tmpHome, "outside.yaml");
    await writeFile(outside, "attacker: payload\n");
    const linkInBackup = join(backupDir, "config-backup-link.yaml");
    await symlink(outside, linkInBackup);
    await expect(
      validateWrapMetaAuxiliary([
        { originalPath: join(hermesDir, "config.yaml"), backupPath: linkInBackup },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects a backupPath that does not exist (nothing to restore from)", async () => {
    await expect(
      validateWrapMetaAuxiliary([
        {
          originalPath: join(hermesDir, "config.yaml"),
          backupPath: join(backupDir, "no-such-backup.yaml"),
        },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("rejects a non-array auxiliary value", async () => {
    await expect(
      validateWrapMetaAuxiliary({ originalPath: "x", backupPath: null })
    ).rejects.toThrow(WrapMetaValidationError);
  });

  // ── Integration: forged meta aborts unwrap with nothing modified ───

  async function writeWrappedStateWithMeta(auxiliary: unknown) {
    const jsonPath = join(hermesDir, "cli-config.json");
    const jsonBackup = join(backupDir, "config-backup-0.json");
    const wrappedJson = JSON.stringify(
      { mcp_servers: { sanctuary: { command: "npx" } } },
      null,
      2
    );
    await writeFile(jsonPath, wrappedJson);
    await writeFile(jsonBackup, JSON.stringify({ mcp_servers: {} }, null, 2));
    await writeFile(
      join(backupDir, "wrap-meta.json"),
      JSON.stringify(
        {
          backupPath: jsonBackup,
          originalPath: jsonPath,
          platform: "hermes",
          wrappedAt: "2026-01-01T00:00:00.000Z",
          auxiliary,
        },
        null,
        2
      )
    );
    return { jsonPath, wrappedJson };
  }

  it("findLatestBackup throws (not swallows) on a forged auxiliary list", async () => {
    await writeWrappedStateWithMeta([
      { originalPath: join(tmpHome, "victim.txt"), backupPath: null },
    ]);
    await expect(findLatestBackup()).rejects.toThrow(WrapMetaValidationError);
  });

  it("unwrap REFUSES a forged originalPath (arbitrary unlink) with nothing modified", async () => {
    const victim = join(tmpHome, "precious.txt");
    await writeFile(victim, "irreplaceable\n");
    const { jsonPath, wrappedJson } = await writeWrappedStateWithMeta([
      { originalPath: victim, backupPath: null },
    ]);

    await expect(runWrap({ unwrap: true }, {})).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("Unwrap REFUSED");
    // Nothing modified: the victim survives AND the primary config was
    // not restored either.
    expect(await readFile(victim, "utf-8")).toBe("irreplaceable\n");
    expect(await readFile(jsonPath, "utf-8")).toBe(wrappedJson);
  });

  it("unwrap REFUSES a forged backupPath (arbitrary file copy) with nothing modified", async () => {
    const attackerReadable = join(tmpHome, "attacker-payload.yaml");
    await writeFile(attackerReadable, "attacker: payload\n");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(yamlPath, "mcp_servers: {}\n");
    const { jsonPath, wrappedJson } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: attackerReadable },
    ]);

    await expect(runWrap({ unwrap: true }, {})).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("Unwrap REFUSED");
    expect(await readFile(yamlPath, "utf-8")).toBe("mcp_servers: {}\n");
    expect(await readFile(jsonPath, "utf-8")).toBe(wrappedJson);
  });

  it("unwrap REFUSES a symlinked restore target with nothing modified (P2-3, restore side)", async () => {
    const victim = join(tmpHome, "victim.yaml");
    await writeFile(victim, "do-not-touch: true\n");
    const yamlPath = join(hermesDir, "config.yaml");
    await symlink(victim, yamlPath);
    const yamlBackup = join(backupDir, "config-backup-1.yaml");
    await writeFile(yamlBackup, "mcp_servers: {}\n");
    const { jsonPath, wrappedJson } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: yamlBackup },
    ]);

    await expect(runWrap({ unwrap: true }, {})).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("Unwrap REFUSED");
    expect(stderrOutput()).toContain("symlink");
    expect(await readFile(victim, "utf-8")).toBe("do-not-touch: true\n");
    expect(await readFile(jsonPath, "utf-8")).toBe(wrappedJson);
  });

  it("a valid auxiliary entry still unwraps cleanly after validation (no false positive)", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(yamlPath, 'mcp_servers:\n  sanctuary:\n    command: "npx"\n');
    const yamlBackup = join(backupDir, "config-backup-2.yaml");
    await writeFile(yamlBackup, "mcp_servers: {}\n");
    const { jsonPath } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: yamlBackup },
    ]);

    await runWrap({ unwrap: true }, {});

    expect(await readFile(yamlPath, "utf-8")).toBe("mcp_servers: {}\n");
    const restored = JSON.parse(await readFile(jsonPath, "utf-8"));
    expect(restored.mcp_servers.sanctuary).toBeUndefined();
  });
});
