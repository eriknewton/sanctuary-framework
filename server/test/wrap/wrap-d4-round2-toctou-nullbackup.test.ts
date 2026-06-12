/**
 * Wrap D4 — round-2 adversarial findings on the round-1 fixes
 *
 * P1-A: the round-1 symlink refusal was lstat-then-write — two syscalls,
 * TOCTOU-raceable (an attacker looping rename+symlink in ~/.hermes could
 * land a symlink between check and sink and redirect the write to an
 * arbitrary victim file). The fix is the atomic no-follow primitive
 * writeFileNoFollow (O_NOFOLLOW open → ELOOP on a symlink, POSIX on both
 * Linux and macOS), used at EVERY sink: the config.yaml write, the
 * auxiliary restore, and the rollback/primary restores (all via
 * restoreConfig). These tests pin the ENFORCEMENT layer deterministically:
 * a symlink already AT the sink path must be refused by the primitive
 * itself, with the victim untouched — no reliance on the courtesy lstat.
 *
 * P1-B: round-1 accepted `backupPath: null` for ANY originalPath under an
 * allowlisted agent config dir, so forged wrap-meta could make unwrap
 * unlink legitimate files (e.g. ~/.hermes/cli-config.json — restored, then
 * deleted). Null-backup (created-by-wrap, delete-on-unwrap) entries are
 * now pinned byte-for-byte to the exact surfaces wrap can create — today
 * only hermesConfigYamlPath().
 *
 * P2: a legitimate unwrap was refused when the auxiliary parent dir no
 * longer existed. For a NULL-backup auxiliary a missing parent means the
 * file cannot exist — the desired end-state ("absent") already holds, so
 * unwrap skips it as an informational no-op. For a BACKED auxiliary the
 * restore path recreates the directory (0o700) instead of stranding the
 * operator.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFile, mkdir, readFile, rm, symlink, access, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  writeFileNoFollow,
  restoreConfig,
  validateWrapMetaAuxiliary,
  WrapMetaValidationError,
} from "../../src/wrap/config-reader.js";
import { runWrap } from "../../src/wrap/cli.js";

describe("Wrap D4 round-2: TOCTOU-safe sinks + null-backup allowlist + missing-parent unwrap", () => {
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
      `sanctuary-d4-round2-${Date.now()}-${Math.random().toString(36).slice(2)}`
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

  /** Wrapped-state fixture shared by the unwrap integration tests. */
  async function writeWrappedStateWithMeta(auxiliary: unknown) {
    const jsonPath = join(hermesDir, "cli-config.json");
    const jsonBackup = join(backupDir, "config-backup-0.json");
    const wrappedJson = JSON.stringify(
      { mcp_servers: { sanctuary: { command: "npx" } } },
      null,
      2
    );
    const originalJson = JSON.stringify({ mcp_servers: {} }, null, 2);
    await writeFile(jsonPath, wrappedJson);
    await writeFile(jsonBackup, originalJson);
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
    return { jsonPath, wrappedJson, originalJson };
  }

  // ── P1-A: atomic no-follow enforcement at the sink ──────────────────

  it("writeFileNoFollow refuses a symlink AT the sink path, victim untouched (P1-A enforcement, no lstat involved)", async () => {
    const victim = join(tmpHome, "victim.yaml");
    await writeFile(victim, "do-not-touch: true\n");
    const sink = join(hermesDir, "config.yaml");
    // Deterministic placement of the post-check/pre-write race outcome:
    // the symlink is already at the sink when the primitive opens it.
    await symlink(victim, sink);

    await expect(
      writeFileNoFollow(sink, "mcp_servers: {}\n", 0o600)
    ).rejects.toThrow(/symlink/);

    expect(await readFile(victim, "utf-8")).toBe("do-not-touch: true\n");
  });

  it("writeFileNoFollow writes a regular/absent path normally", async () => {
    const sink = join(hermesDir, "config.yaml");
    await writeFileNoFollow(sink, "mcp_servers: {}\n", 0o600);
    expect(await readFile(sink, "utf-8")).toBe("mcp_servers: {}\n");
    // Overwrite (O_TRUNC) of an existing regular file also works.
    await writeFileNoFollow(sink, "mcp_servers:\n  sanctuary: {}\n", 0o600);
    expect(await readFile(sink, "utf-8")).toBe("mcp_servers:\n  sanctuary: {}\n");
  });

  it("restoreConfig refuses a symlinked restore target atomically, victim untouched (P1-A, restore sinks)", async () => {
    const victim = join(tmpHome, "victim.json");
    await writeFile(victim, '{"precious":true}\n');
    const backup = join(backupDir, "config-backup-r.json");
    await writeFile(backup, '{"mcp_servers":{}}\n');
    const target = join(hermesDir, "cli-config.json");
    await symlink(victim, target);

    // Called directly: this bypasses every plan-time courtesy lstat, so a
    // pass here pins that the sink itself is the enforcement.
    await expect(restoreConfig(backup, target)).rejects.toThrow(/symlink/);

    expect(await readFile(victim, "utf-8")).toBe('{"precious":true}\n');
  });

  // ── P1-B: null-backup entries pinned to created-by-wrap surfaces ────

  it("validator rejects a null-backup auxiliary that names a legitimate file wrap does not create (P1-B)", async () => {
    await expect(
      validateWrapMetaAuxiliary([
        { originalPath: join(hermesDir, "cli-config.json"), backupPath: null },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("validator still accepts a null-backup auxiliary at the exact Hermes config.yaml surface", async () => {
    const validated = await validateWrapMetaAuxiliary([
      { originalPath: join(hermesDir, "config.yaml"), backupPath: null },
    ]);
    expect(validated).toHaveLength(1);
    expect(validated[0]!.backupPath).toBeNull();
    expect(validated[0]!.alreadyAbsent).toBeUndefined();
  });

  it("unwrap REFUSES a forged null-backup entry pointing at cli-config.json, with nothing modified (P1-B)", async () => {
    const { jsonPath, wrappedJson } = await writeWrappedStateWithMeta([
      // Forged delete-on-unwrap instruction against a legitimate file:
      // round-1 rules would restore cli-config.json and then unlink it.
      { originalPath: join(hermesDir, "cli-config.json"), backupPath: null },
    ]);

    await expect(runWrap({ unwrap: true }, {})).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("Unwrap REFUSED");
    // Nothing modified: the wrapped config survives byte-identical (no
    // restore ran, and crucially no unlink either).
    expect(await readFile(jsonPath, "utf-8")).toBe(wrappedJson);
  });

  it("legitimate created-by-wrap config.yaml unwrap still removes it and restores the primary (P1-B, no false positive)", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(yamlPath, 'mcp_servers:\n  sanctuary:\n    command: "npx"\n');
    const { jsonPath, originalJson } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: null },
    ]);

    await runWrap({ unwrap: true }, {});

    await expect(access(yamlPath)).rejects.toThrow();
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
  });

  // ── P2: missing parent directory must not strand the operator ───────

  it("null-backup auxiliary whose parent dir is gone is a no-op skip, not a refusal (P2)", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    const { jsonPath, originalJson } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: null },
    ]);
    // The operator (or an uninstall) removed ~/.hermes after wrap: the
    // created-by-wrap file cannot exist, so "absent" already holds.
    await rm(hermesDir, { recursive: true, force: true });

    await runWrap({ unwrap: true }, {});

    expect(stderrOutput()).toContain("already absent");
    await expect(access(yamlPath)).rejects.toThrow();
    // The primary restore recreated the directory and the original config.
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
  });

  it("--unwrap --dry-run reports the already-absent skip and writes nothing (P2)", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: null },
    ]);
    await rm(hermesDir, { recursive: true, force: true });

    await runWrap({ unwrap: true, dryRun: true }, {});

    expect(stderrOutput()).toContain("Would skip");
    expect(stderrOutput()).toContain("already absent");
    // Write-free: the removed directory was not recreated.
    await expect(access(hermesDir)).rejects.toThrow();
  });

  it("backed auxiliary whose parent dir is gone is restored into a recreated 0o700 directory (P2)", async () => {
    const yamlPath = join(hermesDir, "config.yaml");
    const yamlBackup = join(backupDir, "config-backup-1.yaml");
    await writeFile(yamlBackup, "mcp_servers: {}\n");
    const { jsonPath, originalJson } = await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: yamlBackup },
    ]);
    await rm(hermesDir, { recursive: true, force: true });

    await runWrap({ unwrap: true }, {});

    expect(await readFile(yamlPath, "utf-8")).toBe("mcp_servers: {}\n");
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
    const dirStat = await stat(hermesDir);
    expect(dirStat.isDirectory()).toBe(true);
  });
});
