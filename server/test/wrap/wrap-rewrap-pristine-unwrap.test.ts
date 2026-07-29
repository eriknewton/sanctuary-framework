/**
 * F6 (v1.6.1 wrap safety): re-running wrap must not destroy the pristine
 * unwrap point.
 *
 * Pre-fix, every wrap run pointed wrap-meta.json at the NEWEST timestamped
 * backup; a second wrap therefore backed up the ALREADY-WRAPPED config, and
 * `--unwrap` "restored" a file that still contained the sanctuary entry. The
 * pristine original survived on disk under the backup dir, but nothing
 * pointed at it.
 *
 * The fix has two halves, both pinned here:
 *   1. saveWrapMeta preserves the first (pristine) backup pointer when a
 *      wrap-meta already exists for the same originalPath, including the
 *      auxiliary Hermes config.yaml surface (where a preserved
 *      `backupPath: null` keeps meaning "wrap created it; unwrap removes it").
 *   2. A completed unwrap retires the wrap-meta pointer files, so a wrap
 *      AFTER an unwrap records a fresh pristine backup instead of preserving
 *      a stale pointer to a config the operator has since edited.
 *
 * Isolation: every test runs against a temp HOME + SANCTUARY_STORAGE_PATH
 * (never the real ~/.sanctuary), per the existing wrap-test idiom.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  writeFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  access,
  unlink,
  chmod,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { runWrap } from "../../src/wrap/cli.js";
import {
  backupConfig,
  findLatestBackup,
  removeWrapMeta,
  saveWrapMeta,
} from "../../src/wrap/config-reader.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

describe("wrap -> wrap -> unwrap restores the pristine pre-wrap config (F6)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn> | undefined;

  beforeEach(async () => {
    // mkdtemp (not a predictable join(tmpdir(), ...) + mkdir): the kernel
    // creates a fresh 0o700 directory atomically, per CodeQL
    // js/insecure-temporary-file.
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-rewrap-f6-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    // Keep the wrap/unwrap operator banners out of the test log.
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    clearHermesParityHook();
    stderrSpy?.mockRestore();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps() {
    // Agree with the scanner via the test-only sidecar hook so these Hermes
    // rewrap/unwrap mechanics tests do not depend on the CI host carrying
    // PyYAML (the parse-parity guard is proven separately in
    // hermes-yaml-parse-parity.test.ts).
    installHermesParityHook(agreeingHermesParity);
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
    };
  }

  it("double wrap then unwrap yields the pre-wrap config byte-for-byte", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristine = JSON.stringify(
      {
        mcpServers: { demo: { command: "node", args: ["demo-server.js"] } },
        theme: "dark",
      },
      null,
      2,
    );
    await writeFile(settingsPath, pristine);

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    // Sanity: the config is now wrapped.
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(wrapped.mcpServers.sanctuary).toBeDefined();

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    // The pristine pre-wrap config, byte-for-byte: no sanctuary entry left.
    expect(await readFile(settingsPath, "utf-8")).toBe(pristine);
  });

  it("hermes: double wrap then unwrap restores config.yaml byte-for-byte", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    const pristineYaml = 'mcp_servers:\n  weather:\n    command: "uvx"\n';
    await writeFile(jsonPath, "{}");
    await writeFile(yamlPath, pristineYaml);

    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    expect(await readFile(yamlPath, "utf-8")).toBe(pristineYaml);
    expect(await readFile(jsonPath, "utf-8")).toBe("{}");
  });

  it("hermes: double wrap then unwrap removes a config.yaml wrap created fresh", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(jsonPath, "{}");
    // No config.yaml: the first wrap creates it fresh (backupPath: null).
    // A second wrap backs up the wrap-created file; the preserved null
    // pointer must win so unwrap still removes the file.

    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    await runWrap({ hermes: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    await expect(access(yamlPath)).rejects.toThrow();
  });

  it("unwrap retires the wrap-meta so a later wrap records a fresh pristine backup", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristineV1 = JSON.stringify({ mcpServers: {} }, null, 2);
    await writeFile(settingsPath, pristineV1);

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    // The pointer is gone: "a wrap-meta exists" means "currently wrapped".
    expect(await findLatestBackup()).toBeNull();

    // The operator edits the config between unwrap and the next wrap; the
    // NEW pristine state must be what a later unwrap restores.
    const pristineV2 = JSON.stringify(
      { mcpServers: { added: { command: "node", args: ["added.js"] } } },
      null,
      2,
    );
    await writeFile(settingsPath, pristineV2);

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    expect(await readFile(settingsPath, "utf-8")).toBe(pristineV2);
  });

  it("saveWrapMeta preserves the pristine pointer for the same originalPath", async () => {
    const configPath = join(tmpHome, "some-config.json");
    await writeFile(configPath, '{"pristine":true}');
    const pristineBackup = await backupConfig(configPath);

    await saveWrapMeta({
      backupPath: pristineBackup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    // Simulate the second wrap's backup of the (now wrapped) config. The
    // small delay keeps the millisecond-resolution backup filenames distinct.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await writeFile(configPath, '{"wrapped":true}');
    const wrappedBackup = await backupConfig(configPath);
    expect(wrappedBackup).not.toBe(pristineBackup);
    await saveWrapMeta({
      backupPath: wrappedBackup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    const meta = await findLatestBackup();
    expect(meta?.backupPath).toBe(pristineBackup);
  });

  it("saveWrapMeta does NOT preserve a pointer across different originalPaths", async () => {
    const firstConfig = join(tmpHome, "first-config.json");
    await writeFile(firstConfig, "{}");
    const firstBackup = await backupConfig(firstConfig);
    await saveWrapMeta({
      backupPath: firstBackup,
      originalPath: firstConfig,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    const secondConfig = join(tmpHome, "second-config.json");
    await writeFile(secondConfig, "{}");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const secondBackup = await backupConfig(secondConfig);
    await saveWrapMeta({
      backupPath: secondBackup,
      originalPath: secondConfig,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    const meta = await findLatestBackup();
    expect(meta?.originalPath).toBe(secondConfig);
    expect(meta?.backupPath).toBe(secondBackup);
  });

  it("saveWrapMeta falls back to the fresh pointer when the pristine backup file is gone", async () => {
    const configPath = join(tmpHome, "pruned-config.json");
    await writeFile(configPath, "{}");
    const pristineBackup = await backupConfig(configPath);
    await saveWrapMeta({
      backupPath: pristineBackup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    // The operator pruned the old backup; a preserved pointer would strand
    // unwrap on a missing file.
    await unlink(pristineBackup);

    await new Promise((resolve) => setTimeout(resolve, 5));
    const freshBackup = await backupConfig(configPath);
    await saveWrapMeta({
      backupPath: freshBackup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    const meta = await findLatestBackup();
    expect(meta?.backupPath).toBe(freshBackup);
  });

  it("a FAILED wrap leaves no wrap-meta, so a later wrap + unwrap restores operator edits made after the failure", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristineV1 = JSON.stringify({ mcpServers: {} }, null, 2);
    await writeFile(settingsPath, pristineV1);

    // A wrap whose rewrite lands garbage fails post-rewrite verification,
    // rolls the config back, and exits non-zero. Harden round: it must NOT
    // leave a wrap-meta behind (the meta is written only after every
    // surface verifies), otherwise the next successful wrap preserved the
    // stale pristine pointer and unwrap discarded interim operator edits.
    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
    try {
      await expect(
        runWrap(
          { claudeCode: true, noOpen: true },
          {
            ...makeDeps(),
            rewriteConfig: async () => {
              await writeFile(settingsPath, "not json {{{");
              return settingsPath;
            },
          },
        ),
      ).rejects.toThrow("process.exit:1");
    } finally {
      exitSpy.mockRestore();
    }
    expect(await findLatestBackup()).toBeNull();
    // The rollback restored the pre-wrap content.
    expect(await readFile(settingsPath, "utf-8")).toBe(pristineV1);

    // Operator edits between the failed wrap and the retry.
    const editedV2 = JSON.stringify(
      { mcpServers: { added: { command: "node", args: ["added.js"] } } },
      null,
      2,
    );
    await writeFile(settingsPath, editedV2);

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());
    expect(await readFile(settingsPath, "utf-8")).toBe(editedV2);
  });

  it("a rewrite that corrupts the config then THROWS rolls both back and exits non-zero", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristine = JSON.stringify({ mcpServers: {} }, null, 2);
    await writeFile(settingsPath, pristine);

    // The primary rewrite writes the live config IN PLACE (O_TRUNC, not
    // temp+rename), so a mid-write throw (disk full, EIO) leaves the config
    // truncated. Harden round: pre-fix the throw escaped runWrap uncaught,
    // no rollback ran, and (with the meta write deferred until after
    // verification) no wrap-meta existed either, so `--unwrap` reported
    // nothing to restore over a corrupted config. The rewrite is now inside
    // the same rollback + exit(1) discipline as the YAML-write path.
    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
    try {
      await expect(
        runWrap(
          { claudeCode: true, noOpen: true },
          {
            ...makeDeps(),
            rewriteConfig: async () => {
              // Simulate the in-place write dying mid-stream: the file is
              // already truncated/corrupted when the error surfaces.
              await writeFile(settingsPath, '{"trunc');
              throw new Error("EIO: i/o error, write");
            },
          },
        ),
      ).rejects.toThrow("process.exit:1");
    } finally {
      exitSpy.mockRestore();
    }

    // Rolled back: pre-wrap content intact, no truncated config, no meta.
    expect(await readFile(settingsPath, "utf-8")).toBe(pristine);
    expect(await findLatestBackup()).toBeNull();
  });

  it("a stale wrap-meta over an UNWRAPPED config does not pin the ancient pointer (pre-1.6.1 unwraps left metas behind)", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const ancientV1 = JSON.stringify({ mcpServers: {} }, null, 2);
    await writeFile(settingsPath, ancientV1);

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    // Simulate a pre-1.6.1 unwrap: config restored by hand, meta LEFT in
    // place (removeWrapMeta did not exist in those releases).
    await writeFile(settingsPath, ancientV1);
    expect(await findLatestBackup()).not.toBeNull();

    // Weeks of operator edits on the live, unwrapped config.
    const editedV2 = JSON.stringify(
      { mcpServers: { added: { command: "node", args: ["added.js"] } } },
      null,
      2,
    );
    await writeFile(settingsPath, editedV2);

    // Re-wrap: the config genuinely contains no sanctuary entry, so the
    // fresh pointer must win over the stale preserved one.
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());
    expect(await readFile(settingsPath, "utf-8")).toBe(editedV2);
  });

  it("unwrap prints a breadcrumb to the newer backup that holds edits made while wrapped", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    // Operator registers a new tool WHILE wrapped; the second wrap backs up
    // this edited state, but the preserved pristine pointer wins on unwrap.
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    wrapped.mcpServers.newtool = { command: "node", args: ["newtool.js"] };
    await writeFile(settingsPath, JSON.stringify(wrapped, null, 2));
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ unwrap: true }, makeDeps());

    const out = (stderrSpy?.mock.calls ?? [])
      .map((call) => call.map(String).join(" "))
      .join("\n");
    expect(out).toContain("may be recoverable from");
  });

  it.skipIf(process.getuid?.() === 0)(
    "unwrap keeps the wrap-meta when an auxiliary restore fails, so --unwrap can be re-run",
    async () => {
      const hermesDir = join(tmpHome, ".hermes");
      await mkdir(hermesDir, { recursive: true });
      const jsonPath = join(hermesDir, "cli-config.json");
      const yamlPath = join(hermesDir, "config.yaml");
      const pristineYaml = 'mcp_servers:\n  weather:\n    command: "uvx"\n';
      await writeFile(jsonPath, "{}");
      await writeFile(yamlPath, pristineYaml);

      await runWrap({ hermes: true, noOpen: true }, makeDeps());
      const meta = await findLatestBackup();
      const auxBackup = meta?.auxiliary?.[0]?.backupPath;
      expect(auxBackup).toBeTruthy();

      // Make ONLY the auxiliary (config.yaml) restore fail: its backup is
      // unreadable. The primary cli-config.json restore still succeeds.
      await chmod(auxBackup!, 0o000);
      await runWrap({ unwrap: true }, makeDeps());

      // Primary restored; yaml still wrapped; the meta MUST survive so the
      // operator can retry from the CLI instead of manual file surgery.
      expect(await readFile(jsonPath, "utf-8")).toBe("{}");
      expect(await readFile(yamlPath, "utf-8")).toContain("sanctuary");
      expect(await findLatestBackup()).not.toBeNull();

      // Fix the cause and retry: the aux restore completes and the meta is
      // retired.
      await chmod(auxBackup!, 0o600);
      await runWrap({ unwrap: true }, makeDeps());
      expect(await readFile(yamlPath, "utf-8")).toBe(pristineYaml);
      expect(await findLatestBackup()).toBeNull();
    },
  );

  it("saveWrapMeta uses the fresh pointer when told the config is no longer wrapped", async () => {
    const configPath = join(tmpHome, "stale-meta-config.json");
    await writeFile(configPath, '{"pristine":true}');
    const ancientBackup = await backupConfig(configPath);
    await saveWrapMeta({
      backupPath: ancientBackup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });

    await new Promise((resolve) => setTimeout(resolve, 5));
    await writeFile(configPath, '{"edited":true}');
    const freshBackup = await backupConfig(configPath);
    await saveWrapMeta(
      {
        backupPath: freshBackup,
        originalPath: configPath,
        platform: "claude-code",
        wrappedAt: new Date().toISOString(),
      },
      { configStillWrapped: false },
    );

    const meta = await findLatestBackup();
    expect(meta?.backupPath).toBe(freshBackup);
  });

  it("removeWrapMeta deletes the pointer files and reports no failures", async () => {
    const configPath = join(tmpHome, "target-config.json");
    await writeFile(configPath, "{}");
    const backup = await backupConfig(configPath);
    await saveWrapMeta({
      backupPath: backup,
      originalPath: configPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
    expect(await findLatestBackup()).not.toBeNull();

    expect(await removeWrapMeta(configPath)).toEqual([]);
    expect(await findLatestBackup()).toBeNull();

    // Idempotent: absent files are not failures.
    expect(await removeWrapMeta(configPath)).toEqual([]);
  });
});
