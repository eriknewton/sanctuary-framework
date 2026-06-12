/**
 * Wrap D4 — round-3 adversarial findings: the symlinked-PARENT class
 *
 * Round-2 closed the leaf-swap TOCTOU window with writeFileNoFollow
 * (O_NOFOLLOW open → ELOOP on a symlinked FINAL component). The reviewer
 * found that O_NOFOLLOW honours only the last path component: a symlinked
 * PARENT directory (e.g. `~/.hermes -> /tmp/victim`) is still traversed
 * transparently, so every "hardened" write/restore/mkdir/unlink lands
 * wherever the link points. mkdir(recursive:true) follows it too.
 *
 * The fix is one shared safe-path discipline routed through EVERY wrap sink:
 *   - assertNoSymlinkInPath walks each component from the trusted root (the
 *     operator HOME) down to the leaf's parent and refuses a symlinked
 *     ancestor; the leaf stays O_NOFOLLOW-guarded by the sink.
 *   - mkdirNoFollowUnderRoot creates each missing segment individually under
 *     the verified parent rather than recursive-mkdir following a link.
 *   - writeFileSafeUnderRoot / unlinkSafeUnderRoot combine the two so a
 *     symlinked parent is refused before any write/unlink.
 *
 * These tests pin the ENFORCEMENT deterministically: a symlink already AT a
 * parent directory must be refused, with the victim file untouched — across
 * the config.yaml write (P1-A), the unwrap unlink (P1-A), the forged
 * null-backup via a symlinked .hermes (P1-B), and the primary-config rewrite
 * (P1-C).
 *
 * RESIDUAL RISK (documented, not papered over): Node exposes no portable
 * per-component O_NOFOLLOW (openat) primitive, so the parent walk is not
 * atomic with the subsequent open/unlink. A same-privilege local attacker
 * who can win the parent-directory race between walk and sink is out of
 * scope for a single-operator wrap; cross-privilege redirection — the real
 * attack this class represents — is closed because the attacker cannot place
 * a symlink the walk does not see.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  writeFile,
  mkdir,
  readFile,
  rm,
  symlink,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  writeFileSafeUnderRoot,
  unlinkSafeUnderRoot,
  restoreConfig,
  rewriteConfigForWrap,
  validateWrapMetaAuxiliary,
  WrapMetaValidationError,
  type AgentConfig,
} from "../../src/wrap/config-reader.js";
import { runWrap } from "../../src/wrap/cli.js";

describe("Wrap D4 round-3: symlinked-parent redirection closed across every sink", () => {
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
      `sanctuary-d4-round3-${Date.now()}-${Math.random().toString(36).slice(2)}`
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

  /**
   * Replace ~/.hermes (a real directory) with a symlink to `victimDir`, so
   * any write to ~/.hermes/<leaf> would land in victimDir/<leaf>. Mirrors a
   * cross-privilege attacker pre-seeding the config dir as a link.
   */
  async function symlinkHermesTo(victimDir: string): Promise<void> {
    await rm(hermesDir, { recursive: true, force: true });
    await symlink(victimDir, hermesDir);
  }

  // ── P1-A: config.yaml write through a symlinked parent ──────────────

  it("writeFileSafeUnderRoot refuses a symlinked PARENT dir, victim untouched (P1-A enforcement)", async () => {
    const victimDir = join(tmpHome, "victim-dir");
    await mkdir(victimDir, { recursive: true });
    const victimFile = join(victimDir, "config.yaml");
    await writeFile(victimFile, "do-not-touch: true\n");
    await symlinkHermesTo(victimDir);

    // Lexical sink path is ~/.hermes/config.yaml; the leaf O_NOFOLLOW alone
    // would have followed the symlinked .hermes and clobbered the victim.
    await expect(
      writeFileSafeUnderRoot(join(hermesDir, "config.yaml"), "mcp_servers: {}\n", {
        mode: 0o600,
      })
    ).rejects.toThrow(/symlink/);

    expect(await readFile(victimFile, "utf-8")).toBe("do-not-touch: true\n");
  });

  it("writeFileSafeUnderRoot creates missing parent segments individually under the verified root (no recursive follow)", async () => {
    // Deep, entirely-absent parent chain under HOME: each segment must be
    // created one-at-a-time after verifying the prior segment is not a link.
    const sink = join(hermesDir, "nested", "deeper", "config.yaml");
    await writeFileSafeUnderRoot(sink, "mcp_servers: {}\n", { mode: 0o600 });
    expect(await readFile(sink, "utf-8")).toBe("mcp_servers: {}\n");
  });

  // ── P1-A: restore through a symlinked parent ────────────────────────

  it("restoreConfig refuses a symlinked PARENT dir on the restore target, victim untouched (P1-A)", async () => {
    const victimDir = join(tmpHome, "victim-restore");
    await mkdir(victimDir, { recursive: true });
    const victimFile = join(victimDir, "cli-config.json");
    await writeFile(victimFile, '{"precious":true}\n');
    const backup = join(backupDir, "config-backup-r3.json");
    await writeFile(backup, '{"mcp_servers":{}}\n');
    await symlinkHermesTo(victimDir);

    await expect(
      restoreConfig(backup, join(hermesDir, "cli-config.json"))
    ).rejects.toThrow(/symlink/);

    expect(await readFile(victimFile, "utf-8")).toBe('{"precious":true}\n');
  });

  // ── P1-A: unwrap unlink through a symlinked parent ──────────────────

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

  it("unlinkSafeUnderRoot refuses to unlink through a symlinked PARENT dir, victim untouched (P1-A)", async () => {
    const victimDir = join(tmpHome, "victim-unlink");
    await mkdir(victimDir, { recursive: true });
    const victimFile = join(victimDir, "config.yaml");
    await writeFile(victimFile, "precious: true\n");
    await symlinkHermesTo(victimDir);

    await expect(
      unlinkSafeUnderRoot(join(hermesDir, "config.yaml"))
    ).rejects.toThrow(/symlink/);

    // The victim still exists: the unlink was refused, not redirected.
    expect(await readFile(victimFile, "utf-8")).toBe("precious: true\n");
  });

  it("unwrap of a created-by-wrap config.yaml is REFUSED when .hermes is symlinked, victim untouched (P1-A end-to-end)", async () => {
    // Prepare wrapped state inside the REAL hermesDir first.
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(yamlPath, "mcp_servers:\n  sanctuary: {}\n");
    await writeWrappedStateWithMeta([
      { originalPath: yamlPath, backupPath: null },
    ]);
    // Now redirect ~/.hermes at a victim holding its own config.yaml.
    const victimDir = join(tmpHome, "victim-e2e");
    await mkdir(victimDir, { recursive: true });
    const victimYaml = join(victimDir, "config.yaml");
    await writeFile(victimYaml, "precious: true\n");
    // Move the real wrapped json out of the way so backup state survives the
    // symlink swap, then point .hermes at the victim.
    await rm(hermesDir, { recursive: true, force: true });
    await symlink(victimDir, hermesDir);

    await expect(runWrap({ unwrap: true }, {})).rejects.toThrow("process.exit:1");

    expect(stderrOutput()).toContain("Unwrap REFUSED");
    // The victim's own config.yaml is NOT unlinked.
    expect(await readFile(victimYaml, "utf-8")).toBe("precious: true\n");
  });

  // ── P1-B: forged null-backup laundered through a symlinked .hermes ──

  it("validator refuses a forged null-backup whose outside path realpath-matches via a symlinked .hermes (P1-B)", async () => {
    // Attack: ~/.hermes -> /tmp/victim, forged originalPath names the OUTSIDE
    // path /tmp/victim/config.yaml. Round-2 realpath-canonicalized both sides,
    // making the forgery EQUAL to the allowlisted ~/.hermes/config.yaml and
    // letting unwrap unlink the outside file. The symlink walk rejects it.
    const victimDir = join(tmpHome, "victim-launder");
    await mkdir(victimDir, { recursive: true });
    const outsideYaml = join(victimDir, "config.yaml");
    await writeFile(outsideYaml, "precious: true\n");
    await symlinkHermesTo(victimDir);

    await expect(
      validateWrapMetaAuxiliary([
        { originalPath: join(hermesDir, "config.yaml"), backupPath: null },
      ])
    ).rejects.toThrow(WrapMetaValidationError);
  });

  it("validator still accepts the legitimate created-by-wrap config.yaml when .hermes is a real dir (P1-B no false positive)", async () => {
    const validated = await validateWrapMetaAuxiliary([
      { originalPath: join(hermesDir, "config.yaml"), backupPath: null },
    ]);
    expect(validated).toHaveLength(1);
    expect(validated[0]!.backupPath).toBeNull();
  });

  // ── P1-C: primary-config rewrite through a symlinked parent ─────────

  it("rewriteConfigForWrap refuses a symlinked PARENT on the primary config path, victim untouched (P1-C)", async () => {
    const victimDir = join(tmpHome, "victim-rewrite");
    await mkdir(victimDir, { recursive: true });
    const victimConfig = join(victimDir, "cli-config.json");
    await writeFile(victimConfig, '{"precious":true}\n');
    await symlinkHermesTo(victimDir);

    const agentConfig: AgentConfig = {
      platform: "hermes",
      configPath: join(hermesDir, "cli-config.json"),
      servers: [],
      rawConfig: { mcp_servers: {} },
    };

    await expect(
      rewriteConfigForWrap(agentConfig, "npx", ["@sanctuary-framework/mcp-server"])
    ).rejects.toThrow(/symlink/);

    // The plain-writeFile round-2 sink would have clobbered the victim with
    // the rewritten config; the safe sink leaves it byte-identical.
    expect(await readFile(victimConfig, "utf-8")).toBe('{"precious":true}\n');
  });

  it("rewriteConfigForWrap refuses a symlinked LEAF config path too (leaf O_NOFOLLOW still enforced)", async () => {
    const victim = join(tmpHome, "victim-leaf.json");
    await writeFile(victim, '{"precious":true}\n');
    const sink = join(hermesDir, "cli-config.json");
    await symlink(victim, sink);

    const agentConfig: AgentConfig = {
      platform: "hermes",
      configPath: sink,
      servers: [],
      rawConfig: { mcp_servers: {} },
    };

    await expect(
      rewriteConfigForWrap(agentConfig, "npx", ["@sanctuary-framework/mcp-server"])
    ).rejects.toThrow(/symlink/);

    expect(await readFile(victim, "utf-8")).toBe('{"precious":true}\n');
  });

  it("rewriteConfigForWrap writes normally to a real config path under HOME (no false positive)", async () => {
    const sink = join(hermesDir, "cli-config.json");
    const agentConfig: AgentConfig = {
      platform: "hermes",
      configPath: sink,
      servers: [],
      rawConfig: { mcp_servers: {} },
    };
    await rewriteConfigForWrap(agentConfig, "npx", ["@sanctuary-framework/mcp-server"]);
    const written = JSON.parse(await readFile(sink, "utf-8"));
    expect(written.mcp_servers.sanctuary.command).toBe("npx");
  });

  // ── parent-race walk re-runs immediately before the sink ────────────

  it("writeFileSafeUnderRoot re-walks before the open, catching a parent symlink swapped in after mkdir (race-window minimisation)", async () => {
    // Stand up a deep real chain, then swap an intermediate dir for a symlink
    // to simulate the post-mkdir/pre-open race the re-walk is meant to shrink.
    const mid = join(hermesDir, "mid");
    await mkdir(mid, { recursive: true });
    const victimDir = join(tmpHome, "victim-swap");
    await mkdir(victimDir, { recursive: true });
    await writeFile(join(victimDir, "config.yaml"), "precious: true\n");
    await rm(mid, { recursive: true, force: true });
    await symlink(victimDir, mid);

    await expect(
      writeFileSafeUnderRoot(join(mid, "config.yaml"), "x\n", { mode: 0o600 })
    ).rejects.toThrow(/symlink/);
    expect(await readFile(join(victimDir, "config.yaml"), "utf-8")).toBe(
      "precious: true\n"
    );
  });
});
