/**
 * Claude Code Stop hook installer — coverage for v1.2.0 F10.
 *
 *  - Fresh-install: creates ~/.claude/settings.json with Sanctuary entry only.
 *  - Existing-install: appends to hooks.Stop; preserves operator hooks verbatim.
 *  - Idempotent re-wrap: no duplicate entry; alreadyPresent=true, envUpdated=false.
 *  - Multi-fortress (most-recent wins): refreshes env values on existing entry.
 *  - Atomic backup: prior settings.json content copied to .sanctuary-backup.
 *  - Corrupt settings.json: install throws cleanly; backup preserved.
 *  - Missing bundled script: install throws with operator-actionable message.
 *  - Remove path: install + remove leaves settings.json minus the entry.
 *  - Tests use hookScriptPath + settingsPath overrides to avoid touching
 *    the developer's real ~/.claude/settings.json.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  writeFile,
  readFile,
  mkdir,
  rm,
  access,
  chmod,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  installClaudeCodeStopHook,
  removeClaudeCodeStopHook,
  SANCTUARY_STOP_HOOK_MATCHER,
  SANCTUARY_BACKUP_SUFFIX,
} from "../../src/cocoon/claude-code-hooks.js";

interface Fixture {
  rootDir: string;
  settingsPath: string;
  hookScriptPath: string;
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

describe("Claude Code Stop hook installer (v1.2.0 F10)", () => {
  let fx: Fixture;

  beforeEach(async () => {
    const root = join(
      tmpdir(),
      `sanctuary-claude-code-hook-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(root, { recursive: true });
    const claudeDir = join(root, ".claude");
    await mkdir(claudeDir, { recursive: true });
    const settingsPath = join(claudeDir, "settings.json");
    const hookScriptPath = join(root, "sanctuary-chat-stop-hook.sh");
    await writeFile(hookScriptPath, "#!/usr/bin/env bash\nexit 0\n", {
      mode: 0o755,
    });
    fx = { rootDir: root, settingsPath, hookScriptPath };
  });

  afterEach(async () => {
    try {
      await rm(fx.rootDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("fresh-install: creates settings.json with Sanctuary entry only", async () => {
    expect(await pathExists(fx.settingsPath)).toBe(false);
    const result = await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });
    expect(result.alreadyPresent).toBe(false);
    expect(result.envUpdated).toBe(false);
    expect(result.installedAt).toBe(fx.settingsPath);

    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(1);
    const entry = written.hooks.Stop[0];
    expect(entry.matcher).toBe(SANCTUARY_STOP_HOOK_MATCHER);
    expect(entry.hooks[0].command).toBe(fx.hookScriptPath);
    expect(entry.hooks[0].env.SANCTUARY_FORTRESS_PATH).toBe("/tmp/fortressA");
    expect(entry.hooks[0].env.SANCTUARY_AGENT_ID).toBe(
      "agent:claude_code:fortressA",
    );
    expect(entry.hooks[0].env.SANCTUARY_IDENTITY_ID).toBe("sanctuary-chat");
  });

  it("existing-install: appends to hooks.Stop; preserves operator hooks verbatim", async () => {
    const operatorHook = {
      matcher: "OperatorVerify",
      hooks: [
        {
          type: "command",
          command: "/usr/local/bin/operator-verify.sh",
          env: { OPERATOR_FLAG: "true" },
        },
      ],
    };
    await writeFile(
      fx.settingsPath,
      JSON.stringify(
        {
          hooks: { Stop: [operatorHook] },
          unrelated: { keep: "me" },
        },
        null,
        2,
      ),
    );

    const result = await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });
    expect(result.alreadyPresent).toBe(false);

    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(2);
    expect(written.hooks.Stop[0]).toEqual(operatorHook);
    expect(written.hooks.Stop[1].matcher).toBe(SANCTUARY_STOP_HOOK_MATCHER);
    // Unrelated keys preserved.
    expect(written.unrelated).toEqual({ keep: "me" });
  });

  it("idempotent re-wrap: no duplicate; alreadyPresent=true, envUpdated=false", async () => {
    const opts = {
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    };
    const r1 = await installClaudeCodeStopHook(opts);
    expect(r1.alreadyPresent).toBe(false);

    const r2 = await installClaudeCodeStopHook(opts);
    expect(r2.alreadyPresent).toBe(true);
    expect(r2.envUpdated).toBe(false);

    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(1);
    expect(written.hooks.Stop[0].matcher).toBe(SANCTUARY_STOP_HOOK_MATCHER);
  });

  it("multi-fortress most-recent wins: refreshes env, alreadyPresent=true envUpdated=true", async () => {
    await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });
    const r2 = await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressB",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressB",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });
    expect(r2.alreadyPresent).toBe(true);
    expect(r2.envUpdated).toBe(true);

    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(1);
    const env = written.hooks.Stop[0].hooks[0].env;
    expect(env.SANCTUARY_FORTRESS_PATH).toBe("/tmp/fortressB");
    expect(env.SANCTUARY_AGENT_ID).toBe("agent:claude_code:fortressB");
  });

  it("atomic backup: prior settings.json copied to .sanctuary-backup", async () => {
    const prior = { hooks: { Stop: [] }, marker: "before-install" };
    await writeFile(fx.settingsPath, JSON.stringify(prior, null, 2));

    await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });

    const backupPath = `${fx.settingsPath}${SANCTUARY_BACKUP_SUFFIX}`;
    expect(await pathExists(backupPath)).toBe(true);
    const backup = JSON.parse(await readFile(backupPath, "utf-8"));
    expect(backup).toEqual(prior);
  });

  it("corrupt settings.json: install throws cleanly with parse error message", async () => {
    await writeFile(fx.settingsPath, "{not valid json", "utf8");

    await expect(
      installClaudeCodeStopHook({
        agentId: "agent:claude_code:fortressA",
        identityId: "sanctuary-chat",
        fortressPath: "/tmp/fortressA",
        settingsPath: fx.settingsPath,
        hookScriptPath: fx.hookScriptPath,
      }),
    ).rejects.toThrow(/not valid JSON/);
  });

  it("missing bundled script: install throws with operator-actionable message", async () => {
    await rm(fx.hookScriptPath, { force: true });

    await expect(
      installClaudeCodeStopHook({
        agentId: "agent:claude_code:fortressA",
        identityId: "sanctuary-chat",
        fortressPath: "/tmp/fortressA",
        settingsPath: fx.settingsPath,
        hookScriptPath: fx.hookScriptPath,
      }),
    ).rejects.toThrow(/bundled hook script not found/);
  });

  it("remove path: install + remove leaves settings.json minus the entry", async () => {
    const operatorHook = {
      matcher: "OperatorVerify",
      hooks: [
        {
          type: "command",
          command: "/usr/local/bin/operator-verify.sh",
        },
      ],
    };
    await writeFile(
      fx.settingsPath,
      JSON.stringify({ hooks: { Stop: [operatorHook] } }, null, 2),
    );
    await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });

    let written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(2);

    const removeResult = await removeClaudeCodeStopHook({
      settingsPath: fx.settingsPath,
    });
    expect(removeResult.removedFrom).toBe(fx.settingsPath);

    written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop).toHaveLength(1);
    expect(written.hooks.Stop[0]).toEqual(operatorHook);
  });

  it("remove path on settings without Sanctuary entry: no-op, removedFrom=null", async () => {
    const settings = {
      hooks: {
        Stop: [
          {
            matcher: "OperatorVerify",
            hooks: [{ type: "command", command: "/usr/bin/op" }],
          },
        ],
      },
    };
    await writeFile(fx.settingsPath, JSON.stringify(settings, null, 2));
    const result = await removeClaudeCodeStopHook({
      settingsPath: fx.settingsPath,
    });
    expect(result.removedFrom).toBeNull();
    const after = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(after).toEqual(settings);
  });

  it("remove path on absent settings file: no-op, removedFrom=null", async () => {
    expect(await pathExists(fx.settingsPath)).toBe(false);
    const result = await removeClaudeCodeStopHook({
      settingsPath: fx.settingsPath,
    });
    expect(result.removedFrom).toBeNull();
    expect(await pathExists(fx.settingsPath)).toBe(false);
  });

  it("hook command resolves to the bundled script path on the entry", async () => {
    await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
    });
    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop[0].hooks[0].command).toBe(fx.hookScriptPath);
    expect(written.hooks.Stop[0].hooks[0].type).toBe("command");
  });

  it("install with sanctuaryBin: env block carries SANCTUARY_BIN", async () => {
    await installClaudeCodeStopHook({
      agentId: "agent:claude_code:fortressA",
      identityId: "sanctuary-chat",
      fortressPath: "/tmp/fortressA",
      settingsPath: fx.settingsPath,
      hookScriptPath: fx.hookScriptPath,
      sanctuaryBin: "/opt/homebrew/bin/sanctuary",
    });
    const written = JSON.parse(await readFile(fx.settingsPath, "utf-8"));
    expect(written.hooks.Stop[0].hooks[0].env.SANCTUARY_BIN).toBe(
      "/opt/homebrew/bin/sanctuary",
    );
  });
});
