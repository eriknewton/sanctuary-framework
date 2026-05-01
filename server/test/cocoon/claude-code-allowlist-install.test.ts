/**
 * `installClaudeCodeAllowlist` / `removeClaudeCodeAllowlist` —
 * v1.2.0 F10-B allowlist installer coverage.
 *
 * Mirrors the shape of claude-code-augmentation-install.test.ts.
 * Tests use a tmp-directory `settingsJsonPath` override so the
 * developer's real ~/.claude/settings.json is never touched.
 *
 * Coverage:
 *   - Fresh install: file does not exist; created with permissions.allow
 *     containing the two Sanctuary entries only.
 *   - Append install: existing settings.json with no Sanctuary entries;
 *     entries appended; operator-existing entries preserved.
 *   - Idempotent re-install: both Sanctuary entries already present;
 *     no-op (file not re-written); `alreadyPresent: true`.
 *   - Partial-present: only one Sanctuary entry present; other entry
 *     added; `added.length === 1`.
 *   - Atomic backup at `.sanctuary-backup` on the modify-existing path.
 *   - Malformed JSON throws with a precise diagnostic.
 *   - permissions.allow with the wrong shape (object, string, non-string
 *     array entry) throws with a precise diagnostic.
 *   - Remove round-trip: install then remove; Sanctuary entries gone,
 *     operator entries preserved.
 *   - Remove no-op when no Sanctuary entries are present.
 *   - Remove no-op when settings.json is missing.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdir,
  rm,
  readFile,
  writeFile,
  access,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  installClaudeCodeAllowlist,
  removeClaudeCodeAllowlist,
  SANCTUARY_CHAT_ALLOWLIST_ENTRIES,
  SANCTUARY_SETTINGS_BACKUP_SUFFIX,
} from "../../src/cocoon/claude-code-allowlist.js";

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

describe("installClaudeCodeAllowlist (v1.2.0 F10-B)", () => {
  let tmpDir: string;
  let settingsPath: string;

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-allow-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpDir, { recursive: true });
    settingsPath = join(tmpDir, "settings.json");
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("fresh install: creates settings.json with the two Sanctuary entries only", async () => {
    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.installedAt).toBe(settingsPath);
    expect(result.alreadyPresent).toBe(false);
    expect(result.added).toEqual([...SANCTUARY_CHAT_ALLOWLIST_ENTRIES]);

    const text = await readFile(settingsPath, "utf8");
    const parsed = JSON.parse(text);
    expect(parsed.permissions.allow).toEqual([
      ...SANCTUARY_CHAT_ALLOWLIST_ENTRIES,
    ]);
  });

  it("append install: existing settings preserved; Sanctuary entries appended", async () => {
    const operator = {
      theme: "dark",
      permissions: {
        allow: ["mcp__other-server__some_tool", "Bash(ls)"],
      },
    };
    await writeFile(settingsPath, JSON.stringify(operator, null, 2), "utf8");

    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.alreadyPresent).toBe(false);
    expect(result.added).toEqual([...SANCTUARY_CHAT_ALLOWLIST_ENTRIES]);

    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.theme).toBe("dark");
    expect(parsed.permissions.allow).toEqual([
      "mcp__other-server__some_tool",
      "Bash(ls)",
      ...SANCTUARY_CHAT_ALLOWLIST_ENTRIES,
    ]);

    expect(await pathExists(`${settingsPath}${SANCTUARY_SETTINGS_BACKUP_SUFFIX}`)).toBe(true);
  });

  it("idempotent re-install: both entries already present; no-op (no re-write)", async () => {
    const seeded = {
      permissions: {
        allow: [...SANCTUARY_CHAT_ALLOWLIST_ENTRIES],
      },
    };
    const seededText = JSON.stringify(seeded, null, 2);
    await writeFile(settingsPath, seededText, "utf8");

    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.alreadyPresent).toBe(true);
    expect(result.added).toEqual([]);

    // Idempotent path does not re-write the file.
    expect(await readFile(settingsPath, "utf8")).toBe(seededText);
    // No backup written on idempotent path.
    expect(await pathExists(`${settingsPath}${SANCTUARY_SETTINGS_BACKUP_SUFFIX}`)).toBe(false);
  });

  it("partial-present: only poll_inbox present; send_reply appended", async () => {
    const seeded = {
      permissions: {
        allow: ["mcp__sanctuary-chat__chat__poll_inbox"],
      },
    };
    await writeFile(settingsPath, JSON.stringify(seeded, null, 2), "utf8");

    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.alreadyPresent).toBe(false);
    expect(result.added).toEqual(["mcp__sanctuary-chat__chat__send_reply"]);

    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.permissions.allow).toEqual([
      "mcp__sanctuary-chat__chat__poll_inbox",
      "mcp__sanctuary-chat__chat__send_reply",
    ]);
  });

  it("malformed JSON: throws with a path-prefixed diagnostic; file untouched", async () => {
    const bad = "{not json";
    await writeFile(settingsPath, bad, "utf8");

    await expect(
      installClaudeCodeAllowlist({ settingsJsonPath: settingsPath }),
    ).rejects.toThrow(/Sanctuary:.*not valid JSON/);

    expect(await readFile(settingsPath, "utf8")).toBe(bad);
  });

  it("permissions object with wrong allow shape: throws with diagnostic", async () => {
    const wrong = { permissions: { allow: "not-an-array" } };
    await writeFile(settingsPath, JSON.stringify(wrong), "utf8");

    await expect(
      installClaudeCodeAllowlist({ settingsJsonPath: settingsPath }),
    ).rejects.toThrow(/permissions\.allow.*must be an array/);
  });

  it("permissions itself wrong shape: throws with diagnostic", async () => {
    const wrong = { permissions: "not-an-object" };
    await writeFile(settingsPath, JSON.stringify(wrong), "utf8");

    await expect(
      installClaudeCodeAllowlist({ settingsJsonPath: settingsPath }),
    ).rejects.toThrow(/permissions.*must be an object/);
  });

  it("non-string entry in permissions.allow: throws with diagnostic", async () => {
    const wrong = { permissions: { allow: ["valid", 42] } };
    await writeFile(settingsPath, JSON.stringify(wrong), "utf8");

    await expect(
      installClaudeCodeAllowlist({ settingsJsonPath: settingsPath }),
    ).rejects.toThrow(/contains a non-string entry/);
  });
});

describe("removeClaudeCodeAllowlist (v1.2.0 F10-B)", () => {
  let tmpDir: string;
  let settingsPath: string;

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-allow-rm-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpDir, { recursive: true });
    settingsPath = join(tmpDir, "settings.json");
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("install + remove round-trip preserves operator entries", async () => {
    const operator = {
      theme: "dark",
      permissions: { allow: ["mcp__other-server__some_tool"] },
    };
    await writeFile(settingsPath, JSON.stringify(operator, null, 2), "utf8");

    await installClaudeCodeAllowlist({ settingsJsonPath: settingsPath });
    const result = await removeClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });

    expect(result.removedFrom).toBe(settingsPath);
    expect(result.removed.length).toBe(2);

    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.theme).toBe("dark");
    expect(parsed.permissions.allow).toEqual(["mcp__other-server__some_tool"]);
  });

  it("remove no-op when no Sanctuary entries are present", async () => {
    const operator = {
      permissions: { allow: ["mcp__other-server__some_tool"] },
    };
    await writeFile(settingsPath, JSON.stringify(operator, null, 2), "utf8");
    const result = await removeClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.removedFrom).toBe(settingsPath);
    expect(result.removed).toEqual([]);
  });

  it("remove no-op when settings.json missing", async () => {
    const result = await removeClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.removedFrom).toBeNull();
    expect(result.removed).toEqual([]);
  });
});
