/**
 * `installClaudeCodeAllowlist` / `removeClaudeCodeAllowlist`,
 * WP-V1.2 reshape allowlist installer coverage.
 *
 * Tests use a tmp-directory `settingsJsonPath` override so the
 * developer's real ~/.claude/settings.json is never touched.
 *
 * Coverage:
 *   - Fresh install: file does not exist; created with permissions.allow
 *     containing the broker entries only.
 *   - Append install: existing settings.json with no Sanctuary entries;
 *     entries appended; operator-existing entries preserved.
 *   - Idempotent re-install: all Sanctuary entries already present;
 *     no-op (file not re-written); `alreadyPresent: true`.
 *   - Partial-present: only some Sanctuary entries present; missing
 *     entries added.
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
  symlink,
  lstat,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  installClaudeCodeAllowlist,
  removeClaudeCodeAllowlist,
  SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
  SANCTUARY_SETTINGS_BACKUP_SUFFIX,
} from "../../src/wrap/claude-code-allowlist.js";

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

describe("installClaudeCodeAllowlist (WP-V1.2 reshape)", () => {
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

  it("fresh install: creates settings.json with the broker entries only", async () => {
    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.installedAt).toBe(settingsPath);
    expect(result.alreadyPresent).toBe(false);
    expect(result.added).toEqual([...SANCTUARY_BROKER_ALLOWLIST_ENTRIES]);

    const text = await readFile(settingsPath, "utf8");
    const parsed = JSON.parse(text);
    expect(parsed.permissions.allow).toEqual([
      ...SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
    ]);
  });

  it("append install: existing settings preserved; broker entries appended", async () => {
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
    expect(result.added).toEqual([...SANCTUARY_BROKER_ALLOWLIST_ENTRIES]);

    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.theme).toBe("dark");
    expect(parsed.permissions.allow).toEqual([
      "mcp__other-server__some_tool",
      "Bash(ls)",
      ...SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
    ]);

    expect(await pathExists(`${settingsPath}${SANCTUARY_SETTINGS_BACKUP_SUFFIX}`)).toBe(true);
  });

  it("idempotent re-install: all entries already present; no-op (no re-write)", async () => {
    const seeded = {
      permissions: {
        allow: [...SANCTUARY_BROKER_ALLOWLIST_ENTRIES],
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

  it("partial-present: only some Sanctuary entries present; rest appended", async () => {
    const seeded = {
      permissions: {
        allow: [SANCTUARY_BROKER_ALLOWLIST_ENTRIES[0]!],
      },
    };
    await writeFile(settingsPath, JSON.stringify(seeded, null, 2), "utf8");

    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.alreadyPresent).toBe(false);
    expect(result.added).toEqual(SANCTUARY_BROKER_ALLOWLIST_ENTRIES.slice(1));

    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.permissions.allow).toEqual([
      ...SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
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

  // ── Symlink-redirection hardening (follow-up to #492) ──────────────
  //
  // Threat model: an attacker who can plant a symlink in (or as) the
  // ~/.claude settings path redirects the wrap-time allowlist write to a
  // file the operator never intended. The install sink must fail closed,
  // never follow the redirect, and leave the victim untouched.

  it("symlinked parent directory: refused; victim untouched (fail-closed)", async () => {
    // Victim directory the attacker's symlink points at, seeded with a file
    // we assert is never written through.
    const victimDir = join(tmpDir, "victim");
    await mkdir(victimDir, { recursive: true });
    const victimFile = join(victimDir, "settings.json");
    const victimContent = JSON.stringify({ victim: "do-not-touch" }, null, 2);
    await writeFile(victimFile, victimContent, "utf8");

    // Attacker redirects the would-be `~/.claude` parent at the victim dir.
    const linkDir = join(tmpDir, "link");
    await symlink(victimDir, linkDir);
    const redirectedSettings = join(linkDir, "settings.json");

    await expect(
      installClaudeCodeAllowlist({ settingsJsonPath: redirectedSettings }),
    ).rejects.toThrow(/is a symlink/i);

    // The victim file (same inode the symlinked parent resolves to) is
    // byte-for-byte unchanged: the install never wrote through the link.
    expect(await readFile(victimFile, "utf8")).toBe(victimContent);
  });

  it("symlinked settings.json leaf: rename replaces the link, victim untouched", async () => {
    // A real ~/.claude parent, but settings.json itself is a symlink that an
    // attacker pointed at an unrelated victim file. The atomic tmp+rename
    // must replace the link in place (rename does not follow a symlinked
    // destination), so the victim's contents survive.
    const realDir = join(tmpDir, "real");
    await mkdir(realDir, { recursive: true });
    const victimFile = join(tmpDir, "victim.json");
    const victimContent = JSON.stringify({ victim: "do-not-touch" }, null, 2);
    await writeFile(victimFile, victimContent, "utf8");

    // Pre-seed a valid settings file at the link target so the install reads
    // valid JSON, then redirect the leaf through a symlink to the victim.
    const linkLeaf = join(realDir, "settings.json");
    await symlink(victimFile, linkLeaf);

    // The link currently resolves to the victim (valid JSON, no Sanctuary
    // entries), so the install takes the append path.
    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: linkLeaf,
    });
    expect(result.alreadyPresent).toBe(false);

    // The victim file is untouched — rename replaced the symlink rather than
    // following it.
    expect(await readFile(victimFile, "utf8")).toBe(victimContent);
    // settings.json is now a regular file (not a symlink) carrying the merge.
    expect((await lstat(linkLeaf)).isSymbolicLink()).toBe(false);
    const parsed = JSON.parse(await readFile(linkLeaf, "utf8"));
    expect(parsed.permissions.allow).toEqual([
      ...SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
    ]);
  });

  it("symlinked backup destination: refused; victim untouched (fail-closed)", async () => {
    // The append path writes a `.sanctuary-backup` sibling at a predictable
    // path. An attacker who can plant a symlink there must not be able to
    // redirect the backup copy and clobber an unrelated victim file. The
    // backup write goes through the same safe-path sink as the primary write.
    const operator = {
      permissions: { allow: ["mcp__other-server__some_tool"] },
    };
    await writeFile(settingsPath, JSON.stringify(operator, null, 2), "utf8");

    const victimFile = join(tmpDir, "victim.json");
    const victimContent = JSON.stringify({ victim: "do-not-touch" }, null, 2);
    await writeFile(victimFile, victimContent, "utf8");

    // Pre-plant a symlink at the exact backup path the install will target.
    const backupPath = `${settingsPath}${SANCTUARY_SETTINGS_BACKUP_SUFFIX}`;
    await symlink(victimFile, backupPath);

    // Backup is best-effort and the symlink is refused (ELOOP), so the install
    // still completes the primary allowlist merge — but the victim that the
    // backup symlink pointed at is byte-for-byte untouched.
    const result = await installClaudeCodeAllowlist({
      settingsJsonPath: settingsPath,
    });
    expect(result.alreadyPresent).toBe(false);

    expect(await readFile(victimFile, "utf8")).toBe(victimContent);
    // The backup path is still the attacker's symlink (the safe sink refused
    // to write through it) rather than a regular file written via the link.
    expect((await lstat(backupPath)).isSymbolicLink()).toBe(true);

    // The primary settings file received the merge as normal.
    const parsed = JSON.parse(await readFile(settingsPath, "utf8"));
    expect(parsed.permissions.allow).toEqual([
      "mcp__other-server__some_tool",
      ...SANCTUARY_BROKER_ALLOWLIST_ENTRIES,
    ]);
  });
});

describe("removeClaudeCodeAllowlist (WP-V1.2 reshape)", () => {
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
    expect(result.removed.length).toBe(SANCTUARY_BROKER_ALLOWLIST_ENTRIES.length);

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
