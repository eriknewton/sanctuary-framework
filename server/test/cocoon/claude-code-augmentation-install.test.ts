/**
 * `installClaudeCodeAugmentation` / `removeClaudeCodeAugmentation` —
 * v1.2.0 F10 augmentation installer coverage.
 *
 * Replaces PR #99's Stop-hook installer tests. The augmentation lives
 * at `~/.claude/CLAUDE.md` and its install footprint is a single
 * fenced section bracketed by HTML comment markers. Tests use a
 * tmp-directory `claudeMdPath` override so the developer's real
 * CLAUDE.md is never touched.
 *
 * Coverage:
 *   - Fresh install: file does not exist; created with the section
 *     only.
 *   - Append install: existing CLAUDE.md with no Sanctuary section;
 *     section appended; operator content above preserved verbatim.
 *   - Idempotent re-install: V1 marker already present; no-op;
 *     `alreadyPresent: true`.
 *   - Multi-fortress idempotent: a second install with a different
 *     fortressPath does not duplicate the section. The augmentation
 *     body is invariant across fortresses; per-fortress binding lives
 *     in the sanctuary-chat MCP-config env block, not in CLAUDE.md.
 *   - Atomic backup at `.sanctuary-backup` on every modify-existing
 *     install path.
 *   - Remove: install + remove leaves the file at its pre-install
 *     state (or deletes the file entirely on the fresh-install path).
 *   - Mid-section corruption (open marker without close): install
 *     throws with a precise diagnostic.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, rm, readFile, writeFile, stat, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  installClaudeCodeAugmentation,
  removeClaudeCodeAugmentation,
  SANCTUARY_AUGMENTATION_OPEN_MARKER,
  SANCTUARY_AUGMENTATION_CLOSE_MARKER,
  SANCTUARY_BACKUP_SUFFIX,
} from "../../src/cocoon/claude-code-augmentation.js";

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

const FORTRESS_A = "/tmp/sanctuary-fortress-A";
const FORTRESS_B = "/tmp/sanctuary-fortress-B";
const AGENT_ID_A = "agent:claude_code:fortressA";
const AGENT_ID_B = "agent:claude_code:fortressB";

describe("installClaudeCodeAugmentation (v1.2.0 F10)", () => {
  let tmpDir: string;
  let claudeMdPath: string;

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-aug-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpDir, { recursive: true });
    claudeMdPath = join(tmpDir, "CLAUDE.md");
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("fresh install: creates CLAUDE.md with the V1 section only", async () => {
    const result = await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    expect(result.alreadyPresent).toBe(false);
    expect(result.installedAt).toBe(claudeMdPath);

    const content = await readFile(claudeMdPath, "utf8");
    expect(content).toContain(SANCTUARY_AUGMENTATION_OPEN_MARKER);
    expect(content).toContain(SANCTUARY_AUGMENTATION_CLOSE_MARKER);
    expect(content).toContain("Sanctuary Operator Chat");
    expect(content).toContain("chat/poll_inbox");
    expect(content).toContain("chat/send_reply");
    // No backup on fresh install (no prior content to preserve).
    expect(await pathExists(`${claudeMdPath}${SANCTUARY_BACKUP_SUFFIX}`)).toBe(
      false,
    );
  });

  it("append install: existing CLAUDE.md gets section appended; operator content above preserved verbatim", async () => {
    const operatorContent = `# My Personal CLAUDE.md

Some operator-supplied global instruction lives here.

- Always use TDD.
- Prefer composition over inheritance.
`;
    await writeFile(claudeMdPath, operatorContent);

    const result = await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    expect(result.alreadyPresent).toBe(false);

    const content = await readFile(claudeMdPath, "utf8");
    // Operator content preserved verbatim at the top of the file.
    expect(content.startsWith(operatorContent)).toBe(true);
    // Sanctuary section appended at the end.
    expect(content).toContain(SANCTUARY_AUGMENTATION_OPEN_MARKER);
    expect(content).toContain(SANCTUARY_AUGMENTATION_CLOSE_MARKER);
    // Backup created with the prior content.
    const backup = await readFile(
      `${claudeMdPath}${SANCTUARY_BACKUP_SUFFIX}`,
      "utf8",
    );
    expect(backup).toBe(operatorContent);
  });

  it("append install: blank-line separator inserted between operator content and Sanctuary section", async () => {
    const operatorContent = `# My CLAUDE.md
single-line preamble`;
    await writeFile(claudeMdPath, operatorContent);

    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });

    const content = await readFile(claudeMdPath, "utf8");
    // The open marker should be preceded by a blank line so the
    // section is visually distinct from operator content above it.
    const openIdx = content.indexOf(SANCTUARY_AUGMENTATION_OPEN_MARKER);
    expect(openIdx).toBeGreaterThan(0);
    const before = content.slice(0, openIdx);
    expect(before.endsWith("\n\n")).toBe(true);
  });

  it("idempotent re-install: V1 marker already present, no-op, alreadyPresent=true", async () => {
    // First install creates the file.
    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const firstContent = await readFile(claudeMdPath, "utf8");
    const firstStat = await stat(claudeMdPath);

    // Second install detects the marker.
    const result = await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    expect(result.alreadyPresent).toBe(true);

    const secondContent = await readFile(claudeMdPath, "utf8");
    expect(secondContent).toBe(firstContent);
    // mtime preserved (no rewrite happened).
    const secondStat = await stat(claudeMdPath);
    expect(secondStat.mtimeMs).toBe(firstStat.mtimeMs);

    // Single section: open marker appears exactly once.
    const occurrences = secondContent.split(
      SANCTUARY_AUGMENTATION_OPEN_MARKER,
    ).length - 1;
    expect(occurrences).toBe(1);
  });

  it("multi-fortress idempotent: install with different fortressPath does not duplicate the section", async () => {
    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const result = await installClaudeCodeAugmentation({
      agentId: AGENT_ID_B,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_B,
      claudeMdPath,
    });
    expect(result.alreadyPresent).toBe(true);

    const content = await readFile(claudeMdPath, "utf8");
    const occurrences = content.split(
      SANCTUARY_AUGMENTATION_OPEN_MARKER,
    ).length - 1;
    expect(occurrences).toBe(1);
  });

  it("mid-section corruption: open marker present without close marker throws diagnostic", async () => {
    const broken = `# Operator CLAUDE.md
${SANCTUARY_AUGMENTATION_OPEN_MARKER}
## Sanctuary Operator Chat
(missing close marker)
`;
    await writeFile(claudeMdPath, broken);

    await expect(
      installClaudeCodeAugmentation({
        agentId: AGENT_ID_A,
        identityId: "sanctuary-chat",
        fortressPath: FORTRESS_A,
        claudeMdPath,
      }),
    ).rejects.toThrow(/contains an open V1 marker.*without a matching close/);
  });

  it("file mode is 0o600 on fresh install (owner read+write only)", async () => {
    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const s = await stat(claudeMdPath);
    // mode bitmask masks off non-permission bits.
    expect(s.mode & 0o777).toBe(0o600);
  });

  it("section body has zero em-dashes (no-em-dash rule for operator-facing copy)", async () => {
    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const content = await readFile(claudeMdPath, "utf8");
    expect(content).not.toContain("—");
  });
});

describe("removeClaudeCodeAugmentation (v1.2.0 F10)", () => {
  let tmpDir: string;
  let claudeMdPath: string;

  beforeEach(async () => {
    tmpDir = join(
      tmpdir(),
      `sanctuary-aug-rm-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpDir, { recursive: true });
    claudeMdPath = join(tmpDir, "CLAUDE.md");
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("no file: returns removedFrom=null", async () => {
    const r = await removeClaudeCodeAugmentation({ claudeMdPath });
    expect(r.removedFrom).toBeNull();
  });

  it("file present, no Sanctuary section: returns removedFrom=null, file untouched", async () => {
    const operator = "# Operator CLAUDE.md\n\nlines preserved.\n";
    await writeFile(claudeMdPath, operator);
    const r = await removeClaudeCodeAugmentation({ claudeMdPath });
    expect(r.removedFrom).toBeNull();
    const content = await readFile(claudeMdPath, "utf8");
    expect(content).toBe(operator);
  });

  it("install + remove on existing operator content: file restored byte-for-byte to pre-install state", async () => {
    const operator = `# Operator CLAUDE.md

Operator preamble.

- rule one
- rule two
`;
    await writeFile(claudeMdPath, operator);

    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const r = await removeClaudeCodeAugmentation({ claudeMdPath });
    expect(r.removedFrom).toBe(claudeMdPath);

    const after = await readFile(claudeMdPath, "utf8");
    expect(after).toBe(operator);
  });

  it("install + remove on fresh-install path: deletes the file (Sanctuary was sole content)", async () => {
    await installClaudeCodeAugmentation({
      agentId: AGENT_ID_A,
      identityId: "sanctuary-chat",
      fortressPath: FORTRESS_A,
      claudeMdPath,
    });
    const r = await removeClaudeCodeAugmentation({ claudeMdPath });
    expect(r.removedFrom).toBe(claudeMdPath);
    expect(await pathExists(claudeMdPath)).toBe(false);
  });

  it("remove preserves operator content below the Sanctuary section", async () => {
    const above = "# Operator CLAUDE.md\n\nAbove the section.\n";
    const below = "\n## Operator section below\n\nBelow the section.\n";
    // Manually craft a file with operator content surrounding the
    // V1 block to exercise the slice logic on both sides.
    const sectionStub = `${SANCTUARY_AUGMENTATION_OPEN_MARKER}\nfake-body\n${SANCTUARY_AUGMENTATION_CLOSE_MARKER}\n`;
    await writeFile(claudeMdPath, above + "\n" + sectionStub + below);

    const r = await removeClaudeCodeAugmentation({ claudeMdPath });
    expect(r.removedFrom).toBe(claudeMdPath);

    const after = await readFile(claudeMdPath, "utf8");
    expect(after).toContain("Above the section.");
    expect(after).toContain("Below the section.");
    expect(after).not.toContain(SANCTUARY_AUGMENTATION_OPEN_MARKER);
    expect(after).not.toContain(SANCTUARY_AUGMENTATION_CLOSE_MARKER);
  });
});
