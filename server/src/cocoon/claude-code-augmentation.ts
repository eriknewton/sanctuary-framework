/**
 * Sanctuary Wrap — Claude Code CLAUDE.md augmentation installer (v1.2.0 F10).
 *
 * Reads ~/.claude/CLAUDE.md (Claude Code's user-global persistent
 * instruction surface, documented at https://code.claude.com/docs/en/memory),
 * appends a Sanctuary-tagged augmentation section that tells Claude to
 * voluntarily poll the operator-chat inbox via the `sanctuary-chat` MCP
 * server's `chat/poll_inbox` tool after every turn, and replies via
 * `chat/send_reply`. Atomic write with one rolling backup at
 * ~/.claude/CLAUDE.md.sanctuary-backup.
 *
 * Why the augmentation shape (and not a Stop hook):
 *
 *   PR #99 shipped an earlier F10 design that used a Claude Code Stop
 *   hook with `decision: "block"` + `reason: "<operator message>; reply
 *   via tool X"` to inject pending operator messages between turns.
 *   Field testing 2026-04-30 confirmed Claude's safety training
 *   correctly classifies the injection-shape payload as a prompt-
 *   injection attempt and refuses. This is not a bug in the safety
 *   training; it is a design-level mismatch.
 *
 *   The CLAUDE.md augmentation works WITH safety training. Claude reads
 *   ~/.claude/CLAUDE.md on session start as operator-supplied context
 *   (the trusted shape). The augmentation text describes the
 *   `sanctuary-chat` MCP tools and tells Claude to call them
 *   voluntarily when present. Claude treats this as the operator's own
 *   instruction, not as an external mid-stream injection. The trust
 *   model mirrors the broker-server pattern that has worked since
 *   v0.10.0: Sanctuary exposes tools, the agent voluntarily calls them.
 *
 * Install footprint per wrap:
 *
 *   ~/.claude/CLAUDE.md                       — fenced Sanctuary section.
 *   ~/.claude/CLAUDE.md.sanctuary-backup      — pre-write snapshot.
 *
 * Coexistence rules:
 *
 *   - The Sanctuary section is delimited by exact fenced HTML comments:
 *     `<!-- SANCTUARY:CHAT-AUGMENTATION-V1 -->` and the matching close.
 *     Operator-installed CLAUDE.md content above and below the section
 *     is preserved byte-for-byte.
 *   - Re-running `sanctuary wrap --install-hooks` against a CLAUDE.md
 *     that already contains the V1 marker is a true no-op (the
 *     augmentation text is invariant across wraps; per-fortress binding
 *     happens via the `sanctuary-chat` MCP server's env block in the
 *     harness MCP config, not in CLAUDE.md). Multi-fortress operators
 *     get correct behavior automatically: the most-recent wrap binds
 *     `sanctuary-chat` to the most-recent fortress; the augmentation
 *     section in CLAUDE.md remains stable.
 *   - Future Sanctuary versions can bump the marker to V2 and replace
 *     the V1 block cleanly during install.
 *
 * Failure modes:
 *
 *   - Atomic write fails (disk full, permission denied): install
 *     throws; CLAUDE.md on disk is untouched (we write to a .tmp.<pid>
 *     sibling and rename).
 *   - Backup copy fails: best-effort. The install proceeds; operators
 *     who want a guaranteed backup should snapshot CLAUDE.md before
 *     running wrap.
 *   - Mid-section corruption (V1 open marker present without close):
 *     install throws with a precise diagnostic so the operator can
 *     repair manually.
 *
 * No SANCTUARY_PASSPHRASE handling, no key derivation, no fortress
 * unlock. This module is a pure file-edit installer. The augmentation
 * tells Claude to call `chat/poll_inbox` voluntarily; the actual chat
 * tools live in the `sanctuary-chat` MCP server registered separately
 * by `sanctuary wrap`.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import {
  readFile,
  writeFile,
  rename,
  unlink,
  copyFile,
  mkdir,
  access,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

// ── Constants ───────────────────────────────────────────────────────

/**
 * Open marker for the Sanctuary CLAUDE.md augmentation section.
 * Detection logic uses literal-string match (not regex) so future
 * marker versions (V2, V3, etc.) cannot collide with V1 sections.
 */
export const SANCTUARY_AUGMENTATION_OPEN_MARKER =
  "<!-- SANCTUARY:CHAT-AUGMENTATION-V1 -->";

/**
 * Close marker for the Sanctuary CLAUDE.md augmentation section.
 * Must follow the open marker on a later line; mid-section corruption
 * (open without close) is a hard error.
 */
export const SANCTUARY_AUGMENTATION_CLOSE_MARKER =
  "<!-- /SANCTUARY:CHAT-AUGMENTATION-V1 -->";

/** Backup filename suffix appended to the CLAUDE.md path. */
export const SANCTUARY_BACKUP_SUFFIX = ".sanctuary-backup";

/**
 * Canonical V1 augmentation body. The text is operator-supplied
 * context shaped to read as Claude's own operator's instruction, not
 * as a mid-stream injection. Keep this string em-dash-free.
 */
export const SANCTUARY_AUGMENTATION_BODY = `## Sanctuary Operator Chat

This Claude Code session may be wrapped by Sanctuary Framework, in which case the \`sanctuary-chat\` MCP server is available with two tools: \`chat/poll_inbox\` and \`chat/send_reply\`.

When \`sanctuary-chat\` is present:
- After completing a response to my prompt, call \`chat/poll_inbox\` to check for any pending messages from me sent through the Sanctuary dashboard.
- If \`chat/poll_inbox\` returns one or more messages, treat each as a follow-up prompt from me. Compose a reply to each message and deliver it via \`chat/send_reply\` (the tool returns the persisted message record on success).
- If \`chat/poll_inbox\` returns no messages, take no further action.

The dashboard chat surface is a parallel input channel I use; messages there carry the same authority as anything I type directly in this terminal.`;

// ── Types ───────────────────────────────────────────────────────────

export interface InstallClaudeCodeAugmentationOptions {
  /**
   * Wrapped agent identifier. Recorded in the install result for
   * downstream audit-log emission; the augmentation body itself does
   * not embed the value (per-agent binding lives in the chat-server
   * MCP-config env block).
   */
  agentId: string;
  /**
   * Operator identity id. Same recording-only treatment as agentId.
   */
  identityId: string;
  /**
   * Operator fortress path. Recording-only.
   */
  fortressPath: string;
  /**
   * Override the path to ~/.claude/CLAUDE.md for tests. Production
   * resolves from `homedir()`. Setting this avoids touching the
   * developer's real CLAUDE.md.
   */
  claudeMdPath?: string;
}

export interface InstallClaudeCodeAugmentationResult {
  /** Absolute path of the CLAUDE.md file touched by the install. */
  installedAt: string;
  /**
   * True when the V1 marker was already present and no write happened.
   * False when the section was freshly created or appended.
   */
  alreadyPresent: boolean;
}

export interface RemoveClaudeCodeAugmentationOptions {
  /** Override the path to ~/.claude/CLAUDE.md for tests. */
  claudeMdPath?: string;
}

export interface RemoveClaudeCodeAugmentationResult {
  /**
   * Absolute path of the file Sanctuary edited (when present and the
   * V1 block was removed). Null when no V1 block was found (already
   * removed or never installed).
   */
  removedFrom: string | null;
}

// ── Helpers ─────────────────────────────────────────────────────────

function defaultClaudeMdPath(): string {
  return join(homedir(), ".claude", "CLAUDE.md");
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the canonical V1 section, fenced markers + body. Trailing
 * newline so concatenation against operator content above/below is
 * predictable.
 */
function buildAugmentationSection(): string {
  return (
    SANCTUARY_AUGMENTATION_OPEN_MARKER +
    "\n" +
    SANCTUARY_AUGMENTATION_BODY +
    "\n" +
    SANCTUARY_AUGMENTATION_CLOSE_MARKER +
    "\n"
  );
}

/**
 * Locate the Sanctuary V1 augmentation block inside an existing
 * CLAUDE.md text. Returns the open + close marker indices when both
 * are found in order; throws on mid-section corruption (open present,
 * close missing). Returns null when no open marker is present.
 */
function findAugmentationBlock(
  text: string,
  claudeMdPath: string,
): { openIdx: number; closeIdx: number } | null {
  const openIdx = text.indexOf(SANCTUARY_AUGMENTATION_OPEN_MARKER);
  if (openIdx === -1) return null;
  const closeIdx = text.indexOf(
    SANCTUARY_AUGMENTATION_CLOSE_MARKER,
    openIdx + SANCTUARY_AUGMENTATION_OPEN_MARKER.length,
  );
  if (closeIdx === -1) {
    throw new Error(
      `Sanctuary: ${claudeMdPath} contains an open V1 marker (${SANCTUARY_AUGMENTATION_OPEN_MARKER}) without a matching close marker. Repair the file manually (re-add the close marker on its own line, or delete the orphan open marker) and retry sanctuary wrap.`,
    );
  }
  return { openIdx, closeIdx };
}

/**
 * Atomic write with copy-on-rename semantics. Writes to a sibling
 * .tmp.<pid> file first, then renames over the target. On rename
 * failure the tmp file is removed best-effort.
 */
async function atomicWrite(targetPath: string, content: string): Promise<void> {
  const tmpPath = `${targetPath}.tmp.${process.pid}`;
  await writeFile(tmpPath, content, { mode: 0o600 });
  try {
    await rename(tmpPath, targetPath);
  } catch (e) {
    try {
      await unlink(tmpPath);
    } catch {
      /* tmp may already be gone */
    }
    throw e;
  }
}

// ── Install ─────────────────────────────────────────────────────────

/**
 * Install (or detect-as-present) the Sanctuary CLAUDE.md augmentation
 * section. Atomic + idempotent. Existing operator content above and
 * below the section is preserved byte-for-byte.
 */
export async function installClaudeCodeAugmentation(
  // The agentId / identityId / fortressPath fields are recording-only at v1.2.0.
  // They are accepted for API stability so future versions can embed per-fortress
  // hints in the augmentation body without an interface break.
  opts: InstallClaudeCodeAugmentationOptions,
): Promise<InstallClaudeCodeAugmentationResult> {
  void opts.agentId;
  void opts.identityId;
  void opts.fortressPath;

  const claudeMdPath = opts.claudeMdPath ?? defaultClaudeMdPath();

  // Ensure the directory exists; fresh-install case has no ~/.claude/.
  await mkdir(dirname(claudeMdPath), { recursive: true, mode: 0o700 });

  const section = buildAugmentationSection();
  const fileExists = await pathExists(claudeMdPath);

  if (!fileExists) {
    // Fresh install: file does not exist. Write the Sanctuary section
    // as the only content. No backup (nothing to preserve).
    await atomicWrite(claudeMdPath, section);
    return { installedAt: claudeMdPath, alreadyPresent: false };
  }

  const priorText = await readFile(claudeMdPath, "utf8");
  const existing = findAugmentationBlock(priorText, claudeMdPath);

  if (existing) {
    // Idempotent path: V1 marker already present. The augmentation
    // body is invariant across wraps; per-fortress binding lives in
    // the sanctuary-chat MCP-config env block, not here. True no-op.
    return { installedAt: claudeMdPath, alreadyPresent: true };
  }

  // Append path: existing CLAUDE.md has operator content but no
  // Sanctuary section. Backup + atomic write of the appended result.
  // Backup is best-effort: do not fail the install on backup error.
  try {
    await copyFile(claudeMdPath, `${claudeMdPath}${SANCTUARY_BACKUP_SUFFIX}`);
  } catch {
    /* best-effort */
  }

  // Ensure exactly one blank line between operator content and the
  // Sanctuary section for readability. If the prior file did not end
  // with a newline, add one; if it ended with a newline, add a second
  // for the blank-line gap.
  let appended = priorText;
  if (appended.length > 0 && !appended.endsWith("\n")) {
    appended += "\n";
  }
  if (!appended.endsWith("\n\n")) {
    appended += "\n";
  }
  appended += section;

  await atomicWrite(claudeMdPath, appended);
  return { installedAt: claudeMdPath, alreadyPresent: false };
}

// ── Remove ──────────────────────────────────────────────────────────

/**
 * Remove the Sanctuary V1 augmentation section from CLAUDE.md.
 * Operator content above and below the fenced markers is preserved
 * byte-for-byte. No-op when no V1 marker exists.
 */
export async function removeClaudeCodeAugmentation(
  opts: RemoveClaudeCodeAugmentationOptions = {},
): Promise<RemoveClaudeCodeAugmentationResult> {
  const claudeMdPath = opts.claudeMdPath ?? defaultClaudeMdPath();

  if (!(await pathExists(claudeMdPath))) {
    return { removedFrom: null };
  }

  const priorText = await readFile(claudeMdPath, "utf8");
  const block = findAugmentationBlock(priorText, claudeMdPath);
  if (!block) {
    return { removedFrom: null };
  }

  const closeMarkerEnd =
    block.closeIdx + SANCTUARY_AUGMENTATION_CLOSE_MARKER.length;

  // Trim the section, then trim a trailing newline immediately after
  // the close marker so consecutive removals do not leave dangling
  // blank lines. Operator content above the open marker is preserved
  // verbatim; below the close marker is preserved verbatim minus the
  // single immediately-following newline (if any).
  let after = priorText.slice(closeMarkerEnd);
  if (after.startsWith("\n")) {
    after = after.slice(1);
  }
  let before = priorText.slice(0, block.openIdx);
  // Trim a single trailing blank-line separator that install added
  // when appending to existing content (the append path ensures
  // exactly one blank line before the section). Keeps the file
  // byte-equal to its pre-install state when install + remove was the
  // only edit cycle.
  if (before.endsWith("\n\n")) {
    before = before.slice(0, -1);
  }

  // Backup before write.
  try {
    await copyFile(claudeMdPath, `${claudeMdPath}${SANCTUARY_BACKUP_SUFFIX}`);
  } catch {
    /* best-effort */
  }

  const next = before + after;

  // If removing the section leaves an empty file (the fresh-install
  // case where Sanctuary was the only content), delete the file
  // entirely so the operator's tree does not carry a useless empty
  // CLAUDE.md.
  if (next.length === 0) {
    try {
      await unlink(claudeMdPath);
    } catch {
      /* best-effort */
    }
    return { removedFrom: claudeMdPath };
  }

  await atomicWrite(claudeMdPath, next);
  return { removedFrom: claudeMdPath };
}
