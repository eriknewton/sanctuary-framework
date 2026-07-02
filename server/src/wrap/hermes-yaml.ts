/**
 * Sanctuary Wrap — Hermes config.yaml MCP Injection
 *
 * Hermes (NousResearch) v0.16.0 loads its MCP servers from
 * ~/.hermes/config.yaml under the top-level `mcp_servers:` key (upstream
 * hermes_cli/mcp_config.py and mcp_startup.py). The JSON cli-config.json
 * surface that wrap historically rewrote is NOT consulted for MCP routing,
 * so a wrap that only touched the JSON recorded the agent but silently left
 * Hermes MCP traffic outside the Sanctuary proxy (D4 staging finding).
 * This module teaches wrap the YAML surface.
 *
 * Like the principal-policy loader (principal-policy/loader.ts), this is a
 * deliberately scoped hand-rolled YAML-subset handler rather than a YAML
 * library: the repo carries no YAML dependency, and the only mutation made
 * here is inserting or replacing ONE entry under ONE top-level block-mapping
 * key. Every other byte of the operator's file — comments, blank lines,
 * unknown keys, existing user entries — is preserved verbatim, which a
 * parse-reserialize round trip through a library could not guarantee.
 *
 * Shapes this module refuses to edit (HermesYamlUnsupportedError, so wrap
 * fails loudly with the file untouched rather than risking corruption):
 *   - `mcp_servers:` carrying a non-empty flow mapping or scalar value
 *   - `mcp_servers:` carrying a block SEQUENCE (`- name: ...` items) —
 *     merging a mapping entry into it would emit mixed sequence+mapping
 *     YAML that PyYAML rejects, breaking Hermes startup
 *   - duplicate top-level `mcp_servers:` keys
 * The empty flow form `mcp_servers: {}` IS supported (rewritten to block
 * form, any trailing comment preserved), since fresh installs commonly
 * ship it.
 */

import { join } from "node:path";
import { homedir } from "node:os";

// ── Types ───────────────────────────────────────────────────────────

/** The Sanctuary server entry to inject under `mcp_servers:`. */
export interface HermesSanctuaryEntry {
  /** Stdio command (mirror of the JSON-surface sanctuary entry). */
  command: string;
  /** Args list passed to the command. */
  args: string[];
  /** Optional env vars, same propagation rules as the JSON surface. */
  env?: Record<string, string>;
}

/** What the injection will do to the file. */
export type HermesYamlAction =
  /** No config.yaml exists; a fresh one is created. */
  | "create-file"
  /** File exists but has no `mcp_servers:` key; the key is appended. */
  | "add-key"
  /** `mcp_servers:` exists; the sanctuary entry is appended to it. */
  | "append-entry"
  /** An existing sanctuary entry is replaced in place. */
  | "replace-entry";

/** Computed injection — pure data, no I/O performed yet. */
export interface HermesYamlPlan {
  action: HermesYamlAction;
  /** Full new file content (always newline-terminated). */
  content: string;
  /** Names of existing non-sanctuary entries left untouched. */
  preservedEntryNames: string[];
}

/**
 * Thrown when config.yaml has a `mcp_servers` shape this module cannot
 * edit without risking corruption of the operator's file. Callers must
 * fail loudly and leave the file untouched — never silently skip the
 * injection (the whole point of the fix is that silent non-routing is
 * the bug).
 */
export class HermesYamlUnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HermesYamlUnsupportedError";
  }
}

// ── Path ────────────────────────────────────────────────────────────

/**
 * Canonical Hermes YAML config path. Upstream v0.16.0 reads exactly this
 * location (hermes_cli/mcp_config.py); computed lazily from the current
 * homedir() so sandboxed callers that reassign HOME at runtime resolve
 * under their current HOME, matching getPlatformPaths().
 */
export function hermesConfigYamlPath(): string {
  return join(homedir(), ".hermes", "config.yaml");
}

// ── Block scanning ──────────────────────────────────────────────────

const MCP_SERVERS_KEY_RE = /^(['"]?)mcp_servers\1\s*:(.*)$/;

interface EntryLocation {
  /** Entry name with surrounding quotes stripped. */
  name: string;
  /** Index of the entry's `name:` line. */
  start: number;
  /** Exclusive end of the entry's lines. */
  end: number;
}

interface McpServersBlock {
  /** Index of the `mcp_servers:` line. */
  keyLine: number;
  /** Exclusive end of the block's indented region. */
  blockEnd: number;
  /** True for the `mcp_servers: {}` empty-flow form. */
  flowEmpty: boolean;
  /**
   * Trailing `# ...` comment on the empty-flow key line (e.g.
   * `mcp_servers: {} # added by installer`), carried onto the rewritten
   * block-form key line so the operator's note survives the rewrite.
   */
  flowEmptyComment: string | null;
  /** Indent of entry names (default 2 when the block is empty). */
  entryIndent: number;
  entries: EntryLocation[];
}

function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

function isBlankOrComment(line: string): boolean {
  const t = line.trim();
  return t === "" || t.startsWith("#");
}

/**
 * Locate the top-level `mcp_servers:` block and its entries.
 * Returns null when the key is absent; throws on unsupported shapes.
 */
function scanMcpServersBlock(lines: string[]): McpServersBlock | null {
  let keyLine = -1;
  let remainder = "";
  for (let i = 0; i < lines.length; i++) {
    const m = MCP_SERVERS_KEY_RE.exec(lines[i]!);
    if (!m) continue;
    if (keyLine !== -1) {
      throw new HermesYamlUnsupportedError(
        "config.yaml has duplicate top-level mcp_servers keys; refusing to edit."
      );
    }
    keyLine = i;
    remainder = m[2]!.trim();
  }
  if (keyLine === -1) return null;

  // The value after the colon must be empty (block mapping follows), a
  // comment, or the empty flow mapping `{}`. Anything else (non-empty flow
  // mapping, scalar, anchor) is a shape we refuse to rewrite.
  let flowEmpty = false;
  let flowEmptyComment: string | null = null;
  if (remainder !== "" && !remainder.startsWith("#")) {
    const emptyFlow = /^\{\s*\}\s*(#.*)?$/.exec(remainder);
    if (emptyFlow) {
      flowEmpty = true;
      flowEmptyComment = emptyFlow[1] ?? null;
    } else {
      throw new HermesYamlUnsupportedError(
        "config.yaml mcp_servers uses an inline value this tool cannot " +
          "safely edit; convert it to block-mapping form and re-run wrap."
      );
    }
  }

  // Block extent: indented lines, blank lines, and column-0 comments all
  // belong to the block region; the first column-0 non-comment content
  // line ends it.
  let blockEnd = keyLine + 1;
  while (blockEnd < lines.length) {
    const line = lines[blockEnd]!;
    if (line.trim() !== "" && indentOf(line) === 0 && !line.trimStart().startsWith("#")) {
      break;
    }
    blockEnd++;
  }

  // Block-SEQUENCE form (`mcp_servers:\n  - name: weather`): upstream
  // Hermes documents mcp_servers as a block MAPPING, and merging a mapping
  // entry into a sequence would emit mixed sequence+mapping YAML that
  // PyYAML rejects — breaking Hermes startup. The first content line in
  // the block decides the form; a dash means sequence, so refuse loudly
  // with the file untouched.
  for (let i = keyLine + 1; i < blockEnd; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    if (line.trimStart().startsWith("-")) {
      throw new HermesYamlUnsupportedError(
        "config.yaml mcp_servers uses a block-sequence form (`- name: ...`) " +
          "this tool cannot safely edit; convert each `- name: <n>` item to " +
          "a `<n>:` mapping key and re-run wrap."
      );
    }
    break;
  }

  // Entries: the first indented `name:` line fixes the entry indent; only
  // lines at exactly that indent start entries (deeper lines are nested
  // fields, e.g. command/args/env).
  const entries: EntryLocation[] = [];
  let entryIndent = 2;
  let sawFirstEntry = false;
  for (let i = keyLine + 1; i < blockEnd; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    if (!sawFirstEntry) {
      entryIndent = indent;
      sawFirstEntry = true;
    }
    if (indent !== entryIndent) continue;
    const m = /^(['"]?)([^:#'"]+)\1\s*:/.exec(line.trim());
    if (!m) continue;
    entries.push({ name: m[2]!.trim(), start: i, end: entryEnd(lines, i, entryIndent, blockEnd) });
  }

  return { keyLine, blockEnd, flowEmpty, flowEmptyComment, entryIndent, entries };
}

/**
 * Exclusive end of an entry's lines: deeper-indented content (including
 * indented comments) belongs to the entry; blank lines are included only
 * when deeper-indented content follows them before the next boundary, so
 * trailing whitespace between entries is never swallowed by a replace.
 */
function entryEnd(
  lines: string[],
  start: number,
  entryIndent: number,
  blockEnd: number
): number {
  let end = start + 1;
  for (let i = start + 1; i < blockEnd; i++) {
    const line = lines[i]!;
    if (line.trim() === "") continue;
    if (indentOf(line) > entryIndent) {
      end = i + 1;
      continue;
    }
    break;
  }
  return end;
}

// ── Serialization ───────────────────────────────────────────────────

/**
 * Double-quote a scalar via JSON. JSON string syntax is valid YAML
 * double-quoted style, so this is safe for any value (including args
 * like "@sanctuary-framework/mcp-server", where a leading `@` is a
 * reserved YAML indicator in plain style).
 */
function yamlScalar(value: string): string {
  return JSON.stringify(value);
}

/** Env var names are emitted bare when plain-safe, quoted otherwise. */
function yamlKey(key: string): string {
  return /^[A-Za-z0-9_-]+$/.test(key) ? key : JSON.stringify(key);
}

/** Serialize the sanctuary entry at the given name indent (step of 2). */
function serializeSanctuaryEntry(
  entry: HermesSanctuaryEntry,
  entryIndent: number
): string[] {
  const i0 = " ".repeat(entryIndent);
  const i1 = " ".repeat(entryIndent + 2);
  const i2 = " ".repeat(entryIndent + 4);
  const lines = [
    `${i0}sanctuary:`,
    `${i1}command: ${yamlScalar(entry.command)}`,
    `${i1}args:`,
    ...entry.args.map((a) => `${i2}- ${yamlScalar(a)}`),
  ];
  if (entry.env && Object.keys(entry.env).length > 0) {
    lines.push(`${i1}env:`);
    for (const [k, v] of Object.entries(entry.env)) {
      lines.push(`${i2}${yamlKey(k)}: ${yamlScalar(v)}`);
    }
  }
  return lines;
}

// ── Plan ────────────────────────────────────────────────────────────

/**
 * Compute the new config.yaml content that routes Hermes MCP traffic
 * through Sanctuary. Pure: no filesystem access, so the dry-run path can
 * report the plan without writing and tests can pin exact output.
 *
 * @param existingContent  Current file content, or null when the file
 *                         does not exist.
 */
export function planHermesYamlInjection(
  existingContent: string | null,
  entry: HermesSanctuaryEntry
): HermesYamlPlan {
  if (existingContent === null) {
    return {
      action: "create-file",
      content: ["mcp_servers:", ...serializeSanctuaryEntry(entry, 2), ""].join("\n"),
      preservedEntryNames: [],
    };
  }

  const lines = existingContent.split("\n");
  const block = scanMcpServersBlock(lines);

  if (block === null) {
    // No mcp_servers key — append one. Existing bytes stay verbatim; only
    // a missing trailing newline is normalized before the appended block.
    const head =
      existingContent === "" || existingContent.endsWith("\n")
        ? existingContent
        : `${existingContent}\n`;
    return {
      action: "add-key",
      content:
        head + ["mcp_servers:", ...serializeSanctuaryEntry(entry, 2), ""].join("\n"),
      preservedEntryNames: [],
    };
  }

  const preservedEntryNames = block.entries
    .map((e) => e.name)
    .filter((n) => n.toLowerCase() !== "sanctuary");

  if (block.flowEmpty) {
    // `mcp_servers: {}` — rewrite the key line to block form, carrying any
    // trailing comment so the operator's note survives.
    const out = [
      ...lines.slice(0, block.keyLine),
      block.flowEmptyComment
        ? `mcp_servers: ${block.flowEmptyComment}`
        : "mcp_servers:",
      ...serializeSanctuaryEntry(entry, 2),
      ...lines.slice(block.keyLine + 1),
    ];
    return { action: "append-entry", content: ensureTrailingNewline(out), preservedEntryNames };
  }

  const existing = block.entries.find((e) => e.name.toLowerCase() === "sanctuary");
  const entryLines = serializeSanctuaryEntry(entry, block.entryIndent);

  if (existing) {
    const out = [
      ...lines.slice(0, existing.start),
      ...entryLines,
      ...lines.slice(existing.end),
    ];
    return { action: "replace-entry", content: ensureTrailingNewline(out), preservedEntryNames };
  }

  // Append after the last existing entry, or directly under the key when
  // the block is empty — trailing comments below the block stay below.
  const insertAt =
    block.entries.length > 0
      ? block.entries[block.entries.length - 1]!.end
      : block.keyLine + 1;
  const out = [...lines.slice(0, insertAt), ...entryLines, ...lines.slice(insertAt)];
  return { action: "append-entry", content: ensureTrailingNewline(out), preservedEntryNames };
}

function ensureTrailingNewline(lines: string[]): string {
  const content = lines.join("\n");
  return content.endsWith("\n") ? content : `${content}\n`;
}

/**
 * Best-effort extraction of the `env:` block persisted on an EXISTING
 * sanctuary entry in config.yaml, so a re-wrap can inherit entry-persisted
 * vars (e.g. SANCTUARY_DASHBOARD_AUTH_TOKEN) on the authoritative Hermes
 * surface exactly like the JSON surface does. The merge itself, including
 * the never-inherit screen for the plaintext-remote downgrade flag and the
 * caller-authoritative tenancy rules, lives in ONE place,
 * `resolveWrapEntryEnv` in wrap/config-reader.ts, and this function only
 * supplies its `inheritedEnv` input for the YAML surface.
 *
 * Parses the block-mapping form this module itself serializes
 * (double-quoted JSON scalars) plus the common hand-authored forms (plain
 * and single-quoted scalars, trailing comments). Anything it cannot read
 * confidently is skipped rather than guessed at; a flow-form `env: {...}`
 * or an unsupported `mcp_servers` shape resolves null (no inheritance).
 * That is safe because the injection that consumes this replaces the
 * entry wholesale anyway and REFUSES unsupported block shapes loudly
 * (HermesYamlUnsupportedError), so a null here never masks a write.
 */
export function extractSanctuaryEntryEnv(
  existingContent: string | null
): Record<string, string> | null {
  if (existingContent === null) return null;
  const lines = existingContent.split("\n");
  let block: McpServersBlock | null;
  try {
    block = scanMcpServersBlock(lines);
  } catch {
    return null;
  }
  if (!block) return null;
  const entry = block.entries.find((e) => e.name.toLowerCase() === "sanctuary");
  if (!entry) return null;

  // Locate the entry's `env:` field line. The first non-blank content line
  // after the entry name fixes the field indent; only lines at exactly
  // that indent are entry fields (deeper lines are nested values).
  let fieldIndent = -1;
  let envLine = -1;
  for (let i = entry.start + 1; i < entry.end; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    if (fieldIndent === -1) fieldIndent = indent;
    if (indent !== fieldIndent) continue;
    if (/^env\s*:\s*(#.*)?$/.test(line.trim())) {
      envLine = i;
      break;
    }
  }
  if (envLine === -1) return null;

  // Collect KEY: value pairs nested under env:. The first var line fixes
  // the var indent; only lines at exactly that indent are env vars. Deeper
  // lines are nested values of a preceding key (whose own scalar parse
  // already resolved null), so they are skipped rather than flattened into
  // phantom vars — "cannot read confidently" means skip, not guess.
  const result: Record<string, string> = {};
  let varIndent = -1;
  for (let i = envLine + 1; i < entry.end; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    if (indent <= fieldIndent) break;
    if (varIndent === -1) varIndent = indent;
    if (indent !== varIndent) continue;
    const m = /^(?:"([^"]+)"|'([^']+)'|([^\s:#'"][^:]*?))\s*:\s*(.*)$/.exec(
      line.trim()
    );
    if (!m) continue;
    const key = (m[1] ?? m[2] ?? m[3] ?? "").trim();
    if (!key) continue;
    const value = parseYamlScalarValue(m[4] ?? "");
    if (value === null) continue;
    result[key] = value;
  }
  return Object.keys(result).length > 0 ? result : null;
}

/**
 * Parse a double-quoted, single-quoted, or plain YAML scalar value.
 * Returns null when the value cannot be read confidently (multi-line,
 * malformed quoting, empty); callers skip such vars rather than guess.
 */
function parseYamlScalarValue(raw: string): string | null {
  const t = raw.trim();
  if (t === "") return null;
  if (t.startsWith('"')) {
    const m = /^("(?:[^"\\]|\\.)*")\s*(?:#.*)?$/.exec(t);
    if (!m) return null;
    try {
      const parsed: unknown = JSON.parse(m[1]!);
      return typeof parsed === "string" ? parsed : null;
    } catch {
      return null;
    }
  }
  if (t.startsWith("'")) {
    const m = /^'((?:[^']|'')*)'\s*(?:#.*)?$/.exec(t);
    return m ? m[1]!.replace(/''/g, "'") : null;
  }
  // Plain scalar: whitespace followed by `#` starts a trailing comment.
  const commentIdx = t.search(/\s#/);
  const v = (commentIdx === -1 ? t : t.slice(0, commentIdx)).trim();
  return v === "" ? null : v;
}

/**
 * Post-write verification: does the content carry a sanctuary entry under
 * a well-formed top-level `mcp_servers:` block? Mirrors the scan the plan
 * used, so a write that landed corrupted fails verification.
 */
export function yamlContainsSanctuaryEntry(content: string): boolean {
  let block: McpServersBlock | null;
  try {
    block = scanMcpServersBlock(content.split("\n"));
  } catch {
    return false;
  }
  if (!block) return false;
  return block.entries.some((e) => e.name.toLowerCase() === "sanctuary");
}
