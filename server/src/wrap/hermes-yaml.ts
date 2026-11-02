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

/**
 * The line-scanner's understanding of a config.yaml, reduced to the two
 * facts every injection edit depends on: whether the scanner sees a
 * top-level `mcp_servers:` block, and the ordered list of entry names it
 * believes live under that block. The parse-parity guard
 * (hermes-yaml-parse-parity.ts) compares THIS against a real PyYAML parse
 * and refuses to edit on any disagreement, so the scanner's guesses can
 * never silently drive a mutation that a real parser would read
 * differently.
 *
 * `unsupported` mirrors the shapes scanMcpServersBlock refuses outright
 * (duplicate keys, block sequence, inline flow); those already abort the
 * wrap via HermesYamlUnsupportedError, but exposing the flag lets the
 * parity guard reason about them without re-throwing.
 */
export interface ScannerMcpServersView {
  /** True when the scanner located a top-level `mcp_servers:` block. */
  hasBlock: boolean;
  /**
   * Entry names the scanner sees under the block, in scan order, with
   * surrounding quotes stripped (the same names planHermesYamlInjection
   * reasons about for append/replace/preserve).
   */
  entryNames: string[];
  /** True when the scan threw HermesYamlUnsupportedError. */
  unsupported: boolean;
}

/**
 * Compute the line-scanner's view of a config.yaml for parity checking.
 * Never throws: an unsupported shape (which the real plan would reject
 * loudly) is reported via `unsupported: true` so the parity guard can make
 * a single fail-closed decision rather than racing two throw sites.
 *
 * @param existingContent  Current file content, or null when absent (an
 *                         absent file has no block and no entries).
 */
/**
 * The value of `env.<key>` inside the `sanctuary` entry of a Hermes
 * `config.yaml`, read through the SAME block scanner the wrap writer uses and
 * scoped to that entry's lines only (a `<key>:` anywhere else in the file is
 * never consulted). Returns `undefined` when the file has no `sanctuary`
 * entry (or an unsupported shape), so a caller never mistakes "not wrapped"
 * for "wrapped without the key"; `null` when the entry has no such env key.
 */
export function hermesSanctuaryEntryEnvValue(
  existingContent: string | null,
  key: string,
): string | null | undefined {
  if (existingContent === null) return undefined;
  const lines = existingContent.split("\n");
  let block: McpServersBlock | null;
  try {
    block = scanMcpServersBlock(lines);
  } catch (err) {
    if (err instanceof HermesYamlUnsupportedError) return undefined;
    throw err;
  }
  const entry = block?.entries.find((e) => e.name === "sanctuary");
  if (!entry) return undefined;
  let inEnv = false;
  let envIndent = -1;
  for (let i = entry.start + 1; i < entry.end; i += 1) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    const trimmed = line.trim();
    if (inEnv && indent <= envIndent) inEnv = false;
    if (!inEnv && /^env\s*:/.test(trimmed)) {
      inEnv = true;
      envIndent = indent;
      continue;
    }
    if (inEnv && trimmed.startsWith(`${key}:`)) {
      const raw = trimmed.slice(key.length + 1).replace(/\s+#.*$/, "").trim();
      const value = raw.replace(/^["']|["']$/g, "");
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

export function scannerMcpServersView(
  existingContent: string | null
): ScannerMcpServersView {
  if (existingContent === null) {
    return { hasBlock: false, entryNames: [], unsupported: false };
  }
  let block: McpServersBlock | null;
  try {
    block = scanMcpServersBlock(existingContent.split("\n"));
  } catch (err) {
    if (err instanceof HermesYamlUnsupportedError) {
      return { hasBlock: false, entryNames: [], unsupported: true };
    }
    throw err;
  }
  if (!block) return { hasBlock: false, entryNames: [], unsupported: false };
  return {
    hasBlock: true,
    entryNames: block.entries.map((e) => e.name),
    unsupported: false,
  };
}

/** Raw managed fields are retained so removal can restore the operator's spelling. */
export interface HermesPostureView {
  top: string[];
  children: Record<string, string[]>;
  raw: Record<string, string | null>;
  enabled: string[];
  disabled: string[];
  mcp: string[];
}
interface PostureField { key: string; start: number; end: number; prefix: string; token: string; suffix: string }
interface PostureBlock { start: number; end: number; fields: PostureField[]; indent: number }
const POSTURE_INDENT = 2; // Hermes's default YAML indentation is two spaces.
const POSTURE_KEYS = ["memory", "plugins", "tool_loop_guardrails"];
const MANAGED_FIELDS = ["memory.provider", "memory.memory_enabled", "memory.user_profile_enabled", "plugins.enabled"];

function postureRefuse(): never {
  throw new HermesYamlUnsupportedError("Hermes config has an unsupported managed YAML shape; refusing to edit.");
}
function splitPostureLine(line: string): Omit<PostureField, "start" | "end"> {
  const match = /^(\s*(?:"([\w-]+)"|'([\w-]+)'|([\w-]+))\s*:\s*)(.*)$/.exec(line);
  if (!match) return postureRefuse();
  const value = match[5]!;
  // Quoted tokens may contain #; a comment starts only after a complete token.
  const parts = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^#]*?)(\s+#.*|#.*|\s*)$/.exec(value);
  if (!parts) return postureRefuse();
  const token = parts[1]!.trimEnd();
  return { key: match[2] ?? match[3] ?? match[4]!, prefix: match[1]!, token, suffix: parts[1]!.slice(token.length) + parts[2]! };
}
function postureBlocks(lines: string[]): Map<string, PostureBlock> {
  const blocks = new Map<string, PostureBlock>();
  for (let start = 0; start < lines.length; start++) {
    const line = lines[start]!;
    if (isBlankOrComment(line) || indentOf(line) !== 0) continue;
    const head = splitPostureLine(line);
    if (blocks.has(head.key)) return postureRefuse();
    let end = start + 1;
    while (end < lines.length && (isBlankOrComment(lines[end]!) || indentOf(lines[end]!) > 0)) end++;
    const block: PostureBlock = { start, end, fields: [], indent: POSTURE_INDENT };
    blocks.set(head.key, block);
    if (!POSTURE_KEYS.includes(head.key)) continue;
    if (head.token !== "" && !/^\{\s*\}$/.test(head.token)) return postureRefuse();
    const content = lines.slice(start + 1, end).filter(line => !isBlankOrComment(line));
    if (content.length) block.indent = indentOf(content[0]!);
    for (let at = start + 1; at < end; at++) {
      if (isBlankOrComment(lines[at]!) || indentOf(lines[at]!) !== block.indent) continue;
      const previous = block.fields.at(-1);
      if (lines[at]!.trimStart().startsWith("-") && previous?.token === "" &&
          head.key === "plugins" && ["enabled", "disabled"].includes(previous.key)) {
        previous.end = entryEnd(lines, at, block.indent, end);
        continue;
      }
      const field = splitPostureLine(lines[at]!);
      if (block.fields.some(item => item.key === field.key)) return postureRefuse();
      block.fields.push({ ...field, start: at, end: entryEnd(lines, at, block.indent, end) });
    }
  }
  return blocks;
}
function simplePostureScalar(token: string): string {
  if (/^[A-Za-z0-9_./-]+$/.test(token)) return token;
  if (/^"[^"\\]*"$/.test(token)) return token.slice(1, -1);
  if (/^'[^']*'$/.test(token)) return token.slice(1, -1);
  return postureRefuse();
}
function postureList(field: PostureField | undefined, lines: string[]): string[] {
  if (!field) return [];
  if (field.token.startsWith("[")) {
    if (field.end !== field.start + 1 || !field.token.endsWith("]")) return postureRefuse();
    const body = field.token.slice(1, -1).trim();
    return body ? body.split(",").map(value => simplePostureScalar(value.trim())) : [];
  }
  if (field.token !== "") return postureRefuse();
  const items: string[] = [];
  for (const line of lines.slice(field.start + 1, field.end)) {
    if (isBlankOrComment(line)) continue;
    const match = /^\s+-\s+([^#]*?)(?:\s+#.*)?$/.exec(line);
    if (!match) return postureRefuse();
    items.push(simplePostureScalar(match[1]!.trim()));
  }
  return items;
}

/** Scanner facts are checked against PyYAML before either install or removal writes. */
export function scanHermesPosture(content: string | null): HermesPostureView {
  const lines = (content ?? "").split("\n");
  const blocks = postureBlocks(lines);
  const mcp = scanMcpServersBlock(lines);
  const raw: Record<string, string | null> = {};
  const children: Record<string, string[]> = {};
  for (const name of POSTURE_KEYS) {
    const block = blocks.get(name);
    if (block) children[name] = block.fields.map(field => field.key);
  }
  for (const path of MANAGED_FIELDS) {
    const [name, key] = path.split(".");
    const field = blocks.get(name!)?.fields.find(field => field.key === key);
    raw[path] = field ? lines.slice(field.start, field.end).join("\n") : null;
    if (field && path !== "plugins.enabled") {
      if (field.end !== field.start + 1) return postureRefuse();
      simplePostureScalar(field.token);
    }
  }
  const enabled = postureList(blocks.get("plugins")?.fields.find(field => field.key === "enabled"), lines);
  const disabled = postureList(blocks.get("plugins")?.fields.find(field => field.key === "disabled"), lines);
  const hardStop = blocks.get("tool_loop_guardrails")?.fields.find(field => field.key === "hard_stop_enabled");
  if (hardStop && (hardStop.end !== hardStop.start + 1 || !/^(false|False|FALSE|no|No|NO|off|Off|OFF)$/.test(hardStop.token))) return postureRefuse();
  if (disabled.includes("sanctuary")) throw new HermesYamlUnsupportedError("sanctuary is in plugins.disabled; refusing to edit.");
  return { top: [...blocks.keys()], children, raw, enabled, disabled, mcp: mcp?.entries.map(entry => entry.name) ?? [] };
}

function renderPostureValue(field: Pick<PostureField, "prefix" | "suffix">, value: string): string {
  const prefix = value && field.prefix.endsWith(":") ? field.prefix + " " : field.prefix;
  const suffix = value && field.suffix.startsWith("#") ? " " + field.suffix : field.suffix;
  return prefix + value + suffix;
}

/** Replace one direct child without reserializing the surrounding document. */
function setPostureField(content: string, name: string, key: string, value: string | null, raw = false): string {
  const lines = content.split("\n");
  const block = postureBlocks(lines).get(name);
  if (!block) {
    if (value === null) return content;
    const head = content && !content.endsWith("\n") ? content + "\n" : content;
    return head + name + ":\n" + (raw ? value : `  ${key}: ${value}`) + "\n";
  }
  const field = block.fields.find(field => field.key === key);
  if (field) {
    const replacement = value === null ? [] : raw ? value.split("\n") : [renderPostureValue(field, value)];
    lines.splice(field.start, field.end - field.start, ...replacement);
  } else if (value !== null) {
    const head = splitPostureLine(lines[block.start]!);
    if (head.token) lines[block.start] = renderPostureValue(head, "");
    const at = block.fields.at(-1)?.end ?? block.start + 1;
    lines.splice(at, 0, ...(raw ? value.split("\n") : [`${" ".repeat(block.indent)}${key}: ${value}`]));
  }
  return lines.join("\n");
}

/** Exact planned bytes and prior raw values form the install record's reversible edit. */
export interface HermesPosturePlan {
  content: string;
  before: HermesPostureView;
  after: HermesPostureView;
  removedMcp: string | null;
}

/** Plan the memory-provider configuration; the caller supplies the shared settings. */
export function planHermesMemoryPosture(
  existing: string | null,
  settings: readonly { block: string; key: string; value: string }[],
): HermesPosturePlan {
  const before = scanHermesPosture(existing);
  let content = existing ?? "";
  for (const setting of settings) content = setPostureField(content, setting.block, setting.key, setting.value);
  if (!before.enabled.includes("sanctuary")) {
    const lines = content.split("\n");
    const field = postureBlocks(lines).get("plugins")?.fields.find(field => field.key === "enabled");
    if (field?.token.startsWith("[")) {
      const token = field.token.slice(0, -1) + (before.enabled.length ? ", " : "") + "sanctuary]";
      content = setPostureField(content, "plugins", "enabled", token);
    } else if (field) {
      const old = lines.slice(field.start, field.end);
      const first = old.slice(1).find(line => /^\s+-/.test(line));
      const indent = first ? indentOf(first) : indentOf(lines[field.start]!) + POSTURE_INDENT;
      old.push(" ".repeat(indent) + "- sanctuary");
      content = setPostureField(content, "plugins", "enabled", old.join("\n"), true);
    } else content = setPostureField(content, "plugins", "enabled", "[sanctuary]");
  }
  const lines = content.split("\n");
  const mcp = scanMcpServersBlock(lines);
  const entry = mcp?.entries.find(entry => entry.name === "sanctuary");
  const removedMcp = entry ? lines.slice(entry.start, entry.end).join("\n") + (entry.end < lines.length ? "\n" : "") : null;
  if (entry && mcp) {
    lines.splice(entry.start, entry.end - entry.start);
    if (mcp.entries.length === 1) {
      const head = splitPostureLine(lines[mcp.keyLine]!);
      lines[mcp.keyLine] = renderPostureValue(head, "{}");
    }
    content = lines.join("\n");
  }
  return { content, before, after: scanHermesPosture(content), removedMcp };
}

/** Changed files restore matching managed values while retaining current line comments. */
export function planHermesMemoryRevert(live: string, original: string | null, installed: string): HermesPosturePlan {
  const before = scanHermesPosture(live);
  scanHermesPosture(original);
  const expected = scanHermesPosture(installed);
  const liveBlocks = postureBlocks(live.split("\n"));
  const originalLines = (original ?? "").split("\n");
  const priorBlocks = postureBlocks(originalLines);
  const installedBlocks = postureBlocks(installed.split("\n"));
  let content = live;
  // A changed managed value belongs to the operator; a comment does not change that value.
  for (const path of MANAGED_FIELDS) {
    const [name, key] = path.split(".");
    const field = liveBlocks.get(name!)?.fields.find(field => field.key === key);
    const selected = installedBlocks.get(name!)?.fields.find(field => field.key === key);
    if (!field || !selected) continue;
    const comparable = (token: string) => key === "provider" ? simplePostureScalar(token) :
      /^(false|no|off)$/i.test(token) ? "false" : token;
    const same = path === "plugins.enabled" ? JSON.stringify(before.enabled) === JSON.stringify(expected.enabled) :
      comparable(field.token) === comparable(selected.token);
    if (!same) continue;
    const prior = priorBlocks.get(name!)?.fields.find(field => field.key === key);
    if (!prior) content = setPostureField(content, name!, key!, null);
    else if (prior.end === prior.start + 1) content = setPostureField(content, name!, key!, prior.token);
    else {
      const oldIndent = indentOf(originalLines[prior.start]!);
      const newIndent = indentOf(field.prefix);
      const body = originalLines.slice(prior.start + 1, prior.end).map(line =>
        line.trim() ? " ".repeat(newIndent) + line.slice(oldIndent) : line);
      const raw = [field.prefix + prior.token + field.suffix, ...body].join("\n");
      content = setPostureField(content, name!, key!, raw, true);
    }
  }
  for (const name of ["memory", "plugins"]) {
    const lines = content.split("\n");
    const block = postureBlocks(lines).get(name);
    // Removing a created empty block lets Hermes apply its defaults for an absent key.
    if (block && !priorBlocks.has(name) && block.fields.length === 0) {
      const comment = splitPostureLine(lines[block.start]!).suffix.trim();
      lines.splice(block.start, 1, ...(comment ? [comment] : []));
      content = lines.join("\n");
    }
  }
  return { content, before, after: scanHermesPosture(content), removedMcp: null };
}
