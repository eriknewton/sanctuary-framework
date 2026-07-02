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
 * Fail-closed contract (HermesYamlUnsupportedError, so wrap fails loudly
 * with the file untouched rather than risking corruption):
 *   - Any CR, NEL (U+0085), LS (U+2028), or PS (U+2029) byte in the file
 *     refuses at scan entry. split("\n") line handling and JS `.` (which
 *     never matches any of these) blind every regex in this module to
 *     line breaks that PyYAML (YAML 1.1) honors just like \n, so scanning
 *     such a file would misread it wholesale (verified: it appended a
 *     duplicate top-level mcp_servers key, silently dropping the
 *     operator's entries under PyYAML last-wins, for CR and separately
 *     for each of NEL/LS/PS).
 *   - `mcp_servers:` carrying a non-empty flow mapping or scalar value,
 *     a block SEQUENCE (`- name: ...` items), or duplicate top-level
 *     `mcp_servers:` keys refuses. Tab indentation inside the block
 *     refuses too: YAML forbids it, and indentOf() would miscount the
 *     block's structure.
 *   - Before an existing sanctuary entry is REPLACED, every line of it
 *     must be affirmatively recognized against the whitelist of shapes
 *     this module can fully read (see assertReplaceableSanctuaryEntry).
 *     The screen is a whitelist, not a blacklist: a shape nobody thought
 *     of refuses by default instead of slipping through. The invariant is
 *     that there is NO input for which the replace-entry write proceeds
 *     while this module's read of the entry was partial: reads are total
 *     or the write is refused.
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

/**
 * Line-break code points PyYAML's scanner (scan_line_break, YAML 1.1)
 * treats as line breaks beyond the plain "\n" this module splits on: CR
 * (used bare or as CRLF), NEL (U+0085), LS (U+2028), and PS (U+2029). Any
 * of these embedded in a line survives split("\n") and is invisible to
 * JS `.` (which matches none of them), so a line carrying one hides its
 * real structure from every anchored `(.*)$` regex in this module while
 * PyYAML reads the break and sees different structure underneath.
 */
const PYYAML_EXTRA_LINE_BREAK_RE = /[\r\u0085\u2028\u2029]/;

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

function hasTabIndent(line: string): boolean {
  return /^ *\t/.test(line);
}

function firstNonMarkerContentLine(lines: string[]): number {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const trimmed = line.trim();
    if (indentOf(line) === 0 && (trimmed === "---" || trimmed === "...")) {
      continue;
    }
    return i;
  }
  return -1;
}

function stripYamlKeyDecorators(
  trimmed: string
): { stripped: string; hadDecorator: boolean } {
  let stripped = trimmed;
  let hadDecorator = false;
  for (;;) {
    const m = /^(?:!(?:[^\s]+)?|&[^\s]+)\s+(.+)$/.exec(stripped);
    if (!m) return { stripped, hadDecorator };
    hadDecorator = true;
    stripped = m[1]!.trimStart();
  }
}

function assertNoHiddenTopLevelMcpServersKey(line: string, lineIdx: number): void {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed.startsWith("#")) return;
  if (/^<<\s*:/.test(trimmed)) {
    throw new HermesYamlUnsupportedError(
      `config.yaml has a top-level YAML merge key (line ${lineIdx + 1}) ` +
        "whose merged fields this scan cannot read; refusing to edit. " +
        "Rewrite mcp_servers as a plain top-level block key and re-run wrap."
    );
  }
  if (trimmed.startsWith("?")) {
    throw new HermesYamlUnsupportedError(
      `config.yaml has an explicit/complex top-level YAML key (line ${lineIdx + 1}) ` +
        "this line-oriented scan cannot resolve; refusing to edit. Rewrite " +
        "mcp_servers as a plain top-level block key and re-run wrap."
    );
  }
  if (trimmed.startsWith("*")) {
    throw new HermesYamlUnsupportedError(
      `config.yaml has a top-level YAML alias key (line ${lineIdx + 1}) ` +
        "this line-oriented scan cannot resolve; refusing to edit. Rewrite " +
        "mcp_servers as a plain top-level block key and re-run wrap."
    );
  }

  const decorated = stripYamlKeyDecorators(trimmed);
  if (!decorated.hadDecorator) return;
  const m = RECOGNIZED_FIELD_RE.exec(decorated.stripped);
  const key = m ? canonicalFieldKey(m) : null;
  if (m === null || key === null || key === "mcp_servers") {
    throw new HermesYamlUnsupportedError(
      `config.yaml has a tagged or anchored top-level key (line ${lineIdx + 1}) ` +
        "this scan cannot safely compare against `mcp_servers`; refusing " +
        "to edit. Rewrite mcp_servers as a plain top-level block key and " +
        "re-run wrap."
    );
  }
}

/**
 * Locate the top-level `mcp_servers:` block and its entries.
 * Returns null when the key is absent; throws on unsupported shapes.
 */
function scanMcpServersBlock(lines: string[]): McpServersBlock | null {
  // Extra-line-break refusal, checked before anything else: the caller
  // split on "\n", so CR, NEL (U+0085), LS (U+2028), and PS (U+2029) bytes
  // remain embedded in lines, and JS `.` never matches any of them, so
  // every anchored `(.*)$` regex below silently fails on a line carrying
  // one. A file using any of these therefore hides its real structure
  // from this scan while PyYAML (YAML 1.1) reads all four as line breaks
  // exactly like \n; the observed failure was an add-key append of a
  // DUPLICATE top-level mcp_servers key that PyYAML last-wins resolved by
  // dropping the operator's original entries, reproduced with CR and,
  // separately, with each of NEL/LS/PS. Refuse the whole file loudly
  // instead.
  if (lines.some((l) => PYYAML_EXTRA_LINE_BREAK_RE.test(l))) {
    throw new HermesYamlUnsupportedError(
      "config.yaml contains a line-break character (CR, CRLF, NEL, LS, or " +
        "PS) this line-oriented scan cannot read reliably; convert the " +
        "file to plain LF line endings and re-run wrap."
    );
  }
  if (lines.some((l) => hasTabIndent(l))) {
    throw new HermesYamlUnsupportedError(
      "config.yaml uses tab indentation this scan cannot measure reliably; " +
        "replace tabs with spaces and re-run wrap."
    );
  }
  const firstContent = firstNonMarkerContentLine(lines);
  if (firstContent !== -1 && indentOf(lines[firstContent]!) !== 0) {
    throw new HermesYamlUnsupportedError(
      `config.yaml has an indented root mapping (line ${firstContent + 1}) ` +
        "that this line-oriented scan cannot safely compare against " +
        "`mcp_servers`; move root keys to column 0 and re-run wrap."
    );
  }
  // Top-level key match uses RECOGNIZED_FIELD_RE + canonicalFieldKey, the
  // SAME decode the field-header and entry-name scans below use, rather
  // than a bare-literal regex. PyYAML resolves a double-quoted escape
  // spelling like `"mcp_servers":` to the literal key `mcp_servers`
  // just as it resolves the bare or plain-quoted spellings; a literal-only
  // match would miss it, take the add-key path, and append a SECOND
  // top-level `mcp_servers:` block that PyYAML last-wins resolves by
  // silently dropping the operator's original block (same silent-drop
  // class as the CR/NEL/LS/PS guard above).
  let keyLine = -1;
  let remainder = "";
  for (let i = 0; i < lines.length; i++) {
    if (indentOf(lines[i]!) !== 0) continue;
    assertNoHiddenTopLevelMcpServersKey(lines[i]!, i);
    const m = RECOGNIZED_FIELD_RE.exec(lines[i]!);
    if (!m) continue;
    if (m[2] !== undefined && canonicalFieldKey(m) === null) {
      // A double-quoted top-level key whose escape sequence canonicalFieldKey
      // cannot decode (e.g. a `\xXX`/`\UXXXXXXXX` YAML hex escape, which
      // PyYAML decodes but JSON.parse does not). We cannot rule out that
      // PyYAML would resolve it to `mcp_servers`, and silently treating it
      // as "some other key" risks the exact add-key duplicate this decode
      // exists to prevent, so refuse loudly instead of guessing.
      throw new HermesYamlUnsupportedError(
        `config.yaml has a top-level key (line ${i + 1}) with an escape ` +
          "sequence this tool cannot decode, so it cannot confirm whether " +
          "the key is `mcp_servers`; refusing to edit. Rewrite the key in " +
          "bare or plain-quoted form and re-run wrap."
      );
    }
    const key = canonicalFieldKey(m);
    if (key !== "mcp_servers") continue;
    if (keyLine !== -1) {
      throw new HermesYamlUnsupportedError(
        "config.yaml has duplicate top-level mcp_servers keys; refusing to edit."
      );
    }
    keyLine = i;
    remainder = (m[4] ?? "").trim();
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

  // Tab refusal for the block region: YAML forbids tabs in indentation,
  // and indentOf() counts a tab as one indent column, so a tab-indented
  // line would corrupt every indent comparison below (entry detection,
  // entry extents) before any per-entry screen could see it. Refuse the
  // block loudly instead of scanning it cross-eyed.
  for (let i = keyLine + 1; i < blockEnd; i++) {
    if (hasTabIndent(lines[i]!)) {
      throw new HermesYamlUnsupportedError(
        "config.yaml mcp_servers block uses tab indentation this scan " +
          "cannot measure reliably; replace tabs with spaces and re-run wrap."
      );
    }
  }

  // Block-SEQUENCE form (`mcp_servers:\n  - name: weather`): upstream
  // Hermes documents mcp_servers as a block MAPPING, and merging a mapping
  // entry into a sequence would emit mixed sequence+mapping YAML that
  // PyYAML rejects, breaking Hermes startup. The first content line in
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
    // Entry-name match uses RECOGNIZED_FIELD_RE + canonicalFieldKey, the
    // SAME decode the top-level key and field-header scans use. A raw
    // literal-only match would miss an escaped spelling like
    // `"sanctuary":` (PyYAML decodes it to the literal name
    // `sanctuary`), recording the entry under its raw, undecoded name
    // instead of its true identity, so the later `name.toLowerCase() ===
    // "sanctuary"` lookup below misses an existing sanctuary entry and
    // the caller appends a SECOND one, which PyYAML last-wins resolves by
    // silently dropping the operator's original entry (and its env vars).
    const m = RECOGNIZED_FIELD_RE.exec(line.trim());
    if (!m) {
      throw new HermesYamlUnsupportedError(
        `config.yaml mcp_servers has an entry line (line ${i + 1}) this ` +
          "scan cannot recognize as `name:`; refusing to edit. Rewrite " +
          "mcp_servers as a plain block mapping and re-run wrap."
      );
    }
    if (m[2] !== undefined && canonicalFieldKey(m) === null) {
      // A double-quoted entry name whose escape sequence canonicalFieldKey
      // cannot decode (e.g. a YAML hex escape JSON.parse does not support).
      // We cannot rule out that PyYAML would resolve it to `sanctuary`, and
      // recording it under its raw undecoded spelling risks the exact
      // append-entry duplicate this decode exists to prevent, so refuse
      // loudly instead of guessing.
      throw new HermesYamlUnsupportedError(
        `config.yaml mcp_servers entry (line ${i + 1}) has a name with an ` +
          "escape sequence this tool cannot decode, so it cannot confirm " +
          "whether the entry is `sanctuary`; refusing to edit. Rewrite the " +
          "entry name in bare or plain-quoted form and re-run wrap."
      );
    }
    const decoded = canonicalFieldKey(m)!;
    entries.push({
      name: decoded,
      start: i,
      end: entryEnd(lines, i, entryIndent, blockEnd),
    });
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
    assertReplaceableSanctuaryEntry(lines, existing);
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

/** The empty flow mapping `{}`, optionally followed by a comment. */
const EMPTY_FLOW_RE = /^\{\s*\}\s*(#.*)?$/;

/**
 * A `key: value` line whose key is a bare plain-safe token, a
 * double-quoted string, or a single-quoted string, and whose value (if
 * any) is separated from the colon by whitespace, as YAML block mappings
 * require. Anything that does not match is NOT a recognized field line.
 */
const RECOGNIZED_FIELD_RE =
  /^(?:([A-Za-z0-9_.-]+)|"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)')\s*:(?:[ \t]+(.*))?$/;

/**
 * Canonical key of a RECOGNIZED_FIELD_RE match: the string PyYAML would
 * resolve the key to, so quoted spellings ("env", 'env') collide with the
 * bare one. Returns null when a double-quoted key carries an escape
 * sequence JSON cannot decode (then the line is not recognized).
 */
function canonicalFieldKey(m: RegExpExecArray): string | null {
  if (m[1] !== undefined) return m[1];
  if (m[2] !== undefined) {
    try {
      const parsed: unknown = JSON.parse(`"${m[2]}"`);
      return typeof parsed === "string" ? parsed : null;
    } catch {
      return null;
    }
  }
  return m[3]!.replace(/''/g, "'");
}

/**
 * WHITELIST screen guarding every replace-entry write: each line of the
 * EXISTING sanctuary entry, from its name line through the entry's end,
 * must be AFFIRMATIVELY recognized as a shape this module can fully read:
 *
 *   (a) blank and comment-only lines;
 *   (b) the entry name line with an empty remainder, a trailing comment,
 *       or the empty flow mapping `{}` (which carries nothing to drop);
 *   (c) block-form `key: value` field lines at one consistent indent,
 *       where the key is bare plain-safe or quoted (no duplicates, no
 *       plain `<<` merge key) and the value is a single-line plain or
 *       quoted scalar with no YAML indicator (| > & * ! [ { %), plus the
 *       empty flow `env: {}`;
 *   (d) under a valueless header field: for `env:`, `KEY: scalar` var
 *       lines at one consistent indent with no duplicate keys; for any
 *       other header (e.g. `args:`), `- scalar` block-sequence items at
 *       one consistent indent.
 *
 * ANY other line refuses (HermesYamlUnsupportedError), including tab
 * indentation, ragged indents, deeper continuations of a scalar-valued
 * field (multi-line plain scalars), nested collections under env vars,
 * and every shape nobody has thought of yet. This inverts the older
 * per-shape blacklist: four adversarial rounds each found a NEW
 * hand-authored PyYAML shape (flow-form entries, quoted env keys, merge
 * keys, next-line flow values, duplicate keys, CR line endings) that a
 * blacklist missed while the wholesale replace silently dropped operator
 * env vars. Under the whitelist the invariant is structural: there is no
 * input for which the replace-entry write proceeds while this module's
 * read of the entry was partial: reads are total or the write refuses
 * loudly with the file untouched.
 */
function refuse(lineIdx: number, why: string): never {
  throw new HermesYamlUnsupportedError(
    `config.yaml sanctuary entry (line ${lineIdx + 1}) ${why}, so this ` +
      "tool cannot fully read the entry it would replace and refuses to " +
      "edit the file. Rewrite the entry in plain block-mapping form " +
      "(one `key: value` field per line with single-line plain or " +
      "quoted scalar values, `args:` as a `- value` list, `env:` as " +
      "`KEY: value` lines) and re-run wrap."
  );
}

function assertReplaceableSanctuaryEntry(
  lines: string[],
  entry: EntryLocation
): void {
  // (b) The entry name line: anything after `sanctuary:` other than a
  // comment or the empty flow mapping `{}` is a flow-form entry whose
  // fields (env included) live in a remainder the line walk below never
  // visits.
  const entryLine = lines[entry.start]!.trim();
  const nameMatch = /^(['"]?)([^:#'"]+)\1\s*:/.exec(entryLine);
  const entryRemainder = nameMatch
    ? entryLine.slice(nameMatch[0].length).trim()
    : "";
  if (
    entryRemainder !== "" &&
    !entryRemainder.startsWith("#") &&
    !EMPTY_FLOW_RE.test(entryRemainder)
  ) {
    refuse(entry.start, "carries an inline (flow-form) value");
  }

  let fieldIndent = -1;
  const seenFieldKeys = new Set<string>();
  const seenEnvKeys = new Set<string>();
  // What a deeper-indented line under the most recent field line would
  // mean: nothing readable ("refuse"), env vars, or sequence items.
  let nested: "refuse" | "env" | "seq" = "refuse";
  let nestedIndent = -1;

  for (let i = entry.start + 1; i < entry.end; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue; // (a)
    if (hasTabIndent(line)) {
      refuse(i, "uses tab indentation");
    }
    const indent = indentOf(line);
    if (fieldIndent === -1) fieldIndent = indent;
    const trimmed = line.trim();

    if (indent === fieldIndent) {
      // (c) A field line of the entry.
      nested = "refuse";
      nestedIndent = -1;
      // A plain `<<` key is the YAML merge key: PyYAML (the parser Hermes
      // runs) folds the anchored mapping's fields, possibly env vars,
      // into this entry, which this line-oriented scan cannot resolve.
      // (A QUOTED "<<" is a literal string key under PyYAML, not a
      // merge, and is recognized as an ordinary field below.)
      if (/^<<\s*:/.test(trimmed)) {
        refuse(i, "uses a YAML merge key (<<) whose merged fields this scan cannot read");
      }
      const m = RECOGNIZED_FIELD_RE.exec(trimmed);
      const key = m ? canonicalFieldKey(m) : null;
      if (m === null || key === null) {
        refuse(i, "has a field line this scan does not recognize as `key: value`");
      }
      if (seenFieldKeys.has(key)) {
        refuse(i, "carries a duplicate field key (PyYAML keeps only the last occurrence, which this scan cannot mirror)");
      }
      seenFieldKeys.add(key);
      const remainder = (m[4] ?? "").trim();
      if (remainder === "" || remainder.startsWith("#")) {
        // A valueless header: nested lines are env vars or seq items (d).
        nested = key === "env" ? "env" : "seq";
      } else if (key === "env" && EMPTY_FLOW_RE.test(remainder)) {
        // `env: {}` carries nothing to inherit and stays editable.
      } else if (parseYamlScalarValue(remainder) === null) {
        refuse(i, "carries a field value this scan cannot read as a single-line scalar");
      }
      // A readable scalar value leaves nested = "refuse": any deeper
      // line after it would be a multi-line plain-scalar continuation.
    } else if (indent > fieldIndent) {
      // (d) Nested content under the most recent header field.
      if (nested === "refuse") {
        refuse(i, "nests content under a field whose value this scan already read as a single line");
      }
      if (nestedIndent === -1) nestedIndent = indent;
      if (indent !== nestedIndent) {
        refuse(i, "has an indentation shape this scan cannot follow");
      }
      if (nested === "env") {
        const m = RECOGNIZED_FIELD_RE.exec(trimmed);
        const key = m ? canonicalFieldKey(m) : null;
        if (m === null || key === null) {
          refuse(i, "has an env line this scan does not recognize as `KEY: value`");
        }
        if (seenEnvKeys.has(key)) {
          refuse(i, "carries a duplicate env var key (PyYAML keeps only the last occurrence, which this scan cannot mirror)");
        }
        seenEnvKeys.add(key);
        if (parseYamlScalarValue((m[4] ?? "").trim()) === null) {
          refuse(i, "carries an env value this scan cannot read as a single-line scalar");
        }
      } else {
        const item = /^-[ \t]+(.*)$/.exec(trimmed);
        if (item === null || parseYamlScalarValue(item[1]!.trim()) === null) {
          refuse(i, "has a nested line this scan does not recognize as a `- value` list item with a single-line scalar");
        }
      }
    } else {
      // Shallower than the entry's fields but still inside the entry
      // region: a ragged indent this scan cannot attribute.
      refuse(i, "has an indentation shape this scan cannot follow");
    }
  }
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
 * confidently is skipped rather than guessed at: block scalars, anchors,
 * aliases, tags, flow collections, and multi-line plain scalars all
 * resolve to no inheritance for that var (never a corrupted literal), and
 * a flow-form `env: {...}` (inline on the field line or opening on the
 * next line) or an unsupported `mcp_servers` shape resolves null.
 *
 * Neither a skip nor a null ever masks a write: before any replace-entry
 * write proceeds, assertReplaceableSanctuaryEntry re-walks the entry
 * against a WHITELIST of fully readable line shapes and refuses loudly
 * (HermesYamlUnsupportedError) on anything else, including every shape
 * this extractor skips. A skipped var can therefore only occur on a plan
 * that was refused, never on one that writes.
 *
 * Skip-not-guess is deliberate, but it must not be SILENT at the operator
 * surface: pass `skippedKeys` and every named var whose value was skipped
 * (and did not end up inherited) is appended to it, so callers can name
 * the vars involved. With the whitelist screen in front, this is a
 * defense-in-depth reporting channel rather than the primary guard.
 */
export function extractSanctuaryEntryEnv(
  existingContent: string | null,
  skippedKeys?: string[]
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
  //
  // Header detection uses RECOGNIZED_FIELD_RE + canonicalFieldKey, the
  // SAME decode assertReplaceableSanctuaryEntry uses to recognize the
  // `env` field header, rather than a narrower raw-literal match.
  // A quoted key that decodes to `env` under PyYAML but is not the exact
  // bare/`"env"`/`'env'` spelling (an escaped-quote or unicode-escape
  // spelling, e.g. `"env":`) is a shape the whitelist screen already
  // treats as the canonical `env` field, so this extractor must recognize
  // it too or the whole block silently resolves null (dropping the entire
  // env block, e.g. SANCTUARY_DASHBOARD_AUTH_TOKEN, on a write the
  // whitelist did not refuse).
  let fieldIndent = -1;
  let envLine = -1;
  for (let i = entry.start + 1; i < entry.end; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    if (fieldIndent === -1) fieldIndent = indent;
    if (indent !== fieldIndent) continue;
    const trimmed = line.trim();
    const m = RECOGNIZED_FIELD_RE.exec(trimmed);
    const key = m ? canonicalFieldKey(m) : null;
    if (key === "env") {
      envLine = i;
      break;
    }
  }
  if (envLine === -1) return null;

  // Collect KEY: value pairs nested under env:. The first var line fixes
  // the var indent; only lines at exactly that indent are env vars. Deeper
  // lines are nested values of a preceding key (whose own scalar parse
  // already resolved null), so they are skipped rather than flattened into
  // phantom vars; "cannot read confidently" means skip, not guess.
  const result: Record<string, string> = {};
  const skipped = new Set<string>();
  let varIndent = -1;
  let lastInheritedKey: string | null = null;
  for (let i = envLine + 1; i < entry.end; i++) {
    const line = lines[i]!;
    if (isBlankOrComment(line)) continue;
    const indent = indentOf(line);
    if (indent <= fieldIndent) break;
    if (varIndent === -1) varIndent = indent;
    if (indent !== varIndent) {
      // A deeper-indented content line directly under an inherited var is
      // a multi-line plain-scalar continuation: the single-line read above
      // captured only a truncated first line, so un-inherit the var
      // (skip, not guess) rather than write a wrong value back.
      if (indent > varIndent && lastInheritedKey !== null) {
        delete result[lastInheritedKey];
        skipped.add(lastInheritedKey);
      }
      lastInheritedKey = null;
      continue;
    }
    lastInheritedKey = null;
    const trimmed = line.trim();
    // A flow-collection opener here means the env value is a flow mapping
    // on its own line(s) (`env:` then an indented `{KEY: v}`, which is
    // valid PyYAML), not a block of var lines; the single-line read would
    // flatten it into a phantom corrupted var (`{KEY` inheriting `v}`).
    // The whole env block is unreadable, so resolve null (skip, not
    // guess); the consuming injection's refusal screen blocks the write.
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) return null;
    // Key decoding uses RECOGNIZED_FIELD_RE + canonicalFieldKey, the SAME
    // decode assertReplaceableSanctuaryEntry uses for env var keys, so
    // this extractor can never diverge from what the whitelist screen
    // already proved readable. A key the whitelist recognizes (e.g. an
    // escaped-quote spelling like "A\"B", or a doubled-quote spelling
    // like 'A''B') but this extractor's OLD narrower key regex could not
    // span would otherwise let a replace-entry write proceed while
    // dropping that var with no key string to name it by in `skipped`
    // (no key means no notice either). Resolve the whole block as
    // unreadable instead when a line's key cannot be decoded at all,
    // matching the flow-collection precedent above: there is no partial
    // key set to guess at.
    const m = RECOGNIZED_FIELD_RE.exec(trimmed);
    const key = m ? canonicalFieldKey(m) : null;
    if (key === null) return null;
    const value = parseYamlScalarValue((m![4] ?? "").trim());
    if (value === null) {
      // Duplicate keys are last-wins under PyYAML (the parser Hermes
      // runs), so an unreadable LAST occurrence un-inherits any readable
      // earlier value: inheriting it would silently REVERT the var to a
      // stale value Hermes was no longer using. Skip-and-notice instead.
      delete result[key];
      skipped.add(key);
      continue;
    }
    result[key] = value;
    skipped.delete(key);
    lastInheritedKey = key;
  }
  if (skippedKeys) {
    // Name only vars that genuinely carry no inherited value (a duplicate
    // key whose LAST occurrence is readable still inherits, matching
    // PyYAML last-wins, so it is not named).
    for (const key of skipped) {
      if (!(key in result)) skippedKeys.push(key);
    }
  }
  return Object.keys(result).length > 0 ? result : null;
}

/**
 * Parse a double-quoted, single-quoted, or plain YAML scalar value.
 * Returns null when the value cannot be read confidently (multi-line,
 * malformed quoting, empty); callers skip such vars rather than guess.
 * Values opening with a YAML indicator the single-line plain read cannot
 * represent (block scalars | >, anchors/aliases & *, tags !, flow
 * collections [ {, directives %) also resolve null: PyYAML (the parser
 * Hermes actually uses) gives them structural meaning, so inheriting the
 * raw text would write a corrupted literal in place of the operator's
 * value.
 */
function parseYamlScalarValue(raw: string): string | null {
  const t = raw.trim();
  if (t === "") return null;
  if ("|>&*![{%".includes(t[0]!)) return null;
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
