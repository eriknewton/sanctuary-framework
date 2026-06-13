/**
 * Plugin substrate — restricted YAML parser (design §3.1, "restricted YAML profile").
 *
 * YAML is a signature-determinism hazard: anchors/aliases, explicit tags, merge keys,
 * duplicate keys, and non-string keys all let the same bytes parse to divergent objects,
 * so a signer and a verifier using different full-YAML parsers can disagree silently
 * (codex MEDIUM, round 1). The contract pins governance.yaml to a *restricted profile*
 * and the signed object is the canonical-JSON projection of THIS parse.
 *
 * This parser supports exactly the subset governance.yaml needs and REJECTS, with a named
 * reason, anything outside it:
 *   - nested block mappings (key: value, key:\n  nested:)
 *   - block sequences ("- item", and "- key: value" maps inside sequences)
 *   - scalar values: strings (plain or "double-quoted"), integers, finite floats,
 *     booleans (true/false), null (null / ~ / empty)
 * REJECTED: anchors (&a) / aliases (*a), explicit tags (!!str, !Foo), merge keys (<<),
 *   duplicate keys at the same level, non-string keys, flow collections ({..}/[..]),
 *   block scalars (| / >), multiple documents (---), non-finite numbers.
 *
 * The deliberate decision (matching principal-policy/loader.ts) is to hand-roll a tight
 * subset rather than pull in a full YAML dependency, because the full grammar is the
 * attack surface we are trying to exclude.
 */

import { reject } from "./errors.js";

/** A parsed scalar/structure: the JSON value space we project onto. */
export type YamlValue =
  | string
  | number
  | boolean
  | null
  | YamlValue[]
  | { [k: string]: YamlValue };

interface Line {
  readonly indent: number;
  readonly content: string;
  readonly raw: string;
  readonly lineNo: number;
}

const FLOW_OPEN = /[[{]/;

/** Parse a restricted-YAML document into a plain JSON-compatible value. */
export function parseRestrictedYaml(text: string): YamlValue {
  if (text.includes("\t")) {
    reject("yaml_malformed", "tabs are not permitted for indentation in governance.yaml");
  }

  const lines = tokenize(text);
  if (lines.length === 0) return {};

  const [value, consumed] = parseBlock(lines, 0, lines[0]!.indent);
  if (consumed !== lines.length) {
    reject(
      "yaml_malformed",
      `unexpected content at line ${lines[consumed]?.lineNo ?? "?"} (inconsistent indentation)`,
    );
  }
  return value;
}

/** Strip comments, blank lines, and document markers; reject multi-document streams. */
function tokenize(text: string): Line[] {
  const out: Line[] = [];
  const rawLines = text.split(/\r?\n/);
  let seenDocMarker = false;

  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i]!;
    const lineNo = i + 1;
    const trimmedRight = stripComment(raw);
    if (trimmedRight.trim() === "") continue;

    if (/^---\s*$/.test(trimmedRight) || /^\.\.\.\s*$/.test(trimmedRight)) {
      if (seenDocMarker) {
        reject("yaml_malformed", "multiple YAML documents are not permitted");
      }
      seenDocMarker = true;
      continue;
    }

    const indent = raw.length - raw.trimStart().length;
    out.push({ indent, content: trimmedRight.trim(), raw, lineNo });
  }
  return out;
}

/**
 * Remove a trailing `# comment` but not a `#` inside a double-quoted string.
 * Plain scalars may not contain `#` after whitespace; we conservatively cut at the
 * first unquoted `#` preceded by whitespace or at line start.
 */
function stripComment(line: string): string {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '"') {
      // honor backslash-escaped quotes
      let backslashes = 0;
      let j = i - 1;
      while (j >= 0 && line[j] === "\\") {
        backslashes++;
        j--;
      }
      if (backslashes % 2 === 0) inQuote = !inQuote;
    } else if (ch === "#" && !inQuote) {
      const prev = line[i - 1];
      if (i === 0 || prev === " " || prev === "\t") {
        return line.slice(0, i);
      }
    }
  }
  return line;
}

/** Parse a block (mapping or sequence) at a given indent. Returns [value, linesConsumed]. */
function parseBlock(lines: Line[], start: number, indent: number): [YamlValue, number] {
  const first = lines[start]!;
  if (first.content.startsWith("- ") || first.content === "-") {
    return parseSequence(lines, start, indent);
  }
  return parseMapping(lines, start, indent);
}

function parseSequence(lines: Line[], start: number, indent: number): [YamlValue, number] {
  const items: YamlValue[] = [];
  let i = start;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.indent < indent) break;
    if (line.indent > indent) {
      reject("yaml_malformed", `unexpected indentation at line ${line.lineNo}`);
    }
    if (!(line.content === "-" || line.content.startsWith("- "))) {
      // de-dent back to a mapping at the same indent => not part of this sequence
      break;
    }

    const afterDash = line.content === "-" ? "" : line.content.slice(2).trim();

    if (afterDash === "") {
      // nested block on following lines
      const [child, consumed] = consumeChild(lines, i + 1, indent);
      items.push(child);
      i = consumed;
      continue;
    }

    // "- key: value" => an inline mapping entry starting in the sequence item.
    if (isMappingEntry(afterDash)) {
      // Re-tokenize this item as a mapping whose first line is `afterDash` at a virtual
      // deeper indent; collect subsequent more-indented lines as its body.
      const virtualIndent = indent + 2;
      const synthetic: Line[] = [
        { indent: virtualIndent, content: afterDash, raw: line.raw, lineNo: line.lineNo },
      ];
      let j = i + 1;
      while (j < lines.length && lines[j]!.indent >= virtualIndent) {
        synthetic.push(lines[j]!);
        j++;
      }
      const [mapVal, consumedLocal] = parseMapping(synthetic, 0, virtualIndent);
      if (consumedLocal !== synthetic.length) {
        reject("yaml_malformed", `malformed sequence item at line ${line.lineNo}`);
      }
      items.push(mapVal);
      i = j;
      continue;
    }

    // "- scalar"
    items.push(parseScalar(afterDash, line.lineNo));
    i++;
  }
  return [items, i];
}

function parseMapping(lines: Line[], start: number, indent: number): [YamlValue, number] {
  // Object.create(null) so a "__proto__" key becomes an OWN property visible to
  // Object.keys() rather than silently mutating Object.prototype (codex HIGH). The
  // governance closure then sees and rejects it. splitKey also rejects it outright.
  const map: Record<string, YamlValue> = Object.create(null) as Record<string, YamlValue>;
  const seen = new Set<string>();
  let i = start;

  while (i < lines.length) {
    const line = lines[i]!;
    if (line.indent < indent) break;
    if (line.indent > indent) {
      reject("yaml_malformed", `unexpected indentation at line ${line.lineNo}`);
    }
    if (line.content.startsWith("- ") || line.content === "-") {
      // a sequence at this indent is not a mapping entry
      break;
    }

    const { key, rest } = splitKey(line.content, line.lineNo);
    if (seen.has(key)) {
      reject("yaml_duplicate_key", `duplicate key "${key}" at line ${line.lineNo}`);
    }
    seen.add(key);

    if (rest === "") {
      // nested block follows
      const [child, consumed] = consumeChild(lines, i + 1, indent);
      map[key] = child;
      i = consumed;
    } else {
      map[key] = parseScalar(rest, line.lineNo);
      i++;
    }
  }
  return [map, i];
}

/** Consume a nested block that must be strictly more-indented than `parentIndent`. */
function consumeChild(lines: Line[], start: number, parentIndent: number): [YamlValue, number] {
  if (start >= lines.length || lines[start]!.indent <= parentIndent) {
    // empty value => null
    return [null, start];
  }
  const childIndent = lines[start]!.indent;
  return parseBlock(lines, start, childIndent);
}

function isMappingEntry(s: string): boolean {
  try {
    splitKey(s, -1);
    return true;
  } catch {
    return false;
  }
}

/** Split "key: rest" honoring a quoted key; reject non-string/structural keys. */
function splitKey(content: string, lineNo: number): { key: string; rest: string } {
  if (content.startsWith("<<")) {
    reject("yaml_merge_key", `merge keys ("<<") are not permitted (line ${lineNo})`);
  }
  if (content.startsWith("? ")) {
    reject("yaml_non_string_key", `explicit/complex keys are not permitted (line ${lineNo})`);
  }

  let key: string;
  let rest: string;
  let quoted = false;
  if (content.startsWith('"')) {
    quoted = true;
    const end = findClosingQuote(content, lineNo);
    key = decodeDoubleQuoted(content.slice(0, end + 1), lineNo);
    const after = content.slice(end + 1).trimStart();
    if (!after.startsWith(":")) {
      reject("yaml_malformed", `expected ":" after quoted key at line ${lineNo}`);
    }
    rest = after.slice(1).trim();
  } else {
    const colon = content.indexOf(":");
    if (colon === -1) {
      reject("yaml_malformed", `mapping entry missing ":" at line ${lineNo}`);
    }
    key = content.slice(0, colon).trim();
    rest = content.slice(colon + 1).trim();
  }

  if (key === "") {
    reject("yaml_malformed", `empty mapping key at line ${lineNo}`);
  }

  // Reject prototype-pollution keys regardless of quoting (defense in depth; the parsed
  // map is also Object.create(null)). A genuine need for these names does not exist in
  // governance.yaml, so a flat reject is safe and explicit (codex HIGH).
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    reject("yaml_non_string_key", `reserved/prototype key "${key}" is not permitted (line ${lineNo})`);
  }

  // a bare-flow key like "[a]" or "{a}" is a non-string structural key
  if (FLOW_OPEN.test(key[0]!)) {
    reject("yaml_non_string_key", `non-string (flow) key at line ${lineNo}`);
  }

  // For UNQUOTED keys, enforce the restricted profile on the key text itself so the
  // parser surface rejects anchors/aliases/tags and number/boolean/null-typed keys
  // rather than leaning on the later governance closure (codex MEDIUM).
  if (!quoted) {
    if (key[0] === "&") reject("yaml_anchor_or_alias", `anchor key ("&") not permitted (line ${lineNo})`);
    if (key[0] === "*") reject("yaml_anchor_or_alias", `alias key ("*") not permitted (line ${lineNo})`);
    if (key[0] === "!") reject("yaml_explicit_tag", `tag key ("!") not permitted (line ${lineNo})`);
    if (
      key === "null" ||
      key === "~" ||
      key === "true" ||
      key === "false" ||
      /^[+-]?\d+$/.test(key) ||
      /^[+-]?\d+\.\d+([eE][+-]?\d+)?$/.test(key) ||
      /^[+-]?\.(inf|nan)$/i.test(key)
    ) {
      reject("yaml_non_string_key", `non-string (typed) key "${key}" not permitted; quote it (line ${lineNo})`);
    }
  }

  return { key, rest };
}

function findClosingQuote(s: string, lineNo: number): number {
  for (let i = 1; i < s.length; i++) {
    if (s[i] === "\\") {
      i++;
      continue;
    }
    if (s[i] === '"') return i;
  }
  reject("yaml_malformed", `unterminated quoted string at line ${lineNo}`);
}

function decodeDoubleQuoted(token: string, lineNo: number): string {
  // token includes surrounding quotes
  const inner = token.slice(1, -1);
  let out = "";
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = inner[++i];
    switch (next) {
      case "n":
        out += "\n";
        break;
      case "t":
        out += "\t";
        break;
      case "r":
        out += "\r";
        break;
      case '"':
        out += '"';
        break;
      case "\\":
        out += "\\";
        break;
      case "/":
        out += "/";
        break;
      case "0":
        out += "\0";
        break;
      default:
        reject("yaml_malformed", `unsupported escape "\\${next ?? ""}" at line ${lineNo}`);
    }
  }
  return out;
}

/** Parse a scalar value, rejecting anchors/aliases/tags/flow/block scalars. */
function parseScalar(raw: string, lineNo: number): YamlValue {
  const s = raw.trim();

  if (s === "") return null;
  if (s[0] === "&") reject("yaml_anchor_or_alias", `anchors ("&") are not permitted (line ${lineNo})`);
  if (s[0] === "*") reject("yaml_anchor_or_alias", `aliases ("*") are not permitted (line ${lineNo})`);
  if (s[0] === "!") reject("yaml_explicit_tag", `explicit tags ("!") are not permitted (line ${lineNo})`);
  if (s[0] === "|" || s[0] === ">") {
    reject("yaml_malformed", `block scalars ("|"/">") are not permitted (line ${lineNo})`);
  }

  // Empty flow collections are unambiguous and deterministic; permit ONLY [] and {}.
  if (s === "[]") return [];
  if (s === "{}") return {};
  if (FLOW_OPEN.test(s[0]!)) {
    reject("yaml_non_string_key", `non-empty flow collections ("{...}"/"[...]") are not permitted (line ${lineNo})`);
  }

  if (s.startsWith('"')) {
    const end = findClosingQuote(s, lineNo);
    if (end !== s.length - 1) {
      reject("yaml_malformed", `trailing content after quoted scalar at line ${lineNo}`);
    }
    return decodeDoubleQuoted(s, lineNo);
  }

  // unquoted plain scalars
  if (s === "null" || s === "~") return null;
  if (s === "true") return true;
  if (s === "false") return false;

  // integer
  if (/^[+-]?\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) {
      reject("json_non_finite_number", `non-finite number at line ${lineNo}`);
    }
    return n;
  }
  // finite float (no .inf / .nan)
  if (/^[+-]?\d+\.\d+([eE][+-]?\d+)?$/.test(s) || /^[+-]?\d+[eE][+-]?\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) {
      reject("json_non_finite_number", `non-finite number at line ${lineNo}`);
    }
    return n;
  }
  if (/^[+-]?\.(inf|nan)$/i.test(s) || /^[+-]?\.?(inf|nan)$/i.test(s)) {
    reject("json_non_finite_number", `non-finite YAML float (.inf/.nan) at line ${lineNo}`);
  }

  // plain string
  return s;
}
