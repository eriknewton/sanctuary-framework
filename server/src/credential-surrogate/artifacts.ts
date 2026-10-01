/**
 * Credential surrogacy: the three on-disk artifacts root arming writes, one
 * shared schema and parse function each (AGENTS.md rule 11).
 *
 * WHY THESE LIVE HERE AND NOT AT EITHER END. Every one of the three files has a
 * writer at one privilege level and a reader at another:
 *
 * | File | Writer | Reader | Mode |
 * |---|---|---|---|
 * | `gate-cred/<uid>.surrogates` | root arming | the release wrapper, as the agent uid | agent 0600 |
 * | `gate-surrogate/<uid>.bindings` | root arming | the helper daemon, and root at release commit | root 0600 |
 * | `gate-surrogate/<uid>.destinations` | root arming | the gate daemon (slice 1b) | gate 0600 |
 *
 * A writer and a reader that each carried their own idea of the format is how a
 * binding gets silently dropped, or worse, how a destination the writer refused
 * is read back as authorized. So each file has exactly one render function and
 * one parse function, both here, and both ends call them.
 *
 * THE ONE EXCEPTION, STATED. The release wrapper (`egress-gate/release-barrier.ts`)
 * is emitted shell-and-node text that runs before any module of this tree is
 * loaded, so it cannot import {@link parseSurrogatePlaceholderFile}. It carries
 * the header grammar and the line grammar as literals instead. Those literals
 * must match {@link SURROGATE_PLACEHOLDER_FILE_KIND} and
 * {@link SURROGATE_PLACEHOLDER_LINE_RE} here, and a test in
 * `server/test/egress-gate/release-barrier.test.ts` pins them by running the
 * wrapper over a file this module rendered.
 *
 * EVERY PARSER HERE IS ALL-OR-NOTHING. A file with one bad line yields a
 * refusal, never the lines that happened to parse. A helper that loaded 3 of 4
 * bindings would answer `unknown_placeholder` for the fourth, which reads to an
 * operator as a policy that does not apply rather than as a corrupt file.
 */

import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_DESTINATIONS_PER_BINDING,
} from "./constants.js";
import {
  validateSurrogateAgentId,
  validateSurrogateEnvName,
  validateSurrogateHeaderName,
  validateSurrogateHost,
  validateSurrogatePort,
  validateSurrogateSecretName,
  type MintedSurrogateBinding,
  type SurrogateDestination,
} from "./binding.js";
import { isSurrogatePlaceholder } from "./placeholder.js";

/**
 * Header-line kind tokens, one per file, so a file that ends up at the wrong
 * path is refused rather than parsed as the format it is not. The bindings file
 * and the destinations file differ in who may read them; a mix-up would hand
 * the gate uid the whole binding table.
 */
export const SURROGATE_BINDINGS_FILE_KIND = "sanctuary-surrogate-bindings";
/** Must match the literal in the release wrapper; see the module header. */
export const SURROGATE_PLACEHOLDER_FILE_KIND = "sanctuary-surrogate-placeholders";
export const SURROGATE_DESTINATIONS_FILE_KIND = "sanctuary-surrogate-destinations";

/** Artifact format version. Bumping it is a breaking change on both ends of all three files. */
export const SURROGATE_ARTIFACT_VERSION = 1 as const;

/**
 * Header grammar, shared by all three files: `<kind> v<version> generation=<digits>`.
 *
 * It is a single LINE rather than a JSON envelope because the release commit
 * path reads only the generation, as root, to decide whether to park
 * (`arming-wiring.ts` base `commitGeneration`), and the release wrapper reads
 * it from emitted script text. A line both can read without a JSON parser keeps
 * one grammar instead of two.
 */
const HEADER_RE = /^([a-z-]+) v([0-9]{1,3}) generation=(0|[1-9][0-9]{0,15})$/;

/** Fixed refusal classes. Never the offending bytes: a binding line names a secret. */
export type SurrogateArtifactRefusal =
  | "empty_file"
  | "bad_header"
  | "wrong_kind"
  | "bad_version"
  | "bad_line"
  | "too_many_bindings"
  | "duplicate_placeholder"
  | "duplicate_secret"
  | "duplicate_env"
  | "duplicate_ordinal";

export class SurrogateArtifactError extends Error {
  readonly refusal: SurrogateArtifactRefusal;

  constructor(refusal: SurrogateArtifactRefusal) {
    super(`surrogate artifact refused: ${refusal}`);
    this.name = "SurrogateArtifactError";
    this.refusal = refusal;
  }
}

function renderHeader(kind: string, generationId: number): string {
  if (!Number.isSafeInteger(generationId) || generationId < 0) {
    throw new Error("surrogate artifact generation id must be a non-negative safe integer");
  }
  return `${kind} v${SURROGATE_ARTIFACT_VERSION} generation=${generationId}`;
}

/**
 * Split a rendered artifact into its header fields and its body lines.
 *
 * Trailing newlines are tolerated (every renderer here emits one); a blank line
 * anywhere else is `bad_line`, not skipped, because a parser that skips blanks
 * also skips a line an editor truncated to nothing.
 */
function splitArtifact(
  text: string,
  kind: string,
): { generationId: number; lines: string[] } {
  if (text.length === 0) throw new SurrogateArtifactError("empty_file");
  const all = text.split("\n");
  while (all.length > 0 && all[all.length - 1] === "") all.pop();
  if (all.length === 0) throw new SurrogateArtifactError("empty_file");
  const header = HEADER_RE.exec(all[0]!);
  if (header === null) throw new SurrogateArtifactError("bad_header");
  if (header[1] !== kind) throw new SurrogateArtifactError("wrong_kind");
  if (Number(header[2]) !== SURROGATE_ARTIFACT_VERSION) {
    throw new SurrogateArtifactError("bad_version");
  }
  return { generationId: Number(header[3]), lines: all.slice(1) };
}

/**
 * Read ONLY the generation from any of the three artifacts.
 *
 * The release commit path calls this and nothing else: it decides whether the
 * bindings on disk belong to the generation being committed, and a full parse
 * there would make a corrupt body line a park reason for a check that is only
 * about the generation.
 */
export function readSurrogateArtifactGeneration(text: string, kind: string): number {
  return splitArtifact(text, kind).generationId;
}

// ---------------------------------------------------------------------------
// `gate-cred/<uid>.surrogates`: what the agent's own wrapper exports
// ---------------------------------------------------------------------------

/**
 * The ONLY legal body line of the placeholder file.
 *
 * Must match the literal in the release wrapper (`release-barrier.ts`) and the
 * grammar design 3.2 states. Anchored, and the placeholder half is spelled out
 * rather than composed, because the wrapper cannot import
 * {@link isSurrogatePlaceholder} and a composed regex here would drift from the
 * wrapper's literal without a test noticing.
 */
export const SURROGATE_PLACEHOLDER_LINE_RE =
  /^([A-Z_][A-Z0-9_]{0,63})=(sanctuary_surrogate_[0-9a-f]{32})$/;

/**
 * Render the agent-readable placeholder file: a header line, then one
 * `ENV_NAME=<placeholder>` line per binding, in ordinal order.
 *
 * NO value and NO destination, ever. This is the one artifact the confined agent
 * uid can open, so anything in it is something the agent knows.
 */
export function renderSurrogatePlaceholderFile(
  generationId: number,
  bindings: readonly MintedSurrogateBinding[],
): string {
  const body = [...bindings]
    .sort((a, b) => a.ordinal - b.ordinal)
    .map((b) => `${b.env}=${b.placeholder}`);
  for (const line of body) {
    if (!SURROGATE_PLACEHOLDER_LINE_RE.test(line)) {
      // Unreachable through the shared validators; loud rather than silent,
      // because a line that fails here is a line the release wrapper would
      // refuse with exit 78 at agent start, long after the operator left.
      throw new SurrogateArtifactError("bad_line");
    }
  }
  return `${renderHeader(SURROGATE_PLACEHOLDER_FILE_KIND, generationId)}\n${body.map((l) => `${l}\n`).join("")}`;
}

/** Parse the placeholder file back. Used by tests and by the wrapper's own pin test. */
export function parseSurrogatePlaceholderFile(text: string): {
  generationId: number;
  entries: { env: string; placeholder: string }[];
} {
  const { generationId, lines } = splitArtifact(text, SURROGATE_PLACEHOLDER_FILE_KIND);
  const entries: { env: string; placeholder: string }[] = [];
  const seenEnv = new Set<string>();
  for (const line of lines) {
    const m = SURROGATE_PLACEHOLDER_LINE_RE.exec(line);
    if (m === null) throw new SurrogateArtifactError("bad_line");
    if (seenEnv.has(m[1]!)) throw new SurrogateArtifactError("duplicate_env");
    seenEnv.add(m[1]!);
    entries.push({ env: m[1]!, placeholder: m[2]! });
  }
  return { generationId, entries };
}

// ---------------------------------------------------------------------------
// `gate-surrogate/<uid>.destinations`: what the gate uid may know
// ---------------------------------------------------------------------------

/**
 * Render the gate-readable destination set: a header line, then one
 * `host:port` line per distinct destination, sorted.
 *
 * The gate is entitled to know which authorities a placeholder may be spent
 * toward, so it can refuse a forward request for an unbound host without
 * asking the helper. It is NOT entitled to the secret name, the env name or
 * which binding a destination belongs to, so none of that is here.
 */
export function renderSurrogateDestinationsFile(
  generationId: number,
  bindings: readonly MintedSurrogateBinding[],
): string {
  const set = new Set<string>();
  for (const binding of bindings) {
    for (const dest of binding.destinations) set.add(`${dest.host}:${dest.port}`);
  }
  const body = [...set].sort();
  return `${renderHeader(SURROGATE_DESTINATIONS_FILE_KIND, generationId)}\n${body.map((l) => `${l}\n`).join("")}`;
}

const DESTINATION_LINE_RE = /^([^\s:]+):([1-9][0-9]{0,4})$/;

/** Parse the gate-readable destination set. Every element re-validated on read. */
export function parseSurrogateDestinationsFile(text: string): {
  generationId: number;
  destinations: SurrogateDestination[];
} {
  const { generationId, lines } = splitArtifact(text, SURROGATE_DESTINATIONS_FILE_KIND);
  const destinations: SurrogateDestination[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const m = DESTINATION_LINE_RE.exec(line);
    if (m === null) throw new SurrogateArtifactError("bad_line");
    const host = m[1]!;
    const port = Number(m[2]);
    // Re-validated on READ, not trusted because root wrote it: the reader is the
    // stage that would dial, and rule 11 parity means both ends judge with the
    // same functions rather than one end trusting the other's judgment.
    if (validateSurrogateHost(host) !== null) throw new SurrogateArtifactError("bad_line");
    if (validateSurrogatePort(port) !== null) throw new SurrogateArtifactError("bad_line");
    if (seen.has(line)) throw new SurrogateArtifactError("bad_line");
    seen.add(line);
    destinations.push({ host, port });
  }
  return { generationId, destinations };
}

// ---------------------------------------------------------------------------
// `gate-surrogate/<uid>.bindings`: the helper's whole table
// ---------------------------------------------------------------------------

const BINDING_LINE_KEYS = [
  "ordinal",
  "placeholder",
  "secret",
  "agent",
  "env",
  "header",
  "destinations",
] as const;

/**
 * Render the root-only binding table: a header line, then one JSON object per
 * line in ordinal order.
 *
 * One object per LINE rather than one JSON document for the whole file so the
 * header stays a line the release commit path can read with a single regex, and
 * so a corrupt body line is bounded to a line rather than costing the parse of
 * the whole table. The cap is enforced HERE as well as at policy parse and at
 * helper load, because this file is the artifact a stale generation could leave
 * behind and the helper load check is the one that runs after a reboot.
 */
export function renderSurrogateBindingsFile(
  generationId: number,
  bindings: readonly MintedSurrogateBinding[],
): string {
  if (bindings.length > MAX_SURROGATE_BINDINGS_PER_AGENT) {
    throw new SurrogateArtifactError("too_many_bindings");
  }
  const body = [...bindings]
    .sort((a, b) => a.ordinal - b.ordinal)
    .map((b) =>
      JSON.stringify({
        ordinal: b.ordinal,
        placeholder: b.placeholder,
        secret: b.secret,
        agent: b.agent,
        env: b.env,
        header: b.header,
        destinations: b.destinations.map((d) => ({ host: d.host, port: d.port })),
      }),
    );
  for (const line of body) {
    if (line.includes("\n")) throw new SurrogateArtifactError("bad_line");
  }
  return `${renderHeader(SURROGATE_BINDINGS_FILE_KIND, generationId)}\n${body.map((l) => `${l}\n`).join("")}`;
}

function parseBindingLine(line: string): MintedSurrogateBinding {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new SurrogateArtifactError("bad_line");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new SurrogateArtifactError("bad_line");
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== BINDING_LINE_KEYS.length) throw new SurrogateArtifactError("bad_line");
  for (const key of BINDING_LINE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      throw new SurrogateArtifactError("bad_line");
    }
  }
  const ordinal = record.ordinal;
  if (typeof ordinal !== "number" || !Number.isInteger(ordinal) || ordinal < 0) {
    throw new SurrogateArtifactError("bad_line");
  }
  if (!isSurrogatePlaceholder(record.placeholder)) throw new SurrogateArtifactError("bad_line");
  if (validateSurrogateSecretName(record.secret) !== null) {
    throw new SurrogateArtifactError("bad_line");
  }
  if (validateSurrogateAgentId(record.agent) !== null) throw new SurrogateArtifactError("bad_line");
  if (validateSurrogateEnvName(record.env) !== null) throw new SurrogateArtifactError("bad_line");
  if (validateSurrogateHeaderName(record.header) !== null) {
    throw new SurrogateArtifactError("bad_line");
  }
  const rawDestinations = record.destinations;
  if (
    !Array.isArray(rawDestinations) ||
    rawDestinations.length === 0 ||
    rawDestinations.length > MAX_SURROGATE_DESTINATIONS_PER_BINDING
  ) {
    throw new SurrogateArtifactError("bad_line");
  }
  const destinations: SurrogateDestination[] = [];
  const seenHosts = new Set<string>();
  for (const entry of rawDestinations) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new SurrogateArtifactError("bad_line");
    }
    const dest = entry as Record<string, unknown>;
    if (Object.keys(dest).length !== 2) throw new SurrogateArtifactError("bad_line");
    if (validateSurrogateHost(dest.host) !== null) throw new SurrogateArtifactError("bad_line");
    if (validateSurrogatePort(dest.port) !== null) throw new SurrogateArtifactError("bad_line");
    const host = dest.host as string;
    if (seenHosts.has(host)) throw new SurrogateArtifactError("bad_line");
    seenHosts.add(host);
    destinations.push({ host, port: dest.port as number });
  }
  return {
    ordinal,
    placeholder: record.placeholder as string,
    secret: record.secret as string,
    agent: record.agent as string,
    env: record.env as string,
    header: record.header as string,
    destinations,
  };
}

/**
 * Parse the root-only binding table.
 *
 * Refuses a duplicate placeholder, secret, env name or ordinal across lines.
 * A duplicate placeholder would make the helper's lookup ambiguous, which is
 * the one way a value could be answered for a destination its own binding does
 * not authorize; the other three are refused because each is a key some stage
 * keys by, and an ambiguous key is a silent wrong answer somewhere downstream.
 */
export function parseSurrogateBindingsFile(text: string): {
  generationId: number;
  bindings: MintedSurrogateBinding[];
} {
  const { generationId, lines } = splitArtifact(text, SURROGATE_BINDINGS_FILE_KIND);
  if (lines.length > MAX_SURROGATE_BINDINGS_PER_AGENT) {
    throw new SurrogateArtifactError("too_many_bindings");
  }
  const bindings: MintedSurrogateBinding[] = [];
  const placeholders = new Set<string>();
  const secrets = new Set<string>();
  const envs = new Set<string>();
  const ordinals = new Set<number>();
  for (const line of lines) {
    const binding = parseBindingLine(line);
    if (placeholders.has(binding.placeholder)) {
      throw new SurrogateArtifactError("duplicate_placeholder");
    }
    if (secrets.has(binding.secret)) throw new SurrogateArtifactError("duplicate_secret");
    if (envs.has(binding.env)) throw new SurrogateArtifactError("duplicate_env");
    if (ordinals.has(binding.ordinal)) throw new SurrogateArtifactError("duplicate_ordinal");
    placeholders.add(binding.placeholder);
    secrets.add(binding.secret);
    envs.add(binding.env);
    ordinals.add(binding.ordinal);
    bindings.push(binding);
  }
  return { generationId, bindings };
}
