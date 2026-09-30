/**
 * Sanctuary egress gate: the surrogate secret helper, a root-owned per-agent
 * LaunchDaemon that holds bound credential values only after an operator unlock.
 *
 * WHY IT EXISTS. The gate uid cannot read the broker keychain: that keychain is
 * a dedicated file in the operator's home, unlocked with the fortress
 * passphrase, and the passphrase resolves from the operator's login keychain or
 * an encrypted fallback. A root daemon cannot resolve that headless, and the
 * fortress-key rule forbids a plaintext copy an agent-side process could read.
 * So the operator pushes values INTO this helper over a socket only the
 * operator uid can open, and the helper never touches a keychain itself.
 *
 * WHAT IT STARTS AS. LOCKED, always. `RunAtLoad` is false and a load carries no
 * values; a freshly installed or freshly rebooted helper answers every query
 * with a denial until an operator unlocks it. A helper that came back from a
 * crash with values would be a credential store that survives reboot without
 * anyone deciding it should.
 *
 * TWO SOCKETS, ONE CODEC EACH. The query socket is owned by the gate uid and
 * speaks only the query codec; the unlock socket is owned by the operator uid
 * and speaks only the unlock codec. A query frame arriving on the unlock socket,
 * or the reverse, is `malformed` and never falls through to the other parser.
 * One codec per socket is what keeps the gate from being able to push a value in
 * and the agent-adjacent side from being able to ask for one.
 *
 * WHAT THIS MODULE MUST NEVER DO. It must never read a keychain, never write a
 * value to disk, never log a value or a placeholder, and never answer a query
 * for a destination outside the binding the placeholder names.
 *
 * SLICE BOUND. Slice 1a builds everything below: the launchd identity, the
 * plist, the argv contract with its refusals, both listeners with one codec
 * each, the table load, the caps, and the unlock validation and clamp. What is
 * NOT here and is slice 1b: the GATE side. No gate code calls this yet, so no
 * swap happens on any request; `surrogate-helper-client.ts` and the forward-mode
 * handler are the next slice, and until they land the gate answers plain HTTP
 * with today's 405 exactly as before.
 */

import { chmod, chown, mkdir, readFile, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { isAbsolute, join } from "node:path";

import {
  SurrogateArtifactError,
  parseSurrogateBindingsFile,
} from "../credential-surrogate/artifacts.js";
import type { MintedSurrogateBinding } from "../credential-surrogate/binding.js";
import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_HELPER_MAX_CONCURRENT_QUERIES,
  SURROGATE_WIRE_MAX_FRAME_BYTES,
} from "../credential-surrogate/constants.js";
import {
  encodeSurrogateQueryResponse,
  parseSurrogateQueryRequest,
  surrogateHeaderLocation,
  type SurrogateDenyReason,
} from "../credential-surrogate/query-codec.js";
import { redactSurrogatePlaceholders } from "../credential-surrogate/redaction.js";
import {
  encodeSurrogateUnlockSocketResponse,
  parseSurrogateUnlockSocketRequest,
  type SurrogateUnlockDenyReason,
} from "../credential-surrogate/unlock-codec.js";
import { SURROGATE_WIRE_VERSION } from "../credential-surrogate/wire.js";

// ---------------------------------------------------------------------------
// Filesystem and launchd identity
// ---------------------------------------------------------------------------

/**
 * Root-owned parent directory for both helper sockets and the root-only binding
 * artifacts. Mode 0711, matching `GATE_CRED_DIR` in `gate-credential.ts` and for
 * the same reason stated there: root-only write and listing, but execute and
 * search for everyone, so the two non-root callers can traverse to the ONE
 * socket each is entitled to. A 0700 parent would block both and make every
 * query and every unlock fail, which reads as a broken helper rather than as a
 * permissions decision.
 *
 * Must match the `gate-surrogate` entry in `runtime-fs-plan.ts`.
 */
export const GATE_SURROGATE_DIR = "/var/db/sanctuary/gate-surrogate";

/**
 * The mode the runtime-fs plan applies to {@link GATE_SURROGATE_DIR}. Declared
 * here, beside the directory and the reasoning above, and imported by
 * `runtime-fs-plan.ts` rather than restated there, so the plan and the daemon
 * can never state two different modes for the one directory (the precedent is
 * `AGENT_HARNESS_HOLD_DIR_MODE`, which that plan already imports for the same
 * reason).
 */
export const GATE_SURROGATE_DIR_MODE = 0o711;

/**
 * The GATE uid's query socket. Owned by the gate uid, mode 0600.
 *
 * Distinct from {@link surrogateUnlockSocketPath} by name as well as by owner:
 * two sockets that differed only by permission would be one typo away from
 * letting the gate push a value in.
 */
export function surrogateQuerySocketPath(
  agentUid: number,
  dir: string = GATE_SURROGATE_DIR,
): string {
  return `${dir}/${agentUid}.query.sock`;
}

/** The OPERATOR uid's unlock socket. Owned by the operator uid, mode 0600. */
export function surrogateUnlockSocketPath(
  agentUid: number,
  dir: string = GATE_SURROGATE_DIR,
): string {
  return `${dir}/${agentUid}.unlock.sock`;
}

/**
 * Root-readable binding table for one agent, written by root arming.
 *
 * Must match the writer in `arming-wiring.ts`. Root 0600: the helper is the only
 * reader, and the table names which credential is spent where.
 */
export function surrogateBindingsPath(
  agentUid: number,
  dir: string = GATE_SURROGATE_DIR,
): string {
  return `${dir}/${agentUid}.bindings`;
}

/**
 * Gate-readable destination table for one agent. Gate uid 0600.
 *
 * Separate from the bindings file because the gate is entitled to know which
 * authority a placeholder may be spent toward and is NOT entitled to the rest of
 * the binding. Must match the writer in `arming-wiring.ts`.
 */
export function surrogateDestinationsPath(
  agentUid: number,
  dir: string = GATE_SURROGATE_DIR,
): string {
  return `${dir}/${agentUid}.destinations`;
}

/** LaunchDaemon label prefix; the resolver's shape with a different family name. */
export const SURROGATE_HELPER_DAEMON_LABEL_PREFIX = "ai.sanctuaryprotocol.surrogate-helper";

/** One helper per agent uid, so the label carries the uid. */
export function surrogateHelperDaemonLabel(agentUid: number): string {
  return `${SURROGATE_HELPER_DAEMON_LABEL_PREFIX}.${agentUid}`;
}

/** Root LaunchDaemon, so `/Library/LaunchDaemons`, matching every other root daemon here. */
export function surrogateHelperDaemonPlistPath(agentUid: number): string {
  return `/Library/LaunchDaemons/${surrogateHelperDaemonLabel(agentUid)}.plist`;
}

/**
 * Operator-readable log paths. Derived exactly like the resolver's
 * (`peer-resolver-daemon.ts`), so the operator can read helper lines without
 * root. Every line carries a fixed code and never a value or a placeholder.
 */
export function surrogateHelperDaemonLogPaths(
  agentUid: number,
  fortressPath: string,
  logDir?: string,
): { stdout: string; stderr: string } {
  const dir = logDir ?? join(fortressPath, "logs");
  return {
    stdout: join(dir, `surrogate-helper-${agentUid}.out.log`),
    stderr: join(dir, `surrogate-helper-${agentUid}.err.log`),
  };
}

/**
 * Umask held across `listen()`.
 *
 * Same value and same reason as `PEER_RESOLVER_SOCKET_UMASK`: `server.listen()`
 * creates the socket file itself, so the mode it is born with is whatever the
 * process umask allows. Narrowing it afterwards with `chmod` leaves a window in
 * which the node is world-accessible. 0o077 makes it owner-only from the first
 * byte; the explicit `chmod`/`chown` that follow are belt on top of that, not
 * the boundary.
 */
export const SURROGATE_HELPER_SOCKET_UMASK = 0o077;

// ---------------------------------------------------------------------------
// Events: a closed enum, no free-form message field
// ---------------------------------------------------------------------------

/**
 * Everything the helper reports.
 *
 * NO `message` FIELD ANYWHERE (round-2 finding B2-S4). The pattern this avoids
 * is `message: err.message` in the resolver and the gate server: an error string
 * built from input is how a value or a placeholder reaches a log. Every failure
 * path here picks a code from this closed set, and a structural test asserts no
 * variant declares a free-form string field.
 *
 * `binding` is the root-assigned ordinal, never a secret name and never a
 * placeholder.
 */
export type SurrogateHelperEvent =
  | { kind: "listening"; agentUid: number; generationId: number; bindings: number }
  | { kind: "unlock_accepted"; agentUid: number; binding: number; ttlSeconds: number }
  | { kind: "unlock_denied"; agentUid: number; reason: SurrogateHelperDenyCode }
  | { kind: "lock_accepted"; agentUid: number; bindingsDropped: number }
  | { kind: "query_answered"; agentUid: number; binding: number }
  | { kind: "query_denied"; agentUid: number; reason: SurrogateHelperDenyCode }
  | { kind: "daemon_error"; agentUid: number; reason: SurrogateHelperDenyCode };

/**
 * Fixed denial and failure codes.
 *
 * Closed on purpose: adding a case here is a deliberate act that a reviewer
 * sees, where a free-form string would let any new failure path invent its own
 * wording out of whatever it was handed.
 */
export type SurrogateHelperDenyCode =
  | "malformed"
  | "unknown_placeholder"
  | "unknown_secret"
  | "destination_not_bound"
  | "wrong_location"
  | "locked"
  | "expired"
  | "generation_mismatch"
  | "value_too_large"
  | "rate_limited"
  | "unexpected_extra_bytes"
  | "socket_error";

// ---------------------------------------------------------------------------
// Argv contract
// ---------------------------------------------------------------------------

/**
 * The four values root bakes into the plist at bring-up.
 *
 * All four are required. None may be inferred at runtime: the helper decides who
 * may unlock it and who may query it from these numbers, so a default would mean
 * a helper that guessed its own trust boundary.
 */
export interface SurrogateHelperDaemonArgs {
  agentUid: number;
  gateUid: number;
  operatorUid: number;
  /** The generation this helper serves. Must equal the bindings file header. */
  generation: number;
}

/** Why an argv was refused. Fixed classes, never the offending text. */
export type SurrogateHelperArgvRefusal =
  | "missing_flag"
  | "not_a_number"
  | "operator_uid_is_root"
  | "operator_uid_is_agent"
  | "operator_uid_is_gate"
  | "agent_uid_is_gate";

export class SurrogateHelperArgvError extends Error {
  readonly refusal: SurrogateHelperArgvRefusal;

  constructor(refusal: SurrogateHelperArgvRefusal) {
    super(`surrogate helper argv refused: ${refusal}`);
    this.name = "SurrogateHelperArgvError";
    this.refusal = refusal;
  }
}

function numericFlag(argv: readonly string[], flag: string): number {
  const equalsPrefix = `${flag}=`;
  let raw: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]!;
    if (token === flag) {
      raw = argv[i + 1];
      break;
    }
    if (token.startsWith(equalsPrefix)) {
      raw = token.slice(equalsPrefix.length);
      break;
    }
  }
  if (raw === undefined || raw.length === 0) throw new SurrogateHelperArgvError("missing_flag");
  // Anchored and digits-only: `Number("0x10")` and `Number(" 7 ")` both parse,
  // and a uid that came from a different reading of the same string than the
  // arming side used is a uid mismatch nothing would report.
  if (!/^(0|[1-9][0-9]{0,9})$/.test(raw)) throw new SurrogateHelperArgvError("not_a_number");
  return Number(raw);
}

/**
 * Parse and VALIDATE the daemon argv, refusing every uid combination that would
 * put the unlock socket in the wrong hands.
 *
 * The three refusals are not hygiene. The unlock socket is chowned to
 * `--operator-uid`, so whoever that names can push a credential value into a
 * root process:
 *  - uid 0 would mean the socket is root's, and the operator's own session could
 *    never unlock the helper it installed, so a helper that looked armed could
 *    never serve;
 *  - the AGENT uid would hand the unlock socket to the account the whole design
 *    exists to keep the value away from;
 *  - the GATE uid would collapse the two sockets into one principal, and the
 *    side that spends values could then also load them.
 *
 * The generation is checked against the bindings file header by the caller, not
 * here, because that read is I/O; this function is pure.
 */
export function parseSurrogateHelperDaemonArgs(
  argv: readonly string[],
): SurrogateHelperDaemonArgs {
  const agentUid = numericFlag(argv, "--agent-uid");
  const gateUid = numericFlag(argv, "--gate-uid");
  const operatorUid = numericFlag(argv, "--operator-uid");
  const generation = numericFlag(argv, "--generation");

  if (operatorUid === 0) throw new SurrogateHelperArgvError("operator_uid_is_root");
  if (operatorUid === agentUid) throw new SurrogateHelperArgvError("operator_uid_is_agent");
  if (operatorUid === gateUid) throw new SurrogateHelperArgvError("operator_uid_is_gate");
  if (agentUid === gateUid) throw new SurrogateHelperArgvError("agent_uid_is_gate");

  return { agentUid, gateUid, operatorUid, generation };
}

// ---------------------------------------------------------------------------
// Plist
// ---------------------------------------------------------------------------

export interface SurrogateHelperDaemonPlistOptions {
  agentUid: number;
  gateUid: number;
  operatorUid: number;
  generation: number;
  /** Absolute program path first, then its arguments. */
  programArguments: string[];
  /** Absolute fortress path; the log dir derives from it unless overridden. */
  fortressPath: string;
  logDir?: string;
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function assertNoControlChars(value: string, what: string): void {
  // A control character in a plist string is how an argument smuggles a second
  // XML element past the escaper. Must match `assertNoControlChars` in
  // `peer-resolver-daemon.ts`; both render root LaunchDaemon plists.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

/**
 * Render the helper's LaunchDaemon plist.
 *
 * `RunAtLoad` is FALSE and `KeepAlive` is `{ Crashed: true }`, the resolver's
 * shape: a load does not start the helper, and a crash restarts it LOCKED,
 * because a restarted helper holds no values.
 *
 * `HardResourceLimits` and `SoftResourceLimits` both set `Core` to 0 (design
 * 3.4.6). This process holds credential values in memory, so a core file would
 * be a plaintext copy of every unlocked value on a disk nothing else guards.
 * HARD as well as soft, because a soft limit alone can be raised by the process
 * or by anything that inherits from it.
 */
export function renderSurrogateHelperDaemonPlist(
  options: SurrogateHelperDaemonPlistOptions,
): string {
  const label = surrogateHelperDaemonLabel(options.agentUid);
  if (options.programArguments.length === 0 || !isAbsolute(options.programArguments[0]!)) {
    throw new Error(
      "surrogate helper daemon programArguments must be non-empty with an absolute program path first",
    );
  }
  for (const arg of options.programArguments) {
    assertNoControlChars(arg, "surrogate helper daemon program argument");
  }
  if (!isAbsolute(options.fortressPath)) {
    throw new Error(`fortress path must be absolute (got ${options.fortressPath})`);
  }
  assertNoControlChars(options.fortressPath, "fortress path");
  const logs = surrogateHelperDaemonLogPaths(
    options.agentUid,
    options.fortressPath,
    options.logDir,
  );
  if (!isAbsolute(logs.stdout)) {
    throw new Error(`surrogate helper log dir must be absolute (got ${logs.stdout})`);
  }
  assertNoControlChars(logs.stdout, "surrogate helper log dir");

  // The four values the argv contract requires, baked by root here and parsed
  // back by `parseSurrogateHelperDaemonArgs` in the child. Must stay in step
  // with that function's flag names.
  const args = [
    ...options.programArguments,
    "--agent-uid",
    String(options.agentUid),
    "--gate-uid",
    String(options.gateUid),
    "--operator-uid",
    String(options.operatorUid),
    "--generation",
    String(options.generation),
  ];
  const argsXml = args.map((a) => `\t\t<string>${xmlEscape(a)}</string>`).join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(label)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
\t<key>EnvironmentVariables</key>
\t<dict>
\t\t<key>SANCTUARY_STORAGE_PATH</key>
\t\t<string>${xmlEscape(options.fortressPath)}</string>
\t</dict>
\t<key>StandardOutPath</key>
\t<string>${xmlEscape(logs.stdout)}</string>
\t<key>StandardErrorPath</key>
\t<string>${xmlEscape(logs.stderr)}</string>
\t<key>Umask</key>
\t<integer>${SURROGATE_HELPER_SOCKET_UMASK}</integer>
\t<key>RunAtLoad</key>
\t<false/>
\t<key>KeepAlive</key>
\t<dict>
\t\t<key>Crashed</key>
\t\t<true/>
\t</dict>
\t<key>HardResourceLimits</key>
\t<dict>
\t\t<key>Core</key>
\t\t<integer>0</integer>
\t</dict>
\t<key>SoftResourceLimits</key>
\t<dict>
\t\t<key>Core</key>
\t\t<integer>0</integer>
\t</dict>
</dict>
</plist>
`;
}

/**
 * The bounds this daemon enforces, re-exported so a reader of this file sees the
 * ceilings without chasing the constants module. Values and derivations live in
 * `credential-surrogate/constants.ts`; this is a view, never a second copy.
 */
export const SURROGATE_HELPER_BOUNDS = {
  maxBindings: MAX_SURROGATE_BINDINGS_PER_AGENT,
  maxConcurrentQueries: SURROGATE_HELPER_MAX_CONCURRENT_QUERIES,
  maxUnlockSeconds: MAX_SURROGATE_UNLOCK_SECONDS,
  maxValueBytes: MAX_SURROGATE_VALUE_BYTES,
} as const;

// ---------------------------------------------------------------------------
// Runtime: the binding table, the two listeners, and the decision rules
// ---------------------------------------------------------------------------

/**
 * One row of the helper's in-memory table.
 *
 * `value` is a `Buffer` and not a string so it can be overwritten on drop
 * (design 3.4.5). It is `null` whenever the row is locked, which is the state a
 * freshly started helper is in for every row.
 */
interface HelperTableRow {
  readonly binding: MintedSurrogateBinding;
  value: Buffer | null;
  /** Epoch milliseconds the unlock expires at, or `null` when locked. */
  expiresAt: number | null;
}

/**
 * Overwrite then drop a held value.
 *
 * `Buffer.fill(0)` is the whole of the memory-hygiene claim, and it is a small
 * one: the value also existed as a JSON string in the parsed frame, and JS
 * strings cannot be zeroed. Design 3.4.5 states that residue rather than
 * claiming it away.
 */
function dropRowValue(row: HelperTableRow): void {
  if (row.value !== null) row.value.fill(0);
  row.value = null;
  row.expiresAt = null;
}

/** Injected clock, so the expiry rules are testable without waiting out a TTL. */
export interface SurrogateHelperClock {
  now(): number;
}

/** Injected filesystem seams, so no test touches a real root-owned path. */
export interface SurrogateHelperFsOps {
  mkdir(path: string): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  chown(path: string, uid: number, gid: number): Promise<void>;
  rm(path: string): Promise<void>;
  readFile(path: string): Promise<string>;
}

/** Everything {@link runSurrogateHelperDaemon} needs. Host-free over these seams. */
export interface SurrogateHelperDaemonDeps extends SurrogateHelperDaemonArgs {
  /** Socket and artifact parent dir override (tests). */
  surrogateDir?: string;
  /** Concurrency cap override (tests only; production uses the constant). */
  maxConcurrentQueries?: number;
  /** Event sink. Default: one redacted JSON line per event on stderr. */
  onEvent?: (event: SurrogateHelperEvent) => void;
  clock?: SurrogateHelperClock;
  fsOps?: SurrogateHelperFsOps;
}

/** A running helper. `close()` drops every value before the sockets go away. */
export interface SurrogateHelperDaemonHandle {
  querySocketPath: string;
  unlockSocketPath: string;
  /** Number of bindings loaded from the table. Never grows after start. */
  bindingCount: number;
  close(): Promise<void>;
}

/** Idle-connection reap, same reason and value as `PEER_RESOLVER_IDLE_TIMEOUT_MS`:
 * a connection that never completes a frame must not hold a slot on a root
 * process for longer than a local round trip plus slack. */
export const SURROGATE_HELPER_IDLE_TIMEOUT_MS = 5_000;

function realFsOps(): SurrogateHelperFsOps {
  return {
    async mkdir(path: string): Promise<void> {
      await mkdir(path, { recursive: true, mode: 0o711 }).catch(() => undefined);
    },
    async chmod(path: string, mode: number): Promise<void> {
      await chmod(path, mode);
    },
    async chown(path: string, uid: number, gid: number): Promise<void> {
      await chown(path, uid, gid);
    },
    async rm(path: string): Promise<void> {
      await rm(path, { force: true });
    },
    async readFile(path: string): Promise<string> {
      return readFile(path, "utf8");
    },
  };
}

/**
 * Read ONE newline-terminated frame from a connection and hand it to `onFrame`,
 * then refuse every further byte.
 *
 * This is the shared half of both codecs' transport: identical framing, one
 * frame each way, `unexpected_extra_bytes` on anything after it. What is NOT
 * shared is which parser `onFrame` calls. Each socket passes exactly one, so a
 * query frame on the unlock socket reaches only the unlock parser, which returns
 * `null`, which is `malformed` (design v2.1 finding B2-B2). There is no
 * fall-through to the other parser and no place to add one.
 */
function serveOneShotConnection(
  socket: Socket,
  ctx: {
    onFrame: (line: string) => Buffer;
    onExtraBytes: () => Buffer;
    onOversize: () => Buffer;
    onSocketError: () => void;
  },
): void {
  let buffer = "";
  let answered = false;
  const reply = (frame: Buffer): void => {
    if (answered) return;
    answered = true;
    try {
      socket.end(frame);
    } catch {
      socket.destroy();
    }
  };
  socket.setTimeout(SURROGATE_HELPER_IDLE_TIMEOUT_MS, () => socket.destroy());
  socket.on("error", () => {
    // A client that disconnects mid-frame is ordinary, not an incident: the
    // helper has answered nothing and holds nothing for it. Recorded, never
    // thrown, because an unhandled socket error in a root process is a crash.
    ctx.onSocketError();
  });
  socket.on("data", (chunk: Buffer) => {
    if (answered) {
      // A byte after the first frame. `supervisor/socket-server.ts` answers and
      // closes here rather than ignoring, so a client that pipelined learns its
      // second request was never served.
      reply(ctx.onExtraBytes());
      return;
    }
    buffer += chunk.toString("utf8");
    // The cap is checked on the ACCUMULATED buffer, before any parse, so an
    // endless stream with no newline cannot pin memory on a root process.
    if (Buffer.byteLength(buffer, "utf8") > SURROGATE_WIRE_MAX_FRAME_BYTES) {
      reply(ctx.onOversize());
      return;
    }
    const nl = buffer.indexOf("\n");
    if (nl === -1) return; // bounded by the cap above
    const line = buffer.slice(0, nl);
    const rest = buffer.slice(nl + 1);
    const frame = ctx.onFrame(line);
    reply(frame);
    if (rest.length > 0) {
      // Extra bytes arrived in the SAME chunk as the frame. The reply above
      // already went out for the frame that was legal; nothing further is
      // served on this connection.
      socket.destroy();
    }
  });
}

/**
 * The query socket's handler: the gate asks, the helper decides.
 *
 * DECISION RULES (design 3.4.2), all four required, in this order:
 *  1. the placeholder is in the CURRENT generation's table;
 *  2. `(host, port)` is one of THAT binding's destinations;
 *  3. `location` is `header:<the binding's own bound header, lowercased>`;
 *  4. the binding is unlocked and not expired.
 * The order is deliberate: membership first, so a caller that guessed a
 * placeholder learns `unknown` and not whether some binding happens to be
 * unlocked. The gate never decides membership; it reports only what it parsed.
 */
function answerQuery(
  line: string,
  ctx: {
    agentUid: number;
    table: Map<string, HelperTableRow>;
    clock: SurrogateHelperClock;
    onEvent: (event: SurrogateHelperEvent) => void;
    acquireSlot: () => boolean;
    releaseSlot: () => void;
  },
): Buffer {
  const req = parseSurrogateQueryRequest(line);
  if (req === null) {
    ctx.onEvent({ kind: "query_denied", agentUid: ctx.agentUid, reason: "malformed" });
    // No `id` to echo: the frame did not parse, so there is nothing trustworthy
    // to correlate with. A synthetic id would be indistinguishable from an
    // answer to a real query.
    return encodeSurrogateQueryResponse({
      v: SURROGATE_WIRE_VERSION,
      id: MALFORMED_CORRELATION_ID,
      kind: "deny",
      reason: "malformed",
    });
  }
  const deny = (reason: SurrogateDenyReason, code: SurrogateHelperDenyCode): Buffer => {
    ctx.onEvent({ kind: "query_denied", agentUid: ctx.agentUid, reason: code });
    return encodeSurrogateQueryResponse({
      v: SURROGATE_WIRE_VERSION,
      id: req.id,
      kind: "deny",
      reason,
    });
  };
  // The concurrency cap is taken AFTER the frame parses and BEFORE any table
  // work, and released on every path below, because a `rate_limited` answer must
  // not depend on which decision the query would have reached.
  if (!ctx.acquireSlot()) return deny("rate_limited", "rate_limited");
  try {
    const row = ctx.table.get(req.placeholder);
    if (row === undefined) return deny("unknown", "unknown_placeholder");
    const bound = row.binding.destinations.some(
      (d) => d.host === req.host && d.port === req.port,
    );
    if (!bound) return deny("misroute", "destination_not_bound");
    if (req.location !== surrogateHeaderLocation(row.binding.header)) {
      return deny("wrong_location", "wrong_location");
    }
    if (row.value === null || row.expiresAt === null) return deny("locked", "locked");
    if (ctx.clock.now() >= row.expiresAt) {
      // Expiry is enforced on READ as well as by the timer, so a timer that a
      // suspended host never fired cannot extend a value's life.
      dropRowValue(row);
      return deny("expired", "expired");
    }
    ctx.onEvent({ kind: "query_answered", agentUid: ctx.agentUid, binding: row.binding.ordinal });
    return encodeSurrogateQueryResponse({
      v: SURROGATE_WIRE_VERSION,
      id: req.id,
      kind: "swap",
      value: row.value.toString("utf8"),
    });
  } finally {
    ctx.releaseSlot();
  }
}

/**
 * The unlock socket's handler: the operator loads, drops or inspects.
 *
 * VALIDATION (design 3.4.3): the secret must be in this helper's own table, the
 * generation must be this helper's own, the value must be 1 to
 * `MAX_SURROGATE_VALUE_BYTES` bytes and every byte a legal HTTP field-value
 * byte, and `ttl_seconds` is CLAMPED (the relying side clamps, AGENTS.md rule
 * 10) rather than refused, so a generous operator request becomes a bounded
 * unlock instead of no unlock at all.
 */
function answerUnlockSocket(
  line: string,
  ctx: {
    agentUid: number;
    generation: number;
    table: Map<string, HelperTableRow>;
    clock: SurrogateHelperClock;
    onEvent: (event: SurrogateHelperEvent) => void;
    armExpiryTimer: () => void;
  },
): Buffer {
  const req = parseSurrogateUnlockSocketRequest(line);
  if (req === null) {
    ctx.onEvent({ kind: "unlock_denied", agentUid: ctx.agentUid, reason: "malformed" });
    return encodeSurrogateUnlockSocketResponse({
      v: SURROGATE_WIRE_VERSION,
      id: MALFORMED_CORRELATION_ID,
      kind: "deny",
      reason: "malformed",
    });
  }
  const deny = (
    reason: SurrogateUnlockDenyReason,
    code: SurrogateHelperDenyCode,
  ): Buffer => {
    ctx.onEvent({ kind: "unlock_denied", agentUid: ctx.agentUid, reason: code });
    return encodeSurrogateUnlockSocketResponse({
      v: SURROGATE_WIRE_VERSION,
      id: req.id,
      kind: "deny",
      reason,
    });
  };
  if (req.kind === "status") {
    // A status answer carries NO value and NO placeholder, by construction of
    // `SurrogateStatusBinding`. It is also the operator CLI's "is this agent
    // armed" probe, so it must answer even when every row is locked.
    return encodeSurrogateUnlockSocketResponse({
      v: SURROGATE_WIRE_VERSION,
      id: req.id,
      kind: "status",
      generation_id: ctx.generation,
      bindings: [...ctx.table.values()]
        .sort((a, b) => a.binding.ordinal - b.binding.ordinal)
        .map((row) => {
          const live = row.value !== null && row.expiresAt !== null && ctx.clock.now() < row.expiresAt;
          return {
            secret: row.binding.secret,
            unlocked: live,
            expires_at: live ? row.expiresAt : null,
          };
        }),
    });
  }
  if (req.kind === "lock") {
    let dropped = 0;
    for (const row of ctx.table.values()) {
      if (row.value !== null) dropped += 1;
      dropRowValue(row);
    }
    // Recorded for EVERY lock regardless of which client sent it (design 3.4.4):
    // the unlock socket is confined by filesystem permission only, so the
    // helper's own log is the complete record of what it holds, and the fortress
    // chain records only what went through the CLI.
    ctx.onEvent({ kind: "lock_accepted", agentUid: ctx.agentUid, bindingsDropped: dropped });
    return encodeSurrogateUnlockSocketResponse({
      v: SURROGATE_WIRE_VERSION,
      id: req.id,
      kind: "ok",
    });
  }
  if (req.generation_id !== ctx.generation) return deny("wrong_generation", "generation_mismatch");
  let target: HelperTableRow | undefined;
  for (const row of ctx.table.values()) {
    if (row.binding.secret === req.secret) {
      target = row;
      break;
    }
  }
  if (target === undefined) return deny("unknown_secret", "unknown_secret");
  // VALUE RULES ARE ENFORCED BY THE PARSER, NOT HERE. `parseSurrogateUnlockSocketRequest`
  // refuses a value that is empty, over `MAX_SURROGATE_VALUE_BYTES`, or carries a
  // byte that is not a legal HTTP field value (CR, LF or NUL), so by this line no
  // value that could split a header has ever existed in this process. Re-checking
  // it here would be a second grammar to keep in step with the first, and the
  // weaker of the two would be the one that eventually diverged. The pin is the
  // `one codec per socket` test in
  // `server/test/egress-gate/surrogate-helper-daemon-runtime.test.ts`, which
  // drives those three refusals through the real socket and asserts `malformed`.
  const valueBytes = Buffer.from(req.value, "utf8");
  const ttlSeconds = clampSurrogateUnlockSeconds(req.ttl_seconds);
  if (ttlSeconds === null) {
    valueBytes.fill(0);
    return deny("malformed", "malformed");
  }
  dropRowValue(target);
  target.value = valueBytes;
  target.expiresAt = ctx.clock.now() + ttlSeconds * 1000;
  ctx.armExpiryTimer();
  ctx.onEvent({
    kind: "unlock_accepted",
    agentUid: ctx.agentUid,
    binding: target.binding.ordinal,
    ttlSeconds,
  });
  return encodeSurrogateUnlockSocketResponse({
    v: SURROGATE_WIRE_VERSION,
    id: req.id,
    kind: "ok",
  });
}

/**
 * Clamp a requested TTL to `MAX_SURROGATE_UNLOCK_SECONDS`, or refuse a shape
 * that is not a positive number of seconds at all.
 *
 * Clamping rather than refusing an over-long TTL is AGENTS.md rule 10: the
 * relying side decides the bound. A zero or negative TTL is a different thing
 * from a generous one, so it is refused rather than clamped up to something the
 * caller did not ask for.
 */
export function clampSurrogateUnlockSeconds(requested: number): number | null {
  if (!Number.isFinite(requested) || !Number.isInteger(requested) || requested <= 0) return null;
  return Math.min(requested, MAX_SURROGATE_UNLOCK_SECONDS);
}

/**
 * The correlation id used when there is nothing to echo.
 *
 * All zeroes, which `newSurrogateCorrelationId` cannot produce in practice and
 * which every client compares against its own id and rejects. A `malformed`
 * answer therefore reads as `malformed` on both ends rather than as a reply the
 * client might match to an outstanding query.
 */
export const MALFORMED_CORRELATION_ID = "0".repeat(32);

/**
 * Load the helper's table from `gate-surrogate/<uid>.bindings` and refuse to
 * start on anything it does not like.
 *
 * REFUSALS, all fail-closed (design 3.4.5): a header generation that differs
 * from the argv generation, a body the shared parser rejects, and a table over
 * `MAX_SURROGATE_BINDINGS_PER_AGENT`. The cap is checked here as well as at
 * policy parse and at render because this is the check that runs after a reboot,
 * when the only thing standing between a stale artifact and a root process is
 * this read.
 *
 * A generation mismatch means the artifact and the argv came from different
 * bring-ups. Refusing to start leaves the gate with connect failures, which it
 * denies as 503, rather than a helper serving a generation nobody committed.
 */
export async function loadSurrogateHelperTable(
  args: SurrogateHelperDaemonArgs,
  fsOps: Pick<SurrogateHelperFsOps, "readFile">,
  dir: string = GATE_SURROGATE_DIR,
): Promise<Map<string, HelperTableRow>> {
  const text = await fsOps.readFile(surrogateBindingsPath(args.agentUid, dir));
  const parsed = parseSurrogateBindingsFile(text);
  if (parsed.generationId !== args.generation) {
    throw new SurrogateHelperStartError("generation_mismatch");
  }
  if (parsed.bindings.length > MAX_SURROGATE_BINDINGS_PER_AGENT) {
    throw new SurrogateHelperStartError("too_many_bindings");
  }
  const table = new Map<string, HelperTableRow>();
  for (const binding of parsed.bindings) {
    table.set(binding.placeholder, { binding, value: null, expiresAt: null });
  }
  return table;
}

/** Why the helper refused to start. Fixed classes, never the offending bytes. */
export type SurrogateHelperStartRefusal =
  | "generation_mismatch"
  | "too_many_bindings"
  | "bindings_unreadable";

export class SurrogateHelperStartError extends Error {
  readonly refusal: SurrogateHelperStartRefusal;

  constructor(refusal: SurrogateHelperStartRefusal) {
    super(`surrogate helper refused to start: ${refusal}`);
    this.name = "SurrogateHelperStartError";
    this.refusal = refusal;
  }
}

/**
 * Create one one-shot listener: umask held across `listen()`, then chmod 0600,
 * then chown to the ONE uid entitled to it.
 *
 * `chmod` BEFORE `chown` on purpose, the resolver's order: the window between
 * `bind()` and the final permissions is then never connectable by a principal
 * other than root, not even transiently. The umask makes the socket owner-only
 * from its first byte; the chmod is belt on top, not the boundary.
 */
async function listenOneShot(
  socketPath: string,
  ownerUid: number,
  fsOps: SurrogateHelperFsOps,
  onConnection: (socket: Socket) => void,
  onServerError: () => void,
): Promise<Server> {
  await fsOps.rm(socketPath); // a stale socket from a prior run is EADDRINUSE otherwise
  const server = createServer(onConnection);
  server.on("error", onServerError);
  const priorUmask = process.umask(SURROGATE_HELPER_SOCKET_UMASK);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
  } finally {
    process.umask(priorUmask);
  }
  await fsOps.chmod(socketPath, 0o600);
  await fsOps.chown(socketPath, ownerUid, -1);
  return server;
}

/**
 * Start the helper for ONE agent: load the table, open both sockets, serve.
 *
 * STARTS LOCKED, always. Nothing in this function can put a value in the table;
 * only the unlock socket can, and only after an operator speaks to it. A helper
 * that came back from a crash holding values would be a credential store that
 * survives reboot without anyone deciding it should.
 *
 * SOCKET ORDER: the UNLOCK socket is opened first, then the query socket. The
 * gate must never find a query socket for a helper whose unlock path is not yet
 * reachable, because that is the window in which every query denies `locked`
 * with no way for the operator to fix it.
 */
export async function runSurrogateHelperDaemon(
  deps: SurrogateHelperDaemonDeps,
): Promise<SurrogateHelperDaemonHandle> {
  // The uid rules of design 3.4.5 are enforced by the argv parser, which is the
  // one entry production uses. Re-asserted here because `runSurrogateHelperDaemon`
  // is also reachable from tests and from a future caller, and a helper that
  // guessed its own trust boundary is the failure this whole file exists to
  // prevent.
  parseSurrogateHelperDaemonArgs([
    "--agent-uid",
    String(deps.agentUid),
    "--gate-uid",
    String(deps.gateUid),
    "--operator-uid",
    String(deps.operatorUid),
    "--generation",
    String(deps.generation),
  ]);

  const dir = deps.surrogateDir ?? GATE_SURROGATE_DIR;
  const fsOps = deps.fsOps ?? realFsOps();
  const clock = deps.clock ?? { now: () => Date.now() };
  const maxConcurrent = deps.maxConcurrentQueries ?? SURROGATE_HELPER_MAX_CONCURRENT_QUERIES;
  const onEvent =
    deps.onEvent ??
    ((event: SurrogateHelperEvent): void => {
      // Sink redaction, even though no event variant carries a placeholder
      // field: the sink is the last line of defense and a future variant that
      // did would otherwise leak silently.
      process.stderr.write(
        `[surrogate-helper] ${JSON.stringify(redactSurrogatePlaceholders(event))}\n`,
      );
    });

  let table: Map<string, HelperTableRow>;
  try {
    table = await loadSurrogateHelperTable(deps, fsOps, dir);
  } catch (err) {
    if (err instanceof SurrogateHelperStartError) throw err;
    // The over-cap refusal keeps its own class, because it is the one an
    // operator can act on (the policy has more bindings than an agent may hold)
    // rather than a corrupt or missing file.
    if (err instanceof SurrogateArtifactError && err.refusal === "too_many_bindings") {
      throw new SurrogateHelperStartError("too_many_bindings");
    }
    // Every other cause (ENOENT, EACCES, a parse refusal) is one class: the
    // bindings file is not usable, so this helper must not serve. The cause is
    // NOT carried into the message, because a parse refusal's text is derived
    // from the file and the file names secrets.
    throw new SurrogateHelperStartError("bindings_unreadable");
  }

  await fsOps.mkdir(dir);
  await fsOps.chmod(dir, 0o711).catch(() => undefined);

  let activeQueries = 0;
  const acquireSlot = (): boolean => {
    if (activeQueries >= maxConcurrent) return false;
    activeQueries += 1;
    return true;
  };
  const releaseSlot = (): void => {
    activeQueries -= 1;
  };

  let expiryTimer: NodeJS.Timeout | null = null;
  const sweepExpired = (): void => {
    const now = clock.now();
    for (const row of table.values()) {
      if (row.expiresAt !== null && now >= row.expiresAt) dropRowValue(row);
    }
  };
  const armExpiryTimer = (): void => {
    if (expiryTimer !== null) return;
    expiryTimer = setInterval(sweepExpired, SURROGATE_HELPER_EXPIRY_SWEEP_MS);
    // The sweep must never hold the process open on its own: expiry is also
    // enforced on read, so an unref'd timer that a suspended host skipped costs
    // nothing but a later drop.
    expiryTimer.unref();
  };

  const unlockSocketPath = surrogateUnlockSocketPath(deps.agentUid, dir);
  const querySocketPath = surrogateQuerySocketPath(deps.agentUid, dir);

  const unlockServer = await listenOneShot(
    unlockSocketPath,
    deps.operatorUid,
    fsOps,
    (socket) =>
      serveOneShotConnection(socket, {
        // ONE codec on this socket. A query frame here reaches only
        // `parseSurrogateUnlockSocketRequest`, which returns null, which is
        // `malformed`. There is no fall-through.
        onFrame: (line) =>
          answerUnlockSocket(line, {
            agentUid: deps.agentUid,
            generation: deps.generation,
            table,
            clock,
            onEvent,
            armExpiryTimer,
          }),
        onExtraBytes: () => {
          onEvent({
            kind: "unlock_denied",
            agentUid: deps.agentUid,
            reason: "unexpected_extra_bytes",
          });
          return encodeSurrogateUnlockSocketResponse({
            v: SURROGATE_WIRE_VERSION,
            id: MALFORMED_CORRELATION_ID,
            kind: "deny",
            reason: "malformed",
          });
        },
        onOversize: () => {
          // Refused on the accumulated byte count, BEFORE `JSON.parse`. An
          // unlock frame is the one frame that legally carries a value, so it is
          // also the one an attacker would grow.
          onEvent({ kind: "unlock_denied", agentUid: deps.agentUid, reason: "value_too_large" });
          return encodeSurrogateUnlockSocketResponse({
            v: SURROGATE_WIRE_VERSION,
            id: MALFORMED_CORRELATION_ID,
            kind: "deny",
            reason: "value_too_long",
          });
        },
        onSocketError: () =>
          onEvent({ kind: "unlock_denied", agentUid: deps.agentUid, reason: "socket_error" }),
      }),
    () => onEvent({ kind: "daemon_error", agentUid: deps.agentUid, reason: "socket_error" }),
  );

  const queryServer = await listenOneShot(
    querySocketPath,
    deps.gateUid,
    fsOps,
    (socket) =>
      serveOneShotConnection(socket, {
        // ONE codec on this socket, the mirror of the unlock side: an `unlock`
        // frame here reaches only `parseSurrogateQueryRequest` and is
        // `malformed`, so the gate uid can never load a value.
        onFrame: (line) =>
          answerQuery(line, {
            agentUid: deps.agentUid,
            table,
            clock,
            onEvent,
            acquireSlot,
            releaseSlot,
          }),
        onExtraBytes: () => {
          onEvent({
            kind: "query_denied",
            agentUid: deps.agentUid,
            reason: "unexpected_extra_bytes",
          });
          return encodeSurrogateQueryResponse({
            v: SURROGATE_WIRE_VERSION,
            id: MALFORMED_CORRELATION_ID,
            kind: "deny",
            reason: "malformed",
          });
        },
        onOversize: () => {
          onEvent({ kind: "query_denied", agentUid: deps.agentUid, reason: "malformed" });
          return encodeSurrogateQueryResponse({
            v: SURROGATE_WIRE_VERSION,
            id: MALFORMED_CORRELATION_ID,
            kind: "deny",
            reason: "malformed",
          });
        },
        onSocketError: () =>
          onEvent({ kind: "query_denied", agentUid: deps.agentUid, reason: "socket_error" }),
      }),
    () => onEvent({ kind: "daemon_error", agentUid: deps.agentUid, reason: "socket_error" }),
  );

  onEvent({
    kind: "listening",
    agentUid: deps.agentUid,
    generationId: deps.generation,
    bindings: table.size,
  });

  return {
    querySocketPath,
    unlockSocketPath,
    bindingCount: table.size,
    async close(): Promise<void> {
      // Values go FIRST, before either socket closes: a close that failed
      // halfway must not leave a live query socket over a table that still
      // holds values.
      for (const row of table.values()) dropRowValue(row);
      if (expiryTimer !== null) {
        clearInterval(expiryTimer);
        expiryTimer = null;
      }
      await new Promise<void>((resolve) => queryServer.close(() => resolve()));
      await new Promise<void>((resolve) => unlockServer.close(() => resolve()));
      await fsOps.rm(querySocketPath).catch(() => undefined);
      await fsOps.rm(unlockSocketPath).catch(() => undefined);
    },
  };
}

/**
 * How often the expiry sweep runs.
 *
 * Derivation: `MAX_SURROGATE_UNLOCK_SECONDS` is a day, and expiry is ALSO
 * enforced on every read, so the sweep is only about not holding an expired
 * value in memory longer than necessary. One second is far below any TTL an
 * operator would set and costs one map walk bounded by
 * `MAX_SURROGATE_BINDINGS_PER_AGENT`.
 */
export const SURROGATE_HELPER_EXPIRY_SWEEP_MS = 1_000;

/**
 * The composition root the `castle-wall surrogate-helper-daemon` verb calls.
 *
 * This is the ONE production entry: it parses argv with the validating parser
 * (so every uid refusal of design 3.4.5 applies), then starts the daemon with
 * real filesystem seams. Nothing here supplies a default for a uid or a
 * generation, and nothing here can put a value in the table.
 */
export async function runSurrogateHelperDaemonFromArgv(
  argv: readonly string[],
): Promise<SurrogateHelperDaemonHandle> {
  const args = parseSurrogateHelperDaemonArgs(argv);
  return runSurrogateHelperDaemon(args);
}
