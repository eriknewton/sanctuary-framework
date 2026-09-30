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
 * SLICE BOUND. Slice 1a builds the process surface below: the launchd identity,
 * both socket paths, the plist, and the argv contract with its refusals. The two
 * listeners and the decision loop land with the rest of design 3.4.2 and 3.4.3.
 * Nothing in the gate calls this yet; the gate-side client is slice 1b.
 */

import { isAbsolute, join } from "node:path";

import {
  MAX_SURROGATE_BINDINGS_PER_AGENT,
  MAX_SURROGATE_UNLOCK_SECONDS,
  MAX_SURROGATE_VALUE_BYTES,
  SURROGATE_HELPER_MAX_CONCURRENT_QUERIES,
} from "../credential-surrogate/constants.js";

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
  | "destination_not_bound"
  | "wrong_location"
  | "locked"
  | "expired"
  | "generation_mismatch"
  | "value_too_large"
  | "illegal_value_bytes"
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
