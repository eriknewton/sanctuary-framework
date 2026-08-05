/**
 * The exclusive-egress gate DAEMON (Unified Protect Slice 5 S5-6): the
 * long-lived LaunchDaemon that runs `startExclusiveEgressGate` under the
 * dedicated `sanctuary-gate-<agentId>` service uid, with the S5-3 TCB wiring
 * the design mandates -- fail-closed client auth (generation-bound bearer +
 * peer uid), the root liveness oracle's signed-freshness-token probe
 * (constructed via `createOracleLivenessProbe`; `singleFlightLiveness` is
 * OMITTED, so the gate's construction guard auto-disables single-flight on
 * the coalescing-forbidden oracle probe), and a real `peerRunner` (without
 * one every CONNECT would deny, fail-closed but useless).
 *
 * PEER RUNNER = THE PRIVILEGED RESOLVER CLIENT (2026-07-24 fix, Option 1,
 * `Gate_Peer_Resolution_Fix_Build_Spec_2026-07-24.md`). This daemon is
 * deliberately UNPRIVILEGED (below), so it cannot itself `lsof` a different
 * uid's socket -- the Mini1 2026-07-24 drill proved that shelling `lsof`
 * locally (the pre-fix default) resolves NOTHING cross-uid and denies every
 * real agent connect. The default `peerRunner` is now
 * `createPrivilegedPeerRunner` (`peer-resolver-client.ts`), which dials the
 * ROOT-owned `peer-resolver-daemon.ts` LaunchDaemon over a per-agent-uid-
 * scoped Unix domain socket instead. `deps.peerRunner` remains overridable
 * (tests inject a scripted `PeerCommandRunner` directly, as before).
 *
 * PROCESS SHAPE (design answer 1): one daemon per confined agent, label
 * `ai.sanctuaryprotocol.egress-gate.<agent_uid>`, `UserName` = the gate
 * service account (NEVER root -- root would defeat the S5-0 gate-uid kernel
 * bound; NEVER the agent -- kernel-denied), `KeepAlive` within its
 * bootstrapped session. Lifecycle owned by the provision ops (installed
 * during the exclusive bring-up, torn down in the same rollback / unprotect).
 *
 * REBIND SEMANTICS (S5-2 `resolveGateRestart`): the daemon reads the
 * COMMITTED gate policy (`exclusive-egress-gate.json`, which carries the
 * port + generation published at G4) and binds exactly that port. A bind
 * failure EXITS non-zero: the gate REFUSES to serve rather than squat a
 * different port (posture goes amber via the owner check + oracle; the root
 * owner coordinates a full new generation). After a successful bind the
 * daemon writes a RUNTIME STATE file (`/var/db/sanctuary/gate-runtime/
 * <uid>/state.json`: port, pid, pid start-time, generation) that the root
 * supervisor's owner check and the posture producer read. The per-uid
 * subdir is PRE-CREATED and chowned to the gate uid by the root supervisor
 * (`runtime-fs-plan.ts`, fix-round BLOCKER-1): the non-root gate daemon can
 * write only inside its own subdir, never the root-owned parent.
 *
 * HONESTY BOUNDS: destination + per-action policy at this gate is
 * USERSPACE-enforced; gate compromise = bypass of per-action destination
 * policy, bounded to the gate uid's kernel-constrained endpoint set (S5-0
 * two-principal model), not arbitrary WAN. Liveness is TTL-fresh (oracle
 * token), not instantaneous. The composed fused flow is S5-DRILL-owed;
 * nothing here advances a capability claim.
 */

import { readFile, mkdir, writeFile, rename, rm } from "node:fs/promises";
import { createPublicKey, type KeyObject } from "node:crypto";
import { basename, isAbsolute, join } from "node:path";

import type { AllowlistRule } from "../castle-wall/allowlist/schema.js";
import { validateExclusiveEgressGatePolicy } from "../castle-wall/allowlist/gate-derivation.js";
import {
  startExclusiveEgressGate,
  type ExclusiveEgressGateHandle,
  type EgressGateEvent,
} from "./gate-server.js";
import { createOracleLivenessProbe, createFsLivenessTokenSource, GATE_LIVENESS_DIR } from "./liveness-oracle.js";
import { createGateClientAuthenticator, type GateClientAuthenticator } from "./gate-client-auth.js";
import { createFsGateAcceptSource, GATE_CRED_DIR } from "./gate-credential.js";
import type { PeerCommandRunner } from "./peer-identity.js";
import { createPrivilegedPeerRunner } from "./peer-resolver-client.js";
import { PEER_RESOLVER_DIR, peerResolverSocketPath } from "./peer-resolver-daemon.js";

/**
 * Root-owned runtime dir (0755 root, EXPLICIT chmod via `runtime-fs-plan.ts`).
 * Root writes the world-readable per-uid CONFIG copies directly in it; each
 * agent's gate daemon writes its runtime STATE inside its own pre-chowned
 * per-uid subdir ({@link egressGateRuntimeUidDirPath}).
 */
export const EGRESS_GATE_RUNTIME_DIR = "/var/db/sanctuary/gate-runtime";

/**
 * Gate-readable CONFIG copies (root-written at G4). The fortress is
 * operator-owned 0700, so the NON-ROOT gate uid cannot (and must not) read
 * it; the root supervisor publishes exactly the two documents the gate
 * needs -- the committed gate policy (+ generation) and the destination
 * rules -- into the root-owned runtime dir as 0644 files. Nothing secret is
 * in either (ports, uids, endpoint hosts); the bearer credential and oracle
 * token stay in their own 0600 owner-bound files.
 */
export function egressGatePolicyConfigPath(agentUid: number, dir: string = EGRESS_GATE_RUNTIME_DIR): string {
  return join(dir, `${agentUid}-policy.json`);
}

/** Gate-readable destination-rules copy path (see {@link egressGatePolicyConfigPath}). */
export function egressGateRulesConfigPath(agentUid: number, dir: string = EGRESS_GATE_RUNTIME_DIR): string {
  return join(dir, `${agentUid}-rules.json`);
}

/** The supervisor oracle PUBLIC key the gate pins (written by the root supervisor). */
export const GATE_ORACLE_PUBLIC_KEY_PATH = `${GATE_LIVENESS_DIR}/supervisor-oracle-pub.pem`;

/** Label prefix; one daemon per confined agent uid. */
export const EGRESS_GATE_DAEMON_LABEL_PREFIX = "ai.sanctuaryprotocol.egress-gate";

/** The per-agent gate daemon label. */
export function egressGateDaemonLabel(agentUid: number): string {
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new Error(`egress-gate daemon label requires a positive integer uid (got ${String(agentUid)})`);
  }
  return `${EGRESS_GATE_DAEMON_LABEL_PREFIX}.${agentUid}`;
}

/** The per-agent gate daemon plist path. */
export function egressGateDaemonPlistPath(agentUid: number): string {
  return `/Library/LaunchDaemons/${egressGateDaemonLabel(agentUid)}.plist`;
}

/**
 * The per-uid runtime-state SUBDIR: owned by the GATE uid (root pre-creates +
 * chowns it at arming time, `runtime-fs-plan.ts`), 0755 so root and the
 * posture producer can read the state file the gate publishes inside it.
 */
export function egressGateRuntimeUidDirPath(agentUid: number, dir: string = EGRESS_GATE_RUNTIME_DIR): string {
  if (!Number.isInteger(agentUid) || agentUid <= 0) {
    throw new Error(`gate runtime-state path requires a positive integer uid (got ${String(agentUid)})`);
  }
  return join(dir, String(agentUid));
}

/** Runtime-state file path for one agent's gate (inside the gate-owned per-uid subdir). */
export function egressGateRuntimeStatePath(agentUid: number, dir: string = EGRESS_GATE_RUNTIME_DIR): string {
  return join(egressGateRuntimeUidDirPath(agentUid, dir), "state.json");
}

/** The gate daemon's published runtime state (root supervisor + posture read it). */
export interface EgressGateRuntimeState {
  agent_uid: number;
  gate_port: number;
  generation_id: number;
  pid: number;
  /** Best-effort process start token (`<pid>-<startEpochMs>`), for pid-reuse defense. */
  pid_start: string;
}

/** Strict parse of a runtime-state document. Throws on any deviation (fail-closed). */
export function parseEgressGateRuntimeState(text: string, path: string): EgressGateRuntimeState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`gate runtime state at ${path} is not valid JSON: ${(err as Error).message}`, { cause: err });
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`gate runtime state at ${path} is not a JSON object`);
  }
  const r = parsed as Record<string, unknown>;
  const int = (field: string, min: number, max = Number.MAX_SAFE_INTEGER): number => {
    const v = r[field];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) {
      throw new Error(`gate runtime state at ${path}: ${field} missing/invalid`);
    }
    return v;
  };
  const pidStart = r.pid_start;
  if (typeof pidStart !== "string" || pidStart.length === 0) {
    throw new Error(`gate runtime state at ${path}: pid_start missing/invalid`);
  }
  return {
    agent_uid: int("agent_uid", 1),
    gate_port: int("gate_port", 1, 65535),
    generation_id: int("generation_id", 1),
    pid: int("pid", 1),
    pid_start: pidStart,
  };
}

/**
 * POSIX-ish service-account name: lowercase start, then a conservative
 * charset, so nothing that could smuggle plist markup or spaces reaches the
 * rendered LaunchDaemon.
 *
 * Must match `SAFE_SERVICE_ACCOUNT_RE` in
 * `castle-wall/provision/account.ts` (the canonical declaration) and
 * `SAFE_ACCOUNT_RE` in `egress-gate/harness-daemon.ts`. Re-declared rather
 * than imported to keep this plist renderer free of a castle-wall dependency.
 * Enforced by `server/test/structure/cross-file-contract-pins.test.ts`.
 *
 * The reserved-name check further down is NOT a mirror: account.ts
 * additionally reserves `admin`.
 */
const SAFE_ACCOUNT_RE = /^[a-z_][a-z0-9._-]{0,63}$/;
const GATE_DAEMON_LOG_DIR_NAME = "logs";

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function assertNoControlChars(value: string, what: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(value)) {
    throw new Error(`${what} contains control characters; refusing to render plist.`);
  }
}

/** Options for {@link renderEgressGateDaemonPlist}. */
export interface EgressGateDaemonPlistOptions {
  /** The confined agent uid this gate serves (names the label). */
  agentUid: number;
  /** The dedicated gate service account (NEVER root, NEVER the agent account). */
  gateAccount: string;
  /** The dedicated gate service account's home directory. The renderer derives logs from this. */
  gateHomeDirectory: string;
  /** Full argv of the gate daemon entrypoint (absolute program path first). */
  programArguments: string[];
  /** Absolute fortress path, rendered as SANCTUARY_STORAGE_PATH. */
  fortressPath: string;
}

/**
 * Derive the gate daemon log directory from the gate account's own home.
 *
 * This intentionally does NOT accept an arbitrary log path. The LaunchDaemon
 * runs as `gateAccount`, so stdout/stderr must live under that account's own
 * home; a caller trying to point it at the agent account's 0700 log directory
 * is refused during plist construction rather than becoming launchd
 * `EX_CONFIG` on hardware.
 */
export function gateDaemonLogDirForHome(input: {
  gateAccount: string;
  gateHomeDirectory: string;
}): string {
  if (!SAFE_ACCOUNT_RE.test(input.gateAccount)) {
    throw new Error(`gate account name is not a safe service-account name (got ${JSON.stringify(input.gateAccount)})`);
  }
  if (!isAbsolute(input.gateHomeDirectory)) {
    throw new Error(`gate home directory must be absolute (got ${input.gateHomeDirectory})`);
  }
  assertNoControlChars(input.gateHomeDirectory, "gate home directory");
  if (basename(input.gateHomeDirectory) !== input.gateAccount) {
    throw new Error(
      `gate home directory ${input.gateHomeDirectory} does not belong to gate account ${input.gateAccount}; ` +
        "refusing to render a gate daemon with cross-account logs",
    );
  }
  return join(input.gateHomeDirectory, GATE_DAEMON_LOG_DIR_NAME);
}

/** The exact stdout/stderr files launchd opens for one gate daemon. */
export function egressGateDaemonLogPaths(input: {
  agentUid: number;
  gateAccount: string;
  gateHomeDirectory: string;
}): { stdoutPath: string; stderrPath: string } {
  if (!Number.isInteger(input.agentUid) || input.agentUid <= 0) {
    throw new Error(`egress-gate log paths require a positive integer uid (got ${String(input.agentUid)})`);
  }
  const logDir = gateDaemonLogDirForHome({
    gateAccount: input.gateAccount,
    gateHomeDirectory: input.gateHomeDirectory,
  });
  return {
    stdoutPath: join(logDir, `egress-gate-${input.agentUid}.out.log`),
    stderrPath: join(logDir, `egress-gate-${input.agentUid}.err.log`),
  };
}

/**
 * Render the gate daemon plist. `RunAtLoad=false` + `KeepAlive={Crashed:true}`
 * deliberately: the ROOT SUPERVISOR sequences gate start inside the exclusive
 * bring-up (owner-checked, generation-bound); an auto-started gate at boot
 * before the pf anchor re-arm would just refuse (oracle token absent), but
 * not starting it at load keeps the boot ordering single-owner (the boot
 * daemon bootstraps it during the release sequence).
 */
export function renderEgressGateDaemonPlist(options: EgressGateDaemonPlistOptions): string {
  const label = egressGateDaemonLabel(options.agentUid);
  if (!SAFE_ACCOUNT_RE.test(options.gateAccount)) {
    throw new Error(`gate account name is not a safe service-account name (got ${JSON.stringify(options.gateAccount)})`);
  }
  if (["root", "_root", "daemon", "wheel"].includes(options.gateAccount)) {
    throw new Error(`refusing to render an egress-gate daemon running as "${options.gateAccount}" (the gate is TCB but must never hold root)`);
  }
  if (options.programArguments.length === 0 || !isAbsolute(options.programArguments[0]!)) {
    throw new Error("gate daemon programArguments must be non-empty with an absolute program path first");
  }
  for (const arg of options.programArguments) {
    assertNoControlChars(arg, "gate daemon program argument");
  }
  if (!isAbsolute(options.fortressPath)) {
    throw new Error(`fortress path must be absolute (got ${options.fortressPath})`);
  }
  assertNoControlChars(options.fortressPath, "fortress path");
  const { stdoutPath, stderrPath } = egressGateDaemonLogPaths(options);
  const argsXml = options.programArguments
    .map((a) => `\t\t<string>${xmlEscape(a)}</string>`)
    .join("\n");
  const logXml =
    `\t<key>StandardOutPath</key>\n\t<string>${xmlEscape(stdoutPath)}</string>\n` +
    `\t<key>StandardErrorPath</key>\n\t<string>${xmlEscape(stderrPath)}</string>\n`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>Label</key>
\t<string>${xmlEscape(label)}</string>
\t<key>UserName</key>
\t<string>${xmlEscape(options.gateAccount)}</string>
\t<key>ProgramArguments</key>
\t<array>
${argsXml}
\t</array>
\t<key>EnvironmentVariables</key>
\t<dict>
\t\t<key>SANCTUARY_STORAGE_PATH</key>
\t\t<string>${xmlEscape(options.fortressPath)}</string>
\t</dict>
${logXml}\t<key>RunAtLoad</key>
\t<false/>
\t<key>KeepAlive</key>
\t<dict>
\t\t<key>Crashed</key>
\t\t<true/>
\t</dict>
</dict>
</plist>
`;
}

/**
 * Resolve the argv prefix that launches the exclusive-egress gate daemon.
 *
 * The gate daemon runs as the confined gate service account, whose launchd
 * PATH has no `node`. Both a supplied `--binary` path and the fallback CLI
 * path are `.js` entrypoints carrying a `#!/usr/bin/env node` shebang, which
 * fails with `env: node: No such file or directory` under that account and
 * crashes the daemon at startup (the "D9" gate-daemon crash proven on
 * hardware 2026-07-21, fixed by #986). Pinning `process.execPath` (an absolute
 * interpreter) makes the launch independent of the account's PATH.
 *
 * SINGLE CHOKEPOINT for all THREE gate-daemon plist producers -- install +
 * repair (`wrap/auto-provision.ts`, which re-exports this) AND the boot
 * self-heal (`arming-wiring.ts` `startExclusiveEgressBootSupervisor`) -- so no
 * call site can ever emit a bare shebang-dependent argv[0]: every producer
 * prepends `process.execPath`, which Node guarantees absolute. Note this makes
 * argv[0] ABSOLUTE at every site; it does NOT make the resolved prefix
 * IDENTICAL across sites -- install passes the persisted `--binary`, boot
 * passes nothing and re-derives from live `process.argv` -- see the callers.
 * At boot `process.execPath` is the boot daemon's own absolute node, so the
 * healed prefix is correct + account-PATH-independent there too.
 *
 * PACKAGING ASSUMPTION (accepted, latent -- PR #994 review LOW-3): the fallback
 * branch `[process.execPath, process.argv[1] ?? "sanctuary"]` is correct only
 * for a NODE-SHEBANG-SCRIPT distribution, where `process.argv[1]` at boot
 * re-materialises the CLI script path. A future single-executable (SEA/pkg)
 * build would make `process.execPath` the binary and `process.argv[1]` the
 * subcommand token, yielding a corrupt argv -- but that packaging would ALSO
 * break the install path today, so it is latent, not live; and the `?? "sanctuary"`
 * relative fallback is itself fail-closed (a relative argv[0] the renderer
 * rejects, or a relative script that crashes the gate -> the barrier parks).
 */
export function resolveGateDaemonArgvPrefix(cliBinary?: string): string[] {
  return cliBinary !== undefined && cliBinary.length > 0
    ? [process.execPath, cliBinary]
    : [process.execPath, process.argv[1] ?? "sanctuary"];
}

/** The fixed gate-daemon subcommand argv suffix (after the interpreter prefix). */
function gateDaemonProgramSuffix(agentUid: number): string[] {
  return ["castle-wall", "egress-gate-daemon", `--agent-uid=${agentUid}`];
}

/**
 * Build one agent's gate-daemon plist: the destination path plus the rendered
 * plist CONTENT, from the SAME inputs the install path uses.
 *
 * ONE builder for BOTH the install bring-up (`arming-wiring.ts`
 * `productionBringUp`) and the boot self-heal (`startExclusiveEgressBootSupervisor`),
 * so the two can never drift on the SUBCOMMAND SUFFIX
 * ({@link gateDaemonProgramSuffix}) or the plist RENDER. It does NOT unify the
 * interpreter PREFIX: that is resolved independently per site by
 * {@link resolveGateDaemonArgvPrefix} (install: the persisted `--binary`; boot:
 * live `process.execPath`), by design -- at boot the prefix self-corrects to
 * the boot daemon's own absolute node (the #986 property). What IS guaranteed
 * everywhere: {@link renderEgressGateDaemonPlist} throws unless
 * `programArguments[0]` is absolute -- the fail-closed backstop that keeps a
 * bare-`node`/`env node` argv off disk.
 */
export function buildGateDaemonPlistContent(input: {
  agentUid: number;
  gateAccount: string;
  gateHomeDirectory: string;
  gateDaemonArgvPrefix: string[];
  fortressPath: string;
}): { plistPath: string; plistContent: string } {
  return {
    plistPath: egressGateDaemonPlistPath(input.agentUid),
    plistContent: renderEgressGateDaemonPlist({
      agentUid: input.agentUid,
      gateAccount: input.gateAccount,
      gateHomeDirectory: input.gateHomeDirectory,
      programArguments: [...input.gateDaemonArgvPrefix, ...gateDaemonProgramSuffix(input.agentUid)],
      fortressPath: input.fortressPath,
    }),
  };
}

/** Injected dependencies for {@link runEgressGateDaemon} (tests are host-free). */
export interface EgressGateDaemonDeps {
  /** The confined agent uid this daemon serves. */
  agentUid: number;
  /** Load the committed gate policy JSON text (default: the gate-readable runtime copy). */
  loadGatePolicy?: () => Promise<string>;
  /** Load the destination allow rules the gate enforces (default: the gate-readable runtime copy). */
  loadRules?: () => Promise<AllowlistRule[]>;
  /** Load the pinned supervisor-oracle PUBLIC key (default: PEM at {@link GATE_ORACLE_PUBLIC_KEY_PATH}). */
  loadOraclePublicKey?: () => Promise<KeyObject>;
  /** The client authenticator (default: FS accept-record authority). */
  clientAuth?: GateClientAuthenticator;
  /** Runtime-state dir override (tests). */
  runtimeDir?: string;
  /** Liveness token dir override (tests). */
  livenessDir?: string;
  /** Credential accept-record dir override (tests). */
  credDir?: string;
  /**
   * Peer-resolution runner (default: {@link createPrivilegedPeerRunner}
   * pointed at this agent's peer-resolver daemon socket -- the 2026-07-24
   * fix, see the module header). Tests inject a scripted `PeerCommandRunner`
   * directly, same as before this fix.
   */
  peerRunner?: PeerCommandRunner;
  /** Peer-resolver socket parent-dir override (tests; default {@link PEER_RESOLVER_DIR}). */
  peerResolverDir?: string;
  /** Event sink (default: stderr lines; production also ships the unified log). */
  onEvent?: (event: EgressGateEvent) => void;
}

/** A running gate daemon handle (the CLI verb holds it until SIGTERM). */
export interface EgressGateDaemonHandle {
  gate: ExclusiveEgressGateHandle;
  generationId: number;
  runtimeStatePath: string;
  close(): Promise<void>;
}

/**
 * Start the gate for the COMMITTED generation: load + validate the gate
 * policy (port + generation, published at G4), load the destination rules,
 * pin the oracle public key, construct the fail-closed client authenticator
 * and the oracle liveness probe (binding = {agent_uid, gate_port} from the
 * policy, generation from the policy file -- so a stale token for another
 * generation reads not-live), start the gate on EXACTLY the committed port
 * (a bind failure throws; the caller exits non-zero, never squats another
 * port), then publish the runtime state file. `singleFlightLiveness` is
 * OMITTED by contract (the oracle probe self-declares coalescing:"forbidden";
 * the gate constructor auto-disables single-flight).
 */
export async function runEgressGateDaemon(deps: EgressGateDaemonDeps): Promise<EgressGateDaemonHandle> {
  const configDir = deps.runtimeDir ?? EGRESS_GATE_RUNTIME_DIR;
  const loadPolicy =
    deps.loadGatePolicy ??
    (async (): Promise<string> => readFile(egressGatePolicyConfigPath(deps.agentUid, configDir), "utf8"));
  const policyText = await loadPolicy();
  let parsedPolicy: unknown;
  try {
    parsedPolicy = JSON.parse(policyText);
  } catch (err) {
    throw new Error(`egress-gate daemon: gate policy is not valid JSON: ${(err as Error).message}`, { cause: err });
  }
  const policy = validateExclusiveEgressGatePolicy(parsedPolicy);
  if (policy === null) {
    throw new Error("egress-gate daemon: gate policy is structurally invalid; refusing to serve");
  }
  if (policy.agent_uid !== deps.agentUid) {
    throw new Error(
      `egress-gate daemon: gate policy names agent_uid ${policy.agent_uid} but this daemon serves uid ${deps.agentUid}; refusing (cross-principal)`,
    );
  }
  // The published policy carries the committed generation (G4). Absent =
  // legacy/uncommitted policy: refuse (the oracle token is generation-bound;
  // an unbound gate could never verify liveness anyway).
  const generationId = (parsedPolicy as { generation_id?: unknown }).generation_id;
  if (typeof generationId !== "number" || !Number.isSafeInteger(generationId) || generationId <= 0) {
    throw new Error("egress-gate daemon: gate policy carries no committed generation_id; refusing to serve");
  }

  const loadRules =
    deps.loadRules ??
    (async (): Promise<AllowlistRule[]> => {
      const text = await readFile(egressGateRulesConfigPath(deps.agentUid, configDir), "utf8");
      const parsed = JSON.parse(text) as unknown;
      if (!Array.isArray(parsed)) {
        throw new Error("egress-gate daemon: rules config is not a JSON array; refusing to serve");
      }
      return parsed as AllowlistRule[];
    });
  const rules = await loadRules();

  const loadOraclePub =
    deps.loadOraclePublicKey ??
    (async (): Promise<KeyObject> => {
      const pem = await readFile(GATE_ORACLE_PUBLIC_KEY_PATH, "utf8");
      return createPublicKey(pem);
    });
  const oraclePublicKey = await loadOraclePub();

  // Fail-closed client auth (S5-3): the accept record is generation-bound on
  // disk (the root supervisor rotates it at each G5), so the authenticator
  // reads the CURRENT accept-state per CONNECT; a stale-generation credential
  // denies without a gate restart.
  const clientAuth =
    deps.clientAuth ??
    createGateClientAuthenticator({
      agentUid: policy.agent_uid,
      acceptSource: createFsGateAcceptSource(deps.credDir ?? GATE_CRED_DIR),
    });

  const livenessProbe = createOracleLivenessProbe({
    source: createFsLivenessTokenSource(deps.livenessDir ?? GATE_LIVENESS_DIR),
    publicKey: oraclePublicKey,
    binding: { agentUid: policy.agent_uid, gatePort: policy.gate_port, generationId },
  });

  const onEvent =
    deps.onEvent ??
    ((event: EgressGateEvent): void => {
      process.stderr.write(`[egress-gate] ${JSON.stringify(event)}\n`);
    });

  // 2026-07-24 fix (Option 1): the default peer runner dials the PRIVILEGED
  // root resolver instead of shelling `lsof` as this (unprivileged) daemon's
  // own uid -- see the module header. `peerResolverDir` lets tests point at a
  // temp socket dir without touching `/var/db/sanctuary`.
  const peerRunner =
    deps.peerRunner ??
    createPrivilegedPeerRunner({
      agentUid: deps.agentUid,
      // gatePort is THIS daemon's own loaded+validated policy port (fix-round
      // BLOCKER) -- never anything the resolver daemon's answer carries.
      gatePort: policy.gate_port,
      socketPath: peerResolverSocketPath(deps.agentUid, deps.peerResolverDir ?? PEER_RESOLVER_DIR),
    });

  // The S5-6 wiring contract: oracle probe + peerRunner + clientAuth, and
  // singleFlightLiveness OMITTED (the construction guard auto-disables it for
  // the coalescing-forbidden oracle probe).
  const gate = await startExclusiveEgressGate({
    policy,
    rules,
    livenessProbe,
    peerRunner,
    clientAuth,
    onEvent,
  });

  const runtimeDir = deps.runtimeDir ?? EGRESS_GATE_RUNTIME_DIR;
  const runtimeStatePath = egressGateRuntimeStatePath(deps.agentUid, runtimeDir);
  const state: EgressGateRuntimeState = {
    agent_uid: policy.agent_uid,
    gate_port: gate.port,
    generation_id: generationId,
    pid: process.pid,
    pid_start: `${process.pid}-${Math.round(Date.now() - process.uptime() * 1000)}`,
  };
  // The per-uid subdir is root-pre-created and chowned to THIS gate uid at
  // arming time (`runtime-fs-plan.ts`). The mkdir here only serves dir-
  // override tests / self-healing when the subdir already belongs to us; a
  // failure to have a writable dir surfaces LOUDLY below (the daemon exits
  // non-zero rather than serving without a readable runtime state).
  const uidDir = egressGateRuntimeUidDirPath(deps.agentUid, runtimeDir);
  try {
    await mkdir(uidDir, { recursive: true });
  } catch (err) {
    throw new Error(
      `egress-gate daemon: runtime dir ${uidDir} is missing and could not be created ` +
        `(${(err as Error).message}); the root supervisor pre-provisions it at arming time -- refusing to serve`,
      { cause: err },
    );
  }
  const tmp = `${runtimeStatePath}.tmp-${process.pid}`;
  await writeFile(tmp, JSON.stringify(state), { mode: 0o644 });
  await rename(tmp, runtimeStatePath);

  return {
    gate,
    generationId,
    runtimeStatePath,
    async close(): Promise<void> {
      await gate.close();
      await rm(runtimeStatePath, { force: true }).catch(() => undefined);
    },
  };
}
