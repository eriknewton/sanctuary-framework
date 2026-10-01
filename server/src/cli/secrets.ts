/**
 * Sanctuary MCP Server — `sanctuary secrets` CLI subcommand
 *
 * Administrative surface for the Secret Broker: add/list/rotate/delete
 * stored credentials, grant/revoke per-skill scope, and query the
 * broker-scoped audit log.
 *
 * Value input for `add` and `rotate` (in priority order):
 *   1. If a value is passed as a second positional argument, use it
 *      directly. This is the path operators naturally reach for;
 *      emits a stderr warning because the value is briefly visible in
 *      `ps aux` during invocation.
 *   2. Else if stdin is NOT a TTY, read one line from stdin. Supports
 *      `echo "..." | sanctuary secrets add X` and shell-scripted
 *      lifecycles. A 30-second read deadline prevents indefinite hangs
 *      when stdin is piped from nothing (the v0.10.0-rc.1 soak mode —
 *      operator passed value via argv, got silently dropped, CLI hung
 *      15 minutes on an open but empty stdin).
 *   3. Else (TTY), prompt silently with echo suppressed.
 *
 * The grant/revoke commands edit ~/.sanctuary/broker-policy.json so the
 * next broker startup picks up the change. Running brokers can call
 * `reloadPolicy()` explicitly (exposed via MCP tool).
 *
 * This module does NOT parse `--fortress`. The fortress comes from
 * `SecretsArgs.storagePath`, or failing that from `loadConfig()` inside
 * `openBroker`, which reads `SANCTUARY_STORAGE_PATH`. `cli.ts` promotes a
 * LEADING `--fortress <path>` into that environment variable before dispatch,
 * so `sanctuary --fortress <path> secrets ...` works. A `--fortress` typed
 * after the word `secrets` reaches this file as an ordinary argv token and is
 * dropped, which is why `assertNoFortressFlag` below refuses it rather than
 * letting it through. See that function for the reproduction.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { dirname } from "node:path";
import { connect } from "node:net";
import { createInterface } from "node:readline";
import type { Backend, SecretScope } from "../disclosure/broker/backend-interface.js";
import {
  openBroker,
  openSurrogateStore,
  loadBrokerPolicyRaw,
  loadSurrogatePolicyDocument,
  saveBrokerPolicy,
  saveSurrogatePolicy,
} from "../disclosure/broker/open.js";
import {
  SURROGATE_POLICY_VERSION,
  parseSurrogatePolicyDocument,
  surrogateBoundSecretNames,
  type SurrogatePolicyDocument,
} from "../disclosure/broker/policy.js";
import { BROKER_OPS } from "../operational/audit-log.js";
import { SURROGATE_BOUND_PORT } from "../credential-surrogate/binding.js";
import { MAX_SURROGATE_UNLOCK_SECONDS, SURROGATE_WIRE_MAX_FRAME_BYTES } from "../credential-surrogate/constants.js";
import { redactSurrogatePlaceholdersInString } from "../credential-surrogate/redaction.js";
import {
  encodeSurrogateUnlockSocketRequest,
  parseSurrogateUnlockSocketResponse,
  type SurrogateUnlockSocketRequest,
  type SurrogateUnlockSocketResponse,
} from "../credential-surrogate/unlock-codec.js";
import { SURROGATE_WIRE_VERSION, newSurrogateCorrelationId } from "../credential-surrogate/wire.js";
import { deriveGateAccountName } from "../egress-gate/gate-account.js";
import { egressGateDaemonLogPaths } from "../egress-gate/gate-daemon.js";
import {
  SURROGATE_HELPER_DAEMON_LABEL_PREFIX,
  surrogateHelperDaemonPlistPath,
  surrogateUnlockSocketPath,
} from "../egress-gate/surrogate-helper-daemon.js";
import { flagValue } from "./argv.js";
import { promptHiddenLine, type RawModeStdin } from "./hidden-prompt.js";

export interface SecretsArgs {
  argv: string[];
  /** Output stream (stdout in prod; captured in tests). */
  out?: NodeJS.WritableStream;
  /** Error stream (stderr in prod; captured in tests). */
  err?: NodeJS.WritableStream;
  /** Pre-resolved passphrase (tests; usually comes from env). */
  passphrase?: string;
  /** Override storage path. */
  storagePath?: string;
  /** Stdin source for value reads (tests). */
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  /**
   * Unlock-socket transport (tests). Production builds the real one per call.
   * Injected rather than reached for so no `secrets surrogate` test ever needs
   * a root helper, a real socket under `/var/db/sanctuary`, or the operator's
   * keychain (AGENTS.md "Test isolation").
   */
  surrogateUnlock?: SurrogateUnlockTransport;
  /**
   * The arming twin's installed state as the operator can see it (tests).
   * Production reads the directory service and the helper's artifact paths;
   * a test injects both so no `dscl` runs and no path under `/Library` or
   * `/var/db/sanctuary` is touched.
   */
  surrogateArming?: SurrogateArmingView;
  /** Re-exec and core-limit seam for `surrogate unlock` (tests). */
  surrogateNoCore?: SurrogateNoCoreOps;
  /** Effective uid for the root-only `surrogate events` check (tests). */
  effectiveUid?: number;
  /** Gate log path for `surrogate events` (tests; the real path needs root). */
  gateLogPathOverride?: string;
  /**
   * Keychain backend for the surrogate label (tests). Threaded to
   * `openSurrogateStore` so a CLI test reaches the real verb body with an
   * in-memory store and never runs a `security` subprocess.
   */
  surrogateBackend?: Backend;
  /**
   * Keychain backend for the BROKER label (tests). Same reason as
   * `surrogateBackend`: `secrets revoke` on a bound name runs the surrogate
   * refusal and then the ordinary broker path, and a host-free test has to
   * reach both halves.
   */
  brokerBackend?: Backend;
}

export interface SecretsGrantFlags {
  scope: SecretScope;
  ttl?: number;
  error?: string;
}

export interface SecretsAuditFlags {
  since?: string;
  limit: number;
}

export async function runSecretsCommand(args: SecretsArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin = args.stdin ?? process.stdin;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
  }

  // ENFORCEMENT SITE for "this command never writes a credential into a
  // fortress the operator did not name": nothing below this line reads
  // `--fortress`, so the flag must be refused here or it is silently dropped.
  // Placed before the dispatch switch so it covers every verb, including the
  // three that write (`add`, `rotate`, `delete`).
  const fortressRefusal = assertNoFortressFlag(rest);
  if (fortressRefusal !== undefined) {
    err.write(fortressRefusal);
    // 2 is this command's usage-error code, matching the unknown-subcommand
    // arm of the switch below. 1 is reserved for an operation that ran and
    // failed; nothing ran here.
    return 2;
  }

  try {
    switch (sub) {
      case "add":
        return await cmdAdd(rest, { out, err, stdin, args });
      case "list":
        return await cmdList({ out, args });
      case "rotate":
        return await cmdRotate(rest, { out, err, stdin, args });
      case "delete":
        return await cmdDelete(rest, { out, err, args });
      case "grant":
        return await cmdGrant(rest, { out, err, args });
      case "revoke":
        return await cmdRevoke(rest, { out, err, args });
      case "audit":
        return await cmdAudit(rest, { out, err, args });
      case "surrogate":
        return await cmdSurrogate(rest, { out, err, stdin, args });
      default:
        err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary secrets: ${msg}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary secrets <command> [args]

  add <name> [value]                 Store a new secret. Value sources, in order:
                                       1. 2nd positional arg (shown here) — convenient
                                          but briefly visible in \`ps aux\`.
                                       2. Piped stdin: \`echo "..." | sanctuary
                                          secrets add NAME\` — not visible in \`ps\`.
                                       3. TTY prompt (echo suppressed) when neither
                                          positional nor pipe is supplied.
  list                               List stored secret names.
  rotate <name> [value]              Replace the value of a stored secret (same
                                     value-source precedence as \`add\`).
  delete <name>                      Remove a secret.
  grant <skill> <secret> [flags]     Authorize a skill to request this secret.
    --scope <read|rotate>            Grant scope (default: read).
    --ttl <seconds>                  Token TTL cap (default: 900).
  revoke <skill> <secret>            Revoke a skill's access to a secret.
  audit [--since <iso>] [--limit N]  Show the broker-scoped audit trail.
  surrogate <command> [args]         Bind a secret to a destination so the agent
                                     is issued a placeholder and never the value.
                                     Run \`sanctuary secrets surrogate\` for its
                                     own command list.

See also: \`sanctuary broker-server\` — run the Secret Broker as a separate
MCP server so skills can request scoped ephemeral tokens over stdio.
`);
}

// ── add ─────────────────────────────────────────────────────────────

async function cmdAdd(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; stdin: NodeJS.ReadableStream & { isTTY?: boolean }; args: SecretsArgs }
): Promise<number> {
  const name = requirePositional(argv, 0, "add <name> [value]");
  const argvValue = optionalPositional(argv, 1);
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
  });
  try {
    const value = await resolveValue(argvValue, ctx.stdin, ctx.err, `Enter value for "${name}"`);
    if (!value) {
      ctx.err.write("Aborted: empty value\n");
      return 1;
    }
    await broker.addSecret(name, value);
    ctx.out.write(`Stored secret: ${name}\n`);
    return 0;
  } finally {
    await close();
  }
}

// ── list ────────────────────────────────────────────────────────────

async function cmdList(ctx: {
  out: NodeJS.WritableStream;
  args: SecretsArgs;
}): Promise<number> {
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
  });
  try {
    const names = await broker.listSecretNames();
    const grants = broker.getGrants();
    const grantsBySecret = new Map<string, string[]>();
    for (const g of grants) {
      if (!grantsBySecret.has(g.secret)) grantsBySecret.set(g.secret, []);
      grantsBySecret.get(g.secret)!.push(`${g.skill}(${g.scope})`);
    }
    if (names.length === 0) {
      ctx.out.write("(no secrets stored)\n");
      return 0;
    }
    for (const name of names.sort()) {
      const scopedTo = grantsBySecret.get(name) ?? [];
      const scopes = scopedTo.length ? scopedTo.join(", ") : "(no skill grants)";
      ctx.out.write(`  ${name}\n    granted to: ${scopes}\n`);
    }
    return 0;
  } finally {
    await close();
  }
}

// ── rotate ──────────────────────────────────────────────────────────

async function cmdRotate(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; stdin: NodeJS.ReadableStream & { isTTY?: boolean }; args: SecretsArgs }
): Promise<number> {
  const name = requirePositional(argv, 0, "rotate <name> [value]");
  const argvValue = optionalPositional(argv, 1);
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
  });
  try {
    const value = await resolveValue(argvValue, ctx.stdin, ctx.err, `Enter new value for "${name}"`);
    if (!value) {
      ctx.err.write("Aborted: empty value\n");
      return 1;
    }
    await broker.rotateSecret(name, value);
    ctx.out.write(`Rotated secret: ${name}\n`);
    return 0;
  } finally {
    await close();
  }
}

// ── delete ──────────────────────────────────────────────────────────

async function cmdDelete(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs }
): Promise<number> {
  const name = requirePositional(argv, 0, "delete <name>");
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
  });
  try {
    await broker.deleteSecret(name);
    ctx.out.write(`Deleted secret: ${name}\n`);
    return 0;
  } finally {
    await close();
  }
}

// ── grant ───────────────────────────────────────────────────────────

async function cmdGrant(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs }
): Promise<number> {
  const skill = requirePositional(argv, 0, "grant <skill> <secret>");
  const secret = requirePositional(argv, 1, "grant <skill> <secret>");
  const flags = parseSecretsGrantFlags(argv);
  if (flags.error) {
    ctx.err.write(flags.error);
    return 2;
  }
  const { scope, ttl } = flags;

  const storagePathForCheck = ctx.args.storagePath ?? (await defaultStoragePath());
  const boundRefusal = await refuseIfSurrogateBound(secret, storagePathForCheck, "grant");
  if (boundRefusal !== undefined) {
    // Checked BEFORE the policy file is rewritten, not after: a grant row
    // written and then reported as refused would leave `broker-policy.json`
    // naming a bound secret, which is exactly the conflict state that makes the
    // broker serve zero grants at its next open.
    ctx.err.write(boundRefusal);
    return 1;
  }

  // Update policy file + in-process broker (so running daemons pick up at next
  // reload; the CLI-local broker gets the grant for audit purposes). Same path
  // the binding check above used, so the two cannot land on different fortresses.
  const storage = storagePathForCheck;
  const policy = await loadBrokerPolicyRaw(storage);
  let skillEntry = policy.skills.find((s) => s.name === skill);
  if (!skillEntry) {
    skillEntry = { name: skill, secrets: [] };
    policy.skills.push(skillEntry);
  }
  const existing = skillEntry.secrets.find((s) => s.name === secret);
  if (existing) {
    existing.scope = scope;
    if (ttl !== undefined) existing.ttl = ttl;
  } else {
    skillEntry.secrets.push({ name: secret, scope, ttl });
  }
  await saveBrokerPolicy(storage, policy.skills);

  // Also grant in the in-process broker so the audit entry fires now.
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: storage,
    backend: ctx.args.brokerBackend,
  });
  try {
    broker.grant({ skill, secret, scope, ttlSeconds: ttl });
    ctx.out.write(`Granted: ${skill} -> ${secret} (scope=${scope}${ttl ? `, ttl=${ttl}s` : ""})\n`);
    return 0;
  } finally {
    await close();
  }
}

// ── revoke ──────────────────────────────────────────────────────────

async function cmdRevoke(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs }
): Promise<number> {
  const skill = requirePositional(argv, 0, "revoke <skill> <secret>");
  const secret = requirePositional(argv, 1, "revoke <skill> <secret>");

  const storage = ctx.args.storagePath ?? (await defaultStoragePath());

  // A revoke on a surrogate-bound secret is the repair for the conflict state
  // (a grant row and a binding for one name, which makes the broker serve zero
  // grants), so it must also drop the binding row. It may only do that while
  // the bound agent is unarmed: removing a row the helper is serving would
  // leave the value in use until the next arm, invisibly (design v2.1 3.3,
  // finding B2-S7).
  const boundRemoval = await removeSurrogateRowForRevoke(secret, storage, argv, ctx);
  if (boundRemoval !== 0) return boundRemoval;

  const policy = await loadBrokerPolicyRaw(storage);
  let removed = false;
  for (const s of policy.skills) {
    if (s.name !== skill) continue;
    const before = s.secrets.length;
    s.secrets = s.secrets.filter((g) => g.name !== secret);
    if (s.secrets.length !== before) removed = true;
  }
  if (removed) {
    await saveBrokerPolicy(storage, policy.skills);
  }
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: storage,
    backend: ctx.args.brokerBackend,
  });
  try {
    broker.revoke(skill, secret);
    ctx.out.write(
      removed
        ? `Revoked: ${skill} -> ${secret}\n`
        : `Revoked (not in policy file): ${skill} -> ${secret}\n`
    );
    return 0;
  } finally {
    await close();
  }
}


/**
 * The surrogate half of `secrets revoke`: 0 when the caller may continue (the
 * name is not bound, or its row was just removed), non-zero when it refused.
 *
 * Separate from `cmdRevoke`'s body so the broker-policy rewrite below it reads
 * as the one thing it has always been; this is the only place a revoke touches
 * `surrogate-policy.json`.
 */
async function removeSurrogateRowForRevoke(
  secret: string,
  storage: string,
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  const loaded = await loadSurrogatePolicyDocument(storage);
  if (loaded.outcome === "failed") {
    ctx.err.write(
      `sanctuary secrets revoke: the surrogate policy is present and could not be ` +
        `read (${loaded.failureClass}).\n` +
        `  Revoke would have to decide whether "${secret}" is bound, and it cannot.\n`,
    );
    return 1;
  }
  if (loaded.outcome === "absent") return 0;
  const bindings = loaded.document.bindings;
  if (!bindings.some((b) => b.secret === secret)) return 0;

  const row = bindings.find((b) => b.secret === secret)!;
  const crossCheck = parseOptionalSurrogateAgentUid(argv, "revoke");
  if (crossCheck.error) {
    ctx.err.write(crossCheck.error);
    return 2;
  }
  const probe = await probeSurrogateBindingArmed({
    transport: surrogateTransportFor(ctx.args),
    arming: surrogateArmingFor(ctx.args),
    secret,
    agentId: row.agent,
    operatorAgentUid: crossCheck.agentUid,
  });
  if (probe.state !== "unarmed") {
    ctx.err.write(describeBindingArmedRefusal(probe, "revoke", secret));
    await recordSurrogateRemovalRefused(ctx, storage, {
      secret,
      agent: row.agent,
      probe,
      verb: "revoke",
    });
    return 1;
  }
  const uid = { agentUid: probe.agentUid ?? null };

  await saveSurrogatePolicy(storage, {
    surrogate_policy_version: SURROGATE_POLICY_VERSION,
    bindings: bindings.filter((b) => b.secret !== secret),
  });
  // The VALUE stays under the surrogate label. `revoke` is a policy verb and
  // has never deleted a secret; `surrogate remove` is the verb that does.
  const { auditLog, close } = await openSurrogateStore({
    passphrase: ctx.args.passphrase,
    storagePath: storage,
    backend: ctx.args.surrogateBackend,
  });
  try {
    await auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.SURROGATE_REMOVED,
      identity_id: "sanctuary-broker",
      result: "success",
      details: { secret, agent_uid: uid.agentUid, removed_value: false },
    });
  } finally {
    await close();
  }
  ctx.out.write(`Removed surrogate binding: ${secret} (the stored value was kept).\n`);
  return 0;
}

// ---------------------------------------------------------------------------
// secrets surrogate: bind a secret to a destination instead of granting it
// ---------------------------------------------------------------------------
//
// WHAT THIS FAMILY IS FOR. A granted secret is one the agent can ask the broker
// for and then holds. A BOUND secret is one the agent is never issued: arming
// mints a placeholder for it, the wrapper exports the placeholder under the
// binding's env name, and only the gate and the root helper can put the real
// value on the wire toward the bound destination.
//
// WHY IT IS A SEPARATE VERB FAMILY AND NOT A NEW `--scope`. `surrogate` is not a
// token scope and must never become one: the broker's `scope` enum is a frozen
// surface, and a scope would put surrogacy back on the token path the separate
// keychain label and the separate policy file exist to keep it off. See the pin
// comments on `SecretScope` and `SCOPE_RANK`.

/**
 * Operator-facing refusal when `secret` is surrogate-bound, or `undefined` when
 * it is not.
 *
 * `verb` names the command in the message so the operator is told which of
 * their own actions was refused. A load failure refuses too: a policy file that
 * is present and broken must not read as "no bindings", which would let a grant
 * land on a name a binding still claims.
 */
async function refuseIfSurrogateBound(
  secret: string,
  storagePath: string,
  verb: string,
): Promise<string | undefined> {
  const result = await loadSurrogatePolicyDocument(storagePath);
  if (result.outcome === "absent") return undefined;
  if (result.outcome === "failed") {
    return (
      `sanctuary secrets ${verb}: the surrogate policy is present and could not be ` +
      `read (${result.failureClass}), so whether "${secret}" is bound cannot be ` +
      `decided. Refusing rather than guessing.\n` +
      `  Repair or remove ${storagePath}/surrogate-policy.json, then retry.\n`
    );
  }
  if (!surrogateBoundSecretNames(result.document.bindings).has(secret)) return undefined;
  return (
    `sanctuary secrets ${verb}: "${secret}" is bound as a surrogate, so the broker ` +
    `never issues it and a grant for it would read as not-found.\n` +
    `  Inspect the binding:  sanctuary secrets surrogate status\n` +
    `  Remove it first:      sanctuary secrets surrogate remove ${secret}\n`
  );
}

async function cmdSurrogate(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    stdin: NodeJS.ReadableStream & { isTTY?: boolean };
    args: SecretsArgs;
  },
): Promise<number> {
  const [sub, ...rest] = argv;
  if (!sub || sub === "--help" || sub === "-h") {
    printSurrogateUsage(ctx.out);
    return 0;
  }
  switch (sub) {
    case "add":
      return await cmdSurrogateAdd(rest, ctx);
    case "list":
      return await cmdSurrogateList(rest, ctx);
    case "remove":
      return await cmdSurrogateRemove(rest, ctx);
    case "unlock":
      return await cmdSurrogateUnlock(rest, ctx);
    case "lock":
      return await cmdSurrogateLock(rest, ctx);
    case "status":
      return await cmdSurrogateStatus(rest, ctx);
    case "events":
      return await cmdSurrogateEvents(rest, ctx);
    default:
      ctx.err.write(`Unknown surrogate subcommand: ${sub}\n`);
      printSurrogateUsage(ctx.err);
      return 2;
  }
}

function printSurrogateUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary secrets surrogate <command> [args]

  add <secret> [value]               Bind a secret to a destination. The agent is
                                     issued a placeholder for it and never the
                                     value. Value sources match \`secrets add\`.
    --agent <id>                     Agent account the binding belongs to.
    --env <NAME>                     Environment variable the wrapper exports.
    --header <Name>                  Request header the gate writes the value into.
    --host <host>[,<host>]           Destination host or hosts, port ${SURROGATE_BOUND_PORT} only.
  list                               List bindings. Never prints a value.
  remove <secret> [--agent-uid <N>]  Remove a binding and its stored value.
                                     Refuses while the binding's own agent is
                                     armed. --agent-uid is only a cross-check.
  unlock <secret> --agent-uid <N> [--ttl S]
                                     Send one bound value to that agent's
                                     helper, which holds it in memory only.
                                     One secret per run. TTL is clamped by
                                     the helper. An unknown outcome names the
                                     status and lock commands to run.
  lock --agent-uid <N>               Drop every value the helper holds.
  status --agent-uid <N>             Show which bindings are unlocked. Never
                                     prints a value or a placeholder.
  events --agent-uid <N> --agent <id>
                                     Root only. Print the gate's surrogate log
                                     lines, with placeholders redacted.

A bound secret cannot be granted, and a granted secret cannot be bound; run
\`sanctuary secrets delete <name>\` first if the name already holds a broker value.
`);
}

/** Flags `surrogate add` accepts, parsed as one grammar so a typo is refused
 * rather than silently dropped the way an unread flag would be. */
interface SurrogateAddFlags {
  agent?: string;
  env?: string;
  header?: string;
  hosts?: string[];
  error?: string;
}

export function parseSurrogateAddFlags(argv: string[]): SurrogateAddFlags {
  const agent = flagValue(argv, "--agent");
  const env = flagValue(argv, "--env");
  const header = flagValue(argv, "--header");
  const host = flagValue(argv, "--host");
  const missing = [
    agent ? null : "--agent",
    env ? null : "--env",
    header ? null : "--header",
    host ? null : "--host",
  ].filter((v): v is string => v !== null);
  if (missing.length > 0) {
    return {
      error:
        `sanctuary secrets surrogate add: missing required ${missing.join(", ")}.\n` +
        `  Every binding names an agent, an env name, a header and at least one host;\n` +
        `  a binding missing any of them has no destination the gate could check.\n`,
    };
  }
  // Split before validating: the shared parser owns the host grammar, so this
  // only has to decide where one host ends and the next begins.
  const hosts = host!.split(",").map((h) => h.trim()).filter((h) => h.length > 0);
  return { agent, env, header, hosts };
}

async function cmdSurrogateAdd(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    stdin: NodeJS.ReadableStream & { isTTY?: boolean };
    args: SecretsArgs;
  },
): Promise<number> {
  const secret = requirePositional(argv, 0, "surrogate add <secret> [value]");
  const argvValue = optionalPositional(argv, 1);
  const flags = parseSurrogateAddFlags(argv);
  if (flags.error) {
    ctx.err.write(flags.error);
    return 2;
  }

  const storagePath = ctx.args.storagePath ?? (await defaultStoragePath());

  // Build the document the loader would accept and let the SHARED parser judge
  // it, rather than validating here. One grammar, checked once, so the CLI can
  // never write a binding root arming or the helper would refuse.
  const existing = await loadSurrogatePolicyDocument(storagePath);
  if (existing.outcome === "failed") {
    ctx.err.write(
      `sanctuary secrets surrogate add: the surrogate policy is present and could ` +
        `not be read (${existing.failureClass}). Refusing to overwrite it.\n`,
    );
    return 1;
  }
  const bindings =
    existing.outcome === "loaded" ? [...existing.document.bindings] : [];
  const candidate: SurrogatePolicyDocument = {
    surrogate_policy_version: SURROGATE_POLICY_VERSION,
    bindings: [
      ...bindings,
      {
        secret,
        agent: flags.agent!,
        env: flags.env!,
        header: flags.header!,
        destinations: flags.hosts!.map((host) => ({ host, port: SURROGATE_BOUND_PORT })),
      },
    ],
  };
  let validated: SurrogatePolicyDocument;
  try {
    validated = parseSurrogatePolicyDocument(candidate);
  } catch {
    // The parser's own message quotes the input, so it is not echoed. The
    // operator is told which rule family they are against, not what they typed.
    ctx.err.write(
      `sanctuary secrets surrogate add: the binding was refused by the policy ` +
        `grammar. Check the agent id, the env name (not a reserved one), the header ` +
        `name, the host names, and that "${secret}" is not already bound.\n`,
    );
    return 1;
  }

  const { broker, close: closeBroker } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath,
  });
  let brokerNames: string[];
  try {
    brokerNames = await broker.listSecretNames();
  } finally {
    await closeBroker();
  }
  if (brokerNames.includes(secret)) {
    // A value under BOTH labels is the one state that makes the label split
    // meaningless: the broker would serve its copy while the gate spends the
    // other. Refused here so the operator deletes one deliberately.
    ctx.err.write(
      `sanctuary secrets surrogate add: "${secret}" already holds a value under the ` +
        `broker label, and a name must never hold a value under both.\n` +
        `  Delete it first:  sanctuary secrets delete ${secret}\n`,
    );
    return 1;
  }

  const { store, auditLog, close } = await openSurrogateStore({
    passphrase: ctx.args.passphrase,
    storagePath,
    backend: ctx.args.surrogateBackend,
  });
  try {
    const value = await resolveValue(
      argvValue,
      ctx.stdin,
      ctx.err,
      `Enter value for "${secret}"`,
    );
    if (!value) {
      ctx.err.write("Aborted: empty value\n");
      return 1;
    }
    // Value first, then the binding row. The other order would leave a binding
    // arming could mint a placeholder for with no value behind it, so the agent
    // would spend a placeholder the helper can never answer.
    await store.bindValue(secret, value);
    await saveSurrogatePolicy(storagePath, validated);
    await auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.SURROGATE_BOUND,
      identity_id: "sanctuary-broker",
      result: "success",
      details: {
        secret,
        agent: flags.agent,
        env: flags.env,
        header: flags.header,
        destinations: flags.hosts,
      },
    });
    ctx.out.write(
      `Bound: ${secret} -> ${flags.agent} (${flags.env}, ${flags.header}, ` +
        `${flags.hosts!.join(", ")})\n` +
        `The agent is issued a placeholder for this secret at the next arming, ` +
        `never the value.\n`,
    );
    return 0;
  } finally {
    await close();
  }
}

async function cmdSurrogateList(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  void argv;
  const storagePath = ctx.args.storagePath ?? (await defaultStoragePath());
  const result = await loadSurrogatePolicyDocument(storagePath);
  if (result.outcome === "failed") {
    ctx.err.write(
      `sanctuary secrets surrogate list: the surrogate policy is present and could ` +
        `not be read (${result.failureClass}).\n`,
    );
    return 1;
  }
  if (result.outcome === "absent" || result.document.bindings.length === 0) {
    ctx.out.write("No surrogate bindings.\n");
    return 0;
  }
  for (const b of result.document.bindings) {
    // Names, destinations and header only. Never a value, and never a
    // placeholder: a placeholder is a live bearer surrogate for its generation.
    ctx.out.write(
      `${b.secret}  agent=${b.agent}  env=${b.env}  header=${b.header}  ` +
        `hosts=${b.destinations.map((d) => `${d.host}:${d.port}`).join(",")}\n`,
    );
  }
  return 0;
}

// ---------------------------------------------------------------------------
// surrogate: the operator's one-shot unlock-socket client
// ---------------------------------------------------------------------------
//
// WHY THIS CLIENT LIVES IN THE CLI AND NOT IN `egress-gate/`. The gate's client
// speaks the QUERY codec on the query socket as the gate uid; this one speaks
// the UNLOCK codec on the unlock socket as the operator uid. They share the
// transport rule (one frame each way, one connection) and nothing else, and the
// helper binds each socket to exactly one codec on purpose (design v2.1 finding
// B2-B2). Folding them into one "helper client" would be the first step toward
// one parser for both sockets, which is the boundary the split exists to hold.

/** How long the operator waits for one unlock-socket answer.
 *
 * Larger than the gate's `SURROGATE_QUERY_TIMEOUT_MS` because nothing is
 * blocked behind it: a slow answer here delays an operator at a terminal, where
 * a slow answer there stalls an agent's request. Small enough that a wedged
 * helper reads as a refusal rather than a hang. */
export const SURROGATE_UNLOCK_CLIENT_TIMEOUT_MS = 5_000;

/** Why the CLI could not get an answer. Fixed classes, never the raw errno
 * string: that text carries the socket path, which names an agent uid. */
export type SurrogateUnlockFailureClass =
  | "permission_denied"
  | "timed_out"
  | "malformed_reply"
  | "connect_failed";

/** What one unlock-socket exchange did. */
export type SurrogateUnlockOutcome =
  | { outcome: "answered"; response: SurrogateUnlockSocketResponse }
  /** The socket node does not exist, so no helper is installed for that agent. */
  | { outcome: "absent" }
  | { outcome: "unreachable"; failureClass: SurrogateUnlockFailureClass };

/** The seam every surrogate verb speaks through. Tests inject; production uses
 * {@link createSurrogateUnlockSocketTransport}. */
export interface SurrogateUnlockTransport {
  send(agentUid: number, request: SurrogateUnlockSocketRequest): Promise<SurrogateUnlockOutcome>;
}

/** The real transport: one connection per request, against the helper's unlock
 * socket at the path the helper itself creates (`surrogateUnlockSocketPath`,
 * `egress-gate/surrogate-helper-daemon.ts`; must match that writer). */
export function createSurrogateUnlockSocketTransport(socketDir?: string): SurrogateUnlockTransport {
  return {
    send: (agentUid, request) =>
      sendOnSurrogateUnlockSocket(surrogateUnlockSocketPath(agentUid, socketDir), request),
  };
}

function sendOnSurrogateUnlockSocket(
  socketPath: string,
  request: SurrogateUnlockSocketRequest,
): Promise<SurrogateUnlockOutcome> {
  return new Promise<SurrogateUnlockOutcome>((resolve) => {
    let settled = false;
    let buffered = "";
    const finish = (result: SurrogateUnlockOutcome): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const socket = connect(socketPath);
    socket.setEncoding("utf8");
    // The deadline covers connect AND reply together, because a helper that
    // accepts and never answers is the same operator experience as one that
    // never accepts, and two separate timers would double the worst case.
    socket.setTimeout(SURROGATE_UNLOCK_CLIENT_TIMEOUT_MS, () =>
      finish({ outcome: "unreachable", failureClass: "timed_out" }),
    );
    socket.on("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "ENOENT") return finish({ outcome: "absent" });
      if (e.code === "EACCES" || e.code === "EPERM") {
        return finish({ outcome: "unreachable", failureClass: "permission_denied" });
      }
      finish({ outcome: "unreachable", failureClass: "connect_failed" });
    });
    socket.on("connect", () => {
      try {
        socket.write(encodeSurrogateUnlockSocketRequest(request));
      } catch {
        // `encodeSurrogateFrame` throws only when the caller built something
        // over the frame bound, which is a local programmer error, not the
        // helper's answer. Classified as malformed so no verb reads it as an
        // absent helper and proceeds.
        finish({ outcome: "unreachable", failureClass: "malformed_reply" });
      }
    });
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      if (Buffer.byteLength(buffered, "utf8") > SURROGATE_WIRE_MAX_FRAME_BYTES) {
        // Checked on the accumulated buffer BEFORE any parse, the same rule the
        // helper applies to us: an endless stream must never pin the operator's
        // memory or reach `JSON.parse`.
        return finish({ outcome: "unreachable", failureClass: "malformed_reply" });
      }
      // The unlock codec is newline-delimited JSON, so the first newline is
      // where one frame ends. `flagValue` remains the only reader of argv in
      // this file. Must match the framing in `credential-surrogate/wire.ts`.
      // cli-argv-indexof-allowed: wire framing, not argv parsing.
      const newline = buffered.indexOf("\n");
      if (newline < 0) return;
      if (buffered.length > newline + 1) {
        // A byte after the first frame. One frame each way is the contract; a
        // second frame means we are not talking to the codec we think we are.
        return finish({ outcome: "unreachable", failureClass: "malformed_reply" });
      }
      const response = parseSurrogateUnlockSocketResponse(buffered.slice(0, newline));
      if (response === null || response.id !== request.id) {
        // The id check is the second layer under the one-connection rule: a
        // reply that is not the answer to THIS request is discarded, never
        // reported as an answer.
        return finish({ outcome: "unreachable", failureClass: "malformed_reply" });
      }
      finish({ outcome: "answered", response });
    });
    socket.on("close", () =>
      finish({ outcome: "unreachable", failureClass: "connect_failed" }),
    );
  });
}

/**
 * Is the bound agent armed?
 *
 * Decided by the operator's own principal, never by a protection-state
 * predicate: a `status` answer is the only evidence that a helper is holding
 * this agent's table right now (design v2.1 section 3.3, finding B2-S7).
 * `indeterminate` is NOT "probably unarmed": EACCES, a timeout or a malformed
 * reply all mean a helper may be serving the binding, and removing a row it
 * serves would leave the value in use until the next arm, invisibly.
 */
export type SurrogateArmedState = "armed" | "unarmed" | "indeterminate";

export async function probeSurrogateHelperArmed(
  transport: SurrogateUnlockTransport,
  agentUid: number,
): Promise<{
  state: SurrogateArmedState;
  generationId?: number;
  /** Secret NAMES the helper's own table holds; present only for `armed`. */
  servedSecrets?: string[];
  failureClass?: SurrogateUnlockFailureClass;
}> {
  const result = await transport.send(agentUid, {
    v: SURROGATE_WIRE_VERSION,
    id: newSurrogateCorrelationId(),
    kind: "status",
  });
  if (result.outcome === "absent") return { state: "unarmed" };
  if (result.outcome === "unreachable") {
    return { state: "indeterminate", failureClass: result.failureClass };
  }
  if (result.response.kind !== "status") {
    // An `ok` or a `deny` in answer to `status` is a helper that does not speak
    // the codec we think it does. Treated as indeterminate, not as unarmed.
    return { state: "indeterminate", failureClass: "malformed_reply" };
  }
  return {
    state: "armed",
    generationId: result.response.generation_id,
    servedSecrets: result.response.bindings.map((b) => b.secret),
  };
}

/**
 * The arming twin's installed state, read as the OPERATOR can read it.
 *
 * Both answers come from the same sources the arming twin itself uses, so the
 * armed check and the arming path cannot disagree about which helper belongs to
 * which agent: the agent uid is the directory-service account
 * `deriveAgentAccountName(agentId)` (the lookup protect uses to find the uid it
 * arms), and the artifacts are `surrogateArtifactPaths(uid)` in
 * `egress-gate/arming-wiring.ts` (must match: the plist, bindings, destinations
 * and placeholder files `installSurrogateHelperForBringUp` writes).
 */
export interface SurrogateArmingView {
  /** The agent's uid, or `undefined` when no such account exists. Throws when
   * the directory service cannot answer, which is never read as "absent". */
  resolveAgentUid(agentId: string): Promise<number | undefined>;
  /** Every uid with an installed helper plist. Throws when the scan fails. */
  installedHelperUids(): Promise<number[]>;
  /** Whether ANY of the four installed artifacts for this uid exists. Throws on
   * a stat failure other than ENOENT. */
  hasHelperArtifacts(agentUid: number): Promise<boolean>;
}

/** Plist basename shape for one helper; must match `surrogateHelperDaemonPlistPath`. */
const SURROGATE_HELPER_PLIST_RE = new RegExp(
  `^${SURROGATE_HELPER_DAEMON_LABEL_PREFIX.replace(/\./g, "\\.")}\\.(\\d+)\\.plist$`,
);

export function createRealSurrogateArmingView(): SurrogateArmingView {
  return {
    async resolveAgentUid(agentId) {
      // Dynamic imports: the account lookup and the artifact list live with the
      // arming code, and loading those modules for every `secrets` verb would
      // cost every verb what only these two pay for.
      const { deriveAgentAccountName } = await import("../castle-wall/provision/account.js");
      const { realAccountProvisionOps } = await import("../wrap/auto-provision.js");
      return realAccountProvisionOps().lookupAccountUid(deriveAgentAccountName(agentId));
    },
    async installedHelperUids() {
      // The directory every helper plist is written into, derived from the one
      // path function the arming twin writes through rather than restated.
      const plistDir = dirname(surrogateHelperDaemonPlistPath(0));
      const names = await readdir(plistDir);
      const uids: number[] = [];
      for (const name of names) {
        const m = SURROGATE_HELPER_PLIST_RE.exec(name);
        if (m !== null) uids.push(Number(m[1]));
      }
      return uids;
    },
    async hasHelperArtifacts(agentUid) {
      const { surrogateArtifactPaths } = await import("../egress-gate/arming-wiring.js");
      const paths = surrogateArtifactPaths(agentUid);
      for (const path of [paths.plist, paths.bindings, paths.destinations, paths.placeholders]) {
        try {
          await stat(path);
          return true;
        } catch (e) {
          // ENOENT is the only "absent". EACCES or anything else is an artifact
          // we could not rule out, so it propagates and the caller refuses.
          if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        }
      }
      return false;
    },
  };
}

function surrogateArmingFor(args: SecretsArgs): SurrogateArmingView {
  return args.surrogateArming ?? createRealSurrogateArmingView();
}

/** Why a destructive verb could not establish that a binding is unserved.
 * Fixed classes, never a path or an errno string. */
export type SurrogateBindingRefusal =
  | "armed"
  | "agent_uid_mismatch"
  | "account_lookup_failed"
  | "artifact_scan_failed"
  | "socket_absent_with_artifacts"
  | SurrogateUnlockFailureClass;

export interface SurrogateBindingProbe {
  state: SurrogateArmedState;
  /** The uid derived from the binding's own agent, when the account exists. */
  agentUid?: number;
  /** The helper uid the refusal is about, when there is one. */
  refusingUid?: number;
  refusal?: SurrogateBindingRefusal;
}

/**
 * Is THIS binding being served by any helper right now?
 *
 * THE ROW'S OWN AGENT DECIDES; AN OPERATOR-NAMED UID CAN ONLY NARROW, NEVER
 * WIDEN. The uid probed is derived from the binding's agent id through the
 * arming twin's own lookup, never taken from `--agent-uid`; a flag that does not
 * EQUAL the derived uid refuses. A mistyped, stale or wrong uid used to read as
 * an absent socket, which read as unarmed, which let the row and value go while
 * a live helper on the real uid kept serving them.
 *
 * Every helper with an installed plist is probed as well as the derived uid,
 * because an account rename or deletion breaks the id-to-uid lookup without
 * stopping the helper that was armed under the old uid; the helper's own
 * `status` table is what says whether it holds this secret.
 *
 * Per helper: a `status` answer listing the secret is `armed`; a `status`
 * answer that does not list it is that helper not serving it; an absent socket
 * is unarmed ONLY when none of that uid's installed artifacts exists, and is
 * `indeterminate` otherwise (an installed helper whose socket is gone may be
 * restarting); every other outcome is `indeterminate`.
 */
export async function probeSurrogateBindingArmed(input: {
  transport: SurrogateUnlockTransport;
  arming: SurrogateArmingView;
  secret: string;
  agentId: string;
  operatorAgentUid?: number;
}): Promise<SurrogateBindingProbe> {
  let derived: number | undefined;
  try {
    derived = await input.arming.resolveAgentUid(input.agentId);
  } catch {
    return { state: "indeterminate", refusal: "account_lookup_failed" };
  }
  if (input.operatorAgentUid !== undefined && input.operatorAgentUid !== derived) {
    // Narrow-only: the flag may confirm the derived uid, never replace it.
    return { state: "indeterminate", agentUid: derived, refusal: "agent_uid_mismatch" };
  }
  let installed: number[];
  try {
    installed = await input.arming.installedHelperUids();
  } catch {
    return { state: "indeterminate", agentUid: derived, refusal: "artifact_scan_failed" };
  }
  const candidates = [...new Set([...(derived === undefined ? [] : [derived]), ...installed])];
  for (const uid of candidates) {
    const probe = await probeSurrogateHelperArmed(input.transport, uid);
    if (probe.state === "armed") {
      if (probe.servedSecrets?.includes(input.secret)) {
        return { state: "armed", agentUid: derived, refusingUid: uid, refusal: "armed" };
      }
      continue;
    }
    if (probe.state === "indeterminate") {
      return {
        state: "indeterminate",
        agentUid: derived,
        refusingUid: uid,
        refusal: probe.failureClass ?? "connect_failed",
      };
    }
    // An absent socket proves nothing while any installed artifact for that
    // uid remains: the helper may be restarting, or its socket was removed out
    // from under it. Only "no socket AND no artifact" is unarmed.
    let artifacts: boolean;
    try {
      artifacts = await input.arming.hasHelperArtifacts(uid);
    } catch {
      return { state: "indeterminate", agentUid: derived, refusingUid: uid, refusal: "artifact_scan_failed" };
    }
    if (artifacts) {
      return {
        state: "indeterminate",
        agentUid: derived,
        refusingUid: uid,
        refusal: "socket_absent_with_artifacts",
      };
    }
  }
  return { state: "unarmed", agentUid: derived };
}

/** The refusal text shared by `secrets revoke` and `surrogate remove`. */
function describeBindingArmedRefusal(
  probe: SurrogateBindingProbe,
  verb: string,
  secret: string,
): string {
  if (probe.refusal === "armed") {
    return (
      `sanctuary secrets ${verb}: "${secret}" is bound as a surrogate and the helper for ` +
      `agent uid ${probe.refusingUid} is serving that binding now.\n` +
      `  Drop the values now:  sanctuary secrets surrogate lock --agent-uid ${probe.refusingUid}\n` +
      `  The binding's placeholder goes away at the next unprotect or re-arm.\n`
    );
  }
  if (probe.refusal === "agent_uid_mismatch") {
    return (
      `sanctuary secrets ${verb}: --agent-uid does not match the uid of "${secret}"'s own ` +
      `agent (${probe.agentUid === undefined ? "no such account" : `uid ${probe.agentUid}`}).\n` +
      `  The binding's agent decides which helper is checked; the flag can only confirm it.\n`
    );
  }
  return (
    `sanctuary secrets ${verb}: could not establish that "${secret}"'s agent is unarmed ` +
    `(${probe.refusal ?? "connect_failed"}).\n` +
    `  A helper may be serving the binding, so the row is left in place.\n`
  );
}

/**
 * Record a refused `remove` or `revoke` on the chain.
 *
 * A refusal is evidence too: an operator who tried to drop a binding while it
 * was being served should find that attempt in the same place the success
 * would have been. `result: "failure"` is the chain's closed vocabulary;
 * `outcome: "refused"` and the fixed refusal class say why. A chain write that
 * fails does not turn the refusal into anything else; it is reported.
 */
async function recordSurrogateRemovalRefused(
  ctx: { err: NodeJS.WritableStream; args: SecretsArgs },
  storagePath: string,
  input: { secret: string; agent: string; probe: SurrogateBindingProbe; verb: string },
): Promise<void> {
  try {
    const { auditLog, close } = await openSurrogateStore({
      passphrase: ctx.args.passphrase,
      storagePath,
      backend: ctx.args.surrogateBackend,
    });
    try {
      await auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SURROGATE_REMOVED,
        identity_id: "sanctuary-broker",
        result: "failure",
        details: {
          secret: input.secret,
          agent: input.agent,
          agent_uid: input.probe.agentUid ?? null,
          verb: input.verb,
          outcome: "refused",
          reason: input.probe.refusal ?? "connect_failed",
        },
      });
    } finally {
      await close();
    }
  } catch (e) {
    ctx.err.write(
      `  The refusal itself could not be recorded on the audit chain ` +
        `(${e instanceof Error ? e.message : String(e)}).\n`,
    );
  }
}

/** Read `--agent-uid` as the verbs that ADDRESS one helper (`unlock`, `lock`,
 * `status`, `events`) all require it: those verbs talk to a helper, not about a
 * binding row, so the uid is the address itself.
 *
 * The verbs that remove a binding row (`surrogate remove`, `secrets revoke`)
 * do NOT take their probe target from here: the row's own agent decides
 * (`probeSurrogateBindingArmed`), and an operator-named uid can only narrow,
 * never widen. They read the flag through `parseOptionalSurrogateAgentUid`. */
export function parseSurrogateAgentUid(argv: string[], verb: string): { agentUid?: number; error?: string } {
  const raw = flagValue(argv, "--agent-uid");
  if (raw === undefined) {
    return {
      error:
        `sanctuary secrets surrogate ${verb}: missing required --agent-uid <N>.\n` +
        `  The helper, its sockets and its tables are keyed by the agent's uid.\n`,
    };
  }
  return parsePositiveAgentUid(raw, verb);
}

/** `--agent-uid` as an optional cross-check: absent is fine, malformed is not. */
export function parseOptionalSurrogateAgentUid(
  argv: string[],
  verb: string,
): { agentUid?: number; error?: string } {
  const raw = flagValue(argv, "--agent-uid");
  if (raw === undefined) return {};
  return parsePositiveAgentUid(raw, verb);
}

function parsePositiveAgentUid(raw: string, verb: string): { agentUid?: number; error?: string } {
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return {
      error: `sanctuary secrets surrogate ${verb}: --agent-uid must be a positive integer.\n`,
    };
  }
  return { agentUid: parsed };
}

function surrogateTransportFor(args: SecretsArgs): SurrogateUnlockTransport {
  return args.surrogateUnlock ?? createSurrogateUnlockSocketTransport();
}

// ── surrogate remove ────────────────────────────────────────────────

async function cmdSurrogateRemove(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  const secret = requirePositional(argv, 0, "surrogate remove <secret> [--agent-uid <N>]");
  const crossCheck = parseOptionalSurrogateAgentUid(argv, "remove");
  if (crossCheck.error) {
    ctx.err.write(crossCheck.error);
    return 2;
  }
  const storagePath = ctx.args.storagePath ?? (await defaultStoragePath());
  const loaded = await loadSurrogatePolicyDocument(storagePath);
  if (loaded.outcome === "failed") {
    ctx.err.write(
      `sanctuary secrets surrogate remove: the surrogate policy is present and could ` +
        `not be read (${loaded.failureClass}).\n`,
    );
    return 1;
  }
  const bindings = loaded.outcome === "absent" ? [] : loaded.document.bindings;
  const row = bindings.find((b) => b.secret === secret);
  if (row === undefined) {
    ctx.err.write(`sanctuary secrets surrogate remove: "${secret}" is not bound.\n`);
    return 1;
  }

  const probe = await probeSurrogateBindingArmed({
    transport: surrogateTransportFor(ctx.args),
    arming: surrogateArmingFor(ctx.args),
    secret,
    agentId: row.agent,
    operatorAgentUid: crossCheck.agentUid,
  });
  if (probe.state !== "unarmed") {
    ctx.err.write(describeBindingArmedRefusal(probe, "surrogate remove", secret));
    await recordSurrogateRemovalRefused(ctx, storagePath, {
      secret,
      agent: row.agent,
      probe,
      verb: "surrogate remove",
    });
    return 1;
  }
  const uid = { agentUid: probe.agentUid ?? null };

  // Row first, then the value. This is the reverse of `add` and for the same
  // reason: the state that must never exist between the two writes is a binding
  // with no value behind it, because arming would mint a placeholder the helper
  // could never answer. A value with no binding is inert.
  const remaining = bindings.filter((b) => b.secret !== secret);
  await saveSurrogatePolicy(storagePath, {
    surrogate_policy_version: SURROGATE_POLICY_VERSION,
    bindings: remaining,
  });

  const { store, auditLog, close } = await openSurrogateStore({
    passphrase: ctx.args.passphrase,
    storagePath,
    backend: ctx.args.surrogateBackend,
  });
  try {
    await store.removeValue(secret);
    await auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.SURROGATE_REMOVED,
      identity_id: "sanctuary-broker",
      result: "success",
      details: { secret, agent_uid: uid.agentUid, removed_value: true },
    });
    ctx.out.write(
      `Removed binding and surrogate value: ${secret}\n` +
        `The placeholder for it stops being minted at the next arming.\n`,
    );
    return 0;
  } finally {
    await close();
  }
}

// ── surrogate unlock: the no-core rule, then the helper, then the keychain ──
//
// STEP ORDER IS THE POINT (design v2.1 section 3.4.4). Every step that could
// bring a value into this process sits BEHIND a check that can refuse without
// one: no-core is established and verified first, then the helper is proved to
// be answering, and only then is a value read. Reordering any two of them makes
// a refusal happen after a value already exists in a process that might dump
// core. The audit row comes LAST, after the helper's own answer, so the chain
// never says `success` for an unlock the helper refused. One value per
// invocation: there is no part-way state to clean up.

/** Marker the re-executed child carries. Never trusted on its own: the child
 * re-reads the actual hard limit before it does anything (3.4.6, "an
 * environment marker alone is never trusted"). */
export const SURROGATE_NO_CORE_MARKER_ENV = "SANCTUARY_SURROGATE_NO_CORE";

/** The shell that drops both core limits and then becomes the real process.
 * Must match the string in `test/cli/secrets-surrogate-unlock.test.ts`. */
export const SURROGATE_NO_CORE_SHELL_SCRIPT =
  'ulimit -H -c 0 && ulimit -S -c 0 && exec "$@"';

/** Seam for the two things the unlock verb does to its own process. Tests
 * inject; production uses {@link createSurrogateNoCoreOps}. */
export interface SurrogateNoCoreOps {
  /** Whether this process is already the re-executed, core-limited child. */
  alreadyReexeced(): boolean;
  /** What `/bin/sh -c 'ulimit -H -c'` prints in a child of this process.
   * A child inherits the parent's limits, so this reads OUR limit. */
  readHardCoreLimit(): Promise<string>;
  /** Re-exec under the no-core shell; resolves with the child's exit code. */
  reexecWithoutCore(): Promise<number>;
}

export function createSurrogateNoCoreOps(): SurrogateNoCoreOps {
  return {
    alreadyReexeced: () => process.env[SURROGATE_NO_CORE_MARKER_ENV] === "1",
    readHardCoreLimit: async () => {
      const { spawnSync } = await import("node:child_process");
      const r = spawnSync("/bin/sh", ["-c", "ulimit -H -c"], { encoding: "utf8" });
      return (r.stdout ?? "").trim();
    },
    reexecWithoutCore: async () => {
      const { spawn } = await import("node:child_process");
      return await new Promise<number>((resolve) => {
        const child = spawn(
          "/bin/sh",
          ["-c", SURROGATE_NO_CORE_SHELL_SCRIPT, "sh", process.execPath, ...process.argv.slice(1)],
          {
            stdio: "inherit",
            env: { ...process.env, [SURROGATE_NO_CORE_MARKER_ENV]: "1" },
          },
        );
        // A child killed by a signal has a null code. Reported as 1 rather than
        // 0: an unlock that died is not an unlock that happened.
        child.on("exit", (code) => resolve(code ?? 1));
        child.on("error", () => resolve(1));
      });
    },
  };
}

/** `ulimit -H -c` prints this and nothing else when core dumps are impossible. */
const NO_CORE_HARD_LIMIT = "0";

async function cmdSurrogateUnlock(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  // ONE VALUE PER INVOCATION, so a failure can never hide a value that an
  // earlier iteration loaded. There is no loop over bindings and no "all
  // bindings" form: a run either sees the helper's `ok` for this one value,
  // sees an answered `deny` (the helper stored nothing), or does not know, and
  // in that last case it says so and names the commands that settle it.
  const secret = requirePositional(argv, 0, "surrogate unlock <secret> --agent-uid <N> [--ttl S]");
  const uid = parseSurrogateAgentUid(argv, "unlock");
  if (uid.error) {
    ctx.err.write(uid.error);
    return 2;
  }
  const ttlRaw = flagValue(argv, "--ttl");
  let ttlSeconds: number | undefined;
  if (ttlRaw !== undefined) {
    ttlSeconds = Number(ttlRaw);
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
      ctx.err.write("sanctuary secrets surrogate unlock: --ttl must be a positive integer.\n");
      return 2;
    }
    // Deliberately NOT bounded here. The helper clamps to
    // MAX_SURROGATE_UNLOCK_SECONDS (AGENTS.md rule 10, the relying side
    // clamps), so a generous request becomes a bounded unlock rather than a
    // refusal the operator has to decode.
  }

  const noCore = ctx.args.surrogateNoCore ?? createSurrogateNoCoreOps();

  // Step 1: the no-core rule. Re-exec, then VERIFY in the child.
  if (!noCore.alreadyReexeced()) {
    return await noCore.reexecWithoutCore();
  }
  const hardLimit = await noCore.readHardCoreLimit();
  if (hardLimit !== NO_CORE_HARD_LIMIT) {
    ctx.err.write(
      `sanctuary secrets surrogate unlock: refusing to read any value because this ` +
        `process could still write a core file (hard core limit reads ` +
        `${JSON.stringify(hardLimit)}, expected ${JSON.stringify(NO_CORE_HARD_LIMIT)}).\n` +
        `  Nothing was sent and no secret was read.\n`,
    );
    return 1;
  }

  // Step 2: prove the helper is answering BEFORE any keychain read, so a down
  // helper or an absent socket never causes the operator's passphrase and
  // master key to be resolved.
  const transport = surrogateTransportFor(ctx.args);
  const probe = await probeSurrogateHelperArmed(transport, uid.agentUid!);
  if (probe.state !== "armed") {
    ctx.err.write(
      probe.state === "unarmed"
        ? `sanctuary secrets surrogate unlock: helper-not-running for agent uid ` +
            `${uid.agentUid}. Nothing was read.\n`
        : `sanctuary secrets surrogate unlock: the helper did not answer ` +
            `(${probe.failureClass ?? "connect_failed"}). Nothing was read.\n`,
    );
    return 1;
  }
  const generationId = probe.generationId!;
  // The helper's own table decides whether this name is unlockable, not the
  // policy file: the policy may already have moved on, while the helper holds
  // exactly the generation that is armed right now. A name it does not serve
  // is refused here, before the keychain is opened.
  if (!(probe.servedSecrets ?? []).includes(secret)) {
    ctx.err.write(
      `sanctuary secrets surrogate unlock: the helper for agent uid ${uid.agentUid} ` +
        `does not serve "${secret}" at generation ${generationId}. Nothing was read.\n`,
    );
    return 1;
  }

  // Step 3: fortress context. Step 4: the one value. Step 5: the chain row,
  // which records what the HELPER ANSWERED and nothing earlier.
  const { store, auditLog, close } = await openSurrogateStore({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
    backend: ctx.args.surrogateBackend,
  });
  try {
    let value: string;
    try {
      value = await store.readValue(secret);
    } catch {
      // Nothing was sent, so nothing can be resident: a plain refusal.
      return await recordUnlockFailure(ctx, auditLog, {
        agentUid: uid.agentUid!,
        generationId,
        secret,
        outcome: "refused",
        reason: "value_unreadable",
      });
    }
    const result = await transport.send(uid.agentUid!, {
      v: SURROGATE_WIRE_VERSION,
      id: newSurrogateCorrelationId(),
      kind: "unlock",
      generation_id: generationId,
      ttl_seconds: ttlSeconds ?? MAX_SURROGATE_UNLOCK_SECONDS,
      secret,
      value,
    });

    if (result.outcome === "answered" && result.response.kind === "ok") {
      // The success row is written only AFTER the helper's `ok`, so the chain
      // never says `success` for a value the helper did not accept.
      try {
        await auditLog.appendCritical({
          layer: "l3",
          operation: BROKER_OPS.SURROGATE_UNLOCKED,
          identity_id: "sanctuary-broker",
          result: "success",
          details: { agent_uid: uid.agentUid, generation_id: generationId, secret },
        });
      } catch (e) {
        // The value IS loaded and the chain does not record it. Said plainly,
        // with the command that drops it; never reported as a success.
        ctx.err.write(
          `sanctuary secrets surrogate unlock: the helper accepted "${secret}" but the ` +
            `audit entry could not be written ` +
            `(${e instanceof Error ? e.message : String(e)}).\n` +
            describeUnlockSettleCommands(uid.agentUid!),
        );
        return 1;
      }
      ctx.out.write(
        `Unlocked "${secret}" for agent uid ${uid.agentUid} at generation ${generationId}.\n`,
      );
      return 0;
    }

    // Only an answered `deny` is the helper saying, in its own words, that it
    // stored nothing. A timeout, a dropped connection or a malformed reply can
    // all follow an accepted unlock, so they are reported as UNKNOWN, with the
    // commands that settle it, and never as a refusal.
    const refused = result.outcome === "answered" && result.response.kind === "deny";
    return await recordUnlockFailure(ctx, auditLog, {
      agentUid: uid.agentUid!,
      generationId,
      secret,
      outcome: refused ? "refused" : "unknown",
      reason: describeUnlockOutcome(result),
    });
  } finally {
    await close();
  }
}

/** Writes the `failure` row for a one-value unlock and the operator lines.
 * `refused` means the helper holds nothing from this run; `unknown` means it
 * may, and the message names the `status` and `lock` commands that settle it. */
async function recordUnlockFailure(
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
  auditLog: Awaited<ReturnType<typeof openSurrogateStore>>["auditLog"],
  f: {
    agentUid: number;
    generationId: number;
    secret: string;
    outcome: "refused" | "unknown";
    reason: string;
  },
): Promise<number> {
  // The secret NAME is safe to print (it is in the policy file the operator
  // wrote); the value and the deny detail are never summarised beyond the
  // fixed reason class.
  ctx.err.write(
    f.outcome === "refused"
      ? `sanctuary secrets surrogate unlock: the helper refused "${f.secret}" (${f.reason}). ` +
          `Nothing was stored.\n`
      : `sanctuary secrets surrogate unlock: the outcome for "${f.secret}" is unknown ` +
          `(${f.reason}); the helper may hold the value.\n` +
          describeUnlockSettleCommands(f.agentUid),
  );
  try {
    await auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.SURROGATE_UNLOCKED,
      identity_id: "sanctuary-broker",
      result: "failure",
      // Names and fixed classes only. Never a value.
      details: {
        agent_uid: f.agentUid,
        generation_id: f.generationId,
        secret: f.secret,
        outcome: f.outcome,
        reason: f.reason,
      },
    });
  } catch (e) {
    ctx.err.write(
      `  The failed unlock could not be recorded on the audit chain ` +
        `(${e instanceof Error ? e.message : String(e)}).\n`,
    );
  }
  return 1;
}

/** The two commands that settle an unknown unlock outcome. Fixed text. */
function describeUnlockSettleCommands(agentUid: number): string {
  return (
    `  Check:  sanctuary secrets surrogate status --agent-uid ${agentUid}\n` +
    `  Drop:   sanctuary secrets surrogate lock --agent-uid ${agentUid}\n`
  );
}

/** One fixed token for an outcome, for an operator line. Never a value. */
function describeUnlockOutcome(result: SurrogateUnlockOutcome): string {
  if (result.outcome === "absent") return "helper-not-running";
  if (result.outcome === "unreachable") return result.failureClass;
  if (result.response.kind === "deny") return result.response.reason;
  return "unexpected_reply";
}

// ── surrogate lock and status ───────────────────────────────────────

async function cmdSurrogateLock(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  const uid = parseSurrogateAgentUid(argv, "lock");
  if (uid.error) {
    ctx.err.write(uid.error);
    return 2;
  }
  const result = await surrogateTransportFor(ctx.args).send(uid.agentUid!, {
    v: SURROGATE_WIRE_VERSION,
    id: newSurrogateCorrelationId(),
    kind: "lock",
  });
  if (result.outcome === "answered" && result.response.kind === "ok") {
    ctx.out.write(`Locked: every value for agent uid ${uid.agentUid} was dropped.\n`);
    return 0;
  }
  ctx.err.write(
    `sanctuary secrets surrogate lock: ${describeUnlockOutcome(result)}.\n`,
  );
  return 1;
}

async function cmdSurrogateStatus(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  const uid = parseSurrogateAgentUid(argv, "status");
  if (uid.error) {
    ctx.err.write(uid.error);
    return 2;
  }
  const result = await surrogateTransportFor(ctx.args).send(uid.agentUid!, {
    v: SURROGATE_WIRE_VERSION,
    id: newSurrogateCorrelationId(),
    kind: "status",
  });
  if (result.outcome === "absent") {
    ctx.out.write(`No helper is running for agent uid ${uid.agentUid} (unarmed).\n`);
    return 0;
  }
  if (result.outcome !== "answered" || result.response.kind !== "status") {
    ctx.err.write(
      `sanctuary secrets surrogate status: ${describeUnlockOutcome(result)}.\n`,
    );
    return 1;
  }
  const { generation_id, bindings } = result.response;
  ctx.out.write(`Agent uid ${uid.agentUid}, generation ${generation_id}\n`);
  for (const b of bindings) {
    // The helper never returns a value or a placeholder on this path, so there
    // is nothing here to redact; what prints is exactly what it sent.
    ctx.out.write(
      `  ${b.secret}  ${b.unlocked ? "unlocked" : "locked"}` +
        `${b.expires_at === null ? "" : `  expires_at=${b.expires_at}`}\n`,
    );
  }
  return 0;
}

// ── surrogate events ────────────────────────────────────────────────

/** The prefix every surrogate line in the gate log carries. Must match the
 * emission site the gate gains in slice 1b; in slice 1a the gate emits none, so
 * this verb is exercised against fixture log lines only. */
export const SURROGATE_GATE_EVENT_PREFIX = "surrogate_";

async function cmdSurrogateEvents(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs },
): Promise<number> {
  // Root only, and checked before anything is opened. The gate's log lives
  // under the gate account's home; a non-root operator reading it would either
  // fail with a path in the error or, worse, succeed on a host where the mode
  // had drifted.
  const euid = ctx.args.effectiveUid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  if (euid !== 0) {
    ctx.err.write(
      "sanctuary secrets surrogate events: must run as root; the gate's log is not " +
        "readable by the operator.\n",
    );
    return 1;
  }
  const uid = parseSurrogateAgentUid(argv, "events");
  if (uid.error) {
    ctx.err.write(uid.error);
    return 2;
  }
  const agentId = flagValue(argv, "--agent");
  if (!agentId) {
    ctx.err.write(
      "sanctuary secrets surrogate events: missing required --agent <id>; the gate log " +
        "path is derived from the gate account name.\n",
    );
    return 2;
  }

  let stderrPath: string;
  if (ctx.args.gateLogPathOverride !== undefined) {
    stderrPath = ctx.args.gateLogPathOverride;
  } else {
    // Dynamic import for the same reason `cli/castle-wall.ts` uses one for this
    // module: `arming-wiring.ts` pulls the whole arming graph in, and a verb
    // that only reads a log file must not make every `sanctuary secrets`
    // invocation pay for it.
    const { GATE_ACCOUNT_HOME_BASE } = await import("../egress-gate/arming-wiring.js");
    const gateAccount = deriveGateAccountName(agentId);
    stderrPath = egressGateDaemonLogPaths({
      agentUid: uid.agentUid!,
      gateAccount,
      gateHomeDirectory: `${GATE_ACCOUNT_HOME_BASE}/${gateAccount}`,
    }).stderrPath;
  }

  let contents: string;
  try {
    contents = await readFile(stderrPath, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      ctx.out.write("No gate log for this agent yet.\n");
      return 0;
    }
    ctx.err.write(`sanctuary secrets surrogate events: the gate log could not be read (${code ?? "unknown"}).\n`);
    return 1;
  }
  let printed = 0;
  for (const line of contents.split("\n")) {
    if (!line.includes(SURROGATE_GATE_EVENT_PREFIX)) continue;
    // Redacted on the way out as well as at the sink. A placeholder is a live
    // bearer surrogate for its generation, and this verb prints to a terminal
    // that is very often being recorded.
    ctx.out.write(`${redactSurrogatePlaceholdersInString(line)}\n`);
    printed += 1;
  }
  if (printed === 0) ctx.out.write("No surrogate events in the gate log.\n");
  return 0;
}

// ── audit ───────────────────────────────────────────────────────────

async function cmdAudit(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs }
): Promise<number> {
  const { since, limit } = parseSecretsAuditFlags(argv);
  const { broker, close } = await openBroker({
    passphrase: ctx.args.passphrase,
    storagePath: ctx.args.storagePath,
  });
  try {
    // OPERATOR CLI: full-fidelity broker audit (secret name, scope, reason).
    // The operator owns the policy; this is NOT the agent-facing redacted
    // `broker/audit_query` (which uses broker.queryAudit).
    const summary = await broker.queryAuditOperator({ since, limit });
    if (summary.entries.length === 0) {
      ctx.out.write("(no broker audit entries)\n");
      return 0;
    }
    for (const e of summary.entries) {
      const skill = e.details?.skill ?? "-";
      const secret = e.details?.secret ?? "-";
      const reason = e.details?.reason ?? "";
      ctx.out.write(
        `${e.timestamp}  ${e.operation.padEnd(26)} ${e.result.padEnd(7)}  skill=${skill} secret=${secret}${reason ? " reason=" + reason : ""}\n`
      );
    }
    return 0;
  } finally {
    await close();
  }
}

// ── helpers ─────────────────────────────────────────────────────────

export function parseSecretsGrantFlags(argv: string[]): SecretsGrantFlags {
  const scopeFlag = flagValue(argv, "--scope");
  const ttlFlag = flagValue(argv, "--ttl");
  const scope: SecretScope = (scopeFlag as SecretScope | undefined) ?? "read";
  if (scope !== "read" && scope !== "rotate") {
    return { scope: "read", error: `--scope must be "read" or "rotate" (got ${scopeFlag})\n` };
  }
  const ttl = ttlFlag ? Number(ttlFlag) : undefined;
  if (ttl !== undefined && (!Number.isFinite(ttl) || ttl <= 0)) {
    return { scope, error: `--ttl must be a positive integer (got ${ttlFlag})\n` };
  }
  return ttl === undefined ? { scope } : { scope, ttl };
}

export function parseSecretsAuditFlags(argv: string[]): SecretsAuditFlags {
  const since = flagValue(argv, "--since");
  const limit = Number(flagValue(argv, "--limit") ?? "200");
  return since === undefined ? { limit } : { since, limit };
}

/**
 * The flag this file refuses, plus the equals-spelling prefix derived from it
 * so the two spellings can never drift apart.
 *
 * Must match the spellings `extractTopLevelFortressFlag` accepts in
 * `top-level-fortress.ts` (`--fortress <path>` and `--fortress=<path>`). A
 * spelling honored there but unrecognized here would reach this file and be
 * dropped, which is the defect below.
 */
const FORTRESS_FLAG = "--fortress";
const FORTRESS_EQUALS_PREFIX = `${FORTRESS_FLAG}=`;

/**
 * Refuse a `--fortress` typed after the word `secrets`.
 *
 * Returns the operator-facing message when the flag is present, `undefined`
 * when it is not.
 *
 * Reproduced end to end on 2026-08-05 against the built CLI, with
 * `SANCTUARY_STORAGE_PATH=$DEFAULT` and an empty `$OTHER`:
 *
 *   sanctuary secrets add demo_token supersecret --fortress $OTHER
 *     -> exit 0, "Stored secret: demo_token"
 *     -> $DEFAULT/state/ gained the audit entry and custody envelope
 *     -> $OTHER stayed empty
 *
 * A credential written to the wrong fortress, reported as success. That is a
 * "never silently degrade to a less-secure behavior" violation (AGENTS.md
 * constraint #5): the operator asked for isolation and got the ambient
 * fortress with no signal. `secrets list --fortress $OTHER` has the same shape
 * on the read side, printing the DEFAULT fortress's secrets under the other
 * fortress's name.
 *
 * Refusing rather than rewriting argv is deliberate. Two earlier attempts to
 * repair the operator's argv (normalizing `--fortress=<path>`, then routing by
 * an allowlist of commands believed to parse the flag) each traded this defect
 * for a new one, because telling a flag's VALUE from a flag needs a per-handler
 * argv grammar this CLI does not have. A refusal cannot corrupt anything and
 * costs one line to recover from.
 *
 * Scope is deliberately this one subcommand, and only because its
 * non-parsing was demonstrated directly. Other subcommands that ignore a
 * trailing `--fortress` are NOT covered here; the general fix is a single
 * shared flag parser, which is tracked separately.
 *
 * The equality and prefix tests are separate so a future `--fortress-url` or
 * `--fortress-path` flag on this command would not be caught by accident.
 */
function assertNoFortressFlag(argv: readonly string[]): string | undefined {
  const present = argv.some(
    (token) =>
      token === FORTRESS_FLAG || token.startsWith(FORTRESS_EQUALS_PREFIX)
  );
  if (!present) return undefined;

  return (
    `sanctuary secrets: ${FORTRESS_FLAG} is not read after the subcommand and ` +
    `would have been ignored, running against the fortress in ` +
    `SANCTUARY_STORAGE_PATH (default ~/.sanctuary) instead of the one you ` +
    `named. On 'add', 'rotate' and 'delete' that writes a credential to the ` +
    `wrong fortress.\n` +
    `  Put the flag before the subcommand:\n` +
    `    sanctuary ${FORTRESS_FLAG} <path> secrets ...\n` +
    `  Or set SANCTUARY_STORAGE_PATH for the whole shell.\n`
  );
}

function requirePositional(argv: string[], i: number, usage: string): string {
  const v = argv[i];
  if (!v || v.startsWith("--")) {
    throw new Error(`Missing argument. Usage: ${usage}`);
  }
  return v;
}

/** Read an optional positional at index `i` — returns undefined if missing or
 *  if the slot is a `--flag` (reserved for named options). */
function optionalPositional(argv: string[], i: number): string | undefined {
  const v = argv[i];
  if (!v || v.startsWith("--")) return undefined;
  return v;
}

/** Deadline on non-TTY stdin reads. Prevents the v0.10.0-rc.1 soak failure
 *  mode where an operator-supplied argv value was silently dropped and the
 *  CLI hung 15 minutes on an open-but-empty stdin. 30s is ample for any
 *  legitimate pipe. */
const STDIN_READ_DEADLINE_MS = 30_000;

/**
 * Resolve the secret value from (in order): argv positional, piped stdin,
 * or an interactive TTY prompt. Emits a stderr warning when the value comes
 * from argv because it is briefly visible in `ps aux`.
 */
async function resolveValue(
  argvValue: string | undefined,
  stdin: NodeJS.ReadableStream & { isTTY?: boolean },
  err: NodeJS.WritableStream,
  prompt: string
): Promise<string> {
  if (argvValue !== undefined) {
    err.write(
      "Warning: secret value passed as CLI argument is briefly visible in `ps aux`.\n" +
      "  For better security, pipe via stdin: `echo \"value\" | sanctuary secrets add NAME`\n"
    );
    return argvValue;
  }
  return await readValue(stdin, prompt);
}

async function defaultStoragePath(): Promise<string> {
  const { loadConfig } = await import("../config.js");
  const cfg = await loadConfig();
  return cfg.storage_path;
}

/**
 * Read a value from stdin. If stdin is a TTY, prompt with echo suppressed.
 * Otherwise consume one line from stdin.
 */
async function readValue(
  stdin: NodeJS.ReadableStream & { isTTY?: boolean },
  prompt: string
): Promise<string> {
  if (stdin.isTTY) {
    // Shared no-echo reader (cli/hidden-prompt.ts) — one source for every
    // custody verb that must not echo a secret. Behavior is byte-identical to
    // the private reader this replaced (prompt on stderr, Ctrl-C exits 130).
    return await promptHiddenLine(stdin as unknown as RawModeStdin, prompt);
  }
  // Non-TTY: consume first line from stdin.
  return await readFirstLine(stdin);
}

async function readFirstLine(stdin: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: stdin });
    let resolved = false;
    const finish = (value: string) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(deadline);
      try { rl.close(); } catch { /* already closed */ }
      resolve(value);
    };
    const deadline = setTimeout(() => {
      // Don't hang forever when stdin is opened but never produces input
      // (the rc.1 soak failure mode). An empty return triggers the
      // "Aborted: empty value" path with a non-zero exit code.
      finish("");
    }, STDIN_READ_DEADLINE_MS);
    rl.once("line", (line) => finish(line));
    rl.once("close", () => finish(""));
    rl.once("error", (e) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(deadline);
      reject(e);
    });
  });
}
