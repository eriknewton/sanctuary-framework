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

import { createInterface } from "node:readline";
import type { SecretScope } from "../disclosure/broker/backend-interface.js";
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
