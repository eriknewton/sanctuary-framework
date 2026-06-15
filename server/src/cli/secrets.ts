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
 */

import { createInterface } from "node:readline";
import type { SecretScope } from "../l3-disclosure/broker/backend-interface.js";
import {
  openBroker,
  loadBrokerPolicyRaw,
  saveBrokerPolicy,
} from "../l3-disclosure/broker/open.js";

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

export async function runSecretsCommand(args: SecretsArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin = args.stdin ?? process.stdin;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
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
  const scopeFlag = parseFlag(argv, "--scope");
  const ttlFlag = parseFlag(argv, "--ttl");
  const scope: SecretScope = (scopeFlag as SecretScope | undefined) ?? "read";
  if (scope !== "read" && scope !== "rotate") {
    ctx.err.write(`--scope must be "read" or "rotate" (got ${scopeFlag})\n`);
    return 2;
  }
  const ttl = ttlFlag ? Number(ttlFlag) : undefined;
  if (ttl !== undefined && (!Number.isFinite(ttl) || ttl <= 0)) {
    ctx.err.write(`--ttl must be a positive integer (got ${ttlFlag})\n`);
    return 2;
  }

  // Update policy file + in-process broker (so running daemons pick up at next
  // reload; the CLI-local broker gets the grant for audit purposes).
  const storage = ctx.args.storagePath ?? (await defaultStoragePath());
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

// ── audit ───────────────────────────────────────────────────────────

async function cmdAudit(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream; args: SecretsArgs }
): Promise<number> {
  const since = parseFlag(argv, "--since");
  const limit = Number(parseFlag(argv, "--limit") ?? "200");
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

function parseFlag(argv: string[], name: string): string | undefined {
  const idx = argv.indexOf(name);
  if (idx === -1) return undefined;
  return argv[idx + 1];
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
    return await promptSilently(stdin as unknown as NodeJS.ReadStream, prompt);
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

async function promptSilently(stdin: NodeJS.ReadStream, prompt: string): Promise<string> {
  process.stderr.write(`${prompt}: `);
  stdin.setRawMode?.(true);
  stdin.resume();
  return await new Promise<string>((resolve) => {
    let buf = "";
    const onData = (chunk: Buffer) => {
      const s = chunk.toString("utf8");
      for (const ch of s) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode?.(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stderr.write("\n");
          resolve(buf);
          return;
        }
        if (ch === "\u0003") {
          // Ctrl-C
          process.exit(130);
        }
        if (ch === "\u007f" || ch === "\b") {
          // Backspace
          buf = buf.slice(0, -1);
        } else {
          buf += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}
