/**
 * sanctuary audit
 *
 * Read-only audit-log inspection commands.
 */

import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  AuditIntegrityError,
  AuditLog,
  type AuditEntry,
  type AuditIntegrityFinding,
} from "../operational/audit-log.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { resolveStoragePath } from "../paths.js";
import { consumeFlagValue } from "./argv.js";

export interface AuditCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

interface SearchOptions {
  types: string[];
  since?: string;
  until?: string;
  actor?: string;
  /**
   * Filter to entries whose `details.request_id` matches exactly.
   *
   * This is the operator's redemption path for a server-minted correlation id.
   * Endpoints that must not tell a caller WHICH check failed (the pre-session
   * federation reissue route) return an opaque id instead and audit the precise
   * reason locally; this flag turns that id back into the reason for someone who
   * can already open the fortress. Without it the lookup is a manual scan of
   * `--json` output, which is exactly the tax the drills paid.
   */
  requestId?: string;
  limit: number;
  json: boolean;
  fortress?: string;
  passphrase?: string;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runAuditCommand(args: AuditCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(sub ? out : err);
    return sub ? 0 : 2;
  }

  if (sub !== "search") {
    write(err, `Unknown audit command: ${sub}\n`);
    printUsage(err);
    return 2;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    printSearchUsage(out);
    return 0;
  }

  let opts: SearchOptions | undefined;
  let masterKey: Uint8Array | undefined;
  try {
    opts = parseSearchOptions(rest);
    const searchOpts = opts;
    const env = args.env ?? process.env;
    const storagePath = searchOpts.fortress ?? resolveStoragePath(env);
    const storage = new FilesystemStorage(join(storagePath, "state"));
    masterKey = await resolveMasterKey(storage, searchOpts, env);
    const auditLog = new AuditLog(storage, masterKey);
    const result = await auditLog.query({
      ...(searchOpts.since ? { since: searchOpts.since } : {}),
      limit: Number.MAX_SAFE_INTEGER,
    });

    const untilMs = searchOpts.until ? Date.parse(searchOpts.until) : undefined;
    let entries = result.entries;
    if (searchOpts.types.length > 0) {
      const wanted = new Set(searchOpts.types);
      entries = entries.filter((entry) => wanted.has(entry.operation));
    }
    if (untilMs !== undefined) {
      entries = entries.filter((entry) => Date.parse(entry.timestamp) <= untilMs);
    }
    if (searchOpts.actor) {
      entries = entries.filter((entry) => entry.identity_id === searchOpts.actor);
    }
    if (searchOpts.requestId) {
      entries = entries.filter(
        (entry) => entry.details?.request_id === searchOpts.requestId,
      );
    }
    const total = entries.length;
    entries = entries.slice(-searchOpts.limit);

    // audit-chokepoint-exempt: fail-closed WARNING surface, findings are printed
    // to the operator and forwarded in the JSON; never a chain-verified claim.
    const findings = result.integrity_findings;
    if (findings.length > 0) {
      printIntegrityWarning(err, findings);
    }

    if (searchOpts.json) {
      write(
        out,
        JSON.stringify(
          {
            entries,
            total,
            ...(findings.length > 0 ? { integrity_findings: findings } : {}),
          },
          null,
          2
        ) + "\n"
      );
    } else {
      printTable(out, entries, searchOpts.requestId !== undefined);
    }
    return findings.length > 0 ? 1 : 0;
  } catch (error) {
    if (error instanceof AuditIntegrityError) {
      printIntegrityWarning(err, error.findings);
      if (opts?.json) {
        write(
          out,
          JSON.stringify({ entries: [], total: 0, integrity_findings: error.findings }, null, 2) +
            "\n"
        );
      }
      return 1;
    }
    write(err, `sanctuary audit search: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  } finally {
    masterKey?.fill(0);
  }
}

function printIntegrityWarning(
  err: Writable,
  findings: readonly AuditIntegrityFinding[]
): void {
  const kinds = [...new Set(findings.map((finding) => finding.kind))].join(", ");
  write(
    err,
    `AUDIT INTEGRITY WARNING: ${findings.length} finding(s) detected (${kinds}); results may be incomplete or tampered.\n`
  );
}

export function parseSearchOptions(argv: string[]): SearchOptions {
  const types: string[] = [];
  let since: string | undefined;
  let until: string | undefined;
  let actor: string | undefined;
  let requestId: string | undefined;
  let limit = 50;
  let json = false;
  let fortress: string | undefined;
  let passphrase: string | undefined;

  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; a search run against
  // the wrong fortress is a constraint-5 violation, not merely a UX papercut.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    throw new Error(consumedFortress.error);
  }
  fortress = consumedFortress.value;
  const filteredArgv = consumedFortress.argv;

  for (let i = 0; i < filteredArgv.length; i++) {
    const arg = filteredArgv[i]!;
    if (arg === "--json") {
      json = true;
    } else if (arg === "--type") {
      for (const type of requireValue(filteredArgv, ++i, "--type").split(",")) {
        if (type.trim()) types.push(type.trim());
      }
    } else if (arg.startsWith("--type=")) {
      for (const type of arg.slice("--type=".length).split(",")) {
        if (type.trim()) types.push(type.trim());
      }
    } else if (arg === "--since") {
      since = parseTimeExpression(requireValue(filteredArgv, ++i, "--since"));
    } else if (arg.startsWith("--since=")) {
      since = parseTimeExpression(arg.slice("--since=".length));
    } else if (arg === "--until") {
      until = parseTimeExpression(requireValue(filteredArgv, ++i, "--until"));
    } else if (arg.startsWith("--until=")) {
      until = parseTimeExpression(arg.slice("--until=".length));
    } else if (arg === "--actor") {
      actor = requireValue(filteredArgv, ++i, "--actor");
    } else if (arg.startsWith("--actor=")) {
      actor = arg.slice("--actor=".length);
    } else if (arg === "--request-id") {
      requestId = requireValue(filteredArgv, ++i, "--request-id");
    } else if (arg.startsWith("--request-id=")) {
      requestId = arg.slice("--request-id=".length);
    } else if (arg === "--limit") {
      limit = parseLimit(requireValue(filteredArgv, ++i, "--limit"));
    } else if (arg.startsWith("--limit=")) {
      limit = parseLimit(arg.slice("--limit=".length));
    } else if (arg === "--passphrase") {
      passphrase = requireValue(filteredArgv, ++i, "--passphrase");
    } else if (arg.startsWith("--passphrase=")) {
      passphrase = arg.slice("--passphrase=".length);
    } else {
      throw new Error(`unknown option: ${arg}`);
    }
  }
  return { types, since, until, actor, requestId, limit, json, fortress, passphrase };
}

export function parseTimeExpression(value: string): string {
  const exact = Date.parse(value);
  if (!Number.isNaN(exact)) return new Date(exact).toISOString();
  const match = /^(\d+)([smhdw])$/.exec(value.trim());
  if (!match) {
    throw new Error(`invalid time expression: ${value}`);
  }
  const amount = Number(match[1]);
  const unit = match[2];
  const multiplier =
    unit === "s" ? 1_000 :
    unit === "m" ? 60_000 :
    unit === "h" ? 3_600_000 :
    unit === "d" ? 86_400_000 :
    604_800_000;
  return new Date(Date.now() - amount * multiplier).toISOString();
}

async function resolveMasterKey(
  storage: FilesystemStorage,
  opts: SearchOptions,
  env: NodeJS.ProcessEnv,
): Promise<Uint8Array> {
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  if (env.SANCTUARY_RECOVERY_KEY) {
    return resolveCliMasterKey(storage, {
      recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    });
  }

  const passphrase = opts.passphrase ?? env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    throw new Error("requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY");
  }

  return resolveCliMasterKey(storage, { passphrase });
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary audit <command> [options]

Commands:
  search   Query the local audit log.
`,
  );
}

function printSearchUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary audit search [--type <event_type>] [--since <iso|relative>] [--until <iso|relative>] [--actor <id>] [--request-id <id>] [--limit <n>] [--json]

Options:
  --type <event_type>  Filter by operation. Repeat or comma-separate.
  --since <time>       ISO time or relative duration like 5m, 2h, 7d.
  --until <time>       ISO time or relative duration like 5m, 2h, 7d.
  --actor <id>         Filter by identity_id.
  --request-id <id>    Filter by details.request_id. Use this to look up the
                       reason behind a request id a client was handed in place
                       of a denial reason (e.g. a federation adopt refusal).
  --limit <n>          Maximum records to print. Defaults to 50.
  --fortress <path>    Override fortress path.
  --passphrase <val>   Passphrase for decrypting audit entries.
  --json               Emit JSON.
`,
  );
}

/**
 * `withReason` expands each row with its `reason` and `operator_next_step`.
 * Enabled for a `--request-id` lookup, where the whole point of the query is to
 * read those two fields: making the operator re-run with `--json` to see the
 * answer they asked for would leave the diagnosability gap half-closed.
 */
function printTable(
  out: Writable,
  entries: AuditEntry[],
  withReason = false,
): void {
  if (entries.length === 0) {
    write(out, "(no audit entries)\n");
    return;
  }
  write(out, "timestamp                    layer result  actor                         operation\n");
  for (const entry of entries) {
    write(
      out,
      `${entry.timestamp.padEnd(28)} ${entry.layer.padEnd(5)} ${entry.result.padEnd(7)} ${truncate(entry.identity_id, 29).padEnd(29)} ${entry.operation}\n`,
    );
    if (!withReason) continue;
    const reason = entry.details?.reason;
    if (typeof reason === "string") {
      write(out, `  reason: ${reason}\n`);
    }
    const nextStep = entry.details?.operator_next_step;
    if (typeof nextStep === "string") {
      write(out, `  next step: ${nextStep}\n`);
    }
  }
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}.`;
}

function parseLimit(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`--limit must be a positive integer (got ${value})`);
  }
  return parsed;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}
