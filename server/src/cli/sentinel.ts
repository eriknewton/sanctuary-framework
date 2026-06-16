/**
 * Sanctuary v1.3 WP-V1.3-1 `sanctuary sentinel` CLI subcommand.
 *
 * Operator-facing surface for the Sentinel Baseline Pack (Castle
 * Layer 2 anchor). Subscribe/unsubscribe writes the persistent
 * subscription file; the running server reads this file on next boot
 * to populate its dispatcher. Findings are read from the encrypted
 * findings store via the same fortress passphrase as `sanctuary
 * secrets`.
 *
 * Subcommands:
 *   list                              Catalog of available sentinels.
 *   list-subscribed                   Subscriptions on this fortress.
 *   subscribe <sentinel-id>           Opt in.
 *   unsubscribe <sentinel-id>         Opt out.
 *   findings [opts]                   Read recent findings.
 *     --since <iso>                     Filter by observed_at >= iso.
 *     --severity <info|warn|alert>      Filter by severity.
 *     --sentinel-id <id>                Filter by emitting sentinel.
 *     --agent-id <id>                   Filter by agent attribution.
 *     --limit <n>                       Cap result count (default 100).
 */

import { loadConfig } from "../config.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import {
  loadSentinelSubscriptions,
  saveSentinelSubscriptions,
} from "../sentinel/subscription-store.js";
import { PHI1_BASELINE_CATALOG } from "../sentinel/sentinels/index.js";
import type { SentinelSeverity } from "../sentinel/types.js";
import { AuditLog } from "../operational/audit-log.js";

export interface SentinelArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  passphrase?: string;
  storagePath?: string;
}

export async function runSentinelCommand(args: SentinelArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
  }

  try {
    switch (sub) {
      case "list":
        return cmdList(out);
      case "list-subscribed":
        return await cmdListSubscribed(rest, { out, err, args });
      case "subscribe":
        return await cmdSubscribe(rest, { out, err, args });
      case "unsubscribe":
        return await cmdUnsubscribe(rest, { out, err, args });
      case "findings":
        return await cmdFindings(rest, { out, err, args });
      default:
        err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary sentinel: ${msg}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary sentinel <command> [args]

  list                                Show the Phi-1 catalog of available
                                      sentinels (egress-volume only at v1.3
                                      Phi-1; more land in Phi-2 ... Phi-5).
  list-subscribed                     Show which sentinels this fortress has
                                      opted into. Loads from
                                      <storage>/sentinel-subscriptions.json.
  subscribe <sentinel-id>             Opt in. Writes the subscription file.
                                      The server picks it up on next boot.
  unsubscribe <sentinel-id>           Opt out.
  findings [opts]                     Read recent findings. Decrypts the
                                      sentinel findings store (uses the
                                      same passphrase as the fortress master
                                      key).
    --since <iso>                       Filter observed_at >= iso.
    --severity <info|warn|alert>        Filter by severity.
    --sentinel-id <id>                  Filter by emitting sentinel.
    --agent-id <id>                     Filter by agent attribution.
    --limit <n>                         Cap result count (default 100).
`);
}

function cmdList(out: NodeJS.WritableStream): number {
  for (const entry of PHI1_BASELINE_CATALOG) {
    out.write(`${entry.sentinelId}\n  ${entry.description}\n`);
  }
  if (PHI1_BASELINE_CATALOG.length === 0) {
    out.write("(no sentinels registered)\n");
  }
  return 0;
}

async function cmdListSubscribed(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: SentinelArgs;
  },
): Promise<number> {
  void argv;
  const storagePath = await resolveStoragePath(ctx.args);
  const subscribed = await loadSentinelSubscriptions(storagePath);
  if (subscribed.size === 0) {
    ctx.out.write("(no subscriptions)\n");
    return 0;
  }
  for (const id of [...subscribed].sort()) {
    ctx.out.write(`${id}\n`);
  }
  return 0;
}

async function cmdSubscribe(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: SentinelArgs;
  },
): Promise<number> {
  const sentinelId = argv[0];
  if (!sentinelId) {
    ctx.err.write("subscribe requires a sentinel-id\n");
    return 2;
  }
  const storagePath = await resolveStoragePath(ctx.args);
  const known = PHI1_BASELINE_CATALOG.find(
    (entry) => entry.sentinelId === sentinelId,
  );
  if (!known) {
    try {
      const masterKey = await deriveSentinelMasterKey(ctx.args);
      const storage = new FilesystemStorage(`${storagePath}/state`);
      const fortressId = fortressIdFromStoragePath(storagePath);
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.append("l2", "sentinel.subscribe", `fortress:${fortressId}`, {
        sentinel_id: sentinelId,
        subscription_path: `${storagePath}/sentinel-subscriptions.json`,
      }, "failure");
    } catch { /* audit best-effort */ }
    ctx.err.write(`Unknown sentinel: ${sentinelId}\n`);
    return 2;
  }
  const subscribed = await loadSentinelSubscriptions(storagePath);
  if (subscribed.has(sentinelId)) {
    ctx.out.write(`Already subscribed: ${sentinelId}\n`);
    return 0;
  }
  subscribed.add(sentinelId);
  await saveSentinelSubscriptions(storagePath, subscribed);
  const masterKey = await deriveSentinelMasterKey(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const auditLog = new AuditLog(storage, masterKey);
  await auditLog.append("l2", "sentinel.subscribe", `fortress:${fortressId}`, {
    sentinel_id: sentinelId,
    subscription_path: `${storagePath}/sentinel-subscriptions.json`,
  });
  ctx.out.write(
    `Subscribed: ${sentinelId}\nRestart Sanctuary or wait for the next dispatcher tick to begin evaluation.\n`,
  );
  return 0;
}

async function cmdUnsubscribe(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: SentinelArgs;
  },
): Promise<number> {
  const sentinelId = argv[0];
  if (!sentinelId) {
    ctx.err.write("unsubscribe requires a sentinel-id\n");
    return 2;
  }
  const storagePath = await resolveStoragePath(ctx.args);
  const subscribed = await loadSentinelSubscriptions(storagePath);
  if (!subscribed.has(sentinelId)) {
    ctx.out.write(`Not subscribed: ${sentinelId}\n`);
    return 0;
  }
  subscribed.delete(sentinelId);
  await saveSentinelSubscriptions(storagePath, subscribed);
  const masterKey = await deriveSentinelMasterKey(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const auditLog = new AuditLog(storage, masterKey);
  await auditLog.append("l2", "sentinel.unsubscribe", `fortress:${fortressId}`, {
    sentinel_id: sentinelId,
    subscription_path: `${storagePath}/sentinel-subscriptions.json`,
  });
  ctx.out.write(`Unsubscribed: ${sentinelId}\n`);
  return 0;
}

async function cmdFindings(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: SentinelArgs;
  },
): Promise<number> {
  const filters = parseFindingFilters(argv);
  const storagePath = await resolveStoragePath(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);

  let passphrase = ctx.args.passphrase ?? process.env["SANCTUARY_PASSPHRASE"];
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase();
    passphrase = resolved.value;
  }
  // Unified custody (master-custody.ts): never derive a fortress master
  // verb-locally — a local derivation can diverge from the envelope.
  const masterKey = await resolveCliMasterKey(storage, {
    passphrase,
    bootstrap: true,
    storagePathHint: storagePath,
  });
  const fortressId = fortressIdFromStoragePath(storagePath);
  const store = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const findings = await store.listFindings({
    limit: filters.limit ?? 100,
    ...(filters.since !== undefined ? { since: filters.since } : {}),
    ...(filters.severity !== undefined ? { severity: filters.severity } : {}),
    ...(filters.sentinelId !== undefined
      ? { sentinelId: filters.sentinelId }
      : {}),
    ...(filters.agentId !== undefined ? { agentId: filters.agentId } : {}),
  });
  if (findings.length === 0) {
    ctx.out.write("(no findings)\n");
    return 0;
  }
  for (const finding of findings) {
    ctx.out.write(
      `[${finding.observed_at}] ${finding.severity.toUpperCase()} ${finding.sentinel_id}${finding.agent_id ? ` (agent ${finding.agent_id})` : ""}: ${finding.summary}\n`,
    );
  }
  return 0;
}

interface FindingFilters {
  since?: string;
  severity?: SentinelSeverity;
  sentinelId?: string;
  agentId?: string;
  limit?: number;
}

function parseFindingFilters(argv: string[]): FindingFilters {
  const filters: FindingFilters = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--since" && argv[i + 1]) {
      filters.since = argv[++i];
    } else if (arg === "--severity" && argv[i + 1]) {
      const next = argv[++i]!;
      if (next === "info" || next === "warn" || next === "alert") {
        filters.severity = next;
      }
    } else if (arg === "--sentinel-id" && argv[i + 1]) {
      filters.sentinelId = argv[++i];
    } else if (arg === "--agent-id" && argv[i + 1]) {
      filters.agentId = argv[++i];
    } else if (arg === "--limit" && argv[i + 1]) {
      const n = Number.parseInt(argv[++i]!, 10);
      if (!Number.isNaN(n) && n > 0) filters.limit = n;
    }
  }
  return filters;
}

async function resolveStoragePath(args: SentinelArgs): Promise<string> {
  if (args.storagePath) return args.storagePath;
  const config = await loadConfig();
  return config.storage_path;
}

async function deriveSentinelMasterKey(args: SentinelArgs): Promise<Uint8Array> {
  const storagePath = await resolveStoragePath(args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  let passphrase = args.passphrase ?? process.env["SANCTUARY_PASSPHRASE"];
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase();
    passphrase = resolved.value;
  }
  // Unified custody (master-custody.ts): see runFindings above.
  const masterKey = await resolveCliMasterKey(storage, {
    passphrase,
    bootstrap: true,
    storagePathHint: storagePath,
  });
  return masterKey;
}
