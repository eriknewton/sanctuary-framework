/**
 * Sanctuary v1.3 WP-V1.3-2 Chi-3 `sanctuary anomaly` CLI subcommand.
 *
 * Operator-facing surface for the Anomaly Detection Pipeline (Chi-1
 * foundation + Chi-2 classifiers). Mirrors the Phi-1
 * `sanctuary sentinel` pattern exactly: subscriptions are persisted
 * to `<storage>/anomaly-subscriptions.json`; the running server
 * reads this file on next boot to populate the dispatcher. Findings
 * + classifier-state are encrypted at rest and decrypted with the
 * fortress passphrase.
 *
 * Subcommands:
 *   detectors list                            Catalog of available
 *                                             detector + classifier
 *                                             tuples.
 *   list-subscribed                           Detector + classifier
 *                                             tuples this fortress
 *                                             has subscribed.
 *   status                                    Alias for list-subscribed.
 *   subscribe <detector-id> --classifier <id>
 *   unsubscribe <detector-id> --classifier <id>
 *   findings [opts]                           Read anomaly findings
 *                                             (filters: --since,
 *                                             --severity, --detector-id,
 *                                             --agent-id, --limit).
 *   findings show <finding-id>                Full drift-inspector
 *                                             detail.
 *   classifier-state <detector-id> --classifier <id>
 *                                             Per-agent training state.
 */

import { loadConfig } from "../config.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelSeverity } from "../sentinel/types.js";
import {
  ANOMALY_CATALOG,
  findCatalogEntry,
} from "../anomaly-detection/anomaly-catalog.js";
import {
  loadAnomalySubscriptions,
  saveAnomalySubscriptions,
  type AnomalySubscriptionTuple,
} from "../anomaly-detection/anomaly-subscription-store.js";
import { ClassifierStateStore } from "../anomaly-detection/classifier-state-store.js";
import { ANOMALY_SENTINEL_ID_PREFIX } from "../anomaly-detection/types.js";
import { AuditLog } from "../operational/audit-log.js";

export interface AnomalyArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  passphrase?: string;
  storagePath?: string;
}

export async function runAnomalyCommand(
  args: AnomalyArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const [sub, ...rest] = args.argv;

  if (!sub || sub === "--help" || sub === "-h") {
    printUsage(out);
    return 0;
  }

  try {
    switch (sub) {
      case "detectors":
        return cmdDetectors(rest, { out });
      case "list-subscribed":
      case "status":
        return await cmdListSubscribed({ out, args });
      case "subscribe":
        if (wantsHelp(rest)) {
          printAnomalySubscribeHelp(out);
          return 0;
        }
        return await cmdSubscribe(rest, { out, err, args });
      case "unsubscribe":
        return await cmdUnsubscribe(rest, { out, err, args });
      case "findings":
        return await cmdFindings(rest, { out, err, args });
      case "classifier-state":
        return await cmdClassifierState(rest, { out, err, args });
      default:
        err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    err.write(`sanctuary anomaly: ${msg}\n`);
    return 1;
  }
}

function wantsHelp(argv: string[]): boolean {
  return argv.includes("--help") || argv.includes("-h");
}

export function printAnomalySubscribeHelp(
  s: NodeJS.WritableStream = process.stdout,
): void {
  s.write(`sanctuary anomaly subscribe. Opt a fortress into an anomaly detector/classifier tuple.

Usage:
  sanctuary anomaly subscribe <detector-id> --classifier <id>

Description:
  Adds the detector/classifier tuple to this fortress's anomaly subscription
  file. The running server picks up the subscription on boot or the next
  dispatcher tick.

Arguments:
  <detector-id>        Detector identifier from "sanctuary anomaly detectors list".

Options:
  --classifier <id>   Classifier identifier paired with the detector.
  --help, -h          Show this help.

Examples:
  sanctuary anomaly detectors list
  sanctuary anomaly subscribe psi-drift --classifier baseline
`);
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary anomaly <command> [args]

  detectors list                          Catalog of available
                                          detector + classifier tuples.
  list-subscribed                         Subscriptions on this fortress.
  status                                  Alias for list-subscribed.
  subscribe <detector-id> --classifier <id>
                                          Opt in. Writes the
                                          subscription file; the server
                                          picks it up on next boot.
  unsubscribe <detector-id> --classifier <id>
                                          Opt out.
  findings [opts]                         Read anomaly findings.
    --since <iso>                           observed_at >= iso.
    --severity <info|warn|alert>            Filter by severity.
    --detector-id <id>                      Filter by emitting detector.
    --agent-id <id>                         Filter by agent attribution.
    --limit <n>                             Cap result count (default 100).
  findings show <finding-id>              Full drift-inspector detail.
  classifier-state <detector-id> --classifier <id>
                                          Per-agent training state.
`);
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  return argv[i + 1];
}

function cmdDetectors(
  argv: string[],
  ctx: { out: NodeJS.WritableStream },
): number {
  const sub = argv[0];
  if (sub !== undefined && sub !== "list") {
    ctx.out.write(`Unknown detectors subcommand: ${sub}\n`);
    return 2;
  }
  if (ANOMALY_CATALOG.length === 0) {
    ctx.out.write("(no detectors registered)\n");
    return 0;
  }
  for (const entry of ANOMALY_CATALOG) {
    ctx.out.write(
      `${entry.detectorId} [classifier: ${entry.classifierId}]\n  ${entry.description}\n`,
    );
  }
  return 0;
}

async function cmdListSubscribed(ctx: {
  out: NodeJS.WritableStream;
  args: AnomalyArgs;
}): Promise<number> {
  const storagePath = await resolveStoragePath(ctx.args);
  const subscribed = await loadAnomalySubscriptions(storagePath);
  if (subscribed.length === 0) {
    ctx.out.write("(no subscriptions)\n");
    return 0;
  }
  for (const t of subscribed) {
    ctx.out.write(`${t.detector_id} [classifier: ${t.classifier_id}]\n`);
  }
  return 0;
}

async function cmdSubscribe(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AnomalyArgs;
  },
): Promise<number> {
  const detectorId = argv[0];
  const classifierId = flagValue(argv, "--classifier");
  if (!detectorId) {
    ctx.err.write("subscribe requires a detector-id\n");
    return 2;
  }
  if (!classifierId) {
    ctx.err.write("subscribe requires --classifier <id>\n");
    return 2;
  }
  const storagePath = await resolveStoragePath(ctx.args);
  const entry = findCatalogEntry(detectorId, classifierId);
  if (!entry) {
    try {
      const masterKey = await deriveFortressMasterKey(ctx);
      const storage = new FilesystemStorage(`${storagePath}/state`);
      const fortressId = fortressIdFromStoragePath(storagePath);
      const auditLog = new AuditLog(storage, masterKey);
      await auditLog.append("l2", "anomaly.subscribe", `fortress:${fortressId}`, {
        detector_id: detectorId,
        classifier_id: classifierId,
        subscription_path: `${storagePath}/anomaly-subscriptions.json`,
      }, "failure");
    } catch { /* audit best-effort; do not mask the original error */ }
    ctx.err.write(
      `Unknown detector/classifier pair: ${detectorId} / ${classifierId}\n`,
    );
    return 2;
  }
  const subscribed = await loadAnomalySubscriptions(storagePath);
  const exists = subscribed.some(
    (t) =>
      t.detector_id === detectorId && t.classifier_id === classifierId,
  );
  if (exists) {
    ctx.out.write(
      `Already subscribed: ${detectorId} [classifier: ${classifierId}]\n`,
    );
    return 0;
  }
  subscribed.push({ detector_id: detectorId, classifier_id: classifierId });
  await saveAnomalySubscriptions(storagePath, subscribed);
  const masterKey = await deriveFortressMasterKey(ctx);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const auditLog = new AuditLog(storage, masterKey);
  await auditLog.append("l2", "anomaly.subscribe", `fortress:${fortressId}`, {
    detector_id: detectorId,
    classifier_id: classifierId,
    subscription_path: `${storagePath}/anomaly-subscriptions.json`,
  });
  ctx.out.write(
    `Subscribed: ${detectorId} [classifier: ${classifierId}]\nRestart Sanctuary or wait for the next dispatcher tick.\n`,
  );
  return 0;
}

async function cmdUnsubscribe(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AnomalyArgs;
  },
): Promise<number> {
  const detectorId = argv[0];
  const classifierId = flagValue(argv, "--classifier");
  if (!detectorId) {
    ctx.err.write("unsubscribe requires a detector-id\n");
    return 2;
  }
  if (!classifierId) {
    ctx.err.write("unsubscribe requires --classifier <id>\n");
    return 2;
  }
  const storagePath = await resolveStoragePath(ctx.args);
  const subscribed = await loadAnomalySubscriptions(storagePath);
  const filtered = subscribed.filter(
    (t) =>
      !(t.detector_id === detectorId && t.classifier_id === classifierId),
  );
  if (filtered.length === subscribed.length) {
    ctx.out.write(
      `Not subscribed: ${detectorId} [classifier: ${classifierId}]\n`,
    );
    return 0;
  }
  await saveAnomalySubscriptions(storagePath, filtered);
  const masterKey = await deriveFortressMasterKey(ctx);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const auditLog = new AuditLog(storage, masterKey);
  await auditLog.append("l2", "anomaly.unsubscribe", `fortress:${fortressId}`, {
    detector_id: detectorId,
    classifier_id: classifierId,
    subscription_path: `${storagePath}/anomaly-subscriptions.json`,
  });
  ctx.out.write(
    `Unsubscribed: ${detectorId} [classifier: ${classifierId}]\n`,
  );
  return 0;
}

async function cmdFindings(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AnomalyArgs;
  },
): Promise<number> {
  if (argv[0] === "show") {
    return await cmdFindingsShow(argv.slice(1), ctx);
  }
  const filters = parseFindingFilters(argv);
  const masterKey = await deriveFortressMasterKey(ctx);
  const storagePath = await resolveStoragePath(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const store = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const filterSentinelId =
    filters.detectorId !== undefined
      ? `${ANOMALY_SENTINEL_ID_PREFIX}${filters.detectorId}`
      : undefined;
  const allFindings = await store.listFindings({
    limit: filters.limit ?? 100,
    ...(filters.since !== undefined ? { since: filters.since } : {}),
    ...(filters.severity !== undefined ? { severity: filters.severity } : {}),
    ...(filterSentinelId !== undefined
      ? { sentinelId: filterSentinelId }
      : {}),
    ...(filters.agentId !== undefined ? { agentId: filters.agentId } : {}),
  });
  // Always narrow to anomaly:* prefix when no detector filter was set
  // so this CLI does not surface Phi-1 sentinel findings.
  const anomalyFindings =
    filterSentinelId !== undefined
      ? allFindings
      : allFindings.filter((f) =>
          f.sentinel_id.startsWith(ANOMALY_SENTINEL_ID_PREFIX),
        );
  if (anomalyFindings.length === 0) {
    ctx.out.write("(no findings)\n");
    return 0;
  }
  for (const finding of anomalyFindings) {
    const detectorId =
      (finding.details["detector_id"] as string | undefined) ?? "";
    const score = finding.details["anomaly_score"];
    const scoreStr = typeof score === "number" ? ` score=${score.toFixed(2)}` : "";
    ctx.out.write(
      `[${finding.observed_at}] ${finding.severity.toUpperCase()} ${detectorId}${finding.agent_id ? ` (agent ${finding.agent_id})` : ""}${scoreStr}: ${finding.summary}\n`,
    );
  }
  return 0;
}

async function cmdFindingsShow(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AnomalyArgs;
  },
): Promise<number> {
  const findingId = argv[0];
  if (!findingId) {
    ctx.err.write("findings show requires a finding-id\n");
    return 2;
  }
  const masterKey = await deriveFortressMasterKey(ctx);
  const storagePath = await resolveStoragePath(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const store = new SentinelFindingStore({ storage, masterKey, fortressId });
  const finding = await store.loadFinding(findingId);
  if (!finding) {
    ctx.err.write(`Finding not found: ${findingId}\n`);
    return 1;
  }
  if (!finding.sentinel_id.startsWith(ANOMALY_SENTINEL_ID_PREFIX)) {
    ctx.err.write(
      `Finding ${findingId} is not an anomaly finding; try sanctuary sentinel findings.\n`,
    );
    return 1;
  }
  ctx.out.write(JSON.stringify(finding, null, 2) + "\n");
  return 0;
}

async function cmdClassifierState(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AnomalyArgs;
  },
): Promise<number> {
  const detectorId = argv[0];
  const classifierId = flagValue(argv, "--classifier");
  if (!detectorId) {
    ctx.err.write("classifier-state requires a detector-id\n");
    return 2;
  }
  if (!classifierId) {
    ctx.err.write("classifier-state requires --classifier <id>\n");
    return 2;
  }
  const entry = findCatalogEntry(detectorId, classifierId);
  if (!entry) {
    ctx.err.write(
      `Unknown detector/classifier pair: ${detectorId} / ${classifierId}\n`,
    );
    return 2;
  }
  const masterKey = await deriveFortressMasterKey(ctx);
  const storagePath = await resolveStoragePath(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  const fortressId = fortressIdFromStoragePath(storagePath);
  const stateStore = new ClassifierStateStore({
    storage,
    masterKey,
    fortressId,
  });
  const agentIds = await stateStore.listAgents(classifierId);
  if (agentIds.length === 0) {
    ctx.out.write("(no classifier state yet)\n");
    return 0;
  }
  for (const agentId of agentIds) {
    try {
      const raw = await stateStore.loadState<{
        sample_count?: number;
      }>(classifierId, agentId);
      if (raw === null) continue;
      const sampleCount =
        typeof raw.sample_count === "number" ? raw.sample_count : "?";
      ctx.out.write(`${agentId}: sample_count=${sampleCount}\n`);
    } catch {
      ctx.out.write(`${agentId}: (load failed)\n`);
    }
  }
  return 0;
}

interface FindingFilters {
  since?: string;
  severity?: SentinelSeverity;
  detectorId?: string;
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
    } else if (arg === "--detector-id" && argv[i + 1]) {
      filters.detectorId = argv[++i];
    } else if (arg === "--agent-id" && argv[i + 1]) {
      filters.agentId = argv[++i];
    } else if (arg === "--limit" && argv[i + 1]) {
      const n = Number.parseInt(argv[++i]!, 10);
      if (!Number.isNaN(n) && n > 0) filters.limit = n;
    }
  }
  return filters;
}

async function resolveStoragePath(args: AnomalyArgs): Promise<string> {
  if (args.storagePath) return args.storagePath;
  const config = await loadConfig();
  return config.storage_path;
}

async function deriveFortressMasterKey(ctx: {
  args: AnomalyArgs;
}): Promise<Uint8Array> {
  const storagePath = await resolveStoragePath(ctx.args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  let passphrase = ctx.args.passphrase ?? process.env["SANCTUARY_PASSPHRASE"];
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase();
    passphrase = resolved.value;
  }
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  const masterKey = await resolveCliMasterKey(storage, {
    passphrase,
    bootstrap: true,
    storagePathHint: storagePath,
  });
  return masterKey;
}

export type { AnomalySubscriptionTuple };
