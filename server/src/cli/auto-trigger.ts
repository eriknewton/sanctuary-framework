/**
 * Sanctuary v1.3 WP-V1.3-7 Nu-1 `sanctuary auto-trigger` CLI.
 *
 * Operator-facing surface for the Auto-Trigger Ladder. Mirrors the
 * Chi-3 `sanctuary anomaly` shape: most operations derive the
 * fortress master key from the configured passphrase + storage path,
 * then operate directly on the encrypted ThresholdConfigStore. The
 * `cancel` subcommand is HTTP-delegated because pending rung-2
 * actions live in the running dispatcher's memory, not on disk.
 *
 * Subcommands:
 *
 *   rules list                              List rules + current rungs.
 *   rules show <rule_id>                    Full detail + history.
 *   rules promote <rule_id> --rule-type <t> Rung N -> N+1.
 *   rules demote <rule_id> --rule-type <t>  Rung N -> N-1.
 *   rules set-threshold <rule_id> --rule-type <t>
 *                                           Update warn/alert sigma +
 *     [--warn-sigma <n>] [--alert-sigma <n>] cancel-window.
 *     [--cancel-window <s>]
 *   cancel <finding_id>                     Cancel a pending rung-2
 *                                           action via HTTP. Reads
 *                                           SANCTUARY_DASHBOARD_URL +
 *                                           SANCTUARY_DASHBOARD_AUTH_TOKEN
 *                                           env vars.
 *
 * Promote/demote/set-threshold write to the encrypted store; the
 * running server picks up the new config on the NEXT finding (each
 * handleFinding call reads the rule config fresh, so no restart is
 * needed).
 */

import { loadConfig } from "../config.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  deriveMasterKey,
  type KeyDerivationParams,
} from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import { getOrCreatePassphrase } from "../wrap/passphrase.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";

import { ThresholdConfigStore } from "../auto-trigger/threshold-config-store.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import {
  ActionDispatcher,
  NotifyOperatorAction,
} from "../auto-trigger/action-dispatcher.js";
import { CalibrationSuggester } from "../auto-trigger/calibration-suggester.js";
import {
  AutoTriggerError,
  type AutoTriggerRuleType,
  type ThresholdOverrides,
} from "../auto-trigger/types.js";

export interface AutoTriggerArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  passphrase?: string;
  storagePath?: string;
}

export async function runAutoTriggerCommand(
  args: AutoTriggerArgs,
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
      case "rules":
        return await cmdRules(rest, { out, err, args });
      case "recommendations":
        return await cmdRecommendations(rest, { out, err, args });
      case "cancel":
        return await cmdCancel(rest, { out, err });
      default:
        err.write(`Unknown subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (cause) {
    const msg = cause instanceof Error ? cause.message : String(cause);
    err.write(`sanctuary auto-trigger: ${msg}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary auto-trigger <command> [args]

  rules list                                List rules + current rungs.
  rules show <rule_id>                      Full detail + history.
  rules promote <rule_id> --rule-type <t>   Rung N -> N+1.
  rules demote <rule_id> --rule-type <t>    Rung N -> N-1.
  rules set-threshold <rule_id> --rule-type <t>
    [--warn-sigma <n>] [--alert-sigma <n>]
    [--promotion-fire-count <n>] [--promotion-window-days <n>]
    [--demotion-cancel-count <n>]
    [--cancel-window <s>]                   Update overrides + window.
  recommendations list                      List active recommendations.
  recommendations show <rule_id>            Show a rule recommendation.
  recommendations accept <rule_id>          Apply operator-accepted change.
  recommendations reject <rule_id>          Suppress for 24h.
    [--cooldown-hours <n>]
  cancel <finding_id>                       Cancel a pending rung-2
                                            action (HTTP-delegated to
                                            the local dashboard).

Rule types: sentinel | anomaly | honeypot

Env (for cancel): SANCTUARY_DASHBOARD_URL, SANCTUARY_DASHBOARD_AUTH_TOKEN
`);
}

async function cmdRecommendations(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const sub = argv[0];
  if (!sub) {
    ctx.err.write("recommendations subcommand required\n");
    return 2;
  }
  const { suggester, auditLog, identityId } = await openCalibration(ctx.args);
  switch (sub) {
    case "list": {
      const recs = await suggester.listRecommendations({
        includeSuppressed: true,
      });
      if (recs.length === 0) {
        ctx.out.write("(no active auto-trigger recommendations)\n");
        return 0;
      }
      for (const rec of recs) {
        const suppressed = rec.suppressed_until
          ? ` suppressed-until=${rec.suppressed_until}`
          : "";
        ctx.out.write(
          `${rec.rule_id} [type: ${rec.rule_type}] ${rec.current_rung}->${rec.recommended_rung} confidence=${rec.confidence}${suppressed}\n`,
        );
      }
      return 0;
    }
    case "show": {
      const ruleId = argv[1];
      if (!ruleId) {
        ctx.err.write("recommendations show requires a rule_id\n");
        return 2;
      }
      const rec = await suggester.getRecommendation(ruleId, {
        includeSuppressed: true,
        includeNoChange: true,
      });
      if (!rec) {
        ctx.err.write(`rule not found: ${ruleId}\n`);
        return 1;
      }
      ctx.out.write(JSON.stringify(rec, null, 2) + "\n");
      return 0;
    }
    case "accept": {
      const ruleId = argv[1];
      if (!ruleId) {
        ctx.err.write("recommendations accept requires a rule_id\n");
        return 2;
      }
      const result = await suggester.acceptRecommendation(ruleId);
      await auditLog.append("l2", "auto-trigger.recommendations.accept", identityId, {
        rule_id: ruleId,
        rule_type: result.recommendation.rule_type,
        current_rung: result.recommendation.current_rung,
        recommended_rung: result.recommendation.recommended_rung,
        confidence: result.recommendation.confidence,
      });
      ctx.out.write(
        `Accepted ${ruleId}: rung ${result.recommendation.current_rung} -> ${result.recommendation.recommended_rung}\n`,
      );
      return 0;
    }
    case "reject": {
      const ruleId = argv[1];
      if (!ruleId) {
        ctx.err.write("recommendations reject requires a rule_id\n");
        return 2;
      }
      const cooldown = parseNumberFlag(argv, "--cooldown-hours");
      const result = await suggester.rejectRecommendation(ruleId, cooldown);
      await auditLog.append("l2", "auto-trigger.recommendations.reject", identityId, {
        rule_id: ruleId,
        suppressed_until: result.suppressed_until,
        cooldown_hours: cooldown ?? 24,
      });
      ctx.out.write(
        `Rejected ${ruleId}: suppressed until ${result.suppressed_until}\n`,
      );
      return 0;
    }
    default:
      ctx.err.write(`Unknown recommendations subcommand: ${sub}\n`);
      return 2;
  }
}

async function cmdRules(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const sub = argv[0];
  if (!sub) {
    ctx.err.write("rules subcommand required\n");
    return 2;
  }
  switch (sub) {
    case "list":
      return await cmdRulesList(ctx);
    case "show":
      return await cmdRulesShow(argv.slice(1), ctx);
    case "promote":
      return await cmdRulesPromote(argv.slice(1), ctx);
    case "demote":
      return await cmdRulesDemote(argv.slice(1), ctx);
    case "set-threshold":
      return await cmdRulesSetThreshold(argv.slice(1), ctx);
    default:
      ctx.err.write(`Unknown rules subcommand: ${sub}\n`);
      return 2;
  }
}

async function cmdRulesList(ctx: {
  out: NodeJS.WritableStream;
  args: AutoTriggerArgs;
}): Promise<number> {
  const { store } = await openStore(ctx.args);
  const ids = await store.listRuleIds();
  if (ids.length === 0) {
    ctx.out.write("(no rules configured; defaults are Rung 1 / no overrides)\n");
    return 0;
  }
  for (const id of ids) {
    const config = await store.get(id);
    if (!config) continue;
    const overrides =
      Object.keys(config.threshold_overrides).length === 0
        ? "defaults"
        : JSON.stringify(config.threshold_overrides);
    ctx.out.write(
      `${id} [type: ${config.rule_type}] rung=${config.current_rung} cancel-window=${config.cancel_window_seconds}s overrides=${overrides}\n`,
    );
  }
  return 0;
}

async function cmdRulesShow(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const ruleId = argv[0];
  if (!ruleId) {
    ctx.err.write("show requires a rule_id\n");
    return 2;
  }
  const { store } = await openStore(ctx.args);
  const config = await store.get(ruleId);
  if (!config) {
    ctx.err.write(`rule not found: ${ruleId}\n`);
    return 1;
  }
  ctx.out.write(JSON.stringify(config, null, 2) + "\n");
  return 0;
}

async function cmdRulesPromote(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const ruleId = argv[0];
  const ruleType = parseRuleType(flagValue(argv, "--rule-type"));
  if (!ruleId) {
    ctx.err.write("promote requires a rule_id\n");
    return 2;
  }
  if (!ruleType) {
    ctx.err.write(
      "promote requires --rule-type (sentinel|anomaly|honeypot)\n",
    );
    return 2;
  }
  const { store, storage, masterKey, fortressId } = await openStore(ctx.args);
  const identityId = process.env["SANCTUARY_IDENTITY_ID"] ?? `fortress:${fortressId}`;
  try {
    const before = await store.get(ruleId);
    const after = await store.promote(ruleId, ruleType);
    const auditLog = new AuditLog(storage, masterKey);
    await auditLog.append("l2", "auto-trigger.rules.promote", identityId, {
      rule_id: ruleId,
      rule_type: ruleType,
      before_rung: before?.current_rung ?? null,
      after_rung: after.current_rung,
    });
    ctx.out.write(`Promoted ${ruleId} -> rung ${after.current_rung}\n`);
    return 0;
  } catch (err) {
    if (err instanceof AutoTriggerError) {
      ctx.err.write(`${err.code}: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

async function cmdRulesDemote(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const ruleId = argv[0];
  const ruleType = parseRuleType(flagValue(argv, "--rule-type"));
  if (!ruleId) {
    ctx.err.write("demote requires a rule_id\n");
    return 2;
  }
  if (!ruleType) {
    ctx.err.write(
      "demote requires --rule-type (sentinel|anomaly|honeypot)\n",
    );
    return 2;
  }
  const { store, storage, masterKey, fortressId } = await openStore(ctx.args);
  const identityId = process.env["SANCTUARY_IDENTITY_ID"] ?? `fortress:${fortressId}`;
  try {
    const before = await store.get(ruleId);
    const after = await store.demote(ruleId, ruleType);
    const auditLog = new AuditLog(storage, masterKey);
    await auditLog.append("l2", "auto-trigger.rules.demote", identityId, {
      rule_id: ruleId,
      rule_type: ruleType,
      before_rung: before?.current_rung ?? null,
      after_rung: after.current_rung,
    });
    ctx.out.write(`Demoted ${ruleId} -> rung ${after.current_rung}\n`);
    return 0;
  } catch (err) {
    if (err instanceof AutoTriggerError) {
      ctx.err.write(`${err.code}: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

async function cmdRulesSetThreshold(
  argv: string[],
  ctx: {
    out: NodeJS.WritableStream;
    err: NodeJS.WritableStream;
    args: AutoTriggerArgs;
  },
): Promise<number> {
  const ruleId = argv[0];
  const ruleType = parseRuleType(flagValue(argv, "--rule-type"));
  if (!ruleId) {
    ctx.err.write("set-threshold requires a rule_id\n");
    return 2;
  }
  if (!ruleType) {
    ctx.err.write(
      "set-threshold requires --rule-type (sentinel|anomaly|honeypot)\n",
    );
    return 2;
  }
  const warnSigma = parseNumberFlag(argv, "--warn-sigma");
  const alertSigma = parseNumberFlag(argv, "--alert-sigma");
  const promotionFireCount = parseNumberFlag(argv, "--promotion-fire-count");
  const promotionWindowDays = parseNumberFlag(argv, "--promotion-window-days");
  const demotionCancelCount = parseNumberFlag(argv, "--demotion-cancel-count");
  const cancelWindow = parseNumberFlag(argv, "--cancel-window");
  const overrides: ThresholdOverrides = {};
  if (warnSigma !== undefined) overrides.warn_sigma = warnSigma;
  if (alertSigma !== undefined) overrides.alert_sigma = alertSigma;
  if (promotionFireCount !== undefined) {
    overrides.promotion_fire_count = Math.floor(promotionFireCount);
  }
  if (promotionWindowDays !== undefined) {
    overrides.promotion_window_days = Math.floor(promotionWindowDays);
  }
  if (demotionCancelCount !== undefined) {
    overrides.demotion_cancel_count = Math.floor(demotionCancelCount);
  }
  if (
    Object.keys(overrides).length === 0 &&
    cancelWindow === undefined
  ) {
    ctx.err.write(
      "set-threshold requires at least one of --warn-sigma, --alert-sigma, --cancel-window\n",
    );
    return 2;
  }
  const { store, storage, masterKey, fortressId } = await openStore(ctx.args);
  const identityId = process.env["SANCTUARY_IDENTITY_ID"] ?? `fortress:${fortressId}`;
  const patch: Parameters<typeof store.updateConfig>[2] = {};
  if (Object.keys(overrides).length > 0) patch.threshold_overrides = overrides;
  if (cancelWindow !== undefined) patch.cancel_window_seconds = cancelWindow;
  const before = await store.get(ruleId);
  const after = await store.updateConfig(ruleId, ruleType, patch);
  const auditLog = new AuditLog(storage, masterKey);
  await auditLog.append("l2", "auto-trigger.rules.set-threshold", identityId, {
    rule_id: ruleId,
    rule_type: ruleType,
    before: {
      threshold_overrides: before?.threshold_overrides ?? {},
      cancel_window_seconds: before?.cancel_window_seconds ?? null,
    },
    after: {
      threshold_overrides: after.threshold_overrides,
      cancel_window_seconds: after.cancel_window_seconds,
    },
  });
  ctx.out.write(
    `Updated ${ruleId}: overrides=${JSON.stringify(after.threshold_overrides)} cancel-window=${after.cancel_window_seconds}s\n`,
  );
  return 0;
}

async function cmdCancel(
  argv: string[],
  ctx: { out: NodeJS.WritableStream; err: NodeJS.WritableStream },
): Promise<number> {
  const findingId = argv[0];
  if (!findingId) {
    ctx.err.write("cancel requires a finding_id\n");
    return 2;
  }
  const baseUrl = process.env["SANCTUARY_DASHBOARD_URL"] ?? "http://127.0.0.1:3501";
  const token = process.env["SANCTUARY_DASHBOARD_AUTH_TOKEN"];
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/auto-trigger/cancel/${encodeURIComponent(findingId)}`, {
      method: "POST",
      headers,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    ctx.err.write(`cancel: cannot reach dashboard at ${baseUrl}: ${msg}\n`);
    return 1;
  }
  if (res.status === 200) {
    ctx.out.write(`Canceled pending action: ${findingId}\n`);
    return 0;
  }
  if (res.status === 404) {
    ctx.err.write(
      `No pending action for ${findingId} (window may have expired)\n`,
    );
    return 1;
  }
  if (res.status === 401) {
    ctx.err.write(
      `cancel: unauthorized (set SANCTUARY_DASHBOARD_AUTH_TOKEN)\n`,
    );
    return 1;
  }
  ctx.err.write(`cancel: HTTP ${res.status}\n`);
  return 1;
}

function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  return argv[i + 1];
}

function parseNumberFlag(argv: string[], name: string): number | undefined {
  const raw = flagValue(argv, name);
  if (raw === undefined) return undefined;
  const n = Number.parseFloat(raw);
  if (Number.isNaN(n)) return undefined;
  return n;
}

function parseRuleType(raw: string | undefined): AutoTriggerRuleType | null {
  if (raw === "sentinel" || raw === "anomaly" || raw === "honeypot") return raw;
  return null;
}

async function resolveStoragePath(args: AutoTriggerArgs): Promise<string> {
  if (args.storagePath) return args.storagePath;
  const config = await loadConfig();
  return config.storage_path;
}

async function openStore(
  args: AutoTriggerArgs,
): Promise<{
  store: ThresholdConfigStore;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  fortressId: string;
}> {
  const storagePath = await resolveStoragePath(args);
  const storage = new FilesystemStorage(`${storagePath}/state`);
  let passphrase = args.passphrase ?? process.env["SANCTUARY_PASSPHRASE"];
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase();
    passphrase = resolved.value;
  }
  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) existingParams = JSON.parse(bytesToString(raw));
  } catch {
    /* first run; nothing to read */
  }
  const { key: masterKey, params } = await deriveMasterKey(
    passphrase,
    existingParams,
  );
  if (!existingParams) {
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params)),
    );
  }
  const fortressId = fortressIdFromStoragePath(storagePath);
  const store = new ThresholdConfigStore({
    storage,
    masterKey,
    fortressId,
  });
  return { store, storage, masterKey, fortressId };
}

async function openCalibration(
  args: AutoTriggerArgs,
): Promise<{ suggester: CalibrationSuggester; auditLog: AuditLog; identityId: string }> {
  const { store, storage, masterKey, fortressId } = await openStore(args);
  const auditLog = new AuditLog(storage, masterKey);
  const identityId = process.env["SANCTUARY_IDENTITY_ID"] ?? `fortress:${fortressId}`;
  const action = new NotifyOperatorAction(auditLog, identityId, fortressId);
  const dispatcher = new ActionDispatcher({
    store,
    action,
    auditLog,
    fortressId,
    identityId,
  });
  const suggester = new CalibrationSuggester({
    store,
    dispatcher,
    auditLog,
    fortressId,
    identityId,
    tickIntervalMs: 0,
  });
  return { suggester, auditLog, identityId };
}
