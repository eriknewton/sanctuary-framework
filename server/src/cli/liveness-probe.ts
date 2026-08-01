/**
 * `sanctuary liveness-probe`
 *
 * Runs one Telegram confined-round-trip probe cycle and prints the outcome.
 */

import { join } from "node:path";
import { Writable } from "node:stream";

import { resolveCliMasterKey } from "../core/master-custody.js";
import { AuditLog } from "../operational/audit-log.js";
import { resolveStoragePath } from "../paths.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  readTelegramLivenessProbeConfigFromFortress,
  runTelegramLivenessProbe,
  TelegramLivenessProbeConfigError,
  type TelegramLivenessProbeConfig,
} from "../castle-wall/provision/index.js";
import {
  cosLivenessFromProbeResult,
  type CosLivenessOutcome,
} from "../castle-wall/provision/orchestrate.js";

export interface LivenessProbeCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

interface LivenessProbeOptions {
  fortress?: string;
  passphrase?: string;
  recoveryKey?: string;
  timeoutMs?: number;
  json: boolean;
  help: boolean;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runLivenessProbeCommand(args: LivenessProbeCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  let parsed: LivenessProbeOptions;
  try {
    parsed = parseLivenessProbeArgs(args.argv);
  } catch (parseErr) {
    write(err, `${(parseErr as Error).message}\n`);
    printUsage(err);
    return 2;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const fortressPath = parsed.fortress ?? resolveStoragePath(env);
  let read;
  try {
    read = await readTelegramLivenessProbeConfigFromFortress({
      fortressPath,
      ...(process.getuid !== undefined ? { expectedOwnerUid: process.getuid() } : {}),
    });
  } catch (configErr) {
    write(err, `liveness-probe config error: ${(configErr as Error).message}\n`);
    return 2;
  }
  if (read.kind === "absent") {
    const result = cosLivenessFromProbeResult(undefined);
    printResult(out, result, parsed.json);
    return 1;
  }

  const config: TelegramLivenessProbeConfig = {
    ...read.config,
    ...(parsed.timeoutMs !== undefined ? { timeoutMs: parsed.timeoutMs } : {}),
  };
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  let masterKey: Uint8Array | undefined;
  try {
    const passphrase = parsed.passphrase ?? env.SANCTUARY_PASSPHRASE;
    const recoveryKey = parsed.recoveryKey ?? env.SANCTUARY_RECOVERY_KEY;
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: fortressPath,
    });
    const auditLog = new AuditLog(storage, masterKey);
    const probe = await runTelegramLivenessProbe({
      config,
      audit: auditLog,
      auditIdentityId: "liveness-probe",
    });
    await auditLog.flush();
    const result = cosLivenessFromProbeResult(probe);
    printResult(out, result, parsed.json);
    return probe.kind === "round_trip" ? 0 : 1;
  } catch (probeErr) {
    const isConfigError = probeErr instanceof TelegramLivenessProbeConfigError;
    write(
      err,
      `${isConfigError ? "liveness-probe config error" : "liveness-probe error"}: ${(probeErr as Error).message}\n`,
    );
    return 2;
  } finally {
    masterKey?.fill(0);
  }
}

function parseLivenessProbeArgs(argv: string[]): LivenessProbeOptions {
  const opts: LivenessProbeOptions = { json: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "--fortress") {
      opts.fortress = requireValue(argv, ++i, "--fortress");
    } else if (arg === "--passphrase") {
      opts.passphrase = requireValue(argv, ++i, "--passphrase");
    } else if (arg === "--recovery-key") {
      opts.recoveryKey = requireValue(argv, ++i, "--recovery-key");
    } else if (arg === "--timeout-ms") {
      opts.timeoutMs = parsePositiveInteger(requireValue(argv, ++i, "--timeout-ms"), "--timeout-ms");
    } else {
      throw new Error(`Unknown liveness-probe option: ${arg}`);
    }
  }
  return opts;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parsePositiveInteger(raw: string, flag: string): number {
  if (!/^\d+$/.test(raw)) throw new Error(`${flag} must be a positive integer`);
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return value;
}

function printResult(
  out: Writable,
  result: ReturnType<typeof cosLivenessFromProbeResult>,
  json: boolean,
): void {
  if (json) {
    write(out, `${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  write(out, `${formatLivenessProbeResultLine(result)}\n`);
}

export function formatLivenessProbeResultLine(result: CosLivenessOutcome): string {
  if (result.kind === "cos_liveness_verified") {
    return `verified: Telegram round trip verified on the confined path ` +
      `channel=${result.roundTrip.channel} request=${result.roundTrip.requestId} response=${result.roundTrip.responseId}`;
  }
  const detail = result.detail !== undefined ? ` detail=${result.detail}` : "";
  return `unverified reason=${result.reason}${detail}`;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary liveness-probe [--fortress <path>] [--passphrase <value> | --recovery-key <value>] [--timeout-ms <ms>] [--json]

Runs one Telegram confined-round-trip liveness probe using:
  <fortress>/config/liveness-probe/telegram.json

Exit codes:
  0  verified
  1  unverified
  2  config or custody error
`,
  );
}
