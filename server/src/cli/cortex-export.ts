/**
 * Sanctuary MCP Server -- `sanctuary cortex-export` CLI subcommand.
 *
 * OPERATOR-facing verb that drives the enforcement-event exporter
 * (`server/src/castle-wall/export/`) off the verified audit chain and delivers
 * the frozen `sanctuary.enforcement-event.v1` metadata stream to the configured
 * sink. It is the operator control for the "the wall enforces on the host; the
 * console sees every denial" rail (PANW Cortex content pack).
 *
 * The version string above and in the `--help` text below is PROSE describing
 * `ENFORCEMENT_EVENT_SCHEMA` in `castle-wall/export/schema.ts`, never a second
 * declaration. Nothing here parses or emits it; a `.v2` mint must update this
 * operator copy in the same PR or the help text will describe a stream shape
 * the exporter no longer produces.
 *
 * SAFE BY DEFAULT: with no `cortex-export.json` config file, or a `sink: "file"`
 * config, this writes the metadata stream LOCALLY (NDJSON to stdout or a file)
 * and touches NO network and needs NO approval. Turning on the OUTBOUND push
 * (`sink: "http"`) requires the operator config file to opt in with a pinned
 * https destination AND a Tier-1 approval at arming time (the gate prompts on a
 * TTY, denies on a non-interactive stream). This is the SAME gate class as
 * `state_export` / `castle_wall_observe_promote`.
 *
 * DURABLE + FAIL-CLOSED: delivery advances a durable cursor so a restart resumes
 * without a re-send storm and without a gap, and a transient sink failure is
 * retried within a bounded budget and then fails closed (never a silent drop,
 * never a fallback to a less-secure sink). All of that lives in the export
 * module; this verb only wires real fortress deps into it.
 *
 * The core is factored into `runExportPipeline` (fully injectable) so the wiring
 * is unit-testable hermetically -- no real `~/.sanctuary`, no real network.
 */

import { createHash } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { createInterface } from "node:readline/promises";

import { resolveStoragePath } from "../paths.js";
import { loadConfig } from "../config.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { AuditLog } from "../operational/audit-log.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { BaselineTracker } from "../principal-policy/baseline.js";
import { ApprovalGate } from "../principal-policy/gate.js";
import { loadPrincipalPolicy } from "../principal-policy/loader.js";
import type { ApprovalChannel } from "../principal-policy/approval-channel.js";
import type { ApprovalRequest, ApprovalResponse } from "../principal-policy/types.js";
import {
  EnforcementExporter,
  EnforcementExportStreamer,
  FileExportCursorStore,
  readExportConfig,
  stdoutLineWriter,
  type EnforcementEventMapOptions,
  type EnforcementExportConfig,
  type ExportApprover,
  type ExportAudit,
  type ExportCursorStore,
  type LineWriter,
  type StreamRunOutcome,
  type VerifiedChainSource,
} from "../castle-wall/export/index.js";
import { loadFortressProducerKey } from "../castle-wall/runtime/producer-signature.js";

export interface CortexExportCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function flagValue(argv: string[], name: string): string | undefined {
  const eq = argv.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name) || argv.some((a) => a.startsWith(`${name}=`));
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary cortex-export <command> [options]

Deliver Castle Wall's enforcement decisions to a security console as a frozen,
metadata-only event stream (sanctuary.enforcement-event.v1). Safe by default:
with no config, or a file-sink config, events are written LOCALLY and no network
is touched. Turning on the outbound push to an HTTP collector requires the
operator config file to opt in with a pinned https destination AND a Tier-1
approval at arming time.

Config file (operator-owned; the agent cannot read or write it):
  <fortress>/policy/egress/cortex-export.json
    { "sink": "file" }                       # default: local NDJSON, no network
    { "sink": "file", "file_path": "..." }   # local NDJSON to a file
    { "sink": "http", "enabled": true,       # outbound push (Tier-1 gated)
      "destination_url": "https://collector.example/xsiam" }

Commands:
  run      Read the config, arm the exporter (Tier-1 approval for an http sink),
           and export every new enforcement event since the last run.

Run "sanctuary cortex-export run --help" for options.
`,
  );
}

function printRunUsage(out: Writable): void {
  write(
    out,
    `sanctuary cortex-export run. Export new enforcement events to the configured sink.

Usage:
  sanctuary cortex-export run [--fortress <path>] [--passphrase <val>] [--json]

Reads <fortress>/policy/egress/cortex-export.json. A missing file means the safe
default: local NDJSON to stdout, no network, no approval. An http sink prompts
for a Tier-1 approval before it arms the outbound push, and refuses (changing
nothing) on a denial or a non-interactive stream.

A durable cursor (<fortress>/state/cortex-export-cursor.json) records how far the
export has caught up, so re-running resumes without re-sending the whole history
and without leaving a gap.

Options:
  --fortress <path>     Override the storage path.
  --passphrase <val>    Passphrase for master-key derivation.
  --json                Emit the run result as JSON.
  --help, -h            Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.
  SANCTUARY_STORAGE_PATH  State directory (default: ~/.sanctuary).
  SANCTUARY_FORTRESS_PATH Operator-friendly alias for STORAGE_PATH.
`,
  );
}

/**
 * The injectable core: build the exporter from a validated config, arm it
 * (applying the Tier-1 gate for the outbound http lane), and, if armed, run one
 * verified-chain streaming pass with the durable cursor. Fully hermetic: every
 * external effect (approval, audit, fetch, file writer, chain source, cursor) is
 * injected, so tests never touch a real fortress or network.
 */
export interface ExportPipelineDeps {
  /** Validated operator config (from `readExportConfig`, or hand-built in a test). */
  config: EnforcementExportConfig;
  /** Tier-1 approval call. Invoked ONLY to arm the outbound http push. */
  approve: ExportApprover;
  /** Local audit append for the export lifecycle ops. */
  audit: ExportAudit;
  /** The verified-chain source (a real `AuditLog`, or a fake in a test). */
  source: VerifiedChainSource;
  /** The durable resume point. */
  cursor: ExportCursorStore;
  /** Line writer for the file sink (stdout by default). */
  fileWriter?: LineWriter;
  /** Injected fetch for the http sink (real `fetch` in production; mocked in tests). */
  fetchImpl?: typeof fetch;
  /** Read-side attribution verification context for mapped Castle Wall rows. */
  mapOptions?: EnforcementEventMapOptions;
  /** Batch size / retry budget forwarded to the streamer. */
  batchSize?: number;
  maxRetries?: number;
  retryBackoffMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export type ExportPipelineResult =
  | { status: "refused"; reason: string }
  | { status: "ran"; touchesNetwork: boolean; stream: StreamRunOutcome };

export async function runExportPipeline(deps: ExportPipelineDeps): Promise<ExportPipelineResult> {
  const exporter = new EnforcementExporter({
    config: deps.config,
    approve: deps.approve,
    audit: deps.audit,
    ...(deps.fileWriter ? { fileWriter: deps.fileWriter } : {}),
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    ...(deps.mapOptions ? { mapOptions: deps.mapOptions } : {}),
  });

  const enable = await exporter.enable();
  if (enable.status === "refused") {
    return { status: "refused", reason: enable.reason };
  }

  const streamer = new EnforcementExportStreamer({
    exporter,
    cursor: deps.cursor,
    audit: deps.audit,
    ...(deps.mapOptions ? { mapOptions: deps.mapOptions } : {}),
    ...(deps.batchSize !== undefined ? { batchSize: deps.batchSize } : {}),
    ...(deps.maxRetries !== undefined ? { maxRetries: deps.maxRetries } : {}),
    ...(deps.retryBackoffMs !== undefined ? { retryBackoffMs: deps.retryBackoffMs } : {}),
    ...(deps.sleep ? { sleep: deps.sleep } : {}),
  });

  const stream = await streamer.runOnce(deps.source);
  return { status: "ran", touchesNetwork: enable.touchesNetwork, stream };
}

/** A TTY-prompt Tier-1 approval channel; denies on a non-interactive stream. */
class CortexExportPromptApprovalChannel implements ApprovalChannel {
  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    write(process.stderr, formatApprovalPrompt(request));
    if (!process.stdin.isTTY) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "stderr:non-interactive",
      };
    }
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      const answer = await rl.question(
        "Approve arming the OUTBOUND enforcement-event push to this pinned collector? [y/N] ",
      );
      const approved = /^y(es)?$/i.test(answer.trim());
      return {
        decision: approved ? "approve" : "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    } finally {
      rl.close();
    }
  }
}

function formatApprovalPrompt(request: ApprovalRequest): string {
  const contextLines = Object.entries(request.context)
    .map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("\n");
  return (
    "\nSanctuary: Tier-1 approval required\n" +
    `  Operation: ${request.operation}\n` +
    `  Reason:    ${request.reason}\n` +
    "  Details:\n" +
    contextLines +
    "\n"
  );
}

/** Minimal audit surface `buildExportAudit` needs (an `AuditLog` in production). */
type ExportAuditSink = Pick<AuditLog, "appendCritical">;

/**
 * Build the export-lifecycle audit sink. Appends are best-effort by design -- a
 * failed audit NEVER blocks the operator verb (the export op still runs). But a
 * DROPPED append is made LOUD on `err` instead of silently swallowed: that
 * silence is the exact per-flow silent-audit-emission class #946 made loud on
 * the Swift side, and it must not re-open here. The operator sees that a
 * lifecycle event went unrecorded, so the audit trail's completeness stays
 * honest (a missing record is visible, not invisible).
 *
 * Exported so the loud-drop path is unit-testable with a throwing audit stub
 * (the production wiring constructs the real `AuditLog` internally).
 */
export function buildExportAudit(auditLog: ExportAuditSink, err: Writable): ExportAudit {
  return async (operation, details, result) => {
    try {
      await auditLog.appendCritical({
        layer: "l1",
        operation,
        identity_id: "operator",
        result,
        details,
      });
    } catch (error) {
      write(
        err,
        `Warning: cortex-export audit append for "${operation}" was dropped ` +
          `(${error instanceof Error ? error.message : String(error)}); the export ` +
          `proceeded but this lifecycle event has no audit record.\n`,
      );
    }
  };
}

/**
 * A file-sink line writer that APPENDS one NDJSON line to `filePath`. Never a
 * network sink. Used when the operator config sets `file_path`.
 */
function appendFileLineWriter(filePath: string): LineWriter {
  return async (line: string) => {
    await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
    await appendFile(filePath, `${line}\n`, { mode: 0o600 });
  };
}

function resolveFortressArg(fortress: string | undefined, env: NodeJS.ProcessEnv): string {
  if (!fortress) return resolveStoragePath(env);
  return isAbsolute(fortress) ? fortress : resolve(process.cwd(), fortress);
}

function fortressIdForAttribution(storagePath: string): string {
  const digest = createHash("sha256").update(storagePath).digest("hex");
  return `fortress-${digest.slice(0, 16)}`;
}

export async function runCortexExportCommand(args: CortexExportCommandArgs): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return argv.length === 0 ? 2 : 0;
  }

  const command = argv[0]!;
  const rest = argv.slice(1);

  if (command === "run") {
    if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
      printRunUsage(out);
      return 0;
    }
    return await cmdRun(rest, out, err, env);
  }

  write(err, `Unknown cortex-export command: ${command}\n`);
  write(err, `Run "sanctuary cortex-export --help" for usage.\n`);
  return 2;
}

async function cmdRun(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");

  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary cortex-export run requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return 1;
  }

  try {
    const config = await loadConfig();
    const fortressPath = resolveFortressArg(fortressFlag, env);
    await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(config.storage_path, "state"));

    const masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });

    const auditLog = new AuditLog(storage, masterKey);

    // Present-but-invalid cortex-export.json throws here (fail closed). A missing
    // file means the safe default: local file sink, no network, no approval.
    const exportConfig = await readExportConfig(config.storage_path);
    const producerKeyLoad = await loadFortressProducerKey(config.storage_path);
    if (producerKeyLoad.status === "unreadable") {
      write(
        err,
        `Error: Castle Wall audit producer key is unavailable (${producerKeyLoad.reason}); refusing to export unverifiable agent attribution.\n`,
      );
      return 1;
    }
    const mapOptions: EnforcementEventMapOptions = {
      pinnedProducerKeyB64url:
        producerKeyLoad.status === "present" ? producerKeyLoad.keyB64url : null,
      subjectFortressId: fortressIdForAttribution(config.storage_path),
    };

    // A best-effort local audit append (a failed audit never blocks the operator
    // verb; the export lifecycle is recorded on a best-effort basis, same posture
    // as the observe CLI). A DROPPED append is made LOUD on stderr (never
    // silently swallowed): see `buildExportAudit` (silent-audit-drop class #946).
    const audit = buildExportAudit(auditLog, err);

    // Tier-1 approval gate, built ONLY when the outbound http lane is configured.
    // For the file sink `approve` is never invoked (enable() short-circuits), so
    // we still pass a gate-backed approver but it never fires on the local path.
    let approve: ExportApprover = async () => ({
      allowed: false,
      reason: "no approval channel wired",
    });
    if (exportConfig.sink === "http") {
      const policy = await loadPrincipalPolicy(config.storage_path);
      const baseline = new BaselineTracker(storage, masterKey);
      const channel = new CortexExportPromptApprovalChannel();
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);
      approve = (operation, context) => gate.evaluate(operation, context);
    }

    // File-sink writer: append to a configured path, else stdout NDJSON.
    const fileWriter: LineWriter =
      exportConfig.file_path !== undefined
        ? appendFileLineWriter(exportConfig.file_path)
        : stdoutLineWriter();

    // The durable cursor is master-key-AUTHENTICATED (MAC'd + chain-identity
    // bound): a hand-written / tampered / stale cursor is discarded loudly and the
    // run re-scans from the start rather than silently going blind. See cursor.ts.
    const cursor = new FileExportCursorStore(fortressPath, masterKey);

    const result = await runExportPipeline({
      config: exportConfig,
      approve,
      audit,
      source: auditLog,
      cursor,
      fileWriter,
      mapOptions,
      // Real fetch for the http sink; the sink is only ever armed behind the gate.
      fetchImpl: fetch,
    });

    if (result.status === "refused") {
      if (json) {
        write(out, `${JSON.stringify({ ok: false, refused: result.reason }, null, 2)}\n`);
      } else {
        write(
          err,
          `Refused: the outbound push was not armed (${result.reason}). Nothing was exported over the network.\n`,
        );
      }
      return 1;
    }

    if (json) {
      write(
        out,
        `${JSON.stringify(
          {
            ok: true,
            sink: exportConfig.sink,
            touches_network: result.touchesNetwork,
            delivered: result.stream.delivered,
            batches: result.stream.batches,
            from_cursor: result.stream.fromCursor,
            to_cursor: result.stream.toCursor,
          },
          null,
          2,
        )}\n`,
      );
    } else {
      write(
        out,
        `Exported ${result.stream.delivered} enforcement event(s) via the ${exportConfig.sink} sink` +
          `${result.touchesNetwork ? " (outbound push to the pinned collector)" : " (local, no network)"}.\n`,
      );
      write(
        out,
        `Cursor advanced ${result.stream.fromCursor} -> ${result.stream.toCursor}; re-run to export new events.\n`,
      );
    }
    return 0;
  } catch (error) {
    write(err, `Error: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}
