#!/usr/bin/env tsx
import { spawn, type ChildProcessByStdio } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

import { generateRandomKey } from "../../server/src/core/random.js";
import { AuditLog, type AuditEntry } from "../../server/src/operational/audit-log.js";
import { FilesystemStorage } from "../../server/src/storage/filesystem.js";
import { startBrokerLivenessHeartbeat } from "../../server/src/broker-mcp/liveness-heartbeat.js";
import {
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
} from "../../server/src/broker-mcp/liveness-constants.js";
import {
  buildFeatureHealthPanel,
  type FeatureHealthRow,
} from "../../server/src/principal-policy/feature-health.js";
import {
  DEFAULT_DIGEST_WINDOW_MS,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
} from "../../server/src/principal-policy/posture.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const TSX_LOADER = join(REPO_ROOT, "server", "node_modules", "tsx", "dist", "loader.mjs");
const EVIDENCE_PATH = join(
  REPO_ROOT,
  "docs",
  "audit",
  "broker-liveness-process-drill-2026-06-20.md",
);

const FORTRESS_ID = "fortress:broker-liveness-process-drill";
const BROKER_ROW_ID = "secret_broker_daemon";
const MIN_BEATS = 3;
const RUNS_PER_LEG = 3;
const HEARTBEAT_INTERVAL_SECONDS = 1;
const HEARTBEAT_INTERVAL_MS = HEARTBEAT_INTERVAL_SECONDS * 1000;

// The reader is real, but this standalone drill injects a short freshness window
// so the process lifecycle can be exercised in seconds rather than waiting for
// the production 10-minute posture window.
const DRILL_FRESHNESS_WINDOW_MS = 2_500;
const DRILL_DIGEST_WINDOW_MS = 60_000;
const DEAD_DETECTION_WAIT_MS = DRILL_FRESHNESS_WINDOW_MS + 750;
const BEAT_OBSERVATION_TIMEOUT_MS =
  HEARTBEAT_INTERVAL_MS * (MIN_BEATS + 2) + 2_000;

interface WorkerArgs {
  storagePath: string;
  masterKeyB64url: string;
  fortressId: string;
  intervalSeconds: number;
}

interface WorkerExit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

interface WorkerProcess {
  child: ChildProcessByStdio<null, Readable, Readable>;
  stdout: string[];
  stderr: string[];
  exited: Promise<WorkerExit>;
}

interface RunContext {
  label: string;
  storagePath: string;
  masterKey: Uint8Array;
  auditLog: AuditLog;
}

interface PhaseRunEvidence {
  phase: "silent_death" | "clean_stop";
  run: number;
  storage_label: string;
  signal_sent: "SIGKILL" | "SIGTERM";
  child_pid: number;
  child_exit: WorkerExit;
  beat_count_before_signal: number;
  stand_down_count_after_exit: number;
  alive_verdict_before_signal: FeatureHealthRow;
  final_verdict_after_dead_window: FeatureHealthRow;
  timings_ms: {
    heartbeat_interval: number;
    reader_freshness_window: number;
    dead_detection_wait: number;
    elapsed_to_min_beats: number;
    elapsed_after_signal_to_verdict: number;
  };
  raw_broker_lifecycle_entries: AuditEntry[];
  child_stdout: string;
  child_stderr: string;
  assertions: Record<string, boolean>;
  pass: boolean;
}

interface HonestyEvidence {
  source_phase_run: string;
  fault_verdict_before_forged_beat: FeatureHealthRow;
  verdict_after_forged_in_process_beat: FeatureHealthRow;
  forged_entry_details: Record<string, unknown>;
  raw_broker_lifecycle_entries_after_forgery: AuditEntry[];
  assertions: Record<string, boolean>;
  pass: boolean;
}

interface CriterionResult {
  id: number;
  name: string;
  pass: boolean;
  evidence: Record<string, unknown>;
}

interface DrillResults {
  generated_at: string;
  overall_pass: boolean;
  config: Record<string, unknown>;
  criteria: CriterionResult[];
  silent_death_runs: PhaseRunEvidence[];
  clean_stop_runs: PhaseRunEvidence[];
  honesty: HonestyEvidence;
}

function encodeKey(key: Uint8Array): string {
  return Buffer.from(key).toString("base64url");
}

function decodeKey(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, "base64url"));
}

function isBrokerLifecycleEntry(entry: AuditEntry): boolean {
  const details = entry.details;
  return (
    entry.layer === "l3" &&
    (entry.operation === BROKER_DAEMON_HEARTBEAT_OPERATION ||
      entry.operation === BROKER_DAEMON_STAND_DOWN_OPERATION) &&
    typeof details === "object" &&
    details !== null &&
    details[BROKER_DAEMON_AUDIT_PROVENANCE_KEY] ===
      BROKER_DAEMON_AUDIT_PROVENANCE_VALUE
  );
}

async function queryBrokerLifecycleEntries(
  auditLog: AuditLog,
): Promise<AuditEntry[]> {
  const { entries } = await auditLog.query({ layer: "l3", limit: 10_000 });
  return entries.filter(isBrokerLifecycleEntry);
}

async function countBrokerOp(
  auditLog: AuditLog,
  operation: string,
): Promise<number> {
  const entries = await queryBrokerLifecycleEntries(auditLog);
  return entries.filter((entry) => entry.operation === operation).length;
}

function brokerRow(rows: FeatureHealthRow[]): FeatureHealthRow {
  const row = rows.find((candidate) => candidate.feature_id === BROKER_ROW_ID);
  if (!row) throw new Error(`feature-health row not found: ${BROKER_ROW_ID}`);
  return row;
}

async function readBrokerVerdict(auditLog: AuditLog): Promise<FeatureHealthRow> {
  const panel = await buildFeatureHealthPanel({
    auditLog,
    originMachine: FORTRESS_ID,
    now: Date.now(),
    freshnessWindowMs: DRILL_FRESHNESS_WINDOW_MS,
    windowMs: DRILL_DIGEST_WINDOW_MS,
  });
  return brokerRow(panel.rows);
}

function spawnWorker(ctx: RunContext): WorkerProcess {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const args: WorkerArgs = {
    storagePath: ctx.storagePath,
    masterKeyB64url: encodeKey(ctx.masterKey),
    fortressId: FORTRESS_ID,
    intervalSeconds: HEARTBEAT_INTERVAL_SECONDS,
  };
  const child = spawn(process.execPath, [
    "--import",
    TSX_LOADER,
    SCRIPT_PATH,
    "--worker",
    JSON.stringify(args),
  ], {
    cwd: REPO_ROOT,
    env: { ...process.env, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => stdout.push(chunk));
  child.stderr.on("data", (chunk: string) => stderr.push(chunk));
  const exited = new Promise<WorkerExit>((resolveExit, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolveExit({ code, signal }));
  });
  return { child, stdout, stderr, exited };
}

async function waitForBeatCount(
  auditLog: AuditLog,
  minCount: number,
): Promise<{ count: number; elapsedMs: number }> {
  const started = Date.now();
  for (;;) {
    const count = await countBrokerOp(auditLog, BROKER_DAEMON_HEARTBEAT_OPERATION);
    if (count >= minCount) return { count, elapsedMs: Date.now() - started };
    if (Date.now() - started > BEAT_OBSERVATION_TIMEOUT_MS) {
      throw new Error(
        `timed out waiting for ${minCount} broker heartbeat entries; saw ${count}`,
      );
    }
    await sleep(100);
  }
}

async function createRunContext(
  tempRoot: string,
  label: string,
): Promise<RunContext> {
  const storagePath = join(tempRoot, label, "state");
  await mkdir(storagePath, { recursive: true });
  const masterKey = generateRandomKey();
  return {
    label,
    storagePath,
    masterKey,
    auditLog: new AuditLog(new FilesystemStorage(storagePath), masterKey, {
      checkpointInterval: 0,
    }),
  };
}

async function runPhase(
  tempRoot: string,
  phase: "silent_death" | "clean_stop",
  run: number,
): Promise<PhaseRunEvidence> {
  const ctx = await createRunContext(tempRoot, `${phase}-${run}`);
  const worker = spawnWorker(ctx);
  const childPid = worker.child.pid;
  if (childPid === undefined) throw new Error("worker process has no pid");

  let childExit: WorkerExit;
  const beatWait = await waitForBeatCount(ctx.auditLog, MIN_BEATS);
  const aliveVerdict = await readBrokerVerdict(ctx.auditLog);

  const signalSent = phase === "silent_death" ? "SIGKILL" : "SIGTERM";
  const signalAt = Date.now();
  worker.child.kill(signalSent);
  childExit = await worker.exited;

  await sleep(DEAD_DETECTION_WAIT_MS);
  const finalVerdict = await readBrokerVerdict(ctx.auditLog);
  const verdictAt = Date.now();
  const standDownCount = await countBrokerOp(
    ctx.auditLog,
    BROKER_DAEMON_STAND_DOWN_OPERATION,
  );
  const rawEntries = await queryBrokerLifecycleEntries(ctx.auditLog);

  const commonAssertions: Record<string, boolean> = {
    observed_at_least_three_marked_beats: beatWait.count >= MIN_BEATS,
    alive_verdict_is_not_green: aliveVerdict.status !== "active",
    alive_verdict_is_alive_idle_unknown:
      aliveVerdict.status === "unknown" &&
      aliveVerdict.basis === "alive_no_recent_enforcement",
  };
  let phaseAssertions: Record<string, boolean>;
  if (phase === "silent_death") {
    phaseAssertions = {
      final_verdict_is_fault_dead_no_heartbeat:
        finalVerdict.status === "fault" &&
        finalVerdict.basis === "dead_no_heartbeat",
      no_stand_down_marker_was_written: standDownCount === 0,
    };
  } else {
    phaseAssertions = {
      final_verdict_is_unknown_intentionally_stopped:
        finalVerdict.status === "unknown" &&
        finalVerdict.basis === "intentionally_stopped",
      final_verdict_is_not_dead_no_heartbeat:
        finalVerdict.basis !== "dead_no_heartbeat",
      final_verdict_is_not_fault: finalVerdict.status !== "fault",
      exactly_one_stand_down_marker_was_written: standDownCount === 1,
    };
  }
  const assertions = { ...commonAssertions, ...phaseAssertions };
  const pass = Object.values(assertions).every(Boolean);

  return {
    phase,
    run,
    storage_label: ctx.label,
    signal_sent: signalSent,
    child_pid: childPid,
    child_exit: childExit,
    beat_count_before_signal: beatWait.count,
    stand_down_count_after_exit: standDownCount,
    alive_verdict_before_signal: aliveVerdict,
    final_verdict_after_dead_window: finalVerdict,
    timings_ms: {
      heartbeat_interval: HEARTBEAT_INTERVAL_MS,
      reader_freshness_window: DRILL_FRESHNESS_WINDOW_MS,
      dead_detection_wait: DEAD_DETECTION_WAIT_MS,
      elapsed_to_min_beats: beatWait.elapsedMs,
      elapsed_after_signal_to_verdict: verdictAt - signalAt,
    },
    raw_broker_lifecycle_entries: rawEntries,
    child_stdout: worker.stdout.join(""),
    child_stderr: worker.stderr.join(""),
    assertions,
    pass,
  };
}

async function appendForgedBrokerBeat(auditLog: AuditLog): Promise<Record<string, unknown>> {
  const details = {
    source: "drill-forged-in-process",
    [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  };
  await auditLog.appendCritical({
    layer: "l3",
    operation: BROKER_DAEMON_HEARTBEAT_OPERATION,
    identity_id: FORTRESS_ID,
    result: "success",
    details,
  });
  return details;
}

async function runSilentDeathWithForgery(
  tempRoot: string,
): Promise<{ phaseRun: PhaseRunEvidence; honesty: HonestyEvidence }> {
  const ctx = await createRunContext(tempRoot, "honesty-forged-beat");
  const worker = spawnWorker(ctx);
  const childPid = worker.child.pid;
  if (childPid === undefined) throw new Error("worker process has no pid");

  const beatWait = await waitForBeatCount(ctx.auditLog, MIN_BEATS);
  const aliveVerdict = await readBrokerVerdict(ctx.auditLog);
  const signalAt = Date.now();
  worker.child.kill("SIGKILL");
  const childExit = await worker.exited;
  await sleep(DEAD_DETECTION_WAIT_MS);
  const faultVerdict = await readBrokerVerdict(ctx.auditLog);
  const faultVerdictAt = Date.now();
  const standDownCount = await countBrokerOp(
    ctx.auditLog,
    BROKER_DAEMON_STAND_DOWN_OPERATION,
  );
  const rawEntriesBeforeForgery = await queryBrokerLifecycleEntries(ctx.auditLog);
  const forgedDetails = await appendForgedBrokerBeat(ctx.auditLog);
  const forgedVerdict = await readBrokerVerdict(ctx.auditLog);
  const rawEntriesAfterForgery = await queryBrokerLifecycleEntries(ctx.auditLog);

  const phaseAssertions = {
    observed_at_least_three_marked_beats: beatWait.count >= MIN_BEATS,
    alive_verdict_is_not_green: aliveVerdict.status !== "active",
    alive_verdict_is_alive_idle_unknown:
      aliveVerdict.status === "unknown" &&
      aliveVerdict.basis === "alive_no_recent_enforcement",
    final_verdict_is_fault_dead_no_heartbeat:
      faultVerdict.status === "fault" && faultVerdict.basis === "dead_no_heartbeat",
    no_stand_down_marker_was_written: standDownCount === 0,
  };
  const phaseRun: PhaseRunEvidence = {
    phase: "silent_death",
    run: RUNS_PER_LEG + 1,
    storage_label: ctx.label,
    signal_sent: "SIGKILL",
    child_pid: childPid,
    child_exit: childExit,
    beat_count_before_signal: beatWait.count,
    stand_down_count_after_exit: standDownCount,
    alive_verdict_before_signal: aliveVerdict,
    final_verdict_after_dead_window: faultVerdict,
    timings_ms: {
      heartbeat_interval: HEARTBEAT_INTERVAL_MS,
      reader_freshness_window: DRILL_FRESHNESS_WINDOW_MS,
      dead_detection_wait: DEAD_DETECTION_WAIT_MS,
      elapsed_to_min_beats: beatWait.elapsedMs,
      elapsed_after_signal_to_verdict: faultVerdictAt - signalAt,
    },
    raw_broker_lifecycle_entries: rawEntriesBeforeForgery,
    child_stdout: worker.stdout.join(""),
    child_stderr: worker.stderr.join(""),
    assertions: phaseAssertions,
    pass: Object.values(phaseAssertions).every(Boolean),
  };

  const honestyAssertions = {
    real_beats_never_made_row_green: aliveVerdict.status !== "active",
    real_silent_death_was_fault_before_forgery:
      faultVerdict.status === "fault" && faultVerdict.basis === "dead_no_heartbeat",
    forged_in_process_beat_relabels_fault_to_non_green_unknown:
      forgedVerdict.status === "unknown" &&
      forgedVerdict.basis === "alive_no_recent_enforcement",
    forged_in_process_beat_did_not_make_green: forgedVerdict.status !== "active",
    daemon_invocation_count_remained_zero: forgedVerdict.invocation_count === 0,
  };
  const honesty: HonestyEvidence = {
    source_phase_run: phaseRun.storage_label,
    fault_verdict_before_forged_beat: faultVerdict,
    verdict_after_forged_in_process_beat: forgedVerdict,
    forged_entry_details: forgedDetails,
    raw_broker_lifecycle_entries_after_forgery: rawEntriesAfterForgery,
    assertions: honestyAssertions,
    pass: Object.values(honestyAssertions).every(Boolean),
  };
  return { phaseRun, honesty };
}

function criterion(
  id: number,
  name: string,
  pass: boolean,
  evidence: Record<string, unknown>,
): CriterionResult {
  return { id, name, pass, evidence };
}

function buildCriteria(
  silentRuns: PhaseRunEvidence[],
  cleanRuns: PhaseRunEvidence[],
  honesty: HonestyEvidence,
  reportWritten: boolean,
): CriterionResult[] {
  const allRuns = [...silentRuns, ...cleanRuns];
  return [
    criterion(1, "Alive -> real beats", allRuns.every((run) => {
      return (
        run.beat_count_before_signal >= MIN_BEATS &&
        run.assertions.observed_at_least_three_marked_beats === true
      );
    }), {
      min_beats_required: MIN_BEATS,
      observed_counts: allRuns.map((run) => ({
        phase: run.phase,
        run: run.run,
        beats: run.beat_count_before_signal,
      })),
    }),
    criterion(2, "Silent death -> fault / dead_no_heartbeat", silentRuns.length >= RUNS_PER_LEG && silentRuns
      .slice(0, RUNS_PER_LEG)
      .every((run) => run.assertions.final_verdict_is_fault_dead_no_heartbeat === true), {
      required_runs: RUNS_PER_LEG,
      verdicts: silentRuns.slice(0, RUNS_PER_LEG).map((run) => ({
        run: run.run,
        status: run.final_verdict_after_dead_window.status,
        basis: run.final_verdict_after_dead_window.basis,
      })),
    }),
    criterion(3, "Clean stop -> no dead_no_heartbeat false alarm", cleanRuns.length >= RUNS_PER_LEG && cleanRuns.every((run) => {
      return (
        run.assertions.final_verdict_is_unknown_intentionally_stopped === true &&
        run.assertions.final_verdict_is_not_dead_no_heartbeat === true &&
        run.assertions.final_verdict_is_not_fault === true
      );
    }), {
      required_runs: RUNS_PER_LEG,
      verdicts: cleanRuns.map((run) => ({
        run: run.run,
        status: run.final_verdict_after_dead_window.status,
        basis: run.final_verdict_after_dead_window.basis,
        stand_down_count: run.stand_down_count_after_exit,
      })),
    }),
    criterion(4, "Honesty / un-greenable", honesty.pass, {
      source_phase_run: honesty.source_phase_run,
      assertions: honesty.assertions,
      before_forgery: {
        status: honesty.fault_verdict_before_forged_beat.status,
        basis: honesty.fault_verdict_before_forged_beat.basis,
      },
      after_forgery: {
        status: honesty.verdict_after_forged_in_process_beat.status,
        basis: honesty.verdict_after_forged_in_process_beat.basis,
        invocation_count:
          honesty.verdict_after_forged_in_process_beat.invocation_count,
      },
    }),
    criterion(5, "Evidence capture", reportWritten, {
      evidence_path: EVIDENCE_PATH,
      raw_entries_captured: allRuns.reduce(
        (sum, run) => sum + run.raw_broker_lifecycle_entries.length,
        honesty.raw_broker_lifecycle_entries_after_forgery.length,
      ),
    }),
  ];
}

function jsonBlock(value: unknown): string {
  return `\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
}

function passFail(pass: boolean): string {
  return pass ? "PASS" : "FAIL";
}

async function writeEvidence(results: DrillResults): Promise<void> {
  await mkdir(dirname(EVIDENCE_PATH), { recursive: true });
  const lines: string[] = [];
  lines.push("# Broker Liveness Process Drill Results");
  lines.push("");
  lines.push(`Generated: ${results.generated_at}`);
  lines.push(`Overall: ${passFail(results.overall_pass)}`);
  lines.push("");
  lines.push("## Configuration");
  lines.push("");
  lines.push(jsonBlock(results.config));
  lines.push("");
  lines.push("## Acceptance Criteria");
  lines.push("");
  lines.push("| # | Criterion | Result | Evidence |");
  lines.push("|---|---|---|---|");
  for (const c of results.criteria) {
    lines.push(
      `| ${c.id} | ${c.name} | ${passFail(c.pass)} | ${JSON.stringify(
        c.evidence,
      )} |`,
    );
  }
  lines.push("");
  lines.push("## Phase A: Silent Death");
  lines.push("");
  for (const run of results.silent_death_runs) {
    lines.push(`### Run ${run.run}: ${passFail(run.pass)}`);
    lines.push(jsonBlock(run));
    lines.push("");
  }
  lines.push("## Phase B: Clean Stop");
  lines.push("");
  for (const run of results.clean_stop_runs) {
    lines.push(`### Run ${run.run}: ${passFail(run.pass)}`);
    lines.push(jsonBlock(run));
    lines.push("");
  }
  lines.push("## Honesty / Forged Beat");
  lines.push("");
  lines.push(jsonBlock(results.honesty));
  lines.push("");
  await writeFile(EVIDENCE_PATH, `${lines.join("\n")}\n`, "utf8");
}

async function runMain(): Promise<void> {
  const tempRoot = await mkdtemp(join(tmpdir(), "broker-liveness-drill-"));
  let overallPass = false;
  try {
    const silentRuns: PhaseRunEvidence[] = [];
    const cleanRuns: PhaseRunEvidence[] = [];

    for (let run = 1; run <= RUNS_PER_LEG; run++) {
      silentRuns.push(await runPhase(tempRoot, "silent_death", run));
    }
    const { phaseRun: honestyPhaseRun, honesty } =
      await runSilentDeathWithForgery(tempRoot);
    silentRuns.push(honestyPhaseRun);
    for (let run = 1; run <= RUNS_PER_LEG; run++) {
      cleanRuns.push(await runPhase(tempRoot, "clean_stop", run));
    }

    const preliminaryCriteria = buildCriteria(silentRuns, cleanRuns, honesty, false);
    const preliminaryPass = preliminaryCriteria
      .filter((candidate) => candidate.id !== 5)
      .every((candidate) => candidate.pass);
    const preliminaryResults: DrillResults = {
      generated_at: new Date().toISOString(),
      overall_pass: preliminaryPass,
      config: {
        fortress_id: FORTRESS_ID,
        heartbeat_interval_seconds: HEARTBEAT_INTERVAL_SECONDS,
        min_beats_required: MIN_BEATS,
        runs_per_leg_required: RUNS_PER_LEG,
        production_default_reader_freshness_window_ms:
          DEFAULT_ENFORCEMENT_FRESHNESS_MS,
        production_default_digest_window_ms: DEFAULT_DIGEST_WINDOW_MS,
        drill_reader_freshness_window_ms: DRILL_FRESHNESS_WINDOW_MS,
        drill_digest_window_ms: DRILL_DIGEST_WINDOW_MS,
        dead_detection_wait_ms: DEAD_DETECTION_WAIT_MS,
        temp_root_cleaned_after_capture: true,
      },
      criteria: preliminaryCriteria,
      silent_death_runs: silentRuns,
      clean_stop_runs: cleanRuns,
      honesty,
    };
    await writeEvidence(preliminaryResults);
    const finalCriteria = buildCriteria(silentRuns, cleanRuns, honesty, true);
    overallPass = finalCriteria.every((candidate) => candidate.pass);
    const finalResults: DrillResults = {
      ...preliminaryResults,
      overall_pass: overallPass,
      criteria: finalCriteria,
    };
    await writeEvidence(finalResults);

    console.log(
      JSON.stringify(
        {
          overall_pass: overallPass,
          evidence_path: EVIDENCE_PATH,
          criteria: finalCriteria.map((candidate) => ({
            id: candidate.id,
            name: candidate.name,
            pass: candidate.pass,
          })),
          silent_death_runs: silentRuns.length,
          clean_stop_runs: cleanRuns.length,
          silent_death_counts: silentRuns.map((run) => run.beat_count_before_signal),
          clean_stop_counts: cleanRuns.map((run) => run.beat_count_before_signal),
        },
        null,
        2,
      ),
    );
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
  if (!overallPass) {
    process.exitCode = 1;
  }
}

async function runWorker(args: WorkerArgs): Promise<void> {
  const auditLog = new AuditLog(
    new FilesystemStorage(args.storagePath),
    decodeKey(args.masterKeyB64url),
    { checkpointInterval: 0 },
  );
  const heartbeat = startBrokerLivenessHeartbeat({
    auditLog,
    fortressId: args.fortressId,
    intervalSeconds: args.intervalSeconds,
  });
  const keepAlive = setInterval(() => undefined, 60_000);
  let shuttingDown = false;
  const standDownAndExit = async (): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    clearInterval(keepAlive);
    await heartbeat.standDown();
    process.exit(0);
  };
  process.on("SIGTERM", () => {
    void standDownAndExit();
  });
  process.on("SIGINT", () => {
    void standDownAndExit();
  });
  console.log(
    JSON.stringify({
      worker: "broker-liveness-process-drill",
      pid: process.pid,
      interval_seconds: args.intervalSeconds,
    }),
  );
}

async function entrypoint(): Promise<void> {
  const workerFlagIndex = process.argv.indexOf("--worker");
  if (workerFlagIndex >= 0) {
    const raw = process.argv[workerFlagIndex + 1];
    if (!raw) throw new Error("--worker requires JSON args");
    await runWorker(JSON.parse(raw) as WorkerArgs);
    return;
  }
  await runMain();
}

entrypoint().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
