import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import type { Readable, Writable } from "node:stream";

import { boundContributionRationale, type PluginContribution } from "./attribution.js";
import { type HookClass } from "./fields.js";
import type { BundleDescriptor } from "./manifest.js";
import { parseStrictJson } from "./strict-json.js";
import type { Governance, HookDecl } from "./governance.js";
import {
  PluginLifecycleController,
  type PluginLifecycleAuditSink,
  type PluginLifecycleHook,
  type PluginLifecycleState,
  type PluginSuspensionReason,
} from "./lifecycle.js";
import { parseVerdictFrame, type EnforcementDecision, type HostDecision, type PluginVerdict } from "./verdict.js";

export const PLUGIN_CONFINEMENT_KIND = "realized-confinement.v1";
export const PLUGIN_SECCOMP_PROFILE_ID = "plugin-v1";
export const DEFAULT_INLINE_TIMEOUT_MS = 500;
export const DEFAULT_EGRESS_TIMEOUT_MS = 150;
export const MAX_VERDICT_FRAME_BYTES = 16 * 1024;
export const MAX_REQUEST_FRAME_BYTES = 64 * 1024;
/** Confinement-report control line cap: the report is a single small JSON line;
 *  a launcher that floods fd 3 with no newline must not balloon host memory. */
export const MAX_CONTROL_LINE_BYTES = 64 * 1024;
/** Bounded FIFO of recently issued request nonces. Host-minted random nonces
 *  cannot be replayed beyond this recent window, so eviction is safe and the
 *  set can never grow without bound over the process lifetime. */
export const MAX_TRACKED_NONCES = 8192;

type InvocationErrorCode = "timeout" | "crash" | "malformed" | "framing" | "closed" | "replay";

export class PluginInvocationError extends Error {
  readonly code: InvocationErrorCode;

  constructor(code: InvocationErrorCode, message: string) {
    super(message);
    this.name = "PluginInvocationError";
    this.code = code;
  }
}

export interface PluginRuntimeClient {
  request(
    payload: Record<string, unknown>,
    expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
    timeoutMs: number,
  ): Promise<PluginVerdict>;
  close?(): void;
}

interface PendingFrame {
  resolve: (text: string) => void;
  reject: (err: Error) => void;
  maxBytes: number;
  timer: ReturnType<typeof setTimeout>;
}

export class FramedJsonPluginClient implements PluginRuntimeClient {
  private buffer = Buffer.alloc(0);
  private pending: PendingFrame | undefined;
  private closed = false;

  constructor(
    private readonly stdin: Writable,
    stdout: Readable,
  ) {
    stdout.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.tryResolvePending();
    });
    stdout.once("end", () => this.rejectPending(new PluginInvocationError("closed", "plugin stdout closed")));
    stdout.once("error", (err) =>
      this.rejectPending(new PluginInvocationError("crash", `plugin stdout error: ${err.message}`)),
    );
  }

  async request(
    payload: Record<string, unknown>,
    expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
    timeoutMs: number,
  ): Promise<PluginVerdict> {
    if (this.closed) throw new PluginInvocationError("closed", "plugin client is closed");
    if (this.pending) throw new PluginInvocationError("framing", "plugin already has an outstanding request");

    const json = Buffer.from(JSON.stringify(payload), "utf8");
    if (json.length > MAX_REQUEST_FRAME_BYTES) {
      throw new PluginInvocationError("framing", `request frame exceeds ${MAX_REQUEST_FRAME_BYTES} bytes`);
    }
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(json.length, 0);

    const verdictFrame = this.readFrame(timeoutMs, MAX_VERDICT_FRAME_BYTES);
    await writeAll(this.stdin, Buffer.concat([prefix, json]));
    const text = await verdictFrame;
    try {
      return parseVerdictFrame(text, expected);
    } catch (err) {
      if (err instanceof Error) {
        throw new PluginInvocationError("malformed", err.message);
      }
      throw new PluginInvocationError("malformed", "plugin verdict was malformed");
    }
  }

  close(): void {
    this.closed = true;
    this.rejectPending(new PluginInvocationError("closed", "plugin client closed"));
  }

  private readFrame(timeoutMs: number, maxBytes: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = undefined;
        reject(new PluginInvocationError("timeout", `plugin verdict timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending = { resolve, reject, maxBytes, timer };
      this.tryResolvePending();
    });
  }

  private tryResolvePending(): void {
    if (!this.pending || this.buffer.length < 4) return;
    const length = this.buffer.readUInt32BE(0);
    if (length > this.pending.maxBytes) {
      const pending = this.pending;
      this.pending = undefined;
      this.buffer = Buffer.alloc(0);
      clearTimeout(pending.timer);
      pending.reject(new PluginInvocationError("framing", `verdict frame exceeds ${pending.maxBytes} bytes`));
      return;
    }
    if (this.buffer.length < 4 + length) return;
    const frame = this.buffer.subarray(4, 4 + length);
    const trailing = this.buffer.subarray(4 + length);
    const pending = this.pending;
    this.pending = undefined;
    this.buffer = Buffer.alloc(0);
    clearTimeout(pending.timer);
    if (trailing.length > 0) {
      pending.reject(new PluginInvocationError("framing", "plugin emitted trailing bytes or a second frame"));
      return;
    }
    pending.resolve(frame.toString("utf8"));
  }

  private rejectPending(err: PluginInvocationError): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = undefined;
    clearTimeout(pending.timer);
    pending.reject(err);
  }
}

export interface RealizedConfinementReport {
  kind: typeof PLUGIN_CONFINEMENT_KIND;
  plugin_id: string;
  instance_id: string;
  privilege_mode: "rootless_userns" | "privileged";
  namespaces_entered: string[];
  rootfs_hash: string;
  cgroup_path: string;
  seccomp_profile_id: typeof PLUGIN_SECCOMP_PROFILE_ID;
  launcher_version: string;
  broker_fd: number;
}

export interface PluginLaunchConfig {
  governance: Governance;
  descriptor: BundleDescriptor;
  bundleHash: string;
  launcherPath: string;
  bundleDir: string;
  scratchDir: string;
  cgroupPath: string;
  rootfsHash: string;
  mode?: "rootless_userns" | "privileged";
  entryArgs?: string[];
  instanceId?: string;
  requestTimeoutMs?: number;
  expectedLauncherVersion?: string;
  rlimits?: {
    cpuSeconds?: number;
    addressSpaceBytes?: number;
    nofile?: number;
  };
}

export interface RunningPluginRegistration {
  governance: Governance;
  descriptor: BundleDescriptor;
  bundleHash: string;
  instanceId?: string;
  requestTimeoutMs?: number;
  client: PluginRuntimeClient;
}

export interface EgressConsultationInput {
  target: { host: string; port: number };
  protocol?: string;
  hostDecision: HostDecision;
  origin?: { channel: string; trust_label: "trusted" | "untrusted" };
  agent_id?: string;
  session_id?: string;
}

export interface EgressConsultationResult {
  decisions: EnforcementDecision[];
  contributors: PluginContribution[];
}

export interface PluginHealth {
  plugin_id: string;
  instance_id: string;
  state: "running" | "suspended" | "unhealthy" | "quarantined" | "evicted";
  hooks: Array<{ hook_class: string; mode: "enforced" | "advisory" | "off" }>;
  last_heartbeat: string;
  today: {
    evaluations: number;
    verdict_tally: Record<string, number>;
    timeouts: number;
    mean_latency_ms: number;
  };
}

interface ManagedPlugin {
  governance: Governance;
  descriptor: BundleDescriptor;
  bundleHash: string;
  instanceId: string;
  requestTimeoutMs: number;
  state: PluginLifecycleState;
  suspensionReason?: PluginSuspensionReason;
  client?: PluginRuntimeClient;
  child?: ChildProcess;
  launchConfig?: PluginLaunchConfig;
  crashTimestamps: number[];
  restartAttempts: number;
  consecutiveTimeouts: number;
  denyWindow: boolean[];
  health: PluginHealth;
}

export interface PluginSupervisorOptions {
  auditSink?: PluginLifecycleAuditSink;
  now?: () => string;
  nonceSource?: () => string;
  denyFlood?: {
    windowSize?: number;
    minEvaluations?: number;
    denyRate?: number;
  };
}

const CRASH_LOOP_LIMIT = 5;
const CRASH_LOOP_WINDOW_MS = 10 * 60 * 1000;
const REPEATED_TIMEOUT_LIMIT = 3;
const DEFAULT_DENY_WINDOW_SIZE = 20;
const DEFAULT_DENY_MIN_EVALUATIONS = 5;
const DEFAULT_DENY_RATE = 0.98;

export class PluginSupervisor {
  private readonly plugins = new Map<string, ManagedPlugin>();
  private readonly lifecycle: PluginLifecycleController;
  private readonly now: () => string;
  private readonly nonceSource: () => string;
  private readonly usedNonces = new Set<string>();
  private readonly denyWindowSize: number;
  private readonly denyMinEvaluations: number;
  private readonly denyRate: number;

  constructor(options: PluginSupervisorOptions = {}) {
    this.lifecycle = new PluginLifecycleController({ auditSink: options.auditSink, now: options.now });
    this.now = options.now ?? (() => new Date().toISOString());
    this.nonceSource = options.nonceSource ?? defaultNonce;
    this.denyWindowSize = options.denyFlood?.windowSize ?? DEFAULT_DENY_WINDOW_SIZE;
    this.denyMinEvaluations = options.denyFlood?.minEvaluations ?? DEFAULT_DENY_MIN_EVALUATIONS;
    this.denyRate = options.denyFlood?.denyRate ?? DEFAULT_DENY_RATE;
  }

  async load(config: PluginLaunchConfig): Promise<void> {
    const instanceId = config.instanceId ?? `inst-${randomUUID()}`;
    const plugin = this.createManagedPlugin(config.governance, config.descriptor, config.bundleHash, instanceId, {
      requestTimeoutMs: config.requestTimeoutMs,
      launchConfig: { ...config, instanceId },
    });
    this.plugins.set(config.governance.plugin_id, plugin);
    await this.transition(plugin, "installed", { reason: "operator_install" });
    await this.transition(plugin, "verified", { reason: "bundle_verified" });

    try {
      await this.spawnAndGate(plugin, config, instanceId);
      await this.transition(plugin, "running", { reason: "confinement_verified" });
    } catch (err) {
      plugin.client?.close?.();
      plugin.child?.kill();
      await this.transition(plugin, "quarantined", {
        reason: err instanceof Error ? err.message : "plugin launch failed",
      });
      throw err;
    }
  }

  async adoptRunningPlugin(registration: RunningPluginRegistration): Promise<void> {
    const instanceId = registration.instanceId ?? `inst-${randomUUID()}`;
    const plugin = this.createManagedPlugin(
      registration.governance,
      registration.descriptor,
      registration.bundleHash,
      instanceId,
      {
        requestTimeoutMs: registration.requestTimeoutMs,
      },
    );
    plugin.client = registration.client;
    this.plugins.set(registration.governance.plugin_id, plugin);
    await this.transition(plugin, "installed", { reason: "adopted_running_client" });
    await this.transition(plugin, "verified", { reason: "adopted_running_client" });
    await this.transition(plugin, "running", { reason: "adopted_running_client" });
  }

  health(): PluginHealth[] {
    return [...this.plugins.values()].map((plugin) => ({ ...plugin.health, today: { ...plugin.health.today } }));
  }

  /**
   * Consult every egress_decision plugin for one host-computed egress decision.
   * NOTE (S4 scope): each plugin's `PluginRuntimeClient` is single-outstanding-
   * request, so this method is NOT yet safe to call concurrently for the SAME
   * plugin (a second in-flight call fails closed to deny). The production egress
   * proxy does not wire a `pluginConsultant` yet, so this path is dormant; when
   * S5 wires it, the caller must serialize per-plugin consultation (or add a
   * per-plugin request queue) to avoid spurious denies under concurrent egress.
   */
  async consultEgress(input: EgressConsultationInput): Promise<EgressConsultationResult> {
    const eligible = [...this.plugins.values()].filter((plugin) => hookFor(plugin, "egress_decision"));
    if (eligible.length === 0) return { decisions: [], contributors: [] };

    const request_id = randomUUID();
    const nonce = this.nonceSource();
    if (this.usedNonces.has(nonce)) {
      const contributors = eligible.map((plugin) =>
        this.failureContribution(plugin, "fail_mode_applied", "replayed request nonce rejected", 0),
      );
      return { decisions: contributors.map(() => "deny"), contributors };
    }
    this.usedNonces.add(nonce);
    if (this.usedNonces.size > MAX_TRACKED_NONCES) {
      // Bounded FIFO: drop the oldest tracked nonce (Set preserves insertion
      // order). The replay guard protects against a plugin echoing a recent
      // host-minted nonce; nonces older than this window are already useless.
      const oldest = this.usedNonces.values().next().value;
      if (oldest !== undefined) this.usedNonces.delete(oldest);
    }

    const decisions: EnforcementDecision[] = [];
    const contributors: PluginContribution[] = [];
    for (const plugin of eligible) {
      const hook = hookFor(plugin, "egress_decision")!;
      if (plugin.state === "suspended" && plugin.suspensionReason === "deny_flood") {
        contributors.push(this.failureContribution(plugin, "unhealthy_skipped", "plugin auto-suspended for deny flood", 0));
        continue;
      }
      if (plugin.state !== "running" || !plugin.client) {
        decisions.push("deny");
        contributors.push(this.failureContribution(plugin, "fail_mode_applied", `plugin state ${plugin.state}`, 0));
        continue;
      }

      const started = Date.now();
      const payload = projectEgressDecisionRequest(
        {
          request_id,
          nonce,
          hook_class: "egress_decision",
          host: input.target.host,
          port: input.target.port,
          protocol: input.protocol ?? "tcp",
          origin: input.origin ?? { channel: "castle_wall", trust_label: "untrusted" },
          agent_id: input.agent_id ?? "unknown",
          session_id: input.session_id ?? "unknown",
          timestamp: this.now(),
        },
        hook.fields,
      );

      try {
        const verdict = await plugin.client.request(
          payload,
          { request_id, nonce, declaredSignalKeys: plugin.governance.signal_keys },
          Math.min(plugin.requestTimeoutMs, DEFAULT_INLINE_TIMEOUT_MS),
        );
        const latency = Date.now() - started;
        decisions.push(verdict.decision);
        contributors.push({
          plugin_id: plugin.governance.plugin_id,
          bundle_hash: plugin.bundleHash,
          instance_id: plugin.instanceId,
          hook_class: "egress_decision",
          verdict: verdict.decision,
          ...(verdict.confidence !== undefined ? { confidence: verdict.confidence } : {}),
          rationale: boundContributionRationale(verdict.rationale),
          latency_ms: latency,
        });
        this.recordEvaluation(plugin, verdict.decision, latency);
        if (verdict.decision === "deny") {
          await this.maybeSuspendForDenyFlood(plugin);
        }
      } catch (err) {
        const latency = Date.now() - started;
        const code = err instanceof PluginInvocationError ? err.code : "crash";
        const verdict = code === "timeout" ? "timeout" : "fail_mode_applied";
        decisions.push("deny");
        contributors.push(
          this.failureContribution(
            plugin,
            verdict,
            code === "timeout" ? "plugin timed out" : "plugin invocation failed",
            latency,
          ),
        );
        this.recordEvaluation(plugin, verdict, latency);
        await this.handleInvocationFailure(plugin, code);
      }
    }
    return { decisions, contributors };
  }

  private createManagedPlugin(
    governance: Governance,
    descriptor: BundleDescriptor,
    bundleHash: string,
    instanceId: string,
    options: { requestTimeoutMs?: number; launchConfig?: PluginLaunchConfig },
  ): ManagedPlugin {
    const hooks = healthHooks(governance);
    return {
      governance,
      descriptor,
      bundleHash,
      instanceId,
      requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_EGRESS_TIMEOUT_MS,
      state: "installed",
      launchConfig: options.launchConfig,
      crashTimestamps: [],
      restartAttempts: 0,
      consecutiveTimeouts: 0,
      denyWindow: [],
      health: {
        plugin_id: governance.plugin_id,
        instance_id: instanceId,
        state: "suspended",
        hooks,
        last_heartbeat: this.now(),
        today: { evaluations: 0, verdict_tally: {}, timeouts: 0, mean_latency_ms: 0 },
      },
    };
  }

  private async spawnAndGate(plugin: ManagedPlugin, config: PluginLaunchConfig, instanceId: string): Promise<void> {
    const mode = config.mode ?? "rootless_userns";
    const child = spawn(
      config.launcherPath,
      [
        "--plugin-id",
        config.governance.plugin_id,
        "--instance-id",
        instanceId,
        "--mode",
        mode,
        "--bundle-dir",
        config.bundleDir,
        "--scratch-dir",
        config.scratchDir,
        "--cgroup-path",
        config.cgroupPath,
        "--rootfs-hash",
        config.rootfsHash,
        "--control-pipe-fd",
        "3",
        "--broker-fd",
        "4",
        "--entry",
        config.governance.entry,
        "--rlimit-cpu",
        String(config.rlimits?.cpuSeconds ?? 60),
        "--rlimit-as",
        String(config.rlimits?.addressSpaceBytes ?? 256 * 1024 * 1024),
        "--rlimit-nofile",
        String(config.rlimits?.nofile ?? 256),
        "--",
        ...(config.entryArgs ?? []),
      ],
      {
        stdio: ["pipe", "pipe", "pipe", "pipe", "pipe"],
        env: {},
      },
    );
    plugin.child = child;
    child.once("exit", () => {
      void this.handleProcessExit(plugin);
    });

    const control = child.stdio[3] as Readable | null;
    const stdin = child.stdin;
    const stdout = child.stdout;
    if (!control || !stdin || !stdout) {
      throw new Error("launcher stdio pipes were not created");
    }
    const reportLine = await readControlLine(control, DEFAULT_INLINE_TIMEOUT_MS, MAX_CONTROL_LINE_BYTES);
    const report = parseConfinementReport(reportLine);
    validateConfinementReport(report, {
      plugin_id: config.governance.plugin_id,
      instance_id: instanceId,
      mode,
      rootfs_hash: config.rootfsHash,
      cgroup_path: config.cgroupPath,
      broker_fd: 4,
      expectedLauncherVersion: config.expectedLauncherVersion,
    });
    plugin.client = new FramedJsonPluginClient(stdin, stdout);
  }

  private async handleInvocationFailure(plugin: ManagedPlugin, code: InvocationErrorCode): Promise<void> {
    if (code === "timeout") {
      plugin.consecutiveTimeouts++;
      plugin.health.today.timeouts++;
      if (plugin.consecutiveTimeouts >= REPEATED_TIMEOUT_LIMIT) {
        plugin.client?.close?.();
        plugin.child?.kill();
        await this.transition(plugin, "unhealthy", { reason: "repeated_timeout" });
      }
      return;
    }
    plugin.client?.close?.();
    plugin.child?.kill();
    await this.recordCrash(plugin);
  }

  private async handleProcessExit(plugin: ManagedPlugin): Promise<void> {
    if (plugin.state === "evicted" || plugin.state === "suspended" || plugin.state === "unhealthy") return;
    plugin.client?.close?.();
    await this.recordCrash(plugin);
  }

  private async recordCrash(plugin: ManagedPlugin): Promise<void> {
    const now = Date.now();
    plugin.crashTimestamps = plugin.crashTimestamps.filter((t) => now - t <= CRASH_LOOP_WINDOW_MS);
    plugin.crashTimestamps.push(now);
    if (plugin.crashTimestamps.length >= CRASH_LOOP_LIMIT) {
      await this.transition(plugin, "unhealthy", { reason: "crash_loop" });
      return;
    }
    if (plugin.launchConfig) {
      await this.restartWithBackoff(plugin);
    }
  }

  private async restartWithBackoff(plugin: ManagedPlugin): Promise<void> {
    plugin.restartAttempts++;
    const delayMs = Math.min(60_000, 1000 * 2 ** Math.max(0, plugin.restartAttempts - 1));
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    if (!plugin.launchConfig || plugin.state === "unhealthy" || plugin.state === "evicted") return;
    try {
      await this.spawnAndGate(plugin, plugin.launchConfig, plugin.instanceId);
      await this.transition(plugin, "running", { reason: "restart_after_crash" });
    } catch {
      await this.transition(plugin, "unhealthy", { reason: "restart_exhausted" });
    }
  }

  private async maybeSuspendForDenyFlood(plugin: ManagedPlugin): Promise<void> {
    if (plugin.denyWindow.length < this.denyMinEvaluations) return;
    const denies = plugin.denyWindow.filter(Boolean).length;
    const rate = denies / plugin.denyWindow.length;
    if (rate < this.denyRate) return;
    plugin.client?.close?.();
    plugin.child?.kill();
    await this.transition(plugin, "suspended", {
      reason: "deny_flood",
      suspension_reason: "deny_flood",
      details: { deny_rate: rate, evaluation_window: plugin.denyWindow.length },
    });
  }

  private recordEvaluation(plugin: ManagedPlugin, verdict: string, latencyMs: number): void {
    plugin.consecutiveTimeouts = verdict === "timeout" ? plugin.consecutiveTimeouts : 0;
    plugin.health.last_heartbeat = this.now();
    plugin.health.today.evaluations++;
    plugin.health.today.verdict_tally[verdict] = (plugin.health.today.verdict_tally[verdict] ?? 0) + 1;
    const count = plugin.health.today.evaluations;
    plugin.health.today.mean_latency_ms =
      (plugin.health.today.mean_latency_ms * (count - 1) + latencyMs) / count;
    plugin.denyWindow.push(verdict === "deny");
    if (plugin.denyWindow.length > this.denyWindowSize) plugin.denyWindow.shift();
  }

  private failureContribution(
    plugin: ManagedPlugin,
    verdict: "fail_mode_applied" | "timeout" | "unhealthy_skipped",
    rationale: string,
    latencyMs: number,
  ): PluginContribution {
    return {
      plugin_id: plugin.governance.plugin_id,
      bundle_hash: plugin.bundleHash,
      instance_id: plugin.instanceId,
      hook_class: "egress_decision",
      verdict,
      rationale,
      latency_ms: latencyMs,
    };
  }

  private async transition(
    plugin: ManagedPlugin,
    state: PluginLifecycleState,
    options: { reason?: string; suspension_reason?: PluginSuspensionReason; details?: Record<string, unknown> },
  ): Promise<void> {
    const record = await this.lifecycle.transition({
      plugin_id: plugin.governance.plugin_id,
      bundle_hash: plugin.bundleHash,
      instance_id: plugin.instanceId,
      hooks: healthHooks(plugin.governance),
      state,
      reason: options.reason,
      suspension_reason: options.suspension_reason,
      details: options.details,
    });
    plugin.state = record.state;
    plugin.suspensionReason = record.suspension_reason;
    plugin.health.state = healthState(record.state);
    plugin.health.hooks = healthHooks(plugin.governance).map((hook) => ({
      hook_class: hook.hook_class,
      mode: record.state === "running" ? hook.mode : "off",
    }));
    plugin.health.last_heartbeat = record.entered_at;
  }
}

export function projectEgressDecisionRequest(
  request: {
    request_id: string;
    nonce: string;
    hook_class: "egress_decision";
    host: string;
    port: number;
    protocol: string;
    origin: { channel: string; trust_label: "trusted" | "untrusted" };
    agent_id: string;
    session_id: string;
    timestamp: string;
  },
  declaredFields: readonly string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    request_id: request.request_id,
    nonce: request.nonce,
    hook_class: request.hook_class,
  };
  const origin: Record<string, unknown> = {};
  for (const field of declaredFields) {
    if (field === "egress.host") out.host = request.host;
    else if (field === "egress.port") out.port = request.port;
    else if (field === "egress.protocol") out.protocol = request.protocol;
    else if (field === "origin.channel") origin.channel = request.origin.channel;
    else if (field === "origin.trust_label") origin.trust_label = request.origin.trust_label;
  }
  if (Object.keys(origin).length > 0) out.origin = origin;
  return out;
}

export function parseConfinementReport(line: string): RealizedConfinementReport {
  const raw = parseStrictJson(line);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("confinement report must be an object");
  }
  const report = raw as Record<string, unknown>;
  const required = [
    "kind",
    "plugin_id",
    "instance_id",
    "privilege_mode",
    "namespaces_entered",
    "rootfs_hash",
    "cgroup_path",
    "seccomp_profile_id",
    "launcher_version",
    "broker_fd",
  ];
  for (const key of required) {
    if (!(key in report)) throw new Error(`confinement report missing ${key}`);
  }
  return report as unknown as RealizedConfinementReport;
}

export function validateConfinementReport(
  report: RealizedConfinementReport,
  expected: {
    plugin_id: string;
    instance_id: string;
    mode: "rootless_userns" | "privileged";
    rootfs_hash: string;
    cgroup_path: string;
    broker_fd: number;
    expectedLauncherVersion?: string;
  },
): void {
  const expectedNamespaces = expected.mode === "rootless_userns" ? ["user", "mount", "net"] : ["mount", "net"];
  const failures: string[] = [];
  if (report.kind !== PLUGIN_CONFINEMENT_KIND) failures.push("kind");
  if (report.plugin_id !== expected.plugin_id) failures.push("plugin_id");
  if (report.instance_id !== expected.instance_id) failures.push("instance_id");
  if (report.privilege_mode !== expected.mode) failures.push("privilege_mode");
  if (report.rootfs_hash !== expected.rootfs_hash) failures.push("rootfs_hash");
  if (report.cgroup_path !== expected.cgroup_path) failures.push("cgroup_path");
  if (report.seccomp_profile_id !== PLUGIN_SECCOMP_PROFILE_ID) failures.push("seccomp_profile_id");
  if (report.broker_fd !== expected.broker_fd) failures.push("broker_fd");
  if (expected.expectedLauncherVersion && report.launcher_version !== expected.expectedLauncherVersion) {
    failures.push("launcher_version");
  }
  const namespaces: unknown = report.namespaces_entered;
  if (
    !Array.isArray(namespaces) ||
    !namespaces.every((value) => typeof value === "string") ||
    !arraysEqual(namespaces as string[], expectedNamespaces)
  ) {
    // A non-array / non-string namespaces field is a clean named deny, never a
    // raw TypeError from arraysEqual (the report is attacker-influenced input).
    failures.push("namespaces_entered");
  }
  if (failures.length > 0) {
    throw new Error(`confinement report mismatch: ${failures.join(",")}`);
  }
}

function hookFor(plugin: ManagedPlugin, hook: HookClass): HookDecl | undefined {
  return plugin.governance.hooks.find((decl) => decl.hook_class === hook);
}

function healthHooks(governance: Governance): PluginLifecycleHook[] {
  return governance.hooks.map((hook) => ({
    hook_class: hook.hook_class,
    mode: hook.hook_class === "ingress_content" ? "advisory" : "enforced",
  }));
}

function healthState(state: PluginLifecycleState): PluginHealth["state"] {
  if (state === "running" || state === "suspended" || state === "unhealthy" || state === "quarantined" || state === "evicted") {
    return state;
  }
  return "suspended";
}

function defaultNonce(): string {
  return randomBytes(16).toString("base64url");
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function writeAll(stream: Writable, bytes: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.write(bytes, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function readControlLine(stream: Readable, timeoutMs: number, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("timed out waiting for realized-confinement report"));
    }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > maxBytes) {
        // Bound the pre-confinement read: a launcher flooding fd 3 with no
        // newline must not balloon host memory within the timeout window.
        cleanup();
        reject(new Error(`confinement report exceeded ${maxBytes} bytes before newline`));
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline >= 0) {
        cleanup();
        resolve(buffer.slice(0, newline));
      }
    };
    const onEnd = () => {
      cleanup();
      reject(new Error("launcher exited before confinement report"));
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      clearTimeout(timer);
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("error", onError);
    };
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}
