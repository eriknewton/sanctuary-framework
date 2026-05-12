/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-2 Filesystem Trap Monitor.
 *
 * Companion to Pi-1's HTTP runtime-trap-handler. Pi-1's HTTP trap
 * runs front-of-dispatch in the dashboard router (one canonical
 * intercept point for inbound requests); the filesystem analogue
 * has no equivalent single chokepoint, so Pi-2 ships the monitor as
 * a pure observation primitive that surfaces a single
 * `observe(operation)` API call sites invoke from wherever
 * filesystem-shaped operations happen.
 *
 * Integration shape: when an internal subsystem (proxy router,
 * state store, audit log, future tool-call dispatcher, operator
 * scripts) performs a filesystem-shaped operation that matters for
 * honeypot detection, that subsystem reports the operation through
 * `monitor.observe(...)`. The monitor checks the deployed
 * filesystem-class traps in the registry and, on match, fires the
 * audit event + sentinel finding via the same canonical pipeline
 * Pi-1 uses (Phi-1 finding store).
 *
 * Pi-2 ships the monitor + observe API. Specific wiring to
 * particular access points lands in follow-up PRs without changing
 * the monitor itself; the contract here is "any caller that wants
 * to participate in filesystem-honeypot observation calls observe()
 * at the access boundary they own."
 *
 * Castle-walking discipline:
 *   - Pure observation; no outbound surface.
 *   - The monitor reads from the per-fortress TrapRegistry (already
 *     scoped) and writes findings into the per-fortress
 *     SentinelFindingStore (already scoped). Multi-fortress
 *     isolation rides on the existing per-fortress instances.
 *   - Best-effort persistence: a finding-store write failure does
 *     not break the operation that triggered the observation. The
 *     observer's caller continues with the operation it was
 *     performing.
 *
 * Path matching: reuses Pi-1's `compileGlob` so the operator's
 * glob syntax is identical across HTTP and filesystem trap classes.
 */

import { randomUUID } from "node:crypto";

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../sentinel/types.js";

import {
  HONEYPOT_AUDIT_OPS,
  honeypotSentinelId,
  type FilesystemOp,
  type TrapSpec,
} from "./types.js";
import { compileGlob, TrapRegistry } from "./trap-registry.js";

/**
 * One filesystem-shaped operation reported through the monitor.
 * Callers populate as much of this shape as they have available;
 * `payload_hash` is optional because not every observation point
 * sees a payload (e.g., a delete is path-only).
 */
export interface FilesystemObservation {
  operation: FilesystemOp;
  path: string;
  caller_identity: string;
  payload_hash?: string;
}

export interface FilesystemTrapMonitorDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  /** Operator identity attribution for audit emissions. */
  operatorId: string;
  /** Stable fortress id stamped on every finding. */
  fortressId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

/**
 * Result of a single observe() call. `triggered` lists every
 * filesystem trap that fired on this observation; callers who care
 * (most do not) can branch on the array length.
 */
export interface FilesystemObserveResult {
  triggered: TrapSpec[];
  findings: SentinelFinding[];
}

export class FilesystemTrapMonitor {
  private readonly registry: TrapRegistry;
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly operatorId: string;
  private readonly fortressId: string;
  private readonly now: () => Date;

  constructor(deps: FilesystemTrapMonitorDeps) {
    this.registry = deps.registry;
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.operatorId = deps.operatorId;
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
  }

  /**
   * Report a filesystem-shaped operation to the monitor. Every
   * filesystem-class trap whose `path_pattern` matches the
   * observation's path AND whose `ops` list contains the
   * observation's operation fires a finding.
   *
   * Returns the list of triggered specs + the emitted findings.
   * Callers typically discard the return value; tests inspect it.
   */
  async observe(
    observation: FilesystemObservation,
  ): Promise<FilesystemObserveResult> {
    const triggered: TrapSpec[] = [];
    const findings: SentinelFinding[] = [];
    for (const spec of this.registry.list()) {
      if (spec.trigger.kind !== "filesystem") continue;
      if (!spec.trigger.ops.includes(observation.operation)) continue;
      const re = compileGlob(spec.trigger.path_pattern);
      if (!re.test(observation.path)) continue;
      const finding = await this.fireTrap(spec, observation);
      triggered.push(spec);
      findings.push(finding);
    }
    return { triggered, findings };
  }

  /** Emit one finding + audit event for a matched filesystem trap. */
  private async fireTrap(
    spec: TrapSpec,
    obs: FilesystemObservation,
  ): Promise<SentinelFinding> {
    const findingId = randomUUID();
    const observedAt = this.now().toISOString();
    const finding: SentinelFinding = {
      finding_id: findingId,
      sentinel_id: honeypotSentinelId(spec.trap_id),
      severity: spec.finding_severity,
      summary: this.buildSummary(spec, obs),
      details: {
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        path_matched: obs.path,
        operation: obs.operation,
        caller_identity: obs.caller_identity,
        ...(obs.payload_hash !== undefined ? { payload_hash: obs.payload_hash } : {}),
      },
      observed_at: observedAt,
      evidence_audit_ids: [],
      fortress_id: this.fortressId,
    };
    // Best-effort persist. A finding-store write failure must NOT
    // break the calling subsystem's operation. The Pi-1 invariant
    // ("trap RESPONSE is server-internal; nothing leaves the
    // fortress") applies here too: the call site continues with
    // whatever it was doing even if the finding fails to land.
    await this.findingStore.saveFinding(finding).catch(() => undefined);

    this.auditLog.append(
      "l2",
      HONEYPOT_AUDIT_OPS.TRIGGERED,
      this.operatorId,
      {
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        path_matched: obs.path,
        operation: obs.operation,
        caller_identity: obs.caller_identity,
        ...(obs.payload_hash !== undefined ? { payload_hash: obs.payload_hash } : {}),
        finding_id: findingId,
        severity: spec.finding_severity,
      },
    );
    return finding;
  }

  private buildSummary(spec: TrapSpec, obs: FilesystemObservation): string {
    if (spec.trigger.kind !== "filesystem") {
      // Defensive: caller-side filtering already excludes non-fs
      // triggers, but the union shape requires the type assertion
      // anyway. Falling back to a generic summary keeps the audit
      // emission honest.
      return `honeypot ${spec.trap_id} triggered`;
    }
    return `honeypot ${spec.trap_id} triggered: filesystem ${obs.operation} on ${obs.path} from ${obs.caller_identity} (severity ${spec.finding_severity}, pattern ${spec.trigger.path_pattern})`;
  }
}
