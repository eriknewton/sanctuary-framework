/**
 * The operator-side enforcement-event exporter.
 *
 * Ties the frozen schema + closed mapping + safe-by-default sinks + the Tier-1
 * enablement gate together, and records the export lifecycle with DISTINCT local
 * audit ops.
 *
 * TWO POSTURES:
 *   - LOCAL (default). `sink: "file"` needs NO approval and touches NO network.
 *     `enable()` just builds the local sink. This is the shipped default.
 *   - OUTBOUND PUSH. `sink: "http"` requires ALL of: the opt-in flag
 *     (`enabled: true`), a well-formed PINNED `destination_url`, AND a Tier-1
 *     operator approval at enable time (the SAME gate class as `state_export` /
 *     key rotation / `castle_wall_observe_promote`). If any is missing, or the
 *     operator denies, `enable()` REFUSES (fail closed) and audits a refusal;
 *     it never arms an outbound sink on the denied/incomplete path.
 *
 * FAIL LOUD ON DELIVERY FAILURE (AGENTS.md must-never #5): if an armed HTTP push
 * cannot reach the pinned collector, `exportEvents()` audits a refusal and
 * RE-THROWS. It never falls back to the file sink and never silently drops a
 * batch while reporting success.
 */

import type { AuditEntry } from "../../operational/audit-log.js";
import type { EnforcementEvent } from "./schema.js";
import { mapEntriesToEnforcementEvents } from "./map.js";
import {
  ENFORCEMENT_EXPORT_EMITTED,
  ENFORCEMENT_EXPORT_ENABLED,
  ENFORCEMENT_EXPORT_REFUSED,
} from "./audit-ops.js";
import type { EnforcementExportConfig } from "./config.js";
import {
  FileExportSink,
  HttpCollectorSink,
  stdoutLineWriter,
  summarizeByClass,
  type EnforcementExportSink,
  type LineWriter,
} from "./sink.js";

/** Tier-1 approval surface. `ApprovalGate.evaluate` satisfies it (mirrors PromoteApprover). */
export type ExportApprover = (
  operation: string,
  context: Record<string, unknown>,
) => Promise<{ allowed: boolean; reason?: string }>;

/** Best-effort local audit append. Wraps `AuditLog.append` in production. */
export type ExportAudit = (
  operation: string,
  details: Record<string, unknown>,
  result: "success" | "failure",
) => Promise<void>;

export interface EnforcementExporterDeps {
  /** Validated operator config. */
  config: EnforcementExportConfig;
  /** Tier-1 approval call. Invoked ONLY to arm the outbound HTTP push. */
  approve: ExportApprover;
  /** Local audit append for the export lifecycle ops. */
  audit: ExportAudit;
  /**
   * Optional injected line writer for the file sink (stdout by default). Injected
   * so tests stay hermetic (they never write a real file or a real socket).
   */
  fileWriter?: LineWriter;
  /**
   * Optional injected fetch for the HTTP sink (mocked in tests). NEVER a real
   * endpoint in a test.
   */
  fetchImpl?: typeof fetch;
}

/** Result of an `enable()` call. */
export type EnableOutcome =
  | { status: "enabled"; touchesNetwork: boolean }
  | { status: "refused"; reason: string };

/** Result of an `exportEvents()` call. */
export type ExportOutcome =
  | { status: "delivered"; count: number }
  | { status: "refused"; reason: string };

/**
 * Build the sink named by config, applying the Tier-1 gate for the outbound
 * lane. Pure of the audit side effects (the caller audits), so the gate logic is
 * unit-testable in isolation.
 */
export class EnforcementExporter {
  private sink: EnforcementExportSink | null = null;

  constructor(private readonly deps: EnforcementExporterDeps) {}

  /** Whether an armed sink opens a network connection. Null before `enable()`. */
  touchesNetwork(): boolean | null {
    return this.sink ? this.sink.touchesNetwork : null;
  }

  /**
   * Arm the exporter. For the file sink this always succeeds with no approval.
   * For the http sink it enforces opt-in + pinned destination + a Tier-1
   * approval, and REFUSES (audits a refusal, arms nothing) on any failure.
   */
  async enable(): Promise<EnableOutcome> {
    const { config } = this.deps;

    if (config.sink === "file") {
      this.sink = new FileExportSink(this.deps.fileWriter ?? stdoutLineWriter());
      await this.deps.audit(
        ENFORCEMENT_EXPORT_ENABLED,
        { sink: "file", touches_network: false },
        "success",
      );
      return { status: "enabled", touchesNetwork: false };
    }

    // ── Outbound HTTP push: fail closed on any missing precondition ──────────
    if (!config.enabled) {
      return this.refuseEnable("outbound push not opted in (enabled=false)");
    }
    if (config.destination_url === undefined) {
      // validateExportConfig already guarantees this for a well-formed http
      // config; the guard keeps the invariant explicit and fails closed if a
      // caller constructs a config object by hand.
      return this.refuseEnable("no pinned destination_url");
    }

    // Tier-1 gate. The approval context shows the human EXACTLY where events
    // would go (the pinned URL) and that outbound network egress is being armed.
    // No secret is placed in the context.
    const approval = await this.deps.approve(ENFORCEMENT_EXPORT_ENABLED, {
      sink: "http",
      pinned_destination_url: config.destination_url,
      forwards: "enforcement metadata only (egress decisions, policy changes, distress beacons)",
      touches_network: true,
    });
    if (!approval.allowed) {
      return this.refuseEnable(approval.reason ?? "Tier-1 approval denied");
    }

    this.sink = new HttpCollectorSink({
      destinationUrl: config.destination_url,
      fetchImpl: this.deps.fetchImpl,
    });
    await this.deps.audit(
      ENFORCEMENT_EXPORT_ENABLED,
      {
        sink: "http",
        pinned_destination_url: config.destination_url,
        touches_network: true,
      },
      "success",
    );
    return { status: "enabled", touchesNetwork: true };
  }

  private async refuseEnable(reason: string): Promise<EnableOutcome> {
    this.sink = null;
    await this.deps.audit(
      ENFORCEMENT_EXPORT_REFUSED,
      { phase: "enable", sink: this.deps.config.sink, reason },
      "failure",
    );
    return { status: "refused", reason };
  }

  /**
   * Map a batch of audit entries to frozen events and deliver them through the
   * armed sink. Non-forwarded / malformed entries are dropped by the mapping.
   *
   * Refuses (fail closed) if not enabled. On delivery failure it audits a
   * refusal and RE-THROWS (never falls back, never silently drops).
   */
  async exportEntries(entries: readonly AuditEntry[]): Promise<ExportOutcome> {
    return this.exportEvents(mapEntriesToEnforcementEvents(entries));
  }

  /** Deliver already-mapped events. See {@link exportEntries}. */
  async exportEvents(events: readonly EnforcementEvent[]): Promise<ExportOutcome> {
    if (this.sink === null) {
      const reason = "exporter not enabled";
      await this.deps.audit(
        ENFORCEMENT_EXPORT_REFUSED,
        { phase: "export", reason },
        "failure",
      );
      return { status: "refused", reason };
    }

    try {
      const result = await this.sink.deliver(events);
      await this.deps.audit(
        ENFORCEMENT_EXPORT_EMITTED,
        {
          sink: this.sink.kind,
          delivered: result.delivered,
          by_class: summarizeByClass(events),
        },
        "success",
      );
      return { status: "delivered", count: result.delivered };
    } catch (err) {
      // FAIL LOUD: audit the refusal, then re-throw. No fallback, no silent drop.
      const reason = err instanceof Error ? err.message : "delivery failed";
      await this.deps.audit(
        ENFORCEMENT_EXPORT_REFUSED,
        { phase: "export", sink: this.sink.kind, reason },
        "failure",
      );
      throw err;
    }
  }
}
