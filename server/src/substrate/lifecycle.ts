import type { HookClass } from "./fields.js";

export type PluginLifecycleState =
  | "installed"
  | "verified"
  | "running"
  | "suspended"
  | "unhealthy"
  | "quarantined"
  | "evicted";

export type PluginSuspensionReason = "operator" | "deny_flood" | "budget";

export interface PluginLifecycleHook {
  hook_class: HookClass;
  mode: "enforced" | "advisory" | "off";
}

export interface PluginLifecycleRecord {
  plugin_id: string;
  bundle_hash: string;
  instance_id: string;
  state: PluginLifecycleState;
  hooks: PluginLifecycleHook[];
  entered_at: string;
  previous_state?: PluginLifecycleState;
  reason?: string;
  suspension_reason?: PluginSuspensionReason;
}

export interface PluginLifecycleAuditSink {
  appendCritical(entry: {
    timestamp?: string;
    layer: "l1" | "l2" | "l3" | "l4";
    operation: string;
    identity_id: string;
    result: "success" | "failure";
    details?: Record<string, unknown>;
  }): Promise<void>;
}

export const PLUGIN_AUDIT_OPS: Record<PluginLifecycleState, string> = {
  installed: "plugin_install",
  verified: "plugin_verify",
  running: "plugin_load",
  suspended: "plugin_suspend",
  unhealthy: "plugin_unhealthy",
  quarantined: "plugin_quarantine",
  evicted: "plugin_revoke",
};

export class PluginLifecycleController {
  private readonly records = new Map<string, PluginLifecycleRecord>();
  private readonly now: () => string;
  private readonly auditSink?: PluginLifecycleAuditSink;

  constructor(options: { auditSink?: PluginLifecycleAuditSink; now?: () => string } = {}) {
    this.auditSink = options.auditSink;
    this.now = options.now ?? (() => new Date().toISOString());
  }

  get(pluginId: string): PluginLifecycleRecord | undefined {
    return this.records.get(pluginId);
  }

  list(): PluginLifecycleRecord[] {
    return [...this.records.values()];
  }

  async transition(input: {
    plugin_id: string;
    bundle_hash: string;
    instance_id: string;
    hooks: PluginLifecycleHook[];
    state: PluginLifecycleState;
    reason?: string;
    suspension_reason?: PluginSuspensionReason;
    details?: Record<string, unknown>;
  }): Promise<PluginLifecycleRecord> {
    const previous = this.records.get(input.plugin_id);
    const enteredAt = this.now();
    const record: PluginLifecycleRecord = {
      plugin_id: input.plugin_id,
      bundle_hash: input.bundle_hash,
      instance_id: input.instance_id,
      state: input.state,
      hooks: input.hooks,
      entered_at: enteredAt,
      ...(previous ? { previous_state: previous.state } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.suspension_reason ? { suspension_reason: input.suspension_reason } : {}),
    };

    await this.auditSink?.appendCritical({
      timestamp: enteredAt,
      layer: "l2",
      operation: PLUGIN_AUDIT_OPS[input.state],
      identity_id: "system",
      result:
        input.state === "quarantined" || input.state === "unhealthy" || input.state === "evicted"
          ? "failure"
          : "success",
      details: {
        plugin_id: input.plugin_id,
        bundle_hash: input.bundle_hash,
        instance_id: input.instance_id,
        state: input.state,
        previous_state: previous?.state ?? null,
        hooks: input.hooks,
        ...(input.reason ? { reason: input.reason } : {}),
        ...(input.suspension_reason ? { suspension_reason: input.suspension_reason } : {}),
        ...(input.details ?? {}),
      },
    });

    this.records.set(input.plugin_id, record);
    return record;
  }
}
