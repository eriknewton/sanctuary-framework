/**
 * Sanctuary Dashboard — Multi-tenant aggregator
 *
 * Produces a host-wide snapshot that powers the multi-agent overview (the
 * `/agents` route served by `sanctuary dashboard --multi`). Source data:
 *
 *   - `discoverTenants()` for the filesystem layout
 *   - each tenant's `runtime.json` (written by its wrap/standalone process)
 *   - a best-effort `/api/health` probe (status-code only, no secrets)
 *
 * The snapshot never decrypts a tenant's encrypted state. The primary
 * payoff for the operator is a one-glance inventory with deep-links into
 * each tenant's full single-tenant dashboard.
 */

import {
  discoverTenants,
  type TenantDescriptor,
  type DiscoveryOptions,
} from "../cli/agents/discovery.js";
import {
  probeTenantDashboard,
  type HealthProbeResult,
} from "../cli/agents/health.js";

export interface MultiTenantTenantRow {
  name: string;
  storage_path: string;
  initialized: boolean;
  passphrase_status: "keychain" | "fallback-file" | "not-initialized";
  keychain_service: string;
  /** http://host:port when runtime.json was written; null otherwise. */
  dashboard_url: string | null;
  dashboard_port: number | null;
  webhook_callback_port: number | null;
  pid: number | null;
  started_at: string | null;
  mode: "wrap" | "standalone" | "co-located" | null;
  /** `/api/health` probe result. */
  running: boolean;
  probe_reason: string | null;
  last_activity: string | null;
}

export interface MultiTenantSnapshot {
  version: 1;
  generated_at: string;
  tenant_count: number;
  running_count: number;
  tenants: MultiTenantTenantRow[];
}

export interface MultiAggregatorOptions {
  /** Override discovery options (for tests). */
  discovery?: DiscoveryOptions;
  /** Swap the probe for tests. */
  probe?: (tenant: TenantDescriptor) => Promise<HealthProbeResult>;
}

function toRow(
  tenant: TenantDescriptor,
  probe: HealthProbeResult
): MultiTenantTenantRow {
  const rt = tenant.runtime;
  const dashboard_url = rt
    ? `http://${rt.dashboard_host}:${rt.dashboard_port}`
    : null;
  return {
    name: tenant.name,
    storage_path: tenant.storage_path,
    initialized: tenant.initialized,
    passphrase_status: tenant.passphrase_status,
    keychain_service: tenant.keychain_service,
    dashboard_url,
    dashboard_port: rt?.dashboard_port ?? null,
    webhook_callback_port: rt?.webhook_callback_port ?? null,
    pid: rt?.pid ?? null,
    started_at: rt?.started_at ?? null,
    mode: rt?.mode ?? null,
    running: probe.running,
    probe_reason: probe.reason,
    last_activity: tenant.last_activity,
  };
}

export async function getMultiTenantSnapshot(
  options: MultiAggregatorOptions = {}
): Promise<MultiTenantSnapshot> {
  const tenants = await discoverTenants(options.discovery ?? {});
  const probe = options.probe ?? probeTenantDashboard;
  const probes = await Promise.all(tenants.map((t) => probe(t)));
  const rows = tenants.map((t, i) => toRow(t, probes[i]!));
  return {
    version: 1,
    generated_at: new Date().toISOString(),
    tenant_count: rows.length,
    running_count: rows.filter((r) => r.running).length,
    tenants: rows,
  };
}
