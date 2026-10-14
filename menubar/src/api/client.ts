// Fortress API client. Talks to the Sanctuary fortress's existing audit-log + agent surfaces.
// Read-only in Sprint Piece 1. Sprint Piece 2 adds approve/deny POST endpoints.

import { fetch } from '@tauri-apps/plugin-http';

export interface PendingTier1Request {
  audit_id: string;
  agent_id: string;
  tool: string;
  timestamp: string;
  operator_message?: string;
}

export interface AuditEvent {
  audit_id: string;
  agent_id: string;
  tool: string;
  tier: 1 | 2 | 3;
  decision: 'approved' | 'denied' | 'auto-allow' | 'pending';
  timestamp: string;
  operator_message?: string;
}

export interface AgentSnapshot {
  agent_id: string;
  tier: 'A' | 'B' | 'C';
  last_activity: string | null;
  status: 'online' | 'idle' | 'offline';
}

export interface FleetSnapshot {
  pending_tier1: PendingTier1Request[];
  recent_events: AuditEvent[];
  agents: AgentSnapshot[];
  fortress_endpoint: string;
  connection_status: 'connected' | 'degraded' | 'disconnected';
}

export interface ClientConfig {
  fortressEndpoint: string;
  authToken?: string;
}

interface DashboardPendingApproval {
  id: string;
  operation: string;
  tier: number;
  reason?: string;
  timestamp?: string;
  created_at?: string;
  context?: Record<string, unknown>;
}

interface DashboardAuditEntry {
  timestamp: string;
  layer?: string;
  operation: string;
  identity_id?: string;
  result?: string;
  details?: Record<string, unknown>;
}

interface DashboardSnapshot {
  generated_at?: string;
  overall?: { status?: string };
  agent?: {
    display_name?: string;
    primary_identity_id?: string;
    identity_count?: number;
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayFromPayload<T>(payload: unknown, key: string): T[] {
  if (Array.isArray(payload)) return payload as T[];
  const record = asRecord(payload);
  const value = record[key];
  return Array.isArray(value) ? (value as T[]) : [];
}

function stringField(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function mapPendingApproval(item: DashboardPendingApproval): PendingTier1Request {
  const context = asRecord(item.context);
  return {
    audit_id: item.id,
    agent_id:
      stringField(context.agent_id) ??
      stringField(context.identity_id) ??
      'fortress',
    tool: item.operation,
    timestamp: item.created_at ?? item.timestamp ?? new Date(0).toISOString(),
    operator_message: item.reason,
  };
}

function tierFromLayer(layer: string | undefined): 1 | 2 | 3 {
  if (layer === 'l1') return 1;
  if (layer === 'l2') return 2;
  return 3;
}

function decisionFromResult(entry: DashboardAuditEntry): AuditEvent['decision'] {
  if (entry.operation.includes('pending')) return 'pending';
  if (entry.result === 'failure') return 'denied';
  if (entry.operation.includes('auto')) return 'auto-allow';
  return 'approved';
}

function mapAuditEntry(entry: DashboardAuditEntry): AuditEvent {
  return {
    audit_id: `${entry.timestamp}:${entry.operation}`,
    agent_id:
      stringField(entry.details?.agent_id) ??
      stringField(entry.identity_id) ??
      'fortress',
    tool: entry.operation,
    tier: tierFromLayer(entry.layer),
    decision: decisionFromResult(entry),
    timestamp: entry.timestamp,
    operator_message: stringField(entry.details?.reason),
  };
}

function mapSnapshotAgents(snapshot: DashboardSnapshot): AgentSnapshot[] {
  const agent = snapshot.agent;
  if (!agent || (agent.identity_count ?? 0) <= 0) return [];
  const status = snapshot.overall?.status;
  return [
    {
      agent_id:
        agent.primary_identity_id ??
        agent.display_name ??
        'fortress-operator',
      tier: status === 'compromised' ? 'C' : status === 'degraded' ? 'B' : 'A',
      last_activity: snapshot.generated_at ?? null,
      status: status === 'compromised' ? 'offline' : 'online',
    },
  ];
}

export class FortressClient {
  private cachedSnapshot: FleetSnapshot | null = null;
  private lastFetchOk = 0;

  constructor(private config: ClientConfig) {}

  setConfig(config: ClientConfig): void {
    this.config = config;
    this.cachedSnapshot = null;
    this.lastFetchOk = 0;
  }

  getConfig(): ClientConfig {
    return this.config;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { Accept: 'application/json' };
    if (this.config.authToken) {
      h['Authorization'] = `Bearer ${this.config.authToken}`;
    }
    return h;
  }

  async fetchPendingTier1Count(): Promise<number> {
    try {
      const res = await fetch(`${this.config.fortressEndpoint}/api/pending`, {
        method: 'GET',
        headers: this.headers(),
      });
      if (!res.ok) {
        return this.cachedSnapshot?.pending_tier1.length ?? 0;
      }
      const data = await res.json();
      return arrayFromPayload<DashboardPendingApproval>(data, 'pending').length;
    } catch {
      return this.cachedSnapshot?.pending_tier1.length ?? 0;
    }
  }

  async fetchFleetSnapshot(): Promise<FleetSnapshot> {
    const endpoint = this.config.fortressEndpoint;
    const headers = this.headers();
    try {
      const [pendingRes, recentRes, agentsRes] = await Promise.all([
        fetch(`${endpoint}/api/pending`, { method: 'GET', headers }),
        fetch(`${endpoint}/api/audit-log?limit=10`, { method: 'GET', headers }),
        fetch(`${endpoint}/api/snapshot`, { method: 'GET', headers }),
      ]);

      const allOk = pendingRes.ok && recentRes.ok && agentsRes.ok;
      const pending = pendingRes.ok
        ? arrayFromPayload<DashboardPendingApproval>(
            await pendingRes.json(),
            'pending',
          ).map(mapPendingApproval)
        : [];
      const recent = recentRes.ok
        ? arrayFromPayload<DashboardAuditEntry>(
            await recentRes.json(),
            'entries',
          ).map(mapAuditEntry)
        : [];
      const agents = agentsRes.ok
        ? mapSnapshotAgents((await agentsRes.json()) as DashboardSnapshot)
        : [];

      const snap: FleetSnapshot = {
        pending_tier1: pending ?? [],
        recent_events: recent ?? [],
        agents: agents ?? [],
        fortress_endpoint: endpoint,
        connection_status: allOk ? 'connected' : 'degraded',
      };

      this.cachedSnapshot = snap;
      this.lastFetchOk = Date.now();
      return snap;
    } catch {
      if (this.cachedSnapshot) {
        return { ...this.cachedSnapshot, connection_status: 'disconnected' };
      }
      return {
        pending_tier1: [],
        recent_events: [],
        agents: [],
        fortress_endpoint: endpoint,
        connection_status: 'disconnected',
      };
    }
  }

  // SSE subscription for live Tier 1 events.
  // Returns an unsubscribe function. The caller should manage lifecycle.
  subscribeTier1Events(onEvent: (event: AuditEvent) => void, onError: (err: unknown) => void): () => void {
    const url = `${this.config.fortressEndpoint}/api/stream`;
    const es = new EventSource(url, { withCredentials: false });
    es.addEventListener('audit', (msg) => {
      try {
        const event = JSON.parse((msg as MessageEvent).data) as AuditEvent;
        if (event.tier === 1 && event.decision === 'pending') {
          onEvent(event);
        }
      } catch (err) {
        onError(err);
      }
    });
    es.addEventListener('error', (err) => {
      onError(err);
    });
    return () => es.close();
  }

  getCachedSnapshot(): FleetSnapshot | null {
    return this.cachedSnapshot;
  }

  msSinceLastFetchOk(): number {
    return this.lastFetchOk === 0 ? Number.POSITIVE_INFINITY : Date.now() - this.lastFetchOk;
  }
}
