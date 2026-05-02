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
      const res = await fetch(`${this.config.fortressEndpoint}/api/audit-log/pending-tier1`, {
        method: 'GET',
        headers: this.headers(),
      });
      if (!res.ok) {
        return this.cachedSnapshot?.pending_tier1.length ?? 0;
      }
      const data = (await res.json()) as { pending: PendingTier1Request[] };
      return data.pending?.length ?? 0;
    } catch {
      return this.cachedSnapshot?.pending_tier1.length ?? 0;
    }
  }

  async fetchFleetSnapshot(): Promise<FleetSnapshot> {
    const endpoint = this.config.fortressEndpoint;
    const headers = this.headers();
    try {
      const [pendingRes, recentRes, agentsRes] = await Promise.all([
        fetch(`${endpoint}/api/audit-log/pending-tier1`, { method: 'GET', headers }),
        fetch(`${endpoint}/api/audit-log?limit=10`, { method: 'GET', headers }),
        fetch(`${endpoint}/api/agents`, { method: 'GET', headers }),
      ]);

      const allOk = pendingRes.ok && recentRes.ok && agentsRes.ok;
      const pending = pendingRes.ok ? ((await pendingRes.json()) as { pending: PendingTier1Request[] }).pending : [];
      const recent = recentRes.ok ? ((await recentRes.json()) as { events: AuditEvent[] }).events : [];
      const agents = agentsRes.ok ? ((await agentsRes.json()) as { agents: AgentSnapshot[] }).agents : [];

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
