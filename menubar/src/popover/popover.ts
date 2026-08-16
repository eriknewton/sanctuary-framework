// Popover view. Renders a fleet snapshot anchored to the menubar tray icon.
// Read-only in Sprint Piece 1. Approve / deny buttons land in Piece 2 once the
// chat-removal PR's click-to-inspect endpoint is merged.

import type { FleetSnapshot, AuditEvent, AgentSnapshot, PendingTier1Request } from '../api/client';

export interface PopoverDeps {
  onOpenDashboard: () => void;
  onOpenSettings: () => void;
}

export class PopoverView {
  private root: HTMLElement;

  constructor(rootSelector: string, private deps: PopoverDeps) {
    const el = document.querySelector(rootSelector) as HTMLElement | null;
    if (!el) throw new Error(`PopoverView: root selector ${rootSelector} not found`);
    this.root = el;
  }

  render(snapshot: FleetSnapshot): void {
    this.root.innerHTML = '';

    const container = document.createElement('div');
    container.className = 'popover-container';

    container.appendChild(this.renderHeader(snapshot));
    container.appendChild(this.renderPendingSection(snapshot.pending_tier1));
    container.appendChild(this.renderRecentSection(snapshot.recent_events));
    container.appendChild(this.renderAgentsSection(snapshot.agents));
    container.appendChild(this.renderFooter(snapshot));

    this.root.appendChild(container);
  }

  renderEmpty(): void {
    this.root.innerHTML = `
      <div class="popover-container">
        <div class="popover-empty">
          <p>Sanctuary is not connected to a fortress yet.</p>
          <p>Run the onboarding wizard to set up your first fortress endpoint.</p>
        </div>
      </div>
    `;
  }

  private renderHeader(snapshot: FleetSnapshot): HTMLElement {
    const header = document.createElement('div');
    header.className = 'popover-header';
    header.innerHTML = `
      <div class="popover-title">Sanctuary</div>
      <div class="popover-subtitle">Watching ${snapshot.agents.length} agent${snapshot.agents.length === 1 ? '' : 's'}</div>
    `;
    return header;
  }

  private renderPendingSection(pending: PendingTier1Request[]): HTMLElement {
    const section = document.createElement('section');
    section.className = 'popover-section pending';
    const heading = document.createElement('h3');
    heading.textContent = `Pending approvals (${pending.length})`;
    section.appendChild(heading);

    if (pending.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'No actions waiting on your approval right now.';
      section.appendChild(empty);
      return section;
    }

    const list = document.createElement('ul');
    list.className = 'pending-list';
    for (const req of pending) {
      const li = document.createElement('li');
      li.className = 'pending-item';
      const message = req.operator_message ?? `${req.agent_id} wants to call ${req.tool}`;
      li.innerHTML = `
        <div class="pending-message">${escapeHtml(message)}</div>
        <div class="pending-meta">
          <span class="agent-id">${escapeHtml(req.agent_id)}</span>
          <span class="timestamp">${formatTimestamp(req.timestamp)}</span>
        </div>
        <div class="pending-actions">
          <span class="action-stub">Approve / deny ships in Sprint Piece 2.</span>
        </div>
      `;
      list.appendChild(li);
    }
    section.appendChild(list);
    return section;
  }

  private renderRecentSection(events: AuditEvent[]): HTMLElement {
    const section = document.createElement('section');
    section.className = 'popover-section recent';
    const heading = document.createElement('h3');
    heading.textContent = 'Recent audit events';
    section.appendChild(heading);

    if (events.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'No recent events.';
      section.appendChild(empty);
      return section;
    }

    const list = document.createElement('ul');
    list.className = 'recent-list';
    for (const event of events.slice(0, 10)) {
      const li = document.createElement('li');
      li.className = `recent-item tier-${event.tier} decision-${event.decision}`;
      const message = event.operator_message ?? `${event.agent_id} called ${event.tool}`;
      li.innerHTML = `
        <div class="recent-message">${escapeHtml(message)}</div>
        <div class="recent-meta">
          <span class="tier-badge">T${event.tier}</span>
          <span class="decision">${event.decision}</span>
          <span class="timestamp">${formatTimestamp(event.timestamp)}</span>
        </div>
      `;
      list.appendChild(li);
    }
    section.appendChild(list);
    return section;
  }

  private renderAgentsSection(agents: AgentSnapshot[]): HTMLElement {
    const section = document.createElement('section');
    section.className = 'popover-section agents';
    const heading = document.createElement('h3');
    heading.textContent = 'Agents';
    section.appendChild(heading);

    if (agents.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'No agents wrapped yet. Run "sanctuary wrap <agent>" to add one.';
      section.appendChild(empty);
      return section;
    }

    const list = document.createElement('ul');
    list.className = 'agents-list';
    for (const agent of agents) {
      const li = document.createElement('li');
      li.className = `agent-item status-${agent.status}`;
      li.innerHTML = `
        <div class="agent-id">${escapeHtml(agent.agent_id)}</div>
        <div class="agent-meta">
          <span class="tier">Tier ${agent.tier}</span>
          <span class="status">${agent.status}</span>
          <span class="last-activity">${agent.last_activity ? formatTimestamp(agent.last_activity) : 'never'}</span>
        </div>
      `;
      list.appendChild(li);
    }
    section.appendChild(list);
    return section;
  }

  private renderFooter(snapshot: FleetSnapshot): HTMLElement {
    const footer = document.createElement('div');
    // The `status-` class is BUILT, not written out, so the two class names it
    // can produce that carry styling -- `status-degraded` and
    // `status-disconnected` -- appear nowhere in this file as literals. Their
    // only literal spelling is the selector pair in
    // `menubar/src/styles/popover.css` (`.status-degraded .status-dot`,
    // `.status-disconnected .status-dot`), which must match the members of the
    // `FleetSnapshot.connection_status` union in `menubar/src/api/client.ts`.
    // `connected` deliberately has no rule: the base `.status-dot` colour IS
    // the connected state.
    //
    // Failure mode: rename a union member and nothing breaks, throws, or fails
    // to compile. The CSS selector simply stops matching and the dot silently
    // renders in the connected colour, so a disconnected fortress looks
    // healthy. A grep for the CSS class will not find this producer either.
    footer.className = `popover-footer status-${snapshot.connection_status}`;
    footer.innerHTML = `
      <div class="connection-info">
        <span class="status-dot"></span>
        <span class="endpoint">${escapeHtml(snapshot.fortress_endpoint)}</span>
        <span class="status-text">${snapshot.connection_status}</span>
      </div>
      <div class="footer-actions">
        <button class="link-btn" data-action="settings">Settings</button>
        <button class="link-btn" data-action="dashboard">Open dashboard</button>
      </div>
    `;
    footer.querySelector('[data-action="dashboard"]')?.addEventListener('click', () => {
      this.deps.onOpenDashboard();
    });
    footer.querySelector('[data-action="settings"]')?.addEventListener('click', () => {
      this.deps.onOpenSettings();
    });
    return footer;
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diffMs = now - d.getTime();
    if (diffMs < 60_000) return 'just now';
    if (diffMs < 3_600_000) return `${Math.floor(diffMs / 60_000)}m ago`;
    if (diffMs < 86_400_000) return `${Math.floor(diffMs / 3_600_000)}h ago`;
    return d.toLocaleString();
  } catch {
    return iso;
  }
}
