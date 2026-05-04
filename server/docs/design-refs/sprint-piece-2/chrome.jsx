/* global React */

// ========== Sidebar ==========
function Sidebar({ surface, onSurface }) {
  const items = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'agents',    label: 'Agents',       n: 4 },
    { id: 'concierge', label: 'Concierge' },
    { id: 'intelligence', label: 'Intelligence' },
    { id: 'policy',    label: 'Policy' },
    { id: 'privacy',   label: 'Privacy' },
    { id: 'coordination', label: 'Coordination' },
    { id: 'health',    label: 'Health' },
    { id: 'exit-drill', label: 'Exit drill' },
  ];
  const surfaceToNav = {
    concierge: 'concierge',
    intelligence: 'intelligence',
    agents: 'agents',
    onboarding: 'dashboard',
    attestation: 'dashboard',
  };
  const active = surfaceToNav[surface] || 'dashboard';
  return (
    <aside className="sidebar">
      <div className="sidebar-mark">
        <div className="mark-glyph" />
        <h1>Sanctuary</h1>
      </div>
      <nav>
        {items.map(it => (
          <a key={it.id} href="#" className={active === it.id ? 'active' : ''}
             onClick={e => { e.preventDefault(); }}>
            <span className="nav-dot" />
            <span>{it.label}</span>
            {it.n != null && <span className="nav-aux">{it.n}</span>}
          </a>
        ))}
      </nav>
      <div className="sidebar-foot">
        <span className="state-dot live" />
        <span>fortress on patrol</span>
      </div>
    </aside>
  );
}

// ========== Topbar ==========
function Topbar({ attestationState = 'verified', showAttestation = true }) {
  return (
    <header className="topbar">
      <span className="brand">fortress.local</span>
      <div className="pills">
        <span className="pill">v1.2.0</span>
        <span className="pill tone-quiet">deployment: local</span>
        <span className="pill tone-quiet">mode: solo</span>
        {showAttestation && <GlobalAttestationBadge state={attestationState} />}
      </div>
      <div className="topbar-actions">
        <button className="btn btn-quiet" title="Theme">◐</button>
        <button className="btn btn-danger">Lockdown</button>
      </div>
    </header>
  );
}

// ========== Fortress column ==========
function FortressColumn({ compact = false }) {
  return (
    <aside className="fortress">
      <div className="card">
        <p className="card-eyebrow">Four enforcement layers</p>
        <div style={{display:'flex', flexDirection:'column', gap:8}}>
          {[
            ['Wall', 'Boundary policy. 12 templates active.'],
            ['Sentinels', 'Behavioral scoring. 3 agents under watch.'],
            ['Charter', 'Operator intent. 4 charter rules.'],
            ['Heralds', 'Outbound messaging. 2 channels.'],
          ].map(([t, d]) => (
            <div key={t} style={{padding:'8px 10px', background:'var(--surface-2)', border:'1px solid var(--rule)', borderRadius:'var(--rad)'}}>
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                <strong style={{fontFamily:'var(--serif)', fontWeight:500, fontSize:13}}>{t}</strong>
                <span className="state-dot live" />
              </div>
              <p style={{margin:'2px 0 0', fontSize:11, color:'var(--ink-3)', fontFamily:'var(--mono)'}}>{d}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <p className="card-eyebrow">Recent activity</p>
        <div className="timeline">
          <div className="timeline-item ok">
            <div className="ts">14:22:08</div>
            <div className="what">research-assistant fetched 3 sources</div>
          </div>
          <div className="timeline-item warn">
            <div className="ts">14:21:54</div>
            <div className="what">intake-triage paused for approval</div>
          </div>
          <div className="timeline-item ok">
            <div className="ts">14:18:31</div>
            <div className="what">doc-reviewer summarized intake.pdf</div>
          </div>
        </div>
      </div>
    </aside>
  );
}

// ========== Attestation badges ==========
function GlobalAttestationBadge({ state = 'verified', hash = '7f3a..b91c' }) {
  const labels = {
    verified: 'attested',
    degraded: 'degraded signature',
    unverified: 'unverified',
    pending: 'pending',
  };
  const stateClass = state === 'pending' ? 'tone-quiet' : state;
  return (
    <span className={`att-global ${state === 'pending' ? '' : state}`} title="Fortress identity attestation">
      <span className="seal">
        <span className={`seal-ring ${state === 'pending' ? 'dashed' : ''}`} />
        <span className="seal-core" />
      </span>
      <span className="label">{labels[state]}</span>
      {state !== 'pending' && <span className="hash">{hash}</span>}
    </span>
  );
}

function AgentAttestationBadge({ state = 'verified' }) {
  const t = { verified: 'attested', degraded: 'degraded', unverified: 'unverified' };
  return (
    <span className={`att-agent ${state}`}>
      <span className="mark" />
      <span>{t[state]}</span>
    </span>
  );
}

function ActionAttestationBadge({ state = 'verified', sig = 'a1b2..f9' }) {
  return (
    <span className={`att-action ${state}`}>
      <span className="tick" />
      <span>{sig}</span>
    </span>
  );
}

function CustodyBadge() {
  return (
    <span className="att-custody" title="Custody provenance: stub at v1.2; future signatures land here.">
      <span className="seal-stub" />
      <span className="stub-tag">custody · stub</span>
    </span>
  );
}

window.Sidebar = Sidebar;
window.Topbar = Topbar;
window.FortressColumn = FortressColumn;
window.GlobalAttestationBadge = GlobalAttestationBadge;
window.AgentAttestationBadge = AgentAttestationBadge;
window.ActionAttestationBadge = ActionAttestationBadge;
window.CustodyBadge = CustodyBadge;
