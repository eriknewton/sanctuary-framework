/* global React */

// ========== Surface 3: Agents + Inspect ==========
const AGENTS_DATA = [
  { id: 'A1', initials: 'RA', name: 'research-assistant', role: 'wrapped agent · gpt-style', state: 'live',  last: '2m ago',   att: 'verified', selected: true },
  { id: 'A2', initials: 'DR', name: 'doc-reviewer',       role: 'wrapped agent · summarizer', state: 'live',  last: '14s ago', att: 'verified' },
  { id: 'A3', initials: 'IT', name: 'intake-triage',      role: 'wrapped agent · router',     state: 'idle', last: '11m ago', att: 'degraded' },
  { id: 'A4', initials: 'CA', name: 'calendar-agent',     role: 'wrapped agent · scheduler',  state: 'off',  last: '2h ago',  att: 'verified' },
];

function AgentsSurface({ state = 'inspect' }) {
  const showEmpty = state === 'empty';
  const showInspect = state === 'inspect';

  if (showEmpty) {
    return (
      <div>
        <div className="page-head">
          <div>
            <p className="eyebrow">Agents</p>
            <h1>Agents.</h1>
            <p className="sub">Wrapped agents run inside your fortress. Sanctuary holds their identity, their policy, and their record. You hold them.</p>
          </div>
        </div>
        <div className="agents-empty">
          <div className="icon-frame"><div className="core" /></div>
          <h2>No agents wrapped yet.</h2>
          <p>Wrap an agent to give it a portable identity, a charter, and approval gates. Run the command in any project where your agent lives.</p>
          <div className="terminal-block">
            <span className="cmd"><span className="prompt">$</span>npx @sanctuary-framework/wrap ./your-agent</span>
            <button className="copy-btn">copy</button>
          </div>
          <button className="btn btn-primary">Wrap your first agent</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <p className="eyebrow">Agents</p>
          <h1>Agents.</h1>
          <p className="sub">{AGENTS_DATA.length} wrapped. Click one to inspect its activity, policy, and pending approvals.</p>
        </div>
        <div className="page-head-actions">
          <button className="btn">Wrap another</button>
          <button className="btn">Export ledger</button>
        </div>
      </div>

      <div className="agents-layout">
        <div className="agents-list">
          <div className="agents-list-head">
            <span>Agent</span>
            <span>State</span>
            <span>Attestation</span>
            <span>Last seen</span>
          </div>
          {AGENTS_DATA.map(a => (
            <div key={a.id} className={`agent-row ${a.selected && showInspect ? 'selected' : ''}`}>
              <div className="agent-identity">
                <div className="agent-glyph">{a.initials}</div>
                <div className="agent-name">
                  <strong>{a.name}</strong>
                  <small>{a.role}</small>
                </div>
              </div>
              <span className="agent-state">
                <span className={`state-dot ${a.state}`} />
                {a.state === 'live' ? 'on patrol' : a.state === 'idle' ? 'idle' : 'stopped'}
              </span>
              <AgentAttestationBadge state={a.att} />
              <span className="agent-last">{a.last}</span>
            </div>
          ))}
        </div>

        {showInspect && <InspectPane />}
      </div>
    </div>
  );
}

function InspectPane() {
  return (
    <div className="inspect-pane">
      <div className="inspect-head">
        <div className="row1">
          <div className="agent-glyph">RA</div>
          <h3>research-assistant</h3>
          <span style={{marginLeft:'auto'}}><AgentAttestationBadge state="verified" /></span>
        </div>
        <div className="meta">
          <span className="pill tone-verified"><span className="dot" />on patrol</span>
          <span className="pill tone-quiet">since 09:14</span>
          <span className="pill tone-quiet">3 sessions today</span>
        </div>
      </div>
      <div className="inspect-body">

        <div className="inspect-section">
          <h4>Pending approvals <span className="count">2</span></h4>
          <div className="approval-row">
            <div className="what">
              <span className="pill tone-degraded">tier-1 gate</span>
              Send three sources to the case folder.
            </div>
            <div className="why">
              The agent reached the per-session limit on outbound writes. This is a Wall rule you set on May 1. Approve once, or extend the limit.
            </div>
            <div className="actions">
              <button className="btn">Deny</button>
              <button className="btn">Extend limit</button>
              <button className="btn btn-primary">Approve once</button>
            </div>
          </div>
          <div className="approval-row">
            <div className="what">
              <span className="pill tone-degraded">tier-1 gate</span>
              Read external link from message 7.
            </div>
            <div className="why">
              The link points outside the substrate's allow-list. Sanctuary will not fetch it without your approval.
            </div>
            <div className="actions">
              <button className="btn">Deny</button>
              <button className="btn btn-primary">Approve once</button>
            </div>
          </div>
        </div>

        <div className="inspect-section">
          <h4>Recent activity</h4>
          <div className="timeline">
            <div className="timeline-item ok">
              <div className="ts">14:22:08 · 412ms</div>
              <div className="what">Fetched 3 sources on indemnity standards.</div>
              <div className="att"><ActionAttestationBadge state="verified" sig="9c7d..2a" /></div>
            </div>
            <div className="timeline-item ok">
              <div className="ts">14:18:31 · 388ms</div>
              <div className="what">Summarized intake.pdf for doc-reviewer.</div>
              <div className="att"><ActionAttestationBadge state="verified" sig="3f12..be" /></div>
            </div>
            <div className="timeline-item warn">
              <div className="ts">14:11:47 · paused</div>
              <div className="what">Outbound payload redacted by privacy filter.</div>
              <div className="att"><ActionAttestationBadge state="degraded" sig="b440..71" /></div>
            </div>
            <div className="timeline-item ok">
              <div className="ts">13:59:02 · 402ms</div>
              <div className="what">Created research note in case folder.</div>
              <div className="att"><ActionAttestationBadge state="verified" sig="e801..04" /></div>
            </div>
          </div>
        </div>

        <div className="inspect-section">
          <h4>Policy summary</h4>
          <div className="policy-line"><span className="k">Charter</span><span className="v">research-only · no outbound mail</span></div>
          <div className="policy-line"><span className="k">Wall templates</span><span className="v">4 active</span></div>
          <div className="policy-line"><span className="k">Sentinel band</span><span className="v">normal</span></div>
          <div className="policy-line"><span className="k">Egress</span><span className="v">case folder · allow-list</span></div>
        </div>

        <div className="inspect-section">
          <h4>Identity</h4>
          <div className="policy-line"><span className="k">Agent id</span><span className="v">agt_7f3a..b91c</span></div>
          <div className="policy-line"><span className="k">Wrapped at</span><span className="v">May 1, 14:22</span></div>
          <div className="policy-line"><span className="k">Substrate</span><span className="v">local · llama-3.1:8b</span></div>
          <div className="policy-line"><span className="k">Custody</span><span className="v"><CustodyBadge /></span></div>
        </div>

        <div className="inspect-section">
          <h4>Timeline · 24h</h4>
          <div style={{display:'grid', gridTemplateColumns:'repeat(24, 1fr)', gap:2, marginTop:6}}>
            {Array.from({length:24}).map((_, i) => {
              const v = [0,0,0,0,0,0,0,1,2,3,2,2,3,2,1,2,3,2,1,0,0,0,0,0][i];
              const map = ['var(--paper-3)', 'var(--sage-bg)', 'var(--sage)', 'var(--ochre)'];
              return <div key={i} style={{height:24, background:map[v], borderRadius:2}} title={`${i}:00`} />;
            })}
          </div>
          <div style={{display:'flex', justifyContent:'space-between', marginTop:6, fontFamily:'var(--mono)', fontSize:10, color:'var(--ink-3)'}}>
            <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span>
          </div>
        </div>

      </div>
    </div>
  );
}

window.AgentsSurface = AgentsSurface;
