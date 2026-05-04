/* global React */

// ========== Surface 2: Intelligence panel ==========
const SURFACES_DATA = [
  {
    key: 'concierge', name: 'Concierge',
    note: 'Operator-facing chat with Sanctuary itself.',
    substrate: 'local · llama-3.1:8b', detail: 'on-device · 412ms p50',
    status: 'ok', failures: 0,
  },
  {
    key: 'gate-advisor', name: 'Gate advisor',
    note: 'Plain-language explanation of policy choices.',
    substrate: 'local · llama-3.1:8b', detail: 'on-device · 388ms p50',
    status: 'ok', failures: 0,
  },
  {
    key: 'sentinel-scoring', name: 'Sentinel scoring',
    note: 'Behavioral risk score on agent activity.',
    substrate: 'frontier-with-filter', detail: 'redacted egress · 1.1s p50',
    status: 'warn', failures: 2,
  },
  {
    key: 'gate-explanation', name: 'Gate explanation',
    note: 'Per-gate decision rationale, on demand.',
    substrate: 'local · llama-3.1:8b', detail: 'on-device · 402ms p50',
    status: 'ok', failures: 0,
  },
  {
    key: 'privacy-filter', name: 'Privacy filter',
    note: 'Redaction model for outbound payloads.',
    substrate: 'venice · llama-3.1:70b', detail: 'no-log host · 920ms p50',
    status: 'ok', failures: 0,
  },
  {
    key: 'template-suggestion', name: 'Template suggestion',
    note: 'Suggested gate templates from Wall library.',
    substrate: 'not configured', detail: 'will fall back to deterministic rules',
    status: 'fail', failures: 4,
  },
];

function IntelligenceSurface({ state = 'configured' }) {
  const showModal = state === 'modal';
  const showFailures = state === 'failures';
  const showBulk = state === 'bulk';

  return (
    <div className="intel-wrap" style={{position: 'relative'}}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Intelligence</p>
          <h1>Substrate routing.</h1>
          <p className="sub">Six surfaces. Six choices. Each surface picks where its thinking happens. Local for privacy. Hosted for capability. Hybrid for both.</p>
        </div>
        <div className="page-head-actions">
          <button className="btn">Test all routes</button>
          <button className="btn btn-primary">Apply changes</button>
        </div>
      </div>

      <div className="intel-bulk">
        <div className="bulk-text">
          <strong>Apply one substrate to all six surfaces.</strong>
          <span>Useful when first wiring up. You can override per-surface afterwards.</span>
        </div>
        <div className="bulk-actions">
          <span className="pill tone-quiet">5 of 6 configured</span>
          {showBulk
            ? <button className="btn btn-primary">Apply local · llama-3.1:8b →</button>
            : <button className="btn">Bulk apply.</button>}
        </div>
      </div>

      <div className="intel-grid">
        {SURFACES_DATA.map((s, i) => {
          const expanded = showFailures && s.key === 'sentinel-scoring';
          return (
            <div key={s.key} className="intel-card">
              <div className="intel-card-head">
                <div className="intel-card-name">
                  <strong>{s.name}</strong>
                  <small>{s.note}</small>
                </div>
                <span className={`intel-card-status ${s.status}`}>
                  <span className={`status-glyph ${s.status}`} />
                  {s.status === 'ok' ? 'healthy' : s.status === 'warn' ? 'degraded' : 'unconfigured'}
                </span>
              </div>
              <div className="intel-substrate">
                <div className="sub-line primary">
                  <span>{s.substrate}</span>
                  <button className="btn btn-quiet" style={{padding:'2px 6px', fontSize:11}}>change</button>
                </div>
                <div className="sub-line secondary"><span>{s.detail}</span></div>
              </div>
              <div className="intel-card-foot">
                <button className={`intel-failures-toggle ${expanded ? 'open' : ''}`}>
                  <span className="caret" />
                  {s.failures > 0 ? `${s.failures} recent failure${s.failures>1?'s':''}` : 'no recent failures'}
                </button>
                <span style={{fontFamily:'var(--mono)', fontSize:11, color:'var(--ink-3)'}}>last route: 14:22:08</span>
              </div>
              {expanded && (
                <div className="intel-failures">
                  <div className="intel-failure-row">
                    <span className="ts">14:18:02</span>
                    <div>
                      <div className="err-class">timeout · upstream</div>
                      <div>The frontier route did not respond in 6s. Sentinel fell back to rule-based scoring on this turn.</div>
                      <div className="remed">Try: lower the timeout cap, or pin sentinel-scoring to local.</div>
                    </div>
                  </div>
                  <div className="intel-failure-row">
                    <span className="ts">14:11:47</span>
                    <div>
                      <div className="err-class">filter · refused</div>
                      <div>The privacy filter dropped a payload field flagged as identifying. The downstream model received a redacted prompt.</div>
                      <div className="remed">Expected behavior. Review the redaction policy if this surface needs the field.</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {showModal && <SubstrateSwitcherModal />}
    </div>
  );
}

function SubstrateSwitcherModal() {
  const opts = [
    {
      k: 'local', name: 'Local', selected: true,
      desc: 'Runs on your machine. Nothing leaves the fortress. Slower on long context.',
      side: 'no key', latency: '~400ms',
    },
    {
      k: 'venice', name: 'Venice', selected: false,
      desc: 'Hosted no-log substrate. Capable; payloads still pass through their host.',
      side: 'paste key', latency: '~900ms',
    },
    {
      k: 'frontier', name: 'Frontier with filter', selected: false,
      desc: 'Top-shelf models with the privacy filter in front. Capable; egress is redacted.',
      side: 'paste key', latency: '~1.1s',
    },
    {
      k: 'hybrid', name: 'Hybrid (local first, frontier on miss)', selected: false,
      desc: 'Try local; fall back to frontier when local declines or stalls. Best for mixed workloads.',
      side: 'paste key', latency: 'variable',
    },
  ];
  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog">
        <h2>Pick a substrate for sentinel scoring.</h2>
        <p className="modal-sub">Sentinel scoring is the model that judges whether an agent's behavior looks normal for that agent. It runs every turn.</p>
        {opts.map(o => (
          <div key={o.k} className={`intel-option ${o.selected ? 'selected' : ''}`}>
            <span className="radio" />
            <div className="intel-option-body">
              <strong>{o.name}</strong>
              <small>{o.desc}</small>
            </div>
            <div className="intel-option-meta">
              <span className="pill tone-quiet">{o.side}</span>
              <span className="pill tone-quiet">{o.latency}</span>
            </div>
          </div>
        ))}
        <div className="intel-suboptions">
          <label>API key (paste once. stored encrypted on your fortress.)</label>
          <input placeholder="sk-•••••••••••••••••••••••••••" />
        </div>
        <div className="modal-actions">
          <button className="btn">Cancel</button>
          <button className="btn btn-primary">Save and route</button>
        </div>
      </div>
    </div>
  );
}

window.IntelligenceSurface = IntelligenceSurface;
