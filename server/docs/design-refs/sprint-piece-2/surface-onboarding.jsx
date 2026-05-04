/* global React */

// ========== Surface 4: Onboarding ==========
function OnboardingSurface({ state = 'welcome' }) {
  return (
    <div className="onb-stage">
      {state === 'welcome' && <OnbWelcome />}
      {state === 'substrate' && <OnbSubstrate />}
      {state === 'success' && <OnbSuccess />}
      {state === 'next' && <OnbNext />}
    </div>
  );
}

function ProgressDots({ step }) {
  const steps = [0,1,2,3];
  return (
    <div className="onb-progress">
      <span>Step {step+1} of 4</span>
      <span className="step-dots">
        {steps.map(i => (
          <span key={i} className={i < step ? 'done' : i === step ? 'active' : ''} />
        ))}
      </span>
    </div>
  );
}

function OnbWelcome() {
  return (
    <div className="onb-card">
      <ProgressDots step={0} />
      <h1>You just installed Sanctuary.</h1>
      <p className="lede">In about three minutes we will: pick where your AI thinks, say hello to your fortress, and show you how to wrap your first agent. You can leave at any step. Nothing is sent anywhere yet.</p>
      <div style={{display:'grid', gridTemplateColumns:'repeat(3, 1fr)', gap:12, marginTop:8}}>
        {[
          ['1', 'Choose a substrate', 'Local. Hosted. Or hybrid.'],
          ['2', 'Round-trip', 'Say hello to your fortress.'],
          ['3', 'Next steps', 'Wrap an agent. Or read a bit.'],
        ].map(([n, t, d]) => (
          <div key={n} style={{background:'var(--paper-2)', border:'1px solid var(--rule)', borderRadius:'var(--rad)', padding:'14px 16px'}}>
            <div style={{fontFamily:'var(--mono)', fontSize:10, color:'var(--ink-4)', marginBottom:4}}>{`step ${n}`}</div>
            <div style={{fontFamily:'var(--serif)', fontSize:15, fontWeight:500, marginBottom:2}}>{t}</div>
            <div style={{fontSize:12, color:'var(--ink-3)'}}>{d}</div>
          </div>
        ))}
      </div>
      <div className="onb-actions">
        <button className="btn">Skip setup</button>
        <button className="btn btn-primary">Begin</button>
        <span className="key">↵ to begin</span>
      </div>
    </div>
  );
}

function OnbSubstrate() {
  return (
    <div className="onb-card">
      <ProgressDots step={1} />
      <h1>Where should your AI think.</h1>
      <p className="lede">A substrate is where the model runs. You can change this any time, per surface. Most people start with local.</p>

      <div className="onb-substrate-list">
        <div className="onb-substrate selected">
          <span className="radio" />
          <div>
            <strong>Local. On your own machine.</strong>
            <div className="tradeoffs">
              <span>private by default</span>
              <span>slower on long context</span>
              <span>no key</span>
            </div>
          </div>
          <div className="meta">
            <span className="pill tone-verified"><span className="dot" />ollama detected</span>
          </div>
        </div>
        <div className="onb-substrate">
          <span className="radio" />
          <div>
            <strong>Hosted. Through a no-log substrate.</strong>
            <div className="tradeoffs">
              <span>capable</span>
              <span>payloads pass through their host</span>
              <span>paste key</span>
            </div>
          </div>
          <div className="meta"><span className="pill tone-quiet">~900ms p50</span></div>
        </div>
        <div className="onb-substrate">
          <span className="radio" />
          <div>
            <strong>Frontier with privacy filter in front.</strong>
            <div className="tradeoffs">
              <span>top capability</span>
              <span>egress is redacted by your fortress</span>
              <span>paste key</span>
            </div>
          </div>
          <div className="meta"><span className="pill tone-quiet">~1.1s p50</span></div>
        </div>
      </div>

      <div className="onb-actions">
        <button className="btn">Back</button>
        <button className="btn btn-primary">Use local. Continue.</button>
        <span className="key">↵ continue</span>
      </div>
    </div>
  );
}

function OnbSuccess() {
  return (
    <div className="onb-card">
      <ProgressDots step={2} />
      <h1>You just talked to Sanctuary.</h1>
      <p className="lede">A round-trip went through your fortress, into your substrate, and back. Nothing left this machine. Here is what happened.</p>

      <div className="onb-success">
        <div className="onb-success-head">
          <span className="check" />
          <span>round-trip · verified</span>
        </div>
        <dl className="onb-receipt">
          <dt>routed through</dt><dd>local · llama-3.1:8b</dd>
          <dt>latency</dt><dd>412ms</dd>
          <dt>egress</dt><dd>none. local only.</dd>
          <dt>signed by</dt><dd>fortress · 7f3a..b91c</dd>
          <dt>recorded at</dt><dd>14:22:08 · ledger entry #1</dd>
        </dl>
      </div>

      <div style={{padding:'14px 16px', background:'var(--paper-2)', border:'1px solid var(--rule)', borderRadius:'var(--rad)', fontSize:13, color:'var(--ink-2)', lineHeight:1.55}}>
        Your fortress signed this round-trip. Every action your agents take from now on will be signed the same way, recorded the same way, and visible to you the same way. That is the whole product, in one motion.
      </div>

      <div className="onb-actions">
        <button className="btn">View ledger entry</button>
        <button className="btn btn-primary">Continue</button>
        <span className="key">↵ continue</span>
      </div>
    </div>
  );
}

function OnbNext() {
  return (
    <div className="onb-card">
      <ProgressDots step={3} />
      <h1>Where would you like to go.</h1>
      <p className="lede">You're set up. Most people do one of three things next. Take your time.</p>

      <div className="onb-next-grid">
        <button className="onb-next">
          <strong>Wrap an agent.</strong>
          <small>Give an existing agent a portable identity, a charter, and approval gates.</small>
          <span className="arrow">→ wrap</span>
        </button>
        <button className="onb-next">
          <strong>Configure substrates.</strong>
          <small>Different surfaces can use different substrates. Tune them when ready.</small>
          <span className="arrow">→ intelligence</span>
        </button>
        <button className="onb-next">
          <strong>Read a bit.</strong>
          <small>The four-layer model: Wall, Sentinels, Charter, Heralds. Ten minutes.</small>
          <span className="arrow">→ docs</span>
        </button>
      </div>

      <div className="onb-actions">
        <button className="btn btn-quiet">Take me to the dashboard</button>
        <span className="key" style={{marginLeft:'auto'}}>esc to dashboard</span>
      </div>
    </div>
  );
}

window.OnboardingSurface = OnboardingSurface;
