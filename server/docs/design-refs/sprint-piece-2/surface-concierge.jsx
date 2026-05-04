/* global React */

// ========== Surface 1: Concierge ==========
function ConciergeSurface({ state = 'empty' }) {
  const showError = state === 'error';
  const showThinking = state === 'thinking';
  const showActive = state === 'active' || state === 'thinking' || state === 'error';
  const showEmpty = state === 'empty';

  const messages = [
    { who: 'operator', body: "What's the status of the intake review I started this morning?" },
    { who: 'concierge', body: "doc-reviewer finished the intake at 09:41. Three documents flagged for your eyes:\n\n· two contracts with non-standard indemnity clauses,\n· one form missing a signature page.\n\nThe agent paused before sending its summary; it's waiting on your approval to release findings to your case folder.", meta: 'substrate: local · 412ms' },
    { who: 'operator', body: 'Show me the contract with the broader indemnity language.' },
    { who: 'concierge', body: "Pulled. Section 9.b extends indemnity to affiliates and assigns. Your usual template caps it at the named counterparty. Want me to draft a redline?", meta: 'substrate: local · 388ms' },
    { who: 'operator', body: 'Yes, draft it; I will review before send.' },
  ];

  return (
    <div className="concierge-wrap">
      <div className="page-head">
        <div>
          <p className="eyebrow">Concierge</p>
          <h1>Talk to your fortress.</h1>
          <p className="sub">A direct line to Sanctuary. Routed through the substrate you chose. Nothing leaves without your hand on it.</p>
        </div>
        <div className="page-head-actions">
          <button className="btn">History</button>
          <button className="btn">Substrate</button>
        </div>
      </div>

      <div className="concierge-card">
        <div className="concierge-header">
          <div className="concierge-persona">
            <div className="glyph-ring" />
            <div className="concierge-persona-text">
              <strong>Sanctuary</strong>
              <small>your fortress, speaking directly</small>
            </div>
          </div>
          <div className="concierge-meta">
            <span className="pill tone-verified">
              <span className="dot" />substrate: local · ollama
            </span>
            <span className="pill tone-quiet">412ms · p50</span>
          </div>
        </div>

        {showEmpty && (
          <div className="concierge-empty">
            <div className="concierge-empty-headline">
              <h2>Where would you like to begin.</h2>
              <p>Ask anything about your fortress. Sanctuary holds your context, your agents, your policy. It will answer plainly, or hand you to the right surface.</p>
            </div>
            <div className="concierge-suggest-grid">
              <button className="concierge-suggest">
                <span className="label">Orient</span>
                What can you help me with?
              </button>
              <button className="concierge-suggest">
                <span className="label">Inspect</span>
                Show me my agents and what they did today.
              </button>
              <button className="concierge-suggest">
                <span className="label">Audit</span>
                Audit log of the last hour, plain language.
              </button>
            </div>
          </div>
        )}

        {showActive && (
          <div className="concierge-history">
            {messages.map((m, i) => (
              <div key={i} className={`concierge-msg concierge-msg-${m.who}`}>
                <span className="concierge-msg-author">{m.who === 'operator' ? 'you' : 'sanctuary'}</span>
                <div className="concierge-msg-body">{m.body}</div>
                {m.meta && <div className="concierge-msg-meta"><span>{m.meta}</span><ActionAttestationBadge state="verified" sig="9c7d..2a" /></div>}
              </div>
            ))}
            {showThinking && (
              <div className="concierge-thinking">
                <span className="thinking-dots"><span /><span /><span /></span>
                <span>thinking. routed local.</span>
              </div>
            )}
            {showError && (
              <div className="concierge-error">
                <span className="icon" />
                <div>
                  <h4>The local substrate did not answer.</h4>
                  <p>ollama at 127.0.0.1:11434 stopped responding 12 seconds ago. Your messages are queued and not sent anywhere else. You can retry, switch to a configured fallback, or open the substrate console.</p>
                </div>
                <div className="actions">
                  <button className="btn">Retry</button>
                  <button className="btn btn-primary">Switch substrate</button>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="concierge-composer">
          <div className="input-wrap">
            <input placeholder="Type to Sanctuary. Enter to send." defaultValue={showError ? 'Yes, draft it; I will review before send.' : ''} />
            <span className="composer-meta">⌘ + ↵</span>
          </div>
          <button className="btn btn-primary" style={{padding:'8px 18px'}}>Send</button>
        </div>
      </div>
    </div>
  );
}

window.ConciergeSurface = ConciergeSurface;
