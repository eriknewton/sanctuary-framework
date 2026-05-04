/* global React */

// ========== Surface 5: Attestation badge gallery ==========
function AttestationSurface() {
  return (
    <div className="att-gallery">
      <div className="page-head">
        <div>
          <p className="eyebrow">Attestation</p>
          <h1>Four classes of badge.</h1>
          <p className="sub">A signature you can see. From the whole fortress, down to a single action. Degrade, never destroy: a failed signature becomes neutral with a tooltip; the surface keeps working.</p>
        </div>
      </div>

      <div className="att-section">
        <div className="att-section-head">
          <div>
            <h2>Global · the fortress itself.</h2>
            <p>Lives in the topbar. Visible on every surface. Tells you the fortress's identity is currently signed and matches the binary you installed.</p>
          </div>
          <span className="label">topbar</span>
        </div>

        <div className="att-row">
          <div className="demo"><GlobalAttestationBadge state="verified" hash="7f3a..b91c" /></div>
          <div className="desc">
            <strong>Verified</strong>
            <small>Identity matches. Binary matches. Default state for a healthy fortress.</small>
          </div>
        </div>
        <div className="att-row">
          <div className="demo"><GlobalAttestationBadge state="degraded" hash="7f3a..b91c" /></div>
          <div className="desc">
            <strong>Degraded</strong>
            <small>The signature is older than the staleness window, or one of two co-signers is unreachable. The fortress keeps running.</small>
          </div>
        </div>
        <div className="att-row">
          <div className="demo"><GlobalAttestationBadge state="unverified" hash="7f3a..b91c" /></div>
          <div className="desc">
            <strong>Unverified</strong>
            <small>The signature did not validate. The surface still works; lockdown is still available; the badge tells you to investigate.</small>
          </div>
        </div>
        <div className="att-row">
          <div className="demo"><GlobalAttestationBadge state="pending" /></div>
          <div className="desc">
            <strong>Pending</strong>
            <small>First-run state. Fortress is signing for the first time. Settles in seconds.</small>
          </div>
        </div>
      </div>

      <div className="att-section">
        <div className="att-section-head">
          <div>
            <h2>Per-agent · in the agents list and inspect pane.</h2>
            <p>A square chip beside each agent. Square because an agent is bounded; the fortress (a circle) contains it.</p>
          </div>
          <span className="label">agents view</span>
        </div>
        <div className="att-row">
          <div className="demo" style={{display:'flex', gap:8, flexWrap:'wrap'}}>
            <AgentAttestationBadge state="verified" />
            <AgentAttestationBadge state="degraded" />
            <AgentAttestationBadge state="unverified" />
          </div>
          <div className="desc">
            <strong>Verified · degraded · unverified</strong>
            <small>Color and the fill pattern carry meaning together. A solid square reads "attested" at a glance; a hatched square reads "trouble" at a glance, even monochrome.</small>
          </div>
        </div>
      </div>

      <div className="att-section">
        <div className="att-section-head">
          <div>
            <h2>Per-action · inline in the activity timeline.</h2>
            <p>Each entry in any timeline carries a small signature fragment. Hover to expand. A tick instead of a fill keeps the row visually quiet at low resolution.</p>
          </div>
          <span className="label">timeline</span>
        </div>
        <div className="att-row">
          <div className="demo" style={{display:'flex', gap:10, flexWrap:'wrap', alignItems:'center'}}>
            <span style={{fontSize:13, color:'var(--ink-2)'}}>14:22:08 · doc-reviewer summarized intake.pdf</span>
            <ActionAttestationBadge state="verified" sig="9c7d..2a" />
          </div>
          <div className="desc">
            <strong>Verified action</strong>
            <small>The most common shape. Two-byte signature fragment is enough; the full signature is one click away.</small>
          </div>
        </div>
        <div className="att-row">
          <div className="demo" style={{display:'flex', gap:10, alignItems:'center'}}>
            <span style={{fontSize:13, color:'var(--ink-2)'}}>14:11:47 · privacy filter redacted payload</span>
            <ActionAttestationBadge state="degraded" sig="b440..71" />
          </div>
          <div className="desc">
            <strong>Degraded action</strong>
            <small>The action signed, but the signature class was less than the policy preferred. Useful when a substrate is still warming up.</small>
          </div>
        </div>
        <div className="att-row">
          <div className="demo" style={{display:'flex', gap:10, alignItems:'center'}}>
            <span style={{fontSize:13, color:'var(--ink-2)'}}>14:09:02 · agent attempted external link</span>
            <ActionAttestationBadge state="neutral" sig="--" />
          </div>
          <div className="desc">
            <strong>Neutral · degrade-not-destroy</strong>
            <small>The signer was unreachable. Rather than hide the action, the badge becomes neutral and a tooltip explains. The action is still recorded.</small>
          </div>
        </div>
      </div>

      <div className="att-section">
        <div className="att-section-head">
          <div>
            <h2>Custody · stub for v1.x.</h2>
            <p>A fourth class, surfaced conservatively. Reserved for forthcoming custody-provenance signatures (x402 payment receipts, ERC-8004 identity assertions). Visible, dashed, clearly stubbed.</p>
          </div>
          <span className="label">stub</span>
        </div>
        <div className="att-row">
          <div className="demo"><CustodyBadge /></div>
          <div className="desc">
            <strong>Custody · stub</strong>
            <small>Dashed border signals "shape reserved, content pending." Will populate when custody signatures land in a future release. Cannot be confused with a verified badge at any zoom level.</small>
          </div>
        </div>
      </div>

      <div className="att-section">
        <div className="att-section-head">
          <div>
            <h2>Tooltip on failure.</h2>
            <p>A failed badge is never silent. The tooltip explains in plain language, suggests one action, and confirms the surface is still working.</p>
          </div>
          <span className="label">degrade not destroy</span>
        </div>
        <div className="att-row">
          <div className="demo">
            <div className="att-tooltip">
              The signer at sig.fortress.local did not respond in 4s. Your fortress kept working. Try: open Health to see the signer status.
            </div>
          </div>
          <div className="desc">
            <strong>Plain-language tooltip</strong>
            <small>Three lines, in order: what happened, what didn't break, what to do. No jargon, no stack trace.</small>
          </div>
        </div>
      </div>
    </div>
  );
}

window.AttestationSurface = AttestationSurface;
