# Sprint Piece 2: Visual Polish Design References

Source: Claude Design dispatch 2026-05-03 (per `Review/Sanctuary/Claude_Design_Sprint_Piece_2_Brief_2026-05-03.md`).

This directory contains design reference code for Sprint Piece 2 surfaces 2-6. These files are NOT the production dashboard; they are visual targets for subsequent translation PRs.

## What's here

- `Sanctuary Visual References.html` - Preview shell. Open in a browser to see all surfaces with theme toggle and state switcher.
- `tokens.css` - Mirrors the production design tokens at `server/src/dashboard/v1_1/html.ts`.
- `dashboard.css` - Base dashboard layout reference.
- `surfaces.css` - 30KB of polished surface CSS, organized per-surface (Concierge, Intelligence, Agents, Onboarding, Attestation).
- `chrome.jsx` - Global chrome (topbar, sidebar) reference.
- `surface-concierge.jsx` - Concierge chat surface reference.
- `surface-intelligence.jsx` - Intelligence panel reference.
- `surface-agents.jsx` - Agents view + Inspect pane reference.
- `surface-onboarding.jsx` - Onboarding visual states reference.
- `surface-attestation.jsx` - Attestation badge surface reference.
- `tweaks-panel.jsx` - Live-preview control panel.

## How translation PRs use these

Each subsequent Sprint Piece 2 PR (2-6) translates one surface's reference code into the production dashboard:

- PR 2 Concierge: `surface-concierge.jsx` + `surfaces.css` Concierge block
- PR 3 Intelligence: `surface-intelligence.jsx` + `surfaces.css` Intelligence block
- PR 4 Agents + Inspect: `surface-agents.jsx` + `surfaces.css` Agents block
- PR 5 Onboarding: `surface-onboarding.jsx` + `surfaces.css` Onboarding block
- PR 6 Attestation: `surface-attestation.jsx` + `surfaces.css` Attestation block

## Hard constraints inherited by translation PRs

- Preserve rc.5 layout fixes (bounded `.concierge-card` height, `min-height: 0` on history, `flex-shrink: 0` on composer + header).
- Preserve rc.6 ZZ green-badge derivation (`failureClass` reset on substrate change; `ollamaHasModel` helper).
- Preserve PR #113 design tokens (`--space-N`), sidebar icon system, and dark-mode toggle UI.
- Em-dash 0 in any user-visible UI copy.
- No competitor names.
- No CIMC attribution.
- WCAG AA contrast.
