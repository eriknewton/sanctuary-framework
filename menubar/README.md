# Sanctuary Menubar

A Tauri 2.x desktop app that lives in the operator's macOS menubar and surfaces fortress state at a glance. It shows pending Tier 1 approvals, recent audit events, and which agents are currently wrapped. When a Tier 1 action is appended to your fortress audit log, the menubar fires an OS notification so you can act without having to open the dashboard.

This is the **Sprint Piece 1** foundation. Approve / deny buttons land in Sprint Piece 2; visual polish and the full onboarding copy land in Sprint Piece 3.

## Castle Architecture position

The menubar lives at the **Charter** layer (Cooperative MCP capability surface). It watches your fortress and shows you what is happening. It does **not** enforce: enforcement is the job of the **Castle Wall** layer (OS-level egress filter, ships separately as WP-V1.x-CASTLE-WALL) and the Cooperative MCP gate inside the fortress. The menubar is the daily-driver UX that makes the substrate visible to the operator.

See `server/rfcs/RFC-0003-castle-architecture.md` for the canonical four-layer model.

## Install

Prerequisites:
- macOS 11 or later (Sprint Piece 1 ships only the macOS backend; Linux libnotify and Windows WinRT Toast backends ship in Sprint Piece 2 / Phase 2)
- Node.js 20 or later
- Rust toolchain (`rustup install stable`)
- Xcode Command Line Tools (`xcode-select --install`)

From the Sanctuary repository root:

```bash
npm run menubar:setup
```

This installs the menubar workspace's npm dependencies. You only need to run it once per fresh clone.

## First run (development)

```bash
npm run menubar:dev
```

The Tauri dev server will compile the Rust backend (first run takes a few minutes; subsequent runs are fast), then launch the menubar. A small "S" icon appears in your macOS top bar.

On first launch, the onboarding wizard opens automatically. Walk through the four steps:
1. Welcome
2. Fortress endpoint (defaults to `http://127.0.0.1:3501`; change if your fortress runs elsewhere)
3. Auth token (skip if your fortress does not require one; tokens are stored in your macOS Keychain)
4. Notification permission (allow so Sanctuary can surface approvals)
5. Done

After the wizard, the popover closes and the menubar starts polling your fortress every two seconds.

## What the menubar shows

Click the menubar icon to open the popover. Three sections:
- **Pending approvals.** Tier 1 actions waiting on your decision. Read-only in Sprint Piece 1; approve / deny buttons land in Sprint Piece 2.
- **Recent audit events.** The last ten audit events from your fortress, with their tier and the decision that was made.
- **Agents.** Each wrapped agent, its tier (A native, B adapter-wrapped, C escape hatch), and last activity.

The footer shows the fortress endpoint, connection status (green / amber / red dot), a Settings link that re-opens the wizard, and an "Open dashboard" link that opens your existing Sanctuary dashboard URL in the default browser.

## Notifications

When a new Tier 1 action is appended to the fortress audit log, the menubar fires a macOS notification. Click the notification to open the popover anchored to the menubar.

Rate limiting: at most one notification per 30 seconds for the same agent + tool combination. This is to prevent a runaway agent from spamming your notification center.

## Configuration

The menubar stores its config under `~/Library/Application Support/com.sanctuaryprotocol.menubar/menubar-config.json`. The auth token is stored separately in the macOS Keychain (service `com.sanctuaryprotocol.menubar`, account `fortress-auth-token`).

To re-run the onboarding wizard, click "Settings" in the popover footer.

## Distributable build

```bash
npm run menubar:build
```

Produces a code-signed `.app` bundle at `menubar/src-tauri/target/release/bundle/macos/Sanctuary Menubar.app`. The bundle uses Tauri's default development signing identity in Sprint Piece 1; a real signing identity (Developer ID Application certificate) lands in Sprint Piece 4 alongside the demo materials.

To install for daily use, drag the `.app` into `/Applications`, then add it to your login items via System Settings.

## Troubleshooting

**Tray icon does not appear.** Check that the Rust build succeeded. If `npm run menubar:dev` aborted with a Rust compile error, run `cargo build` from `menubar/src-tauri/` to see the full error.

**Connection status shows "disconnected".** Check that your fortress is running. From a separate terminal: `cd server && npm run dev`. The default endpoint is `http://127.0.0.1:3501`. Override via the wizard's Settings page.

**Notifications do not fire.** Check System Settings → Notifications → Sanctuary Menubar and confirm notifications are allowed. If permission was denied during onboarding, you can re-grant from the same settings panel.

**Popover appears in the wrong place.** The popover positions itself under the tray icon click point. On multi-monitor setups, make sure the menubar icon is on the display you expect. Sprint Piece 3 will improve multi-monitor positioning.

## Out of scope (deferred sprint pieces)

| Feature | Lands in |
|---|---|
| Approve / deny buttons in popover | Sprint Piece 2 (gated on chat-removal PR's click-to-inspect endpoint) |
| Full onboarding copy | Sprint Piece 3 |
| Visual polish (icons, layout, motion) | Sprint Piece 3 |
| Demo videos and pitch deck assets | Sprint Piece 4 |
| Linux libnotify backend | Sprint Piece 2 or v1.2.5 |
| Windows WinRT Toast backend | Phase 2 (v1.3+) |
| Cross-harness aggregation (multi-fortress view) | WP-V1.3-10 |

## Architecture

Frontend (`menubar/src/`):
- `main.ts` boot, polling loop, SSE subscription, event wiring
- `api/client.ts` fortress HTTP + SSE client
- `popover/popover.ts` popover view rendering
- `wizard/wizard.ts` onboarding wizard skeleton
- `backends/menubar.ts` cross-platform menubar abstraction (macOS full, Linux + Windows stubbed)
- `backends/notification.ts` cross-platform notification abstraction (macOS full, Linux + Windows stubbed)
- `styles/popover.css` minimal styling (polish lands in Sprint Piece 3)

Rust backend (`menubar/src-tauri/src/`):
- `main.rs` entry stub that calls `lib.rs::run()`
- `lib.rs` Tauri builder, tray icon, popover window lifecycle, activation policy
- `commands.rs` command handlers the frontend invokes
- `config.rs` JSON-on-disk config persistence
- `keychain.rs` platform keychain wrapper (macOS Keychain Services / Linux Secret Service / Windows Credential Manager)

Icons (`menubar/src-tauri/icons/`): placeholder PNGs generated by `generate-placeholder-icons.py`. Real icons land in Sprint Piece 3.
