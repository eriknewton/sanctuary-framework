---
title: Castle Wall macOS fresh-binary re-drill, 2026-06-17 (posture-honesty proof + carried-forward re-confirm)
date: 2026-06-17
author: Erik Newton
status: drill-evidence (PRE-DECLARED criteria; hardware results PENDING)
severity: capability-claim evidence, thesis-gate
supersedes: docs/audit/castle-wall-macos-fresh-binary-redrill-2026-06-16.md (adds criterion CW-POSTURE)
---

# Castle Wall macOS fresh-binary re-drill, 2026-06-17

**Status of this document.** Criteria are PRE-DECLARED here BEFORE the hardware run, per the drill-acceptance rule. The hardware-result tables are placeholders to be filled on Mini1 with Erik present. Until those tables carry real captures and the coordinator independently verifies them, every hardware verdict below is PENDING, and the operator PASS is provisional. Nothing public changes until coordinator verification.

## Why this re-drill exists

Two gates ride on this run:

1. **The genuinely new criterion, CW-POSTURE (posture-honesty).** A 2026-06-17 adversarial review found that the live macOS enforcement audit writers did not stamp the `cw_source = "castle_wall_audit_consumer"` provenance marker that the honest posture readers require. As a result the shipped `/v1` posture endpoint, the ARMED banner (#617), and the dashboard hero shield all read amber / "enforcement not confirmed" on a genuinely-enforcing macOS wall. The marker-stamp fix (drilled SHA below) closes this. This drill is the end-to-end hardware proof that a REAL macOS allow and a REAL macOS block light the posture surface ARMED. Before this drill, "posture reads armed on macOS" had only ever been shown with synthetic test fixtures, never real enforcement.

2. **Carried-forward re-confirm on a newer binary.** The 2026-06-16 re-drill proved per-uid allow/deny (N=3), boot-survival (5/5), C6/C7, and a populated boot-audit chain on signed build v807 from tree `053093963dbf` (ASSURANCE_MATRIX row "Egress enforcement: macOS (Castle Wall Phase 1)"). That binary did NOT carry the marker fix, and the proof was explicitly scoped to `053093963dbf`, not current `origin/main` (which is ahead via the L1-L4 rename PRs and #617). The binary drilled here is built from current `origin/main` (`6f82faa5`, #617) plus the marker fix, so this run doubles as the row's stated next step: re-drill on current mainline to confirm behavior-preserving.

## Drilled artifact

| Item | Value |
|---|---|
| Drilled source SHA | `de35f09f` (branch `honesty/macos-cw-provenance`; = `origin/main` `6f82faa5` + the 2-file marker fix) |
| Marker fix files | `server/src/castle-wall/runtime/macos-flow-events.ts`, `server/src/castle-wall/runtime/macos-daemon.ts` |
| Prior drilled tree (06-16, carried-forward) | `053093963dbf` (v807, activated ext sha `26e3c0ce`) |
| Signing host | MBA (Eriks-MacBook-Air, macOS 26.5), Dev-ID "Developer ID Application: Erik Newton (YFQSWQ9BJN)", notary profile `sanctuary-notary` |
| Drill target host | Mini1 (Agents-Mac-mini), macOS Tahoe 26.5.1 |
| Installed extension before this drill | `ai.sanctuaryprotocol.macos.castle-wall` v807, activated+enabled |
| Fresh CFBundleVersion (must be > 807) | TBD at build (record here) |
| Signed extension binary SHA-256 | TBD at build (record here) |
| Activated extension SHA-256 after deploy (proof of replacement) | TBD at deploy (record here; host-app git_sha is NOT proof) |
| Fortress / pin | drill fortress, global pin; real `~/.sanctuary` never touched; operator uid 501, agent uid 502 |

## Pre-hardware software verification (DONE, 2026-06-17, MBA)

Performed on the drilled tree before signing, as the gating de-risk for the whole drill:

- **Typecheck:** clean (`tsc --noEmit`).
- **Targeted suites green:** `macos-flow-events.test.ts` (16), `posture.test.ts` (28), `posture-routes.test.ts` (8) = 52 passing.
- **Full suite green:** 7182 passing locally on macOS (above the 7163 Linux CI floor by platform-only tests; the marker fix adds zero tests).
- **Marker is writer-stamped, not input-derived:** `macos-flow-events.test.ts` drives the writer into a real `AuditLog` and asserts the resulting entry carries `cw_source = "castle_wall_audit_consumer"`, stamped from constructed fields after the event details, so an inbound forged `event.details.cw_source` cannot survive into the entry.
- **Posture reads armed/amber on the marker:** `posture.test.ts` asserts a marker-bearing fresh enforcement entry yields `arm_state: "armed"` with `evidence_basis: "fresh_enforcement_evidence"`, and a non-marker (`"not-castle-wall"`) entry does NOT yield `fresh_enforcement_evidence` (amber). This is the software half of CW-POSTURE.
- **Software coverage gap, disclosed honestly:** the daemon `operator_decision` marker (the second half of the fix) is a one-line mirror of the flow-events stamp and is code-verified, but is NOT unit-asserted (the integration harness cannot populate `pendingRequests` without simulating a full flow round-trip; a fragile harness for a one-liner was judged not worth shipping). It IS exercised on hardware here under CW-POSTURE 6a, which dumps the raw `operator_decision` entry showing the field.

The freshness window for the readers is 10 minutes (`DEFAULT_ENFORCEMENT_FRESHNESS_MS`); the digest window is 24h. macOS runs the "no pinned producer key" floor, so a marker-bearing fresh enforcement entry counts on the channel/marker basis (the C4 producer-signed per-flow trail remains unbuilt and is NOT claimed here).

---

## Pre-declared criteria (authoritative; do not paraphrase from memory)

Enumerated from `docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md` (C1..C7), the #588-corrected boot-service doc, the #596 host-app crash repro, `server/src/principal-policy/posture.ts` (the provenance + signature gates), and `ASSURANCE_MATRIX.md` row "Egress enforcement: macOS (Castle Wall Phase 1)".

### Core criteria (carried forward from 06-16; re-confirm on the new binary)

- **C1 / C2 / C3 per-uid allow/deny, N>=3 deterministic.** Wall armed; operator uid 501 reaches a destination the agent uid 502 cannot; agent allowed on its allowlisted destination, blocked on a non-allowlisted one; operator never cut. The 000/200-vs-301 pattern, repeated >=3x.
  - Verdict: PENDING.
- **Boot-survival 5/5.** Five real reboots; after each, the filter still ENFORCES (not merely present), the safe-mode boot daemon resolved node under the launchd PATH and verified a STABLE pid (`8c8efe68` / `a4b48ac9`), the safe-mode socket is operator-reachable, and allow/deny still holds. Recovery pre-staged before the first reboot.
  - Verdict: PENDING.
- **C6 absent/wrong boot token fails closed.** Targeted sub-test (unit-covered in prior runs; exercise on hardware).
  - Verdict: PENDING.
- **C7 launchd KeepAlive recovery after a daemon kill.** Targeted sub-test.
  - Verdict: PENDING.
- **Boot-audit chain.** The boot-time audit chain records events (empty in the 06-14 run; populated 1052 checkpoints on 06-16) and VERIFIES clean under the recovered master.
  - Verdict: PENDING.
- **#596 host-app crash fix, N>=3.** Reproduce the exact pre-#596 SwiftUI launch-crash scenario on the fresh signed binary; confirm no crash, 3x.
  - Verdict: PENDING.

### NEW criterion (the reason for this re-drill)

- **CW-POSTURE: posture reads ARMED from REAL macOS enforcement, N>=3 deterministic.** With the wall armed and a REAL flow adjudicated (a genuine allow and a genuine block through the macOS extension, NOT a synthetic audit insert):
  - **6a. Audit marker present.** The resulting `egress_allowed` / `egress_blocked` / `operator_decision` audit entries carry `details.cw_source === "castle_wall_audit_consumer"`. Dump the raw entry and show the field. A pre-fix binary does NOT carry it; that contrast is the proof.
    - Verdict: PENDING.
  - **6b. Honest readers light up (within the 10-minute freshness window), from that real evidence, NOT "enforcement not confirmed":**
    - `/v1` posture G4 endpoint -> `arm_state: "armed"`, `evidence_basis: "fresh_enforcement_evidence"`.
    - the `sanctuary wrap` / fortress-view ARMED banner -> Castle Wall ARMED (after the wrap-banner honesty fix lands; if not yet landed, assert the G4 endpoint only and note it).
    - the dashboard hero shield (`getProtectionSnapshot().overall`) -> green "All layers full, Castle Wall enforcing" when the other layers are configured (after the dashboard PR lands), else at minimum `buildCastleWallPosture` returns armed.
    - Verdict: PENDING.
  - **6c. Negative control.** With NO recent real flow (idle past the 10-minute freshness window), the same readers correctly fall back to amber "enforcement not confirmed", proving they track real evidence, not a sticky flag.
    - Verdict: PENDING.
  - This criterion FAILS if a genuinely-enforcing macOS wall produces audit entries without the marker, or if any honest reader shows amber while a real flow was just adjudicated.

## What this drill does NOT prove (carried-forward honest bounds)

- NOT "audited per-rule per-flow" and NOT "tamper-evident per-flow audit". The unforgeable producer-signed per-flow audit trail (C4) remains unbuilt; the marker is a channel-basis floor marker, forgeable by an already-compromised in-process writer (disclosed boundary in `posture.ts`).
- One host, one OS version (Tahoe 26.5.1). Not a fleet or multi-version claim.
- Not a performance claim; no p99 overhead captured.

## Hardware capture (to be filled on Mini1, Erik present)

- Drilled SHA `de35f09f` + signed sha256 + activated-ext sha proof: TBD.
- Per-uid allow/deny logs (all N): TBD.
- 5 reboot results: TBD.
- C6 / C7 closure: TBD.
- Boot-audit chain + verification: TBD.
- #596 re-verify (N>=3): TBD.
- CW-POSTURE: raw marked audit entries (allow + block + operator_decision), the three reader outputs (armed), the negative-control amber: TBD.
- Screen recording of arm -> real-allow -> real-block -> reader-armed -> reboot: TBD.

Sanitize: no private keys, no raw secrets. Delete `~/.cw-asp` and `~/.cw-sudopw` at the end.

## Coordinator verification + claim movement

HALT after capture. Do NOT edit `ASSURANCE_MATRIX.md`, README, or any public copy from the drill thread. The coordinator independently verifies the captured evidence (operator PASS is provisional) and only then drafts the public-claim change for Erik's approval. CW-POSTURE passing is also what unblocks the held dashboard hero-shield PR.
