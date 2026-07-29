# Unified Protect Enforcement Core: Built vs Drill-Owed Status

Status date: 2026-07-03. Owner: Sanctuary coordinator. This document is the
honesty ledger for the exclusive-egress enforcement core (Unified Protect
Slices 1, 2, 3, 4, 8). It states, per slice, what is BUILT (code merged,
unit/integration tested) versus what is DRILL-OWED (no capability claim until
captured, coordinator-verified evidence exists on the platform that matters,
per the thesis-gate rule).

## Approved wording (use this, never more)

- Off-box routing for the agent uid is kernel-enforced (Castle Wall, the
  proven 5/5 per-uid deny floor).
- Destination policy at the gate is userspace-enforced (the gate process's
  TypeScript evaluator; it is NOT kernel-backed).
- Loopback confinement is pf-enforced; the per-uid pf mechanism AND the
  composed build's pf-anchor + fail-closed gate-liveness are drill-proven on
  BOTH macOS families: Tahoe (26.5.1, arm64) and Sonoma (14.6.1, x86_64),
  N=3 each, 2026-07-03, coordinator-verified.
- Do not make absolute bypass-resistance claims in any user-visible string,
  MCP tool description, README, or docs page for this feature. No external
  exclusive-egress claim ships until the cross-OS-family leg below is
  captured.

## Keystone evidence pointer

The pf/loopback keystone (the build's gating question) PASSED on Tahoe:
`Review/Sanctuary/drill-evidence-2026-07-01/unified-protect-keystone/RESULTS.md`
(Mini1, macOS 26.5.1, Erik-present console session, N=3,
coordinator-verified). A per-uid pf anchor on `lo0` dropped agent-uid
connections to a non-gate loopback port while allowing agent-to-gate, with
state-table corroboration. That drill proves the MECHANISM; it does not
prove this composed build.

## Composed-build drill-acceptance (2026-07-03): both OS families

The BUILT enforcement-core code (`armPfAnchor` / `checkPfAnchorLiveness` /
`disarmPfAnchor` / `startExclusiveEgressGate`) was drilled end-to-end, N=3
each, coordinator-verified, on BOTH macOS families:
- Tahoe: MBA, macOS 26.5.1 (arm64) -
  `Review/Sanctuary/drill-evidence-2026-07-03/unified-protect-enforcement-core/RESULTS.md`
- Non-Tahoe: aubries-macbook-pro-2, macOS 14.6.1 Sonoma (x86_64) -
  `.../RESULTS-nontahoe-sonoma.md`

Proven both hosts: P1 the CODE-GENERATED per-uid pf anchor confines the agent
to the gate port (agent->gate CONNECTED, agent->non-gate BLOCKED,
state-table corroborated); P2 the gate FAILS CLOSED the instant the anchor is
flushed (next CONNECT = 503 liveness_refused, re-probed every CONNECT, no
stale-positive cache); recovery clean; pf restored. Cross-version pfctl-format
robustness proven (matchers work on both 14 and 26).

SCOPE OF THIS EVIDENCE (do NOT overclaim): it proves the pf-confinement +
fail-closed-gate-liveness layer of the composed build, cross-OS. It does NOT
cover, and these remain OWED before any external exclusive-egress claim: the
sysext-armed full-design console drills (Slice 1, wall armed), Slice 4
harness self-confinement via the `UserName=<agent>` LaunchDaemon (an
Erik-present arming ceremony), and the kernel off-box wall (Castle Wall
NEFilter) on a second OS family.

## Per-slice status

### Slice 1: Loopback-TCP gate channel + manifest allow rule

- BUILT: greenfield gate module (`server/src/egress-gate/gate-server.ts`)
  listening on `127.0.0.1:<gate-port>` only, applying destination policy via
  the existing `castle-wall/egress-proxy.ts` evaluator (the TS logic that
  must agree with the Swift `AllowlistEvaluator`; parity invariant
  unchanged). Manifest side: `castle-wall/allowlist/gate-derivation.ts`
  derives the single `.agent`-scoped allow rule (`127.0.0.1/32`, gate port,
  TCP, `derived: true`) and `composeEffectiveRules` injects it into the
  signed-manifest generation path when
  `policy/egress/exclusive-egress-gate.json` is present and valid
  (fail-closed: malformed policy derives no rule).
- DRILL-OWED: the design Slice 1 console drill (signed sysext, wall armed):
  agent-uid loopback connection to the gate delivered and matched; non-gate
  loopback connection characterized; off-box agent flow still denied. N>=3,
  current macOS + Tahoe. NOT RUN.

### Slice 2: Peer-identity recovery (ADVISORY-ONLY)

- BUILT: `server/src/egress-gate/peer-identity.ts` resolves the connecting
  client's pid/uid over loopback TCP via an `lsof` shell-out (argv-only, hard
  timeout; the minimalism ladder chose the platform tool over a native
  libproc dependency, marked DEBT in-source). Stance is ADVISORY: a
  mismatch emits a loud `peer_uid_mismatch` event; resolution never grants
  and never solely denies. The TOCTOU window (socket close + ephemeral-port
  reuse between accept and query) is documented, not fixed; the primary
  control is the kernel wall confinement plus the pf anchor.
- DRILL-OWED: resolve the agent service-account uid for a real agent
  connection and a non-agent uid for an operator connection, N>=3, with the
  TOCTOU characterization. NOT RUN.

### Slice 3: Confined-loopback pf anchor + fail-closed runtime liveness

- BUILT: `server/src/egress-gate/pf-anchor.ts` renders the per-uid anchor
  from the SAME policy source as the manifest rule (pass agent-to-gate,
  block-drop all other agent-uid loopback, tcp+udp, v4+v6; the pass rule is
  byte-shaped to the Tahoe drill's captured pfctl output). Arm loads the
  anchor, HOOKS it into the main ruleset when the anchor call rule is
  absent (rules loaded into a named anchor are inert until the main
  ruleset calls the anchor; the hook is composed from the operator's base
  `/etc/pf.conf` plus the Sanctuary call + load lines, the drill-proven
  shape, so the com.apple anchors are preserved), and enables pf with a
  reference token; arm is not reported done until a post-arm settle-probe
  passes the liveness check twice consecutively (the first-arm warmup race
  from the review); settle failure disarms and throws. Disarm symmetry
  flushes the anchor and releases the token (the now-inert main-ruleset
  call rule is deliberately left, documented in-source). The MANDATORY
  liveness check decides by positive evidence only (pf `Status: Enabled`
  AND the expected rules printed from the anchor AND the main ruleset
  printing the anchor call rule -- a loaded-but-unhooked anchor enforces
  nothing and is NOT live -- AND nothing voids the call rule: pf must not
  be set to skip filtering on loopback (`pfctl -v -s Interfaces` must not
  flag `lo0`/`lo` as skip; `set skip on lo0` is a common operator pf.conf
  idiom that leaves the other probes green while pf never evaluates lo0)
  and no earlier `pass ... quick` main-ruleset rule may match lo0 traffic
  (quick terminates evaluation before the anchor call is reached)); any
  pfctl error, timeout, or missing rule is NOT live, and the gate server
  refuses to proxy (503) on a non-live result. A silently-unloaded,
  unhooked, skipped, or preempted anchor therefore surfaces as
  not-protected instead of green-when-dead. Arm additionally refuses to
  hook through a base config containing a loopback `set skip` line
  (fail-closed with an actionable error instead of a settle-probe
  timeout).
- DRILL-OWED: the composed console drill (agent-uid non-gate loopback
  attempt dropped by THIS anchor and captured; agent-to-gate succeeds;
  parity passes), N>=3, on Tahoe AND one non-Tahoe macOS. Durable
  (boot-surviving) anchor installation is also owed: this build arms at
  runtime and does not yet install a boot-survival path. NOT RUN.

### Slice 4: Harness self-confinement engage (plumbing only)

- BUILT: `server/src/egress-gate/harness-daemon.ts`: root LaunchDaemon
  plist generation with `UserName=<agent_account>` (render refuses root or
  any privileged account, relative program paths, control characters, and
  the forbidden secret env names), install/uninstall step planning and
  execution against injected ops, and launchctl-based status detection
  (fail-closed: unparseable status reports not-installed/not-running).
- DRILL-OWED: the actual arming is an Erik-present console ceremony. The
  design Slice 4 acceptance (running harness ruid == agentUid; a
  harness-opened off-box socket classified `.agent` and denied; a spawned
  child denied; no sub-ceiling deputy egress; N>=3 plus 5/5 boot-survival)
  is PENDING. NOT RUN.

### Slice 8: Policy-parity and drift guard

- BUILT: single-source generation (one `ExclusiveEgressGatePolicy` derives
  both the NEFilter manifest rule and the pf anchor) plus
  `server/src/egress-gate/parity.ts`, a CI-runnable parity assertion
  (structure + byte comparison + a redundant cross-parse of the pf pass
  rule). The fixture corpus in `server/test/egress-gate/parity.test.ts`
  includes deliberately-divergent policies that fail the check.
- DRILL-OWED: nothing platform-bound; the parity check runs in CI. The
  RUNTIME divergence case (anchor unloaded while manifest stands) is
  covered by the Slice 3 liveness check, whose composed drill is owed.

## Out-of-scope confirmations (verify, do not rebuild)

- Slice 6 (tunability UX) and Slice 7 (tool surfacing) shipped as #839 and
  #840 (both MERGED; verified via `gh pr view` 2026-07-02).
- Slice 5 (install fusion, `sanctuary protect` orchestration) is DEFERRED
  behind the open hardening PRs #848/#849 that own `server/src/wrap/` and
  the `cli.ts` regions it would touch. Consequence: nothing in this build
  STARTS the gate, arms the anchor, or installs the harness daemon in a
  user flow yet; these are library surfaces awaiting the fusion slice.

## Honest residuals (state plainly, do not bury)

1. OWED non-Tahoe leg: every enforcement claim above is at best
   Tahoe-proven at the mechanism level. The second macOS version
   (cross-OS-family) drill leg is OWED and blocks ANY external
   exclusive-egress claim.
2. Hole B (confused deputy) is BOUNDED, NOT ELIMINATED: `classifyUid`
   treats every sub-ceiling uid as operator; any low-uid egress-capable
   local service remains a potential relay (mDNSResponder DNS exfil et
   al.). The pf anchor closes the arbitrary-loopback-relay path (Hole A)
   once drilled; it does not close deputy relays the agent reaches by
   non-loopback IPC.
3. Multiplexed egress over an already-authorized channel (the inference
   endpoint, an operator browser, Remote Control over api.anthropic.com) is
   SEEN AND AUDITED, NOT BLOCKED. Selective blocking would require TLS
   interception, which Sanctuary refuses. This boundary must appear
   user-visible wherever Protect posture is surfaced (interim placement per
   design open-decision 4: this document plus any posture copy this
   feature ships; Erik may relocate).
4. pf (and Seatbelt, if the defense-in-depth layer lands) are on shaky
   long-term macOS support. Each major macOS release triggers a mandatory
   confined-loopback re-drill before the claim carries forward on that OS
   version.
5. Destination fine-grained control trusts the gate process (userspace).
   If the gate is compromised, kernel enforcement still confines the agent
   uid off-box, but per-action policy is gone. Routing honesty vs
   destination honesty per the design HIGH-3.
6. The liveness check's anchor-void detection is TEXTUAL AND CONSERVATIVE,
   not a pf-semantics model. The skip probe reads the `(skip)` flag from
   `pfctl -v -s Interfaces` (authoritative runtime state); the preemption
   scan flags any earlier quick pass rule not positively bound off
   loopback, WITHOUT modeling the rule's own uid/port/af narrowing, so an
   exotic-but-harmless earlier quick pass on lo0 reads not-live (fail
   closed, never fail open). Not detected: a custom operator interface
   GROUP containing lo0 under a name other than `lo` that is skipped by
   name only (pfctl's per-interface skip flag is expected to surface
   group-driven skips on the member; the composed drill must include one
   `set skip on lo0` negative leg to confirm the probe on the platform
   that matters).
