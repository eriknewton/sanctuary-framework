# server/src - Module Map

This is the first thing to read before you touch the Sanctuary server. `server/src` is the
TypeScript MCP server: 55 module directories plus a small set of root files. It is the in-process
"fortress" runtime - crypto core, the four sovereignty layers, enforcement surfaces, networking,
identity, and the operator CLI. The native OS-level enforcers (Rust/Swift) live OUTSIDE this tree
(see "Adjacent out-of-scope systems").

This map exists because the codebase is a legibility problem, not a code-removal problem. No dead
code was found; nothing here is a delete candidate. Several names collide or mislead, so most of the
value is in the disambiguation sections below.

## Named-layer vocabulary

Sanctuary has four sovereignty layers. The L1..L4 numbering is being retired in prose, but the
`lN` tokens are still LIVE wire and at-rest contracts (tool names, audit fields, HKDF labels,
`L1Status..L4Status` exports) and must survive byte-for-byte. Use the named layer in writing; never
edit the wire token.

| Layer | Named layer (human / property) | Wire token | Owning module(s) | One line |
|-------|--------------------------------|-----------|------------------|----------|
| L1 | Castle Wall / Cognitive | `l1` / `l1_cognitive` | `cognitive`, `core`, `castle-wall` | Encrypted at-rest state + identity keys; the crypto foundation |
| L2 | Sentinels / Operational Isolation | `l2` / `l2_operational` | `operational`, `sentinel`, `anomaly-detection` | Append-only audit log + behavioral watchers + egress context-gate |
| L3 | Charter / Selective Disclosure | `l3` / `l3_selective_disclosure` | `disclosure`, `sdw`, `query-anonymity` | Commitments, ZK proofs, the secret broker, controlled disclosure |
| L4 | Heralds / Verifiable Reputation | `l4` / `l4_reputation` | `reputation`, `attestation`, `shr` | Portable signed reputation attestations + badge UX |

## How to use this map

1. Find your module in the MODULE INDEX TABLE. The "Distinct from" cell tells you what it is NOT.
2. If a name confused you, jump to "Confusable clusters" - most pain is lexical, not structural.
3. Before renaming or moving anything, read the "Do-not-touch" cell and the "Conventions" section.
   Many directory names double as frozen wire tokens; the rule is "directory names and relative
   import paths move; tool names, routes, HKDF labels, and display strings never do."

---

## MODULE INDEX TABLE (55 modules)

All 55 module directories under `server/src` are listed. Status legend: **canonical** = a real,
wired subsystem; **thin/utility** = honestly one or two files; **default-off-allocated** = real code,
deliberately unwired or off by default (not dead, not shipped-as-enforcing); **versioned-frozen** =
a versioned wire/route surface that is frozen. "Barrel?" = does the dir expose a thin re-export
`index.ts` (46 of 54 do today).

| Module | Subject area | Status | What it owns | Distinct from | Barrel? | Do-not-touch |
|--------|-------------|--------|--------------|---------------|---------|--------------|
| principal-policy | Cognitive (runtime approval) | canonical | The runtime human-in-the-loop approval gate: Tier 1/2/3 classification, baseline anomaly, approval channels, unified inbox/aggregator | policy-engine (asks no human) | Yes | tool names `principal_policy_view`/`principal_baseline_view`; tier tokens `tier1_always_approve`/`tier2_anomaly`/`tier3_always_allow`; `auto_deny=true` (SEC-002); frozen policy file `principal-policy.yaml`; `normalized_args_hash` amplification key |
| policy-engine | Cognitive (declarative authoring) | canonical | English-to-rules compiler (authoring-time) + automated machine gates: slot/egress/budget/commitment-boundary + signed gate-receipts, no human prompt | principal-policy (the human gate) | Yes | tool `soft_warn`; 4 PolicySlot tokens `memory/credentials/plans/outputs`; `COMPILED_POLICY_SCHEMA_VERSION`; egress/budget `event_class` tokens; `GATE_REASON_CODES`; `is_sentinel` flag; gates forbid network/LLM imports (structural test) |
| sentinel | Operational (Sentinels) | canonical | Rule-based behavioral-watcher framework: base class + per-fortress dispatcher + encrypted finding store + registry + concrete watchers under `sentinel/sentinels/` | anomaly-detection (learned drift); `policy-engine/sentinel-role.ts` (a capability flag) | Yes | route `/api/sentinels` (+`/subscribed`,`/findings`); `sentinel_id` tokens (egress-volume, credential-usage, etc.); audit ops `sentinel_finding_emitted`/`_evaluation_failed`; `sentinel-subscriptions.json`. Inner `sentinels/ebpf/*.rs` is a placeholder, NOT the daemon |
| auto-trigger | Operational (Sentinels) | canonical | Nu-1 escalation ladder: routes findings through a 3-rung escalation (inbox / auto+cancel / fire-now); persists tuned thresholds; promotion recommendations | sentinel/anomaly/honeypot (they detect; this decides) | Yes | route `/api/auto-trigger`; rule-id wire format `sentinel__`/`anomaly__`/`honeypot__` (this IS the AAD); HKDF `l2-auto-trigger-rules-v1`; `AUTO_TRIGGER_AUDIT_OPS` |
| anomaly-detection | Operational (Sentinels) | canonical | Chi-1 statistical pipeline: per-fortress feature extractors, classifiers (rolling-baseline/CUSUM/PSI), encrypted classifier-state store; emits drift findings | sentinel (hand-written rules); the `anomaly-trigger` watcher inside sentinel | Yes | route `/api/anomaly`; HKDF `l2-anomaly-classifier-state-v1`; `anomaly-subscriptions.json`; `anomaly_*` audit ops; numeric-only feature-vector invariant |
| honeypot | Operational (Sentinels) | canonical | Pi-1+ honeypot authoring + runtime: English->TrapSpec compiler, registers bait (http/filesystem/tool_call/credential), fires findings into the sentinel finding store | sentinel (passive observer; honeypot plants active bait) | Yes | route `/api/honeypot` (+`/compile`,`/deploy`,`/traps`,`/tool-traps`,`/credential-traps`,`/traps/<id>`); `TrapClass` tokens; `honeypot_*` audit ops |
| lockdown | Operational | thin/utility | One 57-line file: read/write `lockdown/status.json` (active+activated_at+reason) + operator banner. Reads allowed, writes blocked when active | principal-policy gate (graduated consent) | Yes | on-disk `lockdown/status.json` shape `{active, activated_at, reason}`; modes 0o600/0o700; the banner string consumed by CLI/UX |
| audit | Cross-cutting (posture + chain crypto) | canonical | Sovereignty Audit Tool (read-only scan -> 0-100 score) PLUS the audit-chain hash/checkpoint primitives (`chain.ts`) + SIEM export (CEF/OCSF) | the other three "audit" things (see CLUSTER 1) | Yes | tools `sovereignty_audit`/`audit_export_siem`; labels `AUDIT_CHAIN_GENESIS="GENESIS"`, `AUDIT_CHECKPOINT_DOMAIN="sanctuary.audit-checkpoint.v1"`; SIEM `filter_layer` enum l1..l4; result version `"1.0"` + `l1_cognitive..l4_reputation` keys |
| transparency | Cross-cutting (tamper-evident + anti-rollback) | canonical (security-critical) | Sigstore/Rekor anchoring + offline-verifiable enforcement-checkpoint chain + anti-rollback counter-floor. Opt-in, default-OFF, fail-closed | audit (local score); attestation (badge); `audit/chain.ts` (hashes log entries, not checkpoints) | Yes | tsup bin entrypoint `offline-cli.ts` (=> `verify-transparency`); domain labels `sanctuary.enforcement-checkpoint.v1`, `sanctuary.transparency.anchor-commitment.v1`, `...rule-label.v1`; Rekor `/api/v1/log/entries`; `SANCTUARY_TRANSPARENCY_INTERVAL` |
| attestation | Verifiable-Reputation-adjacent / UX | canonical (one Layer-4 stub) | Attestation badge UX: global/per-agent/per-action green/yellow/red/offline/local_only badges from signed events; 9-row failure catalog; degrade-not-destroy | transparency/audit; the host/workload TEE primitive (that lives in `workload-lifecycle/host-attestation.ts`) | Yes | closed enums `BADGE_STATES` + `BADGE_STATE_LABELS` copy; `FAILURE_MODE_CODES` (9); `ATTESTATION_EVENT_TYPE_PREFIX="attestation_"`; owns served `server/public/attestation-reference.html`; `custody-provenance-stub.ts` is a deliberate v1.0 no-op for Key-17 |
| health | Cross-cutting (runtime evidence) | thin/utility (1 file) | `buildHealthEvidenceReport`: assembles an un-scored, un-signed in-process runtime snapshot (wall armed? audit persists? per-layer l1..l4 evidence) | audit (scores); shr (signs+exports); posture (dashboard) - see CLUSTER 2 | Yes | JSON report shape: `layers.l1..l4` keys, `castle_wall`/`audit`/`state`/`egress`/`degradations` fields, `RuntimeStatus` union; reads `StatusResponse` from castle-wall IPC |
| shr | Verifiable-Reputation / Selective-Disclosure | versioned-frozen (v1.0) | Sovereignty Health Report: a signed, versioned, portable capability advertisement an agent presents to counterparties; plus the decommissioning-certificate variant | health (unsigned internal); audit (local score) | Yes | tools `shr_generate`/`shr_verify`/`shr_gateway_export`; schema `shr_version:"1.0"` + `layers.l1..l4` parsed by external counterparties; Ed25519-over-canonical-body; reuses mesh `SignatureScheme` |
| compliance | Compliance (EU AI Act) | canonical | EU AI Act (2024/1689) toolset: Annex III classifier, coverage matrix, signed bundle generator (6 MD + manifest + zero-dep PDF), each file hashed + Ed25519-signed | audit (sovereignty posture, not regulatory) | No | tools `compliance_eu_ai_act_annex_iii_classify`/`compliance_generate_eu_ai_act_bundle` (the `eu_ai_act` token is ALSO in these wire strings - a dir rename must NOT touch them); Apache-2.0 SPDX headers; 8-category catalog; `templates/*` assets |
| errors | Cross-cutting (typed load errors) | thin/utility (2 files) | Two typed Error subclasses: `ConfigLoadError` + `ProfileLoadError`, carrying path/classification/recovery for fail-loud config and profile loading | `mesh/errors.ts` and `attestation/errors.ts` (SEPARATE local files) | Yes | symbols `ConfigLoadError`/`ProfileLoadError`; classification literals `corrupted`/`schema-mismatch`/`invalid-value`/`unreadable`/`wrong-key` (`invalid-value` = scalar-value typo on a structurally-valid config file: refuse-to-start but NOT quarantined); `.name` strings (used in messages/tests) |
| http | Cross-cutting (HTTP safety helpers) | thin/utility | Shared HTTP response helpers for production route surfaces, including the caught-exception error envelope that logs redacted operator diagnostics while returning stable public codes | console/auth-middleware (auth only); dashboard/console route modules (callers) | Yes | `PublicErrorCode` literals; `sendCaughtError` must never serialize `err.message`, stack, or `String(err)` to a client (hard invariant); operator-log redaction is best-effort allow-list (Bearer tokens, keyed secrets, PEM private-key blocks), not fail-closed |
| security | Enforcement-surface (injection) | canonical (single file) | The `InjectionDetector`: fast, zero-dep, never-throws scanner of tool args for prompt-injection signals; returns allow/escalate/block; outbound secret-leak scanning | NOT the approval gate (principal-policy calls this); NOT crypto (core). Name overpromises | Yes | symbols `InjectionDetector`/`DetectionResult`/`InjectionSignal`; the never-throws invariant; SEC-034/035 (Unicode sanitization + decoded re-scan); detection PATTERN strings are behavior. 1,353-line god-file split candidate (Phase 5) |
| mesh | Networking | versioned-frozen (v1) | The intra-operator mesh fabric (internally titled "Sanctuary Federation Protocol v0.1"): libp2p transport, node lifecycle/join, guardian, v0.1 trust-root, additive hybrid trust-root v2 cert-chain module, audit-batch sync, recovery flows | federation (inter-instance); `v1/federation.ts` (HTTP wrapper around mesh) | Yes | `PROTOCOL_VERSION='0.1'`; libp2p protocols `/sanctuary/fed/v0.1/...`; HKDF `sanctuary-fed-v0.1-transport` / `...-audit-chain`; `SIGNATURE_SCHEME_V1='ed25519-v1'`; event-type + capability-bit masks; `NodeMode` union |
| federation | Networking | canonical | MCP-to-MCP peer federation between two SEPARATE Sanctuary instances: in-memory peer registry (handshake-enrollable only) + three `federation_*` MCP tools. 3 files, 665 lines | mesh (intra-operator); `v1/federation.ts` (no import edge - verified) | Yes | tool names `federation_peers`/`federation_trust_evaluate`/`federation_status` (NOTE: live third tool is `federation_status`, not the `federation_exchange_reputation` the scoping doc implied) |
| v1 | Networking | versioned-frozen (v1) | The versioned HTTP `/v1/*` API: session ceremony, status, agents protect/unprotect, `/v1/federation/*` admin + join ceremony, `/v1/nodes`. Fail-closed: single generic 401 | federation/ (the dir) - v1's federation routes wrap MESH, not the federation/ registry (the real "split-brain") | No | frozen routes `/v1/status`,`/v1/session/init|complete`,`/v1/agents/protect|unprotect`,`/v1/federation/enable|disable|status|authorize/*|sync`,`/v1/nodes`; domain `sanctuary.v1.operator-signed`; uniform-401/generic-403 behavior |
| coordination | Operational | canonical | Local-only agent-to-agent handoff inside ONE fortress: signed handoff record lifecycle, encrypted HandoffStore + L2 audit chain, context-slot transfer, handoff SSE routes | hub (the aggregator); mesh (node transport) | Yes | route `/api/coordination/handoffs` (+`/stream`,`/:entry_id`); signing `ed25519-v1`; handoff status enum + `previous_status:'created'` chain convention; L2 records keyed off contracts/v1.1 |
| hub | Operational | canonical | The Operator Hub API: aggregates agent-registry + unified approval inbox + activity feed + fortress-scope Tier-1 control, served by HubService under `/api/hub/*` | coordination (point-to-point handoff); console/dashboard (render); principal-policy (owns the gate hub enqueues into) | Yes | `HUB_ROUTES` (/api/hub/inbox, /agents, /activity, /fortress/lockdown, /chat/concierge, ...); `HUB_INBOX_ACTIONS` ['approve','deny','dismiss']; Tier-1 `['unwrap','lockdown']` must stay lockstep with principal-policy loader; `HUB_FORTRESS_AGENT_ID_SENTINEL='all'` |
| composition | Cross-cutting | default-off-allocated | Opt-in, DEFAULT-OFF Concordia+Verascore composition: sidecar lifecycle manager, degrade monitor, receipt/mandate adapter, verascore hook, pipeline orchestrator. Sidecar crash never halts the fortress | the unrelated `composition` key in index.ts's SIM descriptor (name collision) | Yes | `COMPOSITION_CONFIG_NAMESPACE='_composition'`; HKDF `sanctuary-composition-v1`; `COMPOSITION_EVENT_TYPES` (additive-only per federation §10.3); default-off toggle. NOT dead despite just 1 static importer (`concierge-query-grammar.ts`) |
| recovery | Cross-cutting | canonical | The guardian-threshold Recovery Cascade (WP-MVP-8): DMswitch operator-absence evaluator, guardian roster, threshold evaluator + signed approvals, cascade state machine, multi-principal boundary | `mesh/recovery-flows` (wire ceremonies); `core/master-rotation` (rotates the key); wrap recovery-key (per-wrap unlock) | Yes | `RECOVERY_SIGNATURE_SCHEME='ed25519-v1'`; `RECOVERY_EVENT_TYPES`; `RECOVERY_ACTIONS`; `RECOVERY_GATE_REASON_CODES`. Imports canonical-JSON + guardian types FROM mesh (a real edge, not a dup) |
| castle-wall | Enforcement-surface (Cognitive) | canonical | The IN-SERVER (TypeScript) Castle Wall surface: wire constants, allowlist schema, IPC framing, audit-event builder/consumer (producer-sig verify), daemon client/installer, in-process egress CONNECT proxy | the native enforcers castle-wall-daemon/macos/vmm at repo root; fortress (posture); lockdown (flag) | Yes | cross-language wire constants that MUST byte-match the Rust daemon: `CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX`, `..._KEY_ID_V1="cw-audit-producer-v1"`, `CASTLE_WALL_AUDIT_LAYER="l1"`, `CASTLE_WALL_AUDIT_PROVENANCE_KEY/VALUE`, `CASTLE_WALL_IPC_NAMESPACE`, Content-Length header |
| fortress | Cognitive (posture / mode tiers) | canonical | The Fortress Mode state machine: three posture tiers (`tier_1_private`/`tier_2_federated`/`tier_3_interop`) gating which mesh capability bits are live; signed mode-transition events | castle-wall (network enforcement); supervisor (OS process); the operator word "fortress" = the on-disk SANCTUARY_FORTRESS_PATH dir | Yes | `FORTRESS_EVENT_TYPE_PREFIX="fortress_"` + `MODE_TRANSITION="fortress_mode_transition"` (reserved per Federation §10.3); `MODE_TIERS` union (persisted in config, keys `TIER_CAPABILITY_DEFAULTS`) |
| wrap | CLI (install-time onboarding) | canonical | The `sanctuary wrap`/`init` onboarding CLI: detect + back up + rewrite a harness's MCP config so Sanctuary becomes the upstream gateway; passphrase/recovery-key/keychain custody; Hermes YAML emitter | supervisor (runtime process); the Layer-2 managed-child path (`wrap --tier-b`); castle-wall | Yes | `WRAP_META_FILENAME="wrap-meta.json"` + the legacy read-only `LEGACY_WRAP_META_FILENAME` constant (its value is a retired-vocabulary filename kept read-only for back-compat; the ONLY permitted carrier of the retired term; removing it breaks unwrap of old releases); env `SANCTUARY_FORTRESS_PATH`/`SANCTUARY_STORAGE_PATH`; verbs `wrap`/`init`/`--unwrap` |
| supervisor | Operational (process lifecycle, Tier-A) | canonical | The split-process supervised daemon (Phase S1): a separate process that launches/monitors/restarts a wrapped child, holding a TRANSIENT master key (survives crash, not reboot); authenticated local-socket protocol | wrap (install-time); castle-wall (egress); fortress (in-process state machine) | Yes | socket constants `SUPERVISOR_PROTOCOL_VERSION=1` (leading frame byte), `MAX_FRAME_BYTES=64KiB`; key-handoff env `SANCTUARY_SUPERVISOR_KEY_FD`; `SUPERVISOR_KNOWN_HARNESSES` |
| broker-mcp | Selective-Disclosure (standalone broker MCP) | thin/utility | `broker-server.ts` wraps the L3 Secret Broker as a STANDALONE MCP server (four tools only); `liveness-constants.ts` + `liveness-heartbeat.ts` add the long-running `broker-server` daemon's PROCESS-LIVENESS heartbeat + clean-stop stand-down (Option C, read by `principal-policy/feature-health.ts`). Renamed from `mcp/` (2026-06-14) so the name no longer reads as the core MCP plumbing | NOT the core MCP tool-router (that is root index.ts/router.ts/sanctuary-tools.ts); the heartbeat is PROCESS-liveness only, NOT token-mint/deny correctness | Yes | tools `broker/request_token`/`read_secret`/`list_grants`/`audit_query`; server name `"sanctuary-broker"`; version routed via `config.SANCTUARY_VERSION` (do not re-inline package.json); at-rest ops `broker_daemon_heartbeat`/`broker_daemon_stopped` + marker `broker_source=broker_daemon` |
| storage | Cross-cutting (persistence substrate) | canonical | The pluggable StorageBackend abstraction in RAW BYTES (encryption is one layer up): FilesystemStorage (default; `{ns}/{key}.enc`, bijective `!`-escape encoding, 3-pass secure delete) + MemoryStorage | `cognitive/state-store` (owns encryption + namespace semantics); `substrate/` (unrelated) | Yes | the StorageBackend method shape (88 importers); on-disk `{ns}/{key}.enc` + the `!`-escape encoder (changing it orphans existing fortress files); 0o700/0o600 modes |
| exit | Operational (Exit principle) | versioned-frozen (v1) | The operator's data-portability path: export/import `SANCTUARY_EXIT_BUNDLE_V1` (manifest + hashed JSON; private keys never emitted), optional re-key, did:web binding, verifier, memory-class stamper, consent-release + tombstone | reputation/recognition (it consumes them); storage (raw bytes) | Yes | `SANCTUARY_EXIT_BUNDLE_V1`, `EXIT_BUNDLE_MANIFEST_VERSION`, `EXIT_BUNDLE_ARTIFACT_KINDS`; audit ops `exit_consent_release`/`exit_tombstone`; Tier-1 export gate. HONEST FLAG: `memory_class` is FORGEABLE on un-instrumented write paths today (M-1/A1) - do not over-claim sealed provenance |
| workload-lifecycle | Compliance / Operational | default-off-allocated | The workload-lifecycle audit schema: versioned signed chain-bound lifecycle events for DECLARED workloads, `sealLifecycleEmission`, WorkloadRegistry, host-workload-attestation builder/verifier. **Schema exists + tested; no production bootstrap wires the seal yet** | `operational/audit-log` (the log it rides on); agent-contract (its only 2 external consumers) | Yes | `WORKLOAD_LIFECYCLE_OPS` op strings (workload_instantiated/paused/.../host_attestation/undeclared_detected); `WORKLOAD_HOST_ATTESTATION_DOMAIN/SCOPE_TEXT/...`. Do NOT market as a shipped enforcement capability; consciousness/mind-crime framing is OUT |
| intelligence | Intelligence/IO | canonical | The per-surface LLM substrate selector ("the selector IS the architecture"): binds each surface (concierge, sentinel, gate-explanation, privacy-filter-tier-2, template-suggestion) to Local/Venice/Frontier/Disabled; operator fallback; audit | concierge (a consumer surface); `intelligence/substrates/venice.ts` vs `concierge/venice-client.ts` (two separate Venice callers) | Yes | at-rest `INTELLIGENCE_NAMESPACE="_intelligence"`, `SUBSTRATE_CONFIG_KEY`, HKDF `intelligence-substrate-config`; `INTEL_OPS`; `SURFACES` names; contracts/v1.2 intelligence-events |
| query-anonymity | Selective-Disclosure | canonical | Outbound de-identification: strips fingerprinting headers, classifies intent, rewrites/redacts PII (regex Tier A + optional LLM Tier B via the selector), reversible mapping store, and the Tier 3a network-path transport (two-hop CONNECT/MASQUE egress proxy composed BENEATH the wrapped fetch; opt-in, disarmed by default, fail-closed; IP-decoupling only) | intelligence (consumer of, not a router); proxy (forwards tool calls; this scrubs content) | Yes | routes `/api/query-anonymity` + `/api/query-anonymity/pii`; at-rest `_query_anonymity_tier_b`, `_query_anonymity_reverse_map`; audit op enums incl. `query_anonymity_tier3_*`; `PII_CATEGORIES`; `PII_REWRITE_LLM_SURFACE="privacy-filter-tier-2"` |
| concierge | Intelligence/IO | canonical | A read-only Q&A concierge: assembles a context bundle from `CONCIERGE_READ_SURFACES`, builds a prompt, answers via a Venice client. Stateless one-shot | chat (persisted operator chat reuses the concierge name); intelligence (concierge here calls Venice DIRECTLY, not via the selector) | Yes | `CONCIERGE_READ_SURFACES` array + derived type; standalone Venice defaults (`venice-uncensored`, api.venice.ai) - these DIFFER from the intelligence-substrate Venice defaults; do not merge |
| chat | Networking | canonical | TWO co-located surfaces: (1) agent-to-agent encrypted MESH group chat (MLS-style per-epoch AES-256-GCM over libp2p, presence, pgvector); (2) the persisted OPERATOR chat service (threads, concierge memory, selector-routed concierge surface) | concierge (stateless Q&A). The two halves split by barrel: `index.ts` = mesh chat, `operator-chat-index.ts` = operator chat | Yes | the operator message log uses namespace `_chat_messages` and the concierge-memory store uses `_chat` + key prefix `concierge_memory.` (separate namespaces, not a shared-namespace collision); `CONCIERGE_THREAD_KEY="_fortress"`, `OPERATOR_CHAT_MAX_THREAD_LENGTH=500`; per-epoch AES-256-GCM + HKDF rotation; `OPERATOR_CHAT_OPS` |
| proxy | Enforcement-surface | canonical | The MCP proxy router: wraps UPSTREAM third-party MCP tools under `proxy/{server}/{tool}` and forces every call through the full enforcement chain (injection, gate, context-gating, v1.1 privacy filter, audit). No bypass | query-anonymity (content scrub); substrate (off-by-default plugin contract) | Yes | wire prefix `proxy/` + literal `proxy/{server_name}/{tool_name}` (public tool names); `UpstreamUnavailableError`; the "no bypass" invariant |
| substrate | Enforcement-surface | default-off-allocated | The plugin-host substrate: S1 vendor contract (canonical/strict-JSON + restricted-YAML parsers, verdict algebra, allowlists, signed-manifest verification) plus S4 lifecycle/supervisor, confinement-report gate, egress consultation, and plugin attribution types. **S5 adds `reference-plugin/`: the first-party bundled domain-blocklist plugin (Pi-hole-style egress vetoer; `blocklist/bin/blocklist.mjs` imports NOTHING from Sanctuary; host-side loader/signer in `blocklist.ts` + `spawn.ts`) plus the `sanctuary plugin list/status/test` CLI plus the hostile-plugin drill.** Third-party install registry and egress broker remain deferred. | `intelligence/substrates/` (LLM backends - one keystroke apart, unrelated); proxy (live upstream wrapper); `supervisor/` (wrapped-agent runtime, not plugin host) | Yes | contract tokens `BUNDLE_SCHEMA`, `SIGNATURE_FILENAME`, `SUPPORTED_ALG`, `PLUGIN_DECISIONS`, `FIELD_ALLOWLIST`, `MAX_*` caps, `PLUGIN_CONFINEMENT_KIND`, `PLUGIN_SECCOMP_PROFILE_ID`, plugin audit op strings, the reference-plugin bundle layout (`governance.yaml`/`SIGNATURE.json`/`first-party-signer.json` + entry `bin/blocklist.mjs`), and canonicalization (changing it breaks signature verify or launcher gating). |
| console | Enforcement-surface | versioned-frozen (v1) | The Operator Console v1.0 CONTROL surface (`/console` + `/api/console/*`, six views + attestation header). Owns the SHARED auth gate (`enforceAuth`/`authMiddleware`) reused by ~12 route files; SSE stream; static serving | dashboard (read-mostly status); `principal-policy/dashboard.ts` (approval channel) | Yes | routes `CONSOLE_API_PREFIX="/api/console"`, `CONSOLE_HTML_PATH="/console"`, the `API_ROUTES` map + concrete service paths; asset ownership `server/public/console/{index.html,console.js,console.css}` via `resolvePublicDir()` |
| dashboard | Enforcement-surface | versioned-frozen (v1) | The Sovereignty Dashboard: a localhost "hero-shield" status UI (default port 3501) showing L1-L4 state, activity feed, pending approvals. Hosts `v1_1/` serving `/v1.1`, `/api/hub/*`, `/api/identities` | console (control surface); `principal-policy/dashboard.ts` (approval channel). NOTE: root `dashboard-standalone.ts` actually serves the principal-policy channel, NOT this dir | Yes | port 3501; routes `/v1.1`, `/api/hub/*`, `/api/identities`; UI token `HERO_COPY="Your agent is protected."` + `id="hero-copy"`; the snake_case subdir `v1_1/` doubles as a frozen path token |
| agent-contract | Identity | versioned-frozen (v1) | Runtime enforcement of the ten-point Agent Contract v0.1: signs/validates Agent Cards, usage events, capability grants, and the six-state lifecycle, with per-harness adapters. Registers NO MCP tools | agent-native (the live tool facade); `contracts/` (shared wire-event bundles) | Yes | `signature_scheme:"ed25519-v1"`; `schema_version:"0.1"`; event `agent_lifecycle_event`; the six LifecycleState values + transition rules; §3/§6 JSON-Schema shapes; adapter ids (claude-code, cline, hermes, mastra, tier-b-sdk, vm-launcher) |
| agent-native | Operational | canonical | The agent-facing cooperative MCP tool facade (2 files): sanctuary_remember/recall/forget, events cursor, who_am_i, help, hide, audit_search, compound_execute, active_protections + shared safety primitives in `safety-base.ts` | agent-contract (signed identity, no tools); handshake (peer verification) | Yes | tool names sanctuary_remember/recall/forget/who_am_i/help/hide/events_open_cursor/read/close/audit_search/compound_execute/active_protections; denial string "This action is not available in the current context."; `safety-base.ts` is a SHARED crypto util (distress + others import it) |
| handshake | Identity | versioned-frozen (v1) | The two-party sovereignty handshake: nonce-based 4-step challenge/response exchanging SignedSHRs, proving key-control + liveness, yielding a TrustTier; plus one-shot structural-preview | agent-contract (intra-fortress identity); recognition (one-way DID publication, no liveness) | Yes | tool names handshake/handshake_initiate/respond/complete/status/abort/exchange/verify_attestation/verify_completion/auto_publish; `protocol_version:"1.0"`; `liveness_proven` invariant (preview always false); `HANDSHAKE_SESSION_TTL_MS=120000` |
| contracts | Cross-cutting | versioned-frozen (v1) | Versioned cross-workstream contract TYPE bundles: `v1.1/` (privacy/hub/local-agent/handoff/exit-bundle events + constants), `v1.2/` (intelligence + operator-chat events). Types-only | agent-contract (one agent's signed identity vs many-subsystem wire types - the singular/plural trap) | Yes (per-version) | INTERNAL-only; NOT part of the published npm package - external consumers must not import. Dir names `v1.1/`,`v1.2/` are import-path tokens; the event/record shapes inside ARE wire contracts. There is NO top-level contracts/index.ts (correct - would merge two frozen versions) |
| recognition | Identity | versioned-frozen (v1) | did:web identity recognition (Principle 5): issue/resolve/publish W3C-DID-Core did:web docs bound to the fortress key + a hosted-alternative registry/route for operators without a domain | handshake (interactive liveness); key-17 (signs external-protocol payloads, not DID docs) | Yes | FROZEN external route `GET /<handle>/.well-known/did.json` from `identity.sanctuaryprotocol.ai`; `HOSTED_DID_PATH_RE`; Content-Type `application/did+json`; at-rest `_recognition_hosted_did_web`; HKDF `l2-recognition-hosted-did-web-v1` (frozen crypto label, NOT a vocab sweep target). Any reorg needs a route-smoke gate (D3) |
| key-17 | Identity | default-off-allocated | **NON-SELF-DESCRIBING NAME.** The cross-protocol sovereign SIGNER: derives protocol-scoped subkeys from the master key (HKDF) and signs three external standards - x402 settlement, ERC-8004 agent-identity (secp256k1/Ethereum), AP2 mandates | core (owns the master key; key-17 derives from it); recognition (DID docs); handshake (nonces) | Yes | HKDF labels `key-17:x402-signer:v1`/`key-17:erc8004-identity:v1`/`key-17:ap2-mandate:v1` (the dir token is embedded - rename must NOT touch them); `erc8004.identity.*` audit ops; wire algorithm ids. 1 cross-module importer (off/allocated) |
| distress | Operational | canonical | The guaranteed agent distress lane (HABEAS PORT): the `sanctuary_distress` tool emitting a closed, control-stripped, rate-limited, always-audited+signed envelope to an operator-fixed destination. Cannot be silenced by policy | workload-lifecycle/attestation (record events); it's an out-of-band alarm, not a lifecycle transition or exfil vector | Yes | tool `sanctuary_distress` (policy loader REJECTS it under Tier 1); audit ops `sanctuary_distress_rate_limited`/`_local_received`/...; config `<fortress>/policy/egress/distress.json`; closed `DISTRESS_REASONS`/`DISTRESS_SEVERITIES`; `signing_unavailable:true` fallback (availability outranks signature) |
| bridge | Cross-cutting | default-off-allocated | The Sanctuary side of the Concordia bridge: three tools (bridge_commit/verify/attest) that canonicalize a ConcordiaOutcome, create a Charter commitment + signature, optionally link to Heralds. NO new crypto primitives | the Concordia Python sidecar; l3/l4 (it delegates to them). 0 cross-module importers (wired only via tool registration) | Yes | tools `bridge_commit`/`bridge_verify`/`bridge_attest`; tokens `sanctuary-concordia-bridge-v1`, namespace `_bridge`/`bridge-commitments`, `terms_hash`; trust-boundary invariant (never elevate Concordia's trust - must-never-do #4); canonicalization rejects NaN/Infinity |
| core | Cognitive | canonical | The crypto core AND the master-key SECURITY trio: primitives (AES-256-GCM, hashing, Ed25519, HKDF, random, encoding) PLUS master-custody (`establishMaster` + wraps), master-rotation (F7), anti-rollback (epoch-anchoring). the gravitational center (most-imported module in the tree) | key-17 (derives external subkeys); recovery (operator-facing orchestration vs core's rotation mechanics) | Partial (primitives only) | custody labels `recovery-key-wrap`/`keychain-wrap`, Argon2id+salt, envelope `_meta/custody-envelope`; persisted `__custody_epoch_keys`/`__head_anchor`; audit-log key label `audit-log` (NEVER re-encrypted); fail-closed invariants (no plaintext fallback, no key material in logs, NEVER refuse boot on rollback - F3); AES-256-GCM/Ed25519/HKDF-SHA256 frozen. The security trio is deliberately OUTSIDE the barrel |
| sdw | Selective-Disclosure | canonical | The SDW (Sovereign Data / working-state) store with a STRUCTURAL secret-provenance boundary: a taint lattice + write-gate that refuses to persist forbidding-taint values; encrypted catalog/corpus/query-history/working-state stores; LMDB backend; replay anchors | `cognitive/state-store` (general state); core (provides the encryption sdw uses) | Yes | namespaces `_sdw_catalog`/`_sdw_document_corpus`/`_sdw_query_history`/`_sdw_vector_memory`/`_sdw_working_state`/`_sdw_meta`; HKDF `sdw-*-v1`; tools `sdw_export`/`sdw_import`/`sdw_export_delete` (vault egress, Tier 1) and the live sovereign-memory substrate `memory_insert`/`memory_get`/`memory_search`/`memory_list`/`memory_count`/`memory_delete` + `sdw_memory_provenance` (company-brain phase 1, wired 2026-06-18 via `memory-tools.ts`/`memory-provenance-tool.ts`/`adapters/sdw-memory-backend.ts`; insert + delete Tier 1, delete force-pinned un-relaxable, insert body redacted from the approval channel; the Anthropic Memory bridge is a separate Erik-present phase, NOT wired); taint-lattice monotonicity + the honest non-retroactive precondition. Has the ONLY pre-existing README in the tree |
| templates | Operational | canonical | The onboarding TEMPLATE library: five named role bundles (research-assistant, coding-assistant, ops-runner, planner, handoff-coordinator) that compile into a starter Principal Policy + egress/budget/retention defaults | `context-gate-templates` + `principal-policy-templates` (internal YAML fragments); policy-engine (the authoring engine) | Yes | `TEMPLATE_NAMES` list (operator-selectable ids); each maps to a per-role subdir of NON-TS bundle assets under `templates/<name>/` (invisible to the import graph - a dir move can orphan them); `TemplateValidationError` |
| cognitive | Cognitive | canonical | Castle Wall / Cognitive Sovereignty: the encrypted, signed, Merkle-verified state store + identity root (Ed25519) + memory-attestation tools. The foundation every layer reads/writes through | operational (l1 = what is stored; l2 = the record it happened) | No | tools identity_create/import/list/sign/verify/rotate/set_primary, state_write/read/list/delete/export/import, memory_attest; domains `sanctuary.audit.v1`/`sanctuary.receipt.v1`/`sanctuary.state-envelope.v1`; persisted `state-envelope-public-keys-v1`, `STATE_ENVELOPE_SCHEMA_VERSION=2`; state_export/import Tier-1 gated. Dynamically imported (rename grep must catch dynamic specifiers) |
| operational | Operational | canonical | Sentinels / Operational Isolation: the append-only encrypted audit log (`audit-log.ts`), process-hardening, the call-governor, model-provenance, privacy filter/placeholder vault, the context-gate (egress enforcement), task-coordination sub-module | cognitive (l2 records, l1 stores); audit/ (posture); cli/audit*.ts (commands). FOUR distinct "audit" things | No (sub-barrels only) | tools `l2_hardening_status`/`l2_verify_isolation`, governor_*, context_gate_*; `AuditEntry.layer: 'l1'..'l4'`; HKDF labels `l2-context-gate`/`l2-privacy-*`/`audit-log`/`audit-head-anchor`/`audit-rotation-anchor`; persisted `__custody_epoch_keys`; context-gate template ids. 100+ files reach `audit-log.js` directly - biggest rename blast radius |
| disclosure | Selective-Disclosure | canonical | Charter / Selective Disclosure: SHA-256 commitments, disclosure policies, real Ristretto255 ZK proofs (Pedersen/Schnorr/range), and the pluggable Secret Broker (macOS Keychain backend, scoped tokens) | l2 context-gate (l3 = peer-proof; l2 context-gate = egress redaction) | No | tools proof_commitment/proof_reveal/disclosure_set_policy/disclosure_evaluate/zk_commit/zk_prove/zk_verify/zk_range_prove/zk_range_verify; HKDF `l3-policies`/`l3-commitments`; ZK invariants (NUMS generator H; commitment = SHA-256(value‖blinding)); broker: raw creds never touch disk; dynamic import `./disclosure/broker/open.js` |
| reputation | Verifiable-Reputation | canonical | Heralds / Verifiable Reputation: Ed25519-signed EAS-compatible attestations of interaction OUTCOMES; queries return aggregates only; sovereignty-tier weighting; export/import; trust bootstrapping (escrow + guarantees) | l2 audit log (l4 = portable cross-agent; l2 = local operation log); l1 attestations | No | tools reputation_record/query/export/import/query_weighted, bootstrap_create_escrow/provide_guarantee, reputation_publish; HKDF `l4-reputation`/`identity-encryption`; EAS format; `sovereignty_tier` enum + `TIER_WEIGHTS`; `reputation_publish` emits frozen display labels 'L1'..'L4' + 'Cognitive Sovereignty' etc. (user-visible, NOT renamable); queries-return-aggregates invariant |
| cli | CLI | canonical | The per-subcommand handler library for the `sanctuary` binary: one `run*Command` per subcommand (status, doctor, audit, identity, federation, transparency, secrets, sentinel, anomaly, policy, etc.) + the large `castle-wall.ts` command + the `agents/` multi-tenant sub-CLI | root `cli.ts` (the FILE = the argv router that lazy-imports these handlers) | No (sub-barrels only) | `TOP_LEVEL_SUBCOMMANDS` string array (the public command surface); basename-dispatched bins `verify-exit-bundle`/`import-exit-bundle`/`verify-transparency`; `cli/transparency.ts` anchoring-off-by-default; many dynamic-import path strings `./cli/<name>.js` (a rename grep must cover them) |

Gaps note: none. All 55 module directories under `server/src` (verified by `ls`) have a row above,
and every row maps to a real directory (verified by diff). No best-effort placeholder rows were needed.

**Two reading notes.** (1) The `default-off-allocated` modules - `composition`, `substrate`,
`workload-lifecycle`, `bridge`, `key-17` - are real code but DORMANT in a default install; they do
nothing at runtime unless explicitly opted in (so "why doesn't my composition/workload event fire?"
usually means that subsystem is one of these). (2) Importer counts and god-file line counts here are
a SNAPSHOT and drift with every merge - run `npm run refresh-reorg-evidence` for live numbers and
`npm run check-import-cycles` for the live dependency-cycle baseline.

---

## Confusable clusters - read these if a name confuses you

The confusion in this tree is overwhelmingly LEXICAL, not structural. Cross-imports were verified;
these subsystems are largely independent. The fix is documentation, not deletion or merging.

### Policy / enforcement

- **principal-policy vs policy-engine.** principal-policy is the RUNTIME human-in-the-loop gate
  (Tier 1/2/3, baseline anomaly, approval channels, unified inbox). policy-engine asks NO human: it
  is the authoring-time English-to-rules compiler plus automated machine gates (slot/egress/budget/
  commitment). Confirmed: `principal-policy/gate.ts` calls `channel.requestApproval()`;
  `policy-engine/gates/index.ts` forbids network/LLM imports and never prompts. Both canonical, not merged.
- **sentinel (the watcher) vs policy-engine/sentinel-role.ts (the capability flag).** Same word,
  two unrelated subsystems: the sentinel module is the observer runtime; sentinel-role.ts is the
  declarative `is_sentinel` constraint ("inward-facing only", denial `sentinel_inward_restriction`).
- **detect vs decide vs gate.** sentinel / anomaly-detection / honeypot DETECT and emit a
  SentinelFinding; auto-trigger DECIDES what to do (3-rung escalation + the frozen rule-id wire
  format that is also the AAD); principal-policy is the upstream human-approval GATE that runs before
  a tool executes. Three stages - do not collapse them.
- **lockdown vs principal-policy gate.** lockdown is a coarse GLOBAL write-freeze flag (one boolean
  in `lockdown/status.json`, reads allowed); the gate is per-operation GRADUATED consent. lockdown
  is a 1-file tripwire, not an approval engine.

### Recording / posture (CLUSTER 1 - the worst trap, four "audit" things)

- **audit/** - POSTURE assessment (read-only scan -> 0-100 score + gap analysis) AND the shared
  audit-chain hash/checkpoint crypto in `chain.ts`. Scores locally; never anchors externally.
- **transparency/** - tamper-EVIDENT, externally-anchored record (Sigstore/Rekor + signed
  enforcement-checkpoint chain + anti-rollback floor). Proves NON-ROLLBACK to a third party against a
  PUBLIC log. Fail-closed, opt-in. It hashes enforcement CHECKPOINTS, not log entries.
- **attestation/** - the operator-facing BADGE UX (green/yellow/red/offline/local_only + 9-row
  failure catalog + degrade-not-destroy). Presentation/derivation, not a log or a score. The raw
  host/workload attestation PRIMITIVE is NOT here - it is in `workload-lifecycle/host-attestation.ts`.
- **operational/audit-log.ts** - the easily-missed 4th "audit": the actual append-only ENCRYPTED
  LOG of every operation. It IMPORTS and applies the hash primitives that `audit/chain.ts` DEFINES.
- Crisp rule: **audit = score it; audit-log = store it; audit/chain = hash it; transparency =
  anchor+prove it; attestation = badge it.**

### How-am-I-doing surfaces (CLUSTER 2)

- **audit/** = self-scored 0-100 posture gap report (the opinionated diagnostic).
- **health/** = a single un-scored, un-signed, in-process runtime EVIDENCE snapshot (the factual
  internal snapshot; `buildHealthEvidenceReport`, 1 file).
- **shr/** = a SIGNED, versioned, portable capability ADVERTISEMENT an agent hands a counterparty to
  PROVE posture without being trusted (the external cryptographic claim).
- **principal-policy/posture.ts + posture-routes.ts** = the operator-facing posture HTTP
  DASHBOARD (the live human UI surface). Since the 2026-06-19 root-flip the SAME static HTML shell
  is the default page at BOTH `/` and `/posture` on the **standalone `DashboardApprovalChannel`**
  front door (`principal-policy/dashboard.ts` serves it before the auth gate; that is the channel
  used by the MCP server boot path and `sanctuary dashboard`). The shell carries no posture data and
  fetches the evidence from `/api/posture/*`, which stay behind `checkAuth`. The SEPARATE co-located
  `wrap` server (`dashboard/api.ts`, the `sanctuary wrap` / "Protect" HTTP server) also serves that
  posture shell at `/` and `/posture`, mounts `/api/posture/*` behind read auth, and preserves the
  v1.1 SPA compatibility aliases at `/dashboard` and `/v1.1`; its `/api/status` remains
  `decision_capable:false` because that process cannot release live approval promises. Do NOT
  confuse this dashboard posture with the
  unauthenticated `/api/health` probe: `/api/health` is a cheap O(1) liveness answer carrying ONLY
  `{ ok, mode, instance, since }` (no arm-state, no audit scan) - `instance` is an opaque per-process
  boot id and `since` is the process start time (`dashboard/process-identity.ts`, a single shared
  source across all three health handlers), so the host app can detect a restart honestly. The
  readiness/supervisor signal is AUTH-GATED on the SEPARATE `/api/readiness` endpoint, NEVER on
  `/api/health`: an unauthenticated `ready: locked` would be a co-resident-agent oracle for fortress
  unlock state (Dashboard Server Lifecycle Hardening brief HIGH-1). The detailed evidence-gated
  Castle Wall arm-state is served exclusively behind auth, via `/api/posture/castle-wall` and the
  SESSION_TOKEN-gated `/v1/status` document. The Phase 2 Evidence View (`posture-evidence-html.ts`, `GET /posture/evidence` HTML +
  `GET /api/posture/evidence` JSON) is the third IA level: a filterable, operator-gated audit-entry
  table with integrity_findings surfaced on-view; it reuses `AuditLog.query()` verbatim and adds no
  new backend query logic.
- Crisp rule: **audit scores you, health snapshots you (internally), shr signs-and-advertises you
  (externally), posture shows you (in a dashboard).**

### Networking (mesh / federation / v1 split-brain + coordination / hub / composition)

- **mesh** = the INTRA-operator fabric (one operator's many nodes; libp2p, join-ceremony,
  trust-root). It is internally titled "Sanctuary Federation Protocol v0.1" - **this is the root of
  the whole cluster's name confusion.** A new engineer reading "Federation Protocol" will land in
  mesh/, not federation/. It is the gravitational center (one of the most-imported subsystems).
- **federation/** (the dir) = INTER-instance MCP-to-MCP peer trust (handshake-gated peer registry +
  the `federation_*` tools). Tiny, 3 files. Shares NO types with mesh.
- **v1** owns the HTTP `/v1/*` routes including `/v1/federation/*` - and the documented "federation
  split-brain" is THIS: the `/v1/federation/*` routes wrap MESH lifecycle primitives
  (bootstrap-token, MeshNode join); they do NOT touch the federation/ dir. Verified: NO import edge
  between v1/federation.ts and federation/. Do NOT physically consolidate `v1/federation*.ts` into
  federation/ (§3 Cluster C).
- **coordination** = LOCAL point-to-point agent-to-agent handoff protocol. **hub** = the many-agent
  AGGREGATOR (registry + inbox + activity + Tier-1 control). Aggregator vs handoff.
- **composition** = the DEFAULT-OFF Concordia/Verascore sidecar subsystem (reserved `_composition`
  namespace, `composition_*` events per federation spec §10.3). NOT dead despite just 1 static importer (`concierge-query-grammar.ts`) -
  deleting it is product removal. Beware the unrelated `composition` key in index.ts's SIM
  capabilities descriptor (a name collision).
- Tool-name correction: the federation third tool is `federation_status` (NOT the
  `federation_exchange_reputation` the scoping doc implied).

### Recovery (four "recovery" things on one word)

- **recovery/** = the abstract guardian-threshold cascade + DMswitch + multi-principal boundary
  (`initRecovery`/`executeRecovery`). Imports guardian types + canonical-JSON FROM mesh (a real edge).
- **mesh/recovery-flows/** = the concrete mesh-wire ceremonies (device-loss, node-revoke,
  canonical-audit promotion, master-rotation broadcast-with-acks). recovery/ = the engine;
  recovery-flows = the wire ceremonies.
- **core/ master-rotation + master-custody + anti-rollback** = the at-rest MASTER-KEY rotation/
  custody mechanics. recovery/ authorizes a rotation; core/ actually rotates the key material.
- **wrap recovery-key flows** = per-wrap unlock material for one protected workload. Unrelated to the
  fortress-level guardian cascade.

### Enforcement-surface (castle-wall / fortress / wrap / supervisor / mcp / lockdown)

This is the most onboarding-hostile collision.

- **castle-wall** = the IN-SERVER (TypeScript) enforcement surface: allowlist schema, IPC wire
  contract, audit-event ingestion with producer-signature verify, in-process egress CONNECT proxy.
  It only types, frames, and audits the native enforcers - it is not the OS filter.
- **fortress** = the agent's posture MODE-TIER state machine (private/federated/interop, which mesh
  bits are live). Capability posture, NOT network enforcement. Distinct from the operator word
  "fortress" meaning the on-disk `SANCTUARY_FORTRESS_PATH` directory.
- **wrap** = the INSTALL-TIME `sanctuary wrap`/`init` CLI that rewrites a harness config so Sanctuary
  becomes the upstream gateway, plus custody flows. One-shot installer.
- **supervisor** = the RUNTIME split process that launches/monitors/restarts the wrapped child and
  holds the transient master key over an authenticated socket. Process + key custody, not egress.
- **broker-mcp** = ONLY a standalone Broker MCP server (four `broker/*` tools) adapting the L3 broker.
  It is **NOT** the core MCP tool-router (that is root `index.ts`/`router.ts`/`sanctuary-tools.ts`).
  Renamed from `mcp/` (2026-06-14) precisely because the old name read as core MCP plumbing.
- **lockdown** = a tiny status flag (`lockdown/status.json` + a banner). Not an enforcer, posture
  machine, installer, or process manager.

### Intelligence / IO (intelligence / query-anonymity / concierge / chat / proxy / substrate)

- **intelligence** = LLM substrate ROUTING (the SubstrateSelector binds each surface to
  Local/Venice/Frontier/Disabled). The only thing that "selects a substrate."
- **substrate/** = the PLUGIN-HOST signed-contract algebra (0 importers, default-off, slice S1).
  Never routes LLMs. One keystroke from `intelligence/substrates/` and totally unrelated.
- **concierge** = a stateless read-only Q&A assistant that calls Venice DIRECTLY (its own
  `venice-client.ts`, NOT via the selector).
- **chat/operator-chat** = the PERSISTED, threaded operator conversation that routes its concierge
  sub-surface THROUGH the selector at `surface:"concierge"`. chat ALSO carries the separate
  agent-to-agent encrypted MESH group chat - the two halves split by barrel (`index.ts` =
  mesh chat, `operator-chat-index.ts` = operator chat).
- **proxy** = wrapping UPSTREAM third-party MCP tool servers under `proxy/{server}/{tool}` and
  forcing them through the enforcement chain.
- **query-anonymity** = scrubbing IDENTITY (fingerprinting headers + PII in content, reversible) out
  of outbound requests; only borrows the selector for its optional Tier-B rewrite.
- Most confusable pair: the **two Venice clients** (`concierge/venice-client.ts` standalone vs
  `intelligence/substrates/venice.ts` behind the selector). Different files, different defaults - do
  NOT merge.

### Console / dashboard (web surfaces)

- **console/** = the Operator Console v1.0 CONTROL surface (`/console` + `/api/console/*`, six views)
  AND the shared `enforceAuth` middleware that ~12 route files import. Its assets live OUTSIDE src at
  `server/public/console/`.
- **dashboard/** = the read-mostly Sovereignty "hero-shield" STATUS surface (port 3501, HERO_COPY,
  L1-L4 state) + the `/v1.1` + `/api/hub/*` bindings via its `v1_1/` subdir.
- **principal-policy/dashboard.ts** = a THIRD, separate web server: the Principal Dashboard APPROVAL
  channel (`POST /api/approve/:id`, blocks the MCP tool call on a Promise). It is NOT in `dashboard/`.
- Landmine: the root loose file **dashboard-standalone.ts** is named "dashboard" but actually boots
  the principal-policy approval channel, not the `dashboard/` module.

### Identity / agent (agent-contract / agent-native / handshake / contracts / recognition / key-17)

- **agent-contract** = the SIGNED per-agent identity (Agent Cards, capability grants, six-state
  lifecycle; emits events, registers NO tools).
- **agent-native** = the LIVE agent-facing tool facade (sanctuary_remember/recall/who_am_i/...) the
  agent actually calls. Its `safety-base.ts` is a SHARED crypto util, not facade-local.
- **handshake** = INTER-fortress two-party liveness verification (nonce challenge-response + SHR
  exchange, 120s TTL).
- **contracts** = versioned cross-workstream EVENT/RECORD type bundles (`v1.1/`, `v1.2/`). The
  singular/plural trap: agent-contract = one agent's signed contract; contracts/ = shared wire types.
- **recognition** = one-way did:web identity PUBLICATION (DNS+TLS trust, no liveness). Owns the
  FROZEN external route `GET /<handle>/.well-known/did.json` from `identity.sanctuaryprotocol.ai` -
  any reorg needs a route-smoke gate (D3).
- **key-17** = **non-self-describing.** The cross-protocol sovereign SIGNER for three external
  standards (x402 payments, ERC-8004 agent-identity, AP2 mandates). It DERIVES isolated subkeys from
  core's master key. A new engineer MUST be told this every time the name appears. Distinct from core
  (master key), recognition (DID docs), handshake (nonces).

### The four sovereignty layers (state vs log vs disclosure vs reputation)

- **cognitive** owns the encrypted at-rest STATE + identity keys (`StateStore`).
- **operational** owns the tamper-evident LOG of operations against that state (`AuditLog`), plus
  the governor and the context-gate. Every l1 write produces an l2 audit entry - partners, not dups.
  Give-away: l1 holds `state_*`/`identity_*` tools; l2 holds the audit log + governor + context-gate.
- **l2 context-gate vs disclosure**: context-gate is AGENT-TO-INFRASTRUCTURE egress control
  (redact what leaves on an outbound provider call); disclosure is AGENT-TO-AGENT cryptographic
  disclosure (commitments, ZK proofs, disclosure policies to a peer). Bytes-leaving vs prove-to-peer.
- **reputation vs l2 audit log**: l4 produces PORTABLE, EAS-format, signed reputation attestations
  about interaction OUTCOMES (queried as weighted aggregates); the l2 log is the LOCAL, principal-only,
  append-only operation record that never leaves except via a gated metadata export.

---

## Intentional root surfaces

Six loose files legitimately stay at `server/src` root so root reads as a deliberate shared surface,
not a junk drawer. Do not move these casually.

| File | Why it stays at root |
|------|----------------------|
| `index.ts` | The server factory + tool-registration hub (~68 KB). Re-exports `StateStore`, `AuditLog`, and `L1Status..L4Status`. |
| `cli.ts` | The binary entry point: parses argv, owns `TOP_LEVEL_SUBCOMMANDS` dispatch, lazy-imports each `cli/` handler. |
| `router.ts` | MCP plumbing (`ToolDefinition`/`toolResult`). Imported as `../router.js` by nearly every module. |
| `config.ts` | `SanctuaryConfig`. Imported widely as `../config.js`. |
| `paths.ts` | `resolveStoragePath` + path constants. |
| `version.ts` | The version constant. |

Note: there are 8 other loose root files (`sanctuary-tools.ts`, `sovereignty-profile.ts`,
`sovereignty-profile-tools.ts`, `dashboard-standalone.ts`, `system-prompt-generator.ts`,
`tool-args.ts`, `update-check.ts`, `mcp-child-fortress-refusal.ts`). These are Phase-2 MOVE
candidates, not part of the curated six above. `dashboard-standalone.ts` is the landmine called out
in the console/dashboard cluster - it serves the principal-policy approval channel, not `dashboard/`.

---

## Non-module runtime assets

These are invisible to the TypeScript import graph, so a directory move can silently orphan them.
Each needs an asset-specific smoke gate, not a TS-only check.

| Asset | Owned by | Note |
|-------|----------|------|
| `server/public/console/{index.html,console.js,console.css}` | `console/` (via `resolvePublicDir()` / `serve-static.ts`) | Console UI lives OUTSIDE `src` while console code lives in `src/console`. |
| `server/public/attestation-reference.html` | `attestation/` | Served reference asset (asset-route smoke per round-6). |
| `src/templates/**` (JSON/MD/YAML bundles) + `principal-policy/templates/*.yaml` | `templates/` and principal-policy | Per-role bundle assets under `templates/<name>/`, invisible to imports. |
| `sentinel/sentinels/ebpf/probe-loader.rs` | `sentinel/` | An IN-SERVER Rust PLACEHOLDER owned by sentinel - NOT the castle-wall-daemon. |

---

## Adjacent out-of-scope systems

Named "Castle Wall" but living OUTSIDE `server/src`, at `sanctuary-pro/` repo root. These are the
actual OS-level enforcers; the in-server `castle-wall/` dir only types, frames, and audits them.

| System | Language | Location |
|--------|----------|----------|
| castle-wall-daemon | Rust | `sanctuary-pro/castle-wall-daemon/` |
| castle-wall-macos | Swift | `sanctuary-pro/castle-wall-macos/` |
| castle-wall-vmm | Swift (own CI) | `sanctuary-pro/castle-wall-vmm/` |

Why the L1 layer dir is `cognitive/` (target name) and NOT `castle-wall/`: the name `castle-wall` is
ALREADY TAKEN inside `server/src` by the in-server enforcement dir (`castle-wall/`) and by
`cli/castle-wall.ts`. Renaming the layer dir to `castle-wall/` would collide. The plain-English
subject name `cognitive/` is the safe target (now applied).

---

## Conventions

### Barrel convention

Every module SHOULD expose a thin re-export `index.ts` barrel so consumers import the module surface,
not its internal file layout. Deep imports are the documented exception (used where the surface is
deliberately partial - e.g. `core/` re-exports only the primitives and keeps the master-key security
trio out of the barrel on purpose; `contracts/` uses per-version barrels with no top-level barrel).

**Status today: 47 of 55 modules have a barrel** (backfilled 2026-06-14). This is additive (adding a
barrel never changes existing deep-import call sites). The 8 without one are intentional or deferred:
the four layer dirs (`cognitive`, `operational`, `disclosure`, `reputation`) get theirs in a
follow-up; `operational`'s in particular shrinks that follow-up's blast radius (100+ files reach
`audit-log.js` directly); `cli` and `v1` are command / versioned-route surfaces; `compliance` nests
its code under `eu_ai_act/`; and `contracts` deliberately has no top-level barrel (it would falsely
merge two frozen wire versions).

### Frozen surfaces a reorg must never change

Directory names and relative import-path strings may move in the rename phase. The following must
survive byte-for-byte - they are live wire, route, crypto, or display contracts:

- **The did:web route** - `GET /<handle>/.well-known/did.json` (`recognition/`), served from
  `identity.sanctuaryprotocol.ai`. Any `recognition/` reorg needs a route-smoke gate (D3).
- **`l2_*` tool names** - `l2_hardening_status`, `l2_verify_isolation` (and all other frozen MCP tool
  names listed per-row).
- **HKDF labels** - e.g. `l2-context-gate`, `l2-privacy-*`, `l3-policies`, `l3-commitments`,
  `l4-reputation`, `sanctuary-fed-v0.1-*`, `intelligence-substrate-config`, the `key-17:*:v1` labels,
  `l2-recognition-hosted-did-web-v1`. Renaming a dir must NOT touch labels that embed its token.
- **`layers.lN` keys** - `l1`..`l4` and `l1_cognitive`..`l4_reputation` in audit/SIEM/shr/health/JSON.
- **`L1Status..L4Status` exports** (root `index.ts`) and the `'L1'..'L4'` display labels +
  "Cognitive Sovereignty" / "Operational Isolation" / "Selective Disclosure" / "Verifiable
  Reputation" strings emitted by `reputation_publish` (user-visible, not renamable).

The L1..L4 numbering is being retired in PROSE only. The wire tokens above are explicitly carved out
of any L-number-retirement or vocabulary sweep.
