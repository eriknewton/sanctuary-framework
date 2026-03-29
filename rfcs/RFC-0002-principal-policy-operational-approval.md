# RFC-0002: Principal Policy and Operational Approval

### Human-in-the-Loop Defense Against Prompt Injection

**Status:** Draft
**Author:** Erik Newton
**Date:** March 26, 2026
**Sanctuary Framework Version:** 0.2
**Depends on:** RFC-0001 (Sanctuary MCP Server)
**License:** Apache 2.0

---

## 1. Abstract

This RFC specifies the **Principal Policy** system — an immutable, human-controlled policy layer that gates agent operations through a three-tier approval framework. The system addresses the fundamental limitation of software-only security: a prompt-injected agent retains access to its own keys and can perform any operation the legitimate agent could. Principal Policy limits the blast radius of such compromises by requiring human approval for anomalous or high-risk operations, through a channel the agent cannot access or manipulate.

The design is guided by a core UX constraint: **approvals must be rare enough that users never disable them, and comprehensive enough that attacks cannot route around them.**

---

## 2. Motivation

### 2.1 The Prompt Injection Problem

Sanctuary RFC-0001 provides strong defense against external threats: encrypted state defeats filesystem exfiltration (Atomic Stealer), integrity verification defeats memory poisoning (MINJA, MemoryGraft), and identity isolation prevents cross-agent impersonation.

However, prompt injection attacks compromise the agent's *reasoning*, not its *infrastructure*. A successfully injected agent:

- **Can read its own encrypted state.** It calls `sanctuary/state_read` and receives decrypted data in its context window. The encryption protects against external attackers but not against the agent itself.
- **Can sign with its own keys.** It calls `sanctuary/identity_sign` and produces valid signatures. The private keys never appear in tool responses (that invariant holds), but the agent can use them operationally.
- **Can create fraudulent reputation records.** It calls `sanctuary/reputation_record` with fabricated outcomes.
- **Cannot erase the audit log.** This is the one defense that holds — the append-only audit log has no delete or modify tool, and entries are written with monotonic identifiers.

The append-only audit log provides forensic value after an incident, but does not prevent the incident. Principal Policy adds *preventive* defense.

### 2.2 Why Not Just Better Prompt Injection Defense?

Prompt injection is an unsolved problem in the research community. No production system reliably distinguishes injected instructions from legitimate ones. Betting Sanctuary's security model on the assumption that prompt injection will be solved is not a credible strategy. Principal Policy assumes the agent *will* be compromised and limits what a compromised agent can do.

### 2.3 The Approval Fatigue Problem

Security systems that require constant human intervention get disabled. UAC dialogs in Windows Vista, SSL certificate warnings before browsers made them blocking, cookie consent banners — all demonstrate that users habituate to security prompts and approve reflexively. A Principal Policy that fires on every state write would be worse than no policy at all, because it trains the human to approve without reading.

The design must therefore be *quiet most of the time and loud only when it matters*.

---

## 3. Architecture

### 3.1 Separation of Control Planes

Principal Policy introduces a strict separation between two control planes:

**Agent Plane** — The MCP tool interface. The agent can call any registered tool. This is the plane that prompt injection compromises.

**Principal Plane** — The policy configuration. Controlled exclusively by the human principal through direct file editing, CLI commands, or (in future) a dashboard. No MCP tool can modify the principal plane. The agent can *read* the policy (transparency) but cannot *write* to it.

This separation is the core architectural invariant. If any code path allows the agent plane to modify the principal plane, the entire system is defeated.

### 3.2 Policy File

The Principal Policy is defined in a YAML configuration file loaded at server startup:

**Location:** `{storage_path}/principal-policy.yaml`
**Permissions:** `0o600` (owner read/write only)
**Loaded:** Once at server initialization
**Modifiable at runtime:** No. Changes require server restart.
**Exposed to agent:** Read-only via `sanctuary/principal_policy_view`

```yaml
# Sanctuary Principal Policy v1
# This file controls what your agent can do without asking.
# Edit this file directly. Your agent cannot modify it.

version: 1

# ─── Tier 1: Always Requires Approval ────────────────────────────────────
# These operations ALWAYS require your explicit approval, regardless of
# behavioral history. They are inherently high-risk.
tier1_always_approve:
  - state_export        # Bulk export of encrypted state
  - state_import        # Importing external state
  - identity_rotate     # Changing cryptographic keys
  - reputation_import   # Importing external reputation
  - bootstrap_provide_guarantee  # Signing guarantees for other agents

# ─── Tier 2: Behavioral Anomaly Detection ────────────────────────────────
# These thresholds trigger approval when the agent's behavior deviates
# from its established baseline. Adjust these to match your agent's
# normal activity patterns.
tier2_anomaly:
  # First access to a namespace the agent hasn't used before
  new_namespace_access: approve    # approve | log | allow

  # First interaction with an unknown counterparty DID
  new_counterparty: approve        # approve | log | allow

  # Tool call frequency exceeds N× the session baseline
  frequency_spike_multiplier: 5

  # Maximum signing operations per minute before triggering
  max_signs_per_minute: 10

  # Reading more than N keys in a single namespace within 60 seconds
  bulk_read_threshold: 20

  # First-time operations (no baseline exists yet)
  # On first session, more approvals fire. This is intentional —
  # it teaches the user what their agent does.
  first_session_policy: approve    # approve | log | allow

# ─── Tier 3: Always Allowed (Audit Only) ─────────────────────────────────
# These operations never trigger approval but are always logged.
# Read-only and low-risk operations belong here.
tier3_always_allow:
  - state_read          # Within known namespaces
  - state_write         # Within known namespaces
  - state_list
  - state_delete
  - identity_create
  - identity_list
  - identity_sign       # Within frequency limits
  - identity_verify
  - proof_commitment
  - proof_reveal
  - disclosure_set_policy
  - disclosure_evaluate
  - reputation_record   # With known counterparties
  - reputation_query
  - reputation_export
  - bootstrap_create_escrow
  - exec_attest
  - monitor_health
  - monitor_audit_log
  - manifest
  - principal_policy_view

# ─── Approval Channel ────────────────────────────────────────────────────
# How Sanctuary reaches you when approval is needed.
approval_channel:
  type: stderr          # stderr | webhook | callback
  timeout_seconds: 300  # How long to wait before auto-denying
  auto_deny: true       # Deny if timeout expires (true) or allow (false)

  # Future: webhook configuration
  # webhook_url: https://your-endpoint.com/sanctuary/approve
  # webhook_secret: "your-hmac-secret"
```

### 3.3 Default Policy

Sanctuary ships with a sensible default policy that provides meaningful protection without requiring configuration. The default is designed for a single-agent setup doing general-purpose work:

- Tier 1 gates bulk data movement and key rotation (rare operations that should always be intentional)
- Tier 2 detects behavioral anomalies with conservative thresholds
- Tier 3 allows normal read/write/sign/query operations without friction
- Approval channel defaults to stderr with a 5-minute timeout and auto-deny

A user who never edits the policy file still gets protection. A power user can tune thresholds. An enterprise deployment can lock down Tier 2 aggressively.

---

## 4. Behavioral Baseline Tracking

### 4.1 Session Profile

During each session, Sanctuary maintains a lightweight behavioral profile that tracks:

```typescript
interface SessionProfile {
  /** Namespaces accessed (read or write) */
  known_namespaces: Set<string>;

  /** Counterparty DIDs seen in reputation operations */
  known_counterparties: Set<string>;

  /** Tool call counts per 60-second sliding window */
  tool_call_rates: Map<string, number[]>;

  /** Per-namespace read counts in current 60-second window */
  namespace_read_counts: Map<string, number>;

  /** Total signing operations in current 60-second window */
  sign_count_window: number[];

  /** Whether this is the first session (no prior baseline) */
  is_first_session: boolean;

  /** Session start time */
  started_at: string;
}
```

### 4.2 Baseline Persistence

The session profile is persisted (encrypted under L1) at session end. On the next session start, the previous profile is loaded to establish the baseline. This means:

- **First session:** No baseline exists. Tier 2 rules with `first_session_policy: approve` fire on first use of each operation type. This is by design — the user learns what their agent does.
- **Second session onward:** The baseline from prior sessions defines "normal." Only deviations trigger approval.
- **Gradual baseline shift:** The baseline updates each session. If an agent legitimately starts using a new namespace, the first access triggers approval, but subsequent sessions treat it as normal.

### 4.3 Anti-Manipulation

A compromised agent that persists across sessions could attempt to slowly shift the baseline (accessing one new namespace per session until the anomaly detector considers it normal). Defenses:

- **Baseline changes are audit-logged.** Every new namespace, new counterparty, or rate threshold adjustment produces an audit entry.
- **Principal can review baseline history.** A new tool `sanctuary/principal_baseline_view` shows the current baseline and recent changes.
- **Baseline is stored with integrity verification.** Tampering with the persisted baseline is detectable via L1's Merkle verification.

---

## 5. Approval Gate

### 5.1 Tool Call Interception

The approval gate sits between the MCP tool router and the tool handler. Every tool call passes through the gate before execution:

```
Agent → MCP Request → Router → [Approval Gate] → Tool Handler → Response
                                      │
                                      ├── Tier 1 match? → Request approval
                                      ├── Tier 2 anomaly? → Request approval
                                      └── Tier 3 / no match → Allow (audit log)
```

### 5.2 Evaluation Order

For each tool call, the gate evaluates in order:

1. **Tier 1 check.** Is this tool's operation name in the `tier1_always_approve` list? If yes → request approval. This check is a simple set lookup and cannot be bypassed by behavioral manipulation.

2. **Tier 2 check.** Does this call represent a behavioral anomaly?
   - New namespace? Check `known_namespaces` against the current call's namespace argument.
   - New counterparty? Check `known_counterparties` against any DID argument.
   - Frequency spike? Check current tool call rate against `frequency_spike_multiplier × baseline_rate`.
   - Bulk read? Check `namespace_read_counts` against `bulk_read_threshold`.
   - Sign frequency? Check `sign_count_window` against `max_signs_per_minute`.
   - First session? If `is_first_session` and `first_session_policy` is `approve`, request approval for any operation not in Tier 3.

3. **Tier 3 / default.** Allow the operation. Log it to the audit trail.

### 5.3 Approval Request Format

When approval is required, Sanctuary emits a structured prompt to the configured channel:

```
╔══════════════════════════════════════════════════════════════════╗
║  SANCTUARY: Approval Required                                    ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Operation:  state_export                                        ║
║  Tier:       1 (always requires approval)                        ║
║  Namespace:  agent-memory                                        ║
║  Identity:   test-agent-alpha                                    ║
║  Reason:     Bulk state export is a Tier 1 operation             ║
║                                                                  ║
║  Context: The agent is requesting to export all encrypted state  ║
║  from the "agent-memory" namespace as a portable bundle.         ║
║                                                                  ║
║  [A]pprove  [D]eny  [V]iew details                              ║
╚══════════════════════════════════════════════════════════════════╝
```

For Tier 2 anomalies, the prompt includes behavioral context:

```
║  Operation:  state_read                                          ║
║  Tier:       2 (behavioral anomaly)                              ║
║  Namespace:  _identities                                         ║
║  Reason:     First access to namespace "_identities"             ║
║              (not in session baseline)                            ║
║                                                                  ║
║  Baseline:   agent-memory, preferences, task-history             ║
║  This is:    A namespace the agent has never accessed before      ║
```

### 5.4 Approval Response

The gate blocks until it receives one of:

- **Approve** → Execute the tool call. Log the approval decision.
- **Deny** → Return an error to the agent: `{"error": "Operation denied by principal policy", "operation": "state_export", "tier": 1}`. Log the denial.
- **Timeout** → If `auto_deny` is true, treat as denial. If false, treat as approval. Log the timeout.

The agent receives a clear, structured denial that does not reveal the policy rules (preventing an attacker from learning which operations are gated).

### 5.5 Denial Response to Agent

When an operation is denied, the tool returns:

```json
{
  "error": "Operation requires principal approval and was not approved.",
  "operation": "state_export",
  "retry_allowed": true
}
```

The response deliberately does not include: which tier triggered the denial, what the thresholds are, or what the behavioral baseline looks like. This prevents a compromised agent from learning the policy and adapting its behavior to avoid future triggers.

---

## 6. Approval Channels

### 6.1 Stderr (Default, MVS)

The default channel writes the approval prompt to stderr and reads the response from stdin. This works because:

- MCP stdio transport uses stdin/stdout for protocol messages, but stderr is available for out-of-band communication.
- Claude Code and other harnesses surface stderr to the user.
- The agent communicates through the MCP protocol on stdout and cannot inject content into stderr.

**Limitation:** The stdin response channel requires the harness to support user input during an MCP tool call. If the harness does not support this, the timeout mechanism provides a fallback (auto-deny after 5 minutes).

### 6.2 Webhook (Future)

For remote and headless deployments:

```yaml
approval_channel:
  type: webhook
  webhook_url: https://your-endpoint.com/sanctuary/approve
  webhook_secret: "hmac-sha256-secret"
  timeout_seconds: 600
```

Sanctuary sends an HMAC-signed POST to the webhook URL with the approval request. The endpoint responds with approve/deny. This enables mobile notifications, Slack integrations, and enterprise approval workflows.

### 6.3 Callback (Future)

For programmatic integration:

```typescript
const server = await createSanctuaryServer({
  approvalCallback: async (request: ApprovalRequest) => {
    // Custom approval logic
    return { decision: "approve" };
  },
});
```

---

## 7. New MCP Tools

### 7.1 `sanctuary/principal_policy_view`

Read-only view of the active Principal Policy.

**Input:** `{}`

**Output:**
```json
{
  "version": 1,
  "tier1_operations": ["state_export", "state_import", "identity_rotate", ...],
  "tier2_config": {
    "new_namespace_access": "approve",
    "new_counterparty": "approve",
    "frequency_spike_multiplier": 5,
    ...
  },
  "tier3_operations": ["state_read", "state_write", ...],
  "approval_channel": "stderr",
  "timeout_seconds": 300,
  "auto_deny": true
}
```

**Rationale:** Transparency. The agent (and through it, the user) can see what rules are in effect. A compromised agent gains no advantage from reading the policy — the rules are enforced server-side and cannot be modified through the MCP interface.

### 7.2 `sanctuary/principal_baseline_view`

Read-only view of the current behavioral baseline.

**Input:** `{}`

**Output:**
```json
{
  "known_namespaces": ["agent-memory", "preferences"],
  "known_counterparties": ["did:key:abc123"],
  "session_duration_minutes": 12,
  "tool_call_counts": {
    "state_read": 45,
    "state_write": 12,
    "identity_sign": 3
  },
  "is_first_session": false,
  "baseline_loaded_from": "2026-03-25T14:30:00Z"
}
```

---

## 8. Security Analysis

### 8.1 Attacks Defended

| Attack | Defense |
|--------|---------|
| Prompt injection → bulk state exfiltration | Tier 1 gates `state_export`; Tier 2 detects access to unfamiliar namespaces |
| Prompt injection → fraudulent reputation | Tier 2 detects new counterparty DIDs |
| Prompt injection → signing at scale | Tier 2 rate limiting on `identity_sign` |
| Attacker modifies approval rules | No MCP tool can modify the policy file. Agent plane is separated from principal plane. |
| Attacker suppresses approval prompt | Stderr is outside the MCP protocol. Agent cannot write to stderr in the MCP stdio model. |
| Attacker learns policy to evade detection | Denial responses do not reveal tier, thresholds, or baseline. |
| Low-and-slow baseline manipulation | Baseline changes are audit-logged. Cross-session analysis is possible (post-MVS). |

### 8.2 Residual Risks

| Risk | Mitigation | Status |
|------|-----------|--------|
| Compromised agent reads decrypted state within approved operations | Disclosure policies limit what the agent should share; audit log records all reads | Partial (policy is advisory) |
| User habituates to approvals and auto-approves | Tier 1 list is deliberately short (5 operations); Tier 2 is behavioral, not static | By design |
| Harness does not surface stderr to user | Auto-deny timeout ensures operations fail closed | Fallback |
| Attacker social-engineers user ("Please approve this export for your backup") | Approval prompt includes context showing why the operation was flagged | Partial |

### 8.3 What This Does Not Solve

Principal Policy does not solve prompt injection. No software system does. What it does:

1. **Limits blast radius.** A compromised agent cannot bulk-export state or rotate keys without human approval.
2. **Detects anomalies.** Behavioral deviation triggers human attention at the moment it matters.
3. **Creates accountability.** Every approval decision (approve, deny, timeout) is audit-logged with the operation context.
4. **Fails closed.** Timeouts deny by default. Missing policy files apply the built-in default policy. The system is secure in its default state.

---

## 9. Implementation Plan

### Phase 1: Core (This Build)

1. Principal Policy YAML loader with validation and default generation
2. Behavioral baseline tracker (session profile, persistence)
3. Three-tier approval gate in the tool router
4. Stderr approval channel
5. `principal_policy_view` and `principal_baseline_view` tools
6. Integration tests

### Phase 2: Hardening (Post-MVS)

1. Cross-session anomaly detection
2. Webhook approval channel
3. Callback approval channel
4. Policy file integrity verification (signed by principal)
5. Dashboard visualization of baseline and approval history

---

## 10. Relationship to RFC-0001

This RFC extends but does not modify RFC-0001. All existing tools, security invariants, and architectural decisions remain in effect. Principal Policy adds a new interception layer between the router and tool handlers. The two new tools (`principal_policy_view`, `principal_baseline_view`) are read-only and do not affect the existing tool set.

The Principal Policy system reinforces RFC-0001's design philosophy: the Dual Sovereignty Principle. The human principal controls what the agent can do (principal plane). The agent controls how it does it (agent plane). Neither can override the other.
