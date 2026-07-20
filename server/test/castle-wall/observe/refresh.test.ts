/**
 * Castle Wall Observe -- refresh chokepoint regression tests (sweep finding
 * R3-1, 2026-07-14: the pre-watermark engine re-folded the full retained
 * audit history additively on every refresh, inflating `times_seen` ~N-fold
 * per refresh and resurrecting promoted/discarded candidates from stale
 * history).
 *
 * The two load-bearing pins the fix demands (spawn prompt, item 3):
 *   1. refresh-twice yields IDENTICAL `times_seen` (idempotency);
 *   2. promote-then-refresh does NOT resurrect the promoted destination.
 * Plus the round-3 sweep's empirical-probe scenario as a fixture (fold the
 * same 2-event history through two refreshes: times_seen must stay 2, where
 * the old engine yielded 4).
 *
 * Everything runs against a REAL AuditLog (MemoryStorage) so the watermark
 * rides the real authenticated chain sequence from `streamVerifiedChain`,
 * and a REAL ObserveStore over a real StateStore -- no mocked fold plumbing.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../../src/operational/audit-log.js";
import { StateStore } from "../../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { createIdentity } from "../../../src/core/identity.js";
import { derivePurposeKey } from "../../../src/core/key-derivation.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_SCHEMA_VERSION_V1,
} from "../../../src/castle-wall/constants.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import { ObserveStore } from "../../../src/castle-wall/observe/store.js";
import {
  refreshCandidatesFromAudit,
  candidateCurrentlyAllowed,
  inProcessRefreshLock,
  type RefreshAllowlistRead,
  type RefreshLock,
} from "../../../src/castle-wall/observe/refresh.js";
import {
  candidateKey,
  type CandidateObservation,
  type FoldWatermark,
} from "../../../src/castle-wall/observe/types.js";

interface Harness {
  auditLog: AuditLog;
  store: ObserveStore;
  lock: RefreshLock;
  masterKey: Uint8Array;
  pinnedProducerKeyB64url: string;
  /** Replace the audit log with a brand-new chain on FRESH storage (simulates an audit-store reset/rebuild underneath a persisted observe store). */
  resetAuditChain(): void;
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const producerPriv = ed25519.utils.randomPrivateKey();
const producerPubB64 = toBase64url(ed25519.getPublicKey(producerPriv));
const SIGNED_AT_MS = 1_777_777_777_777;
let nextSignedSeq = 1;

function signedDetailsFor(input: {
  timestamp: string;
  operation: string;
  identityId: string;
  result: "success" | "failure";
  details: Record<string, unknown>;
}): Record<string, unknown> {
  const seq = nextSignedSeq++;
  const body = JSON.stringify({
    timestamp: input.timestamp,
    layer: "l1",
    operation: input.operation,
    identity_id: input.identityId,
    result: input.result,
    details: input.details,
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    producerPriv,
  );
  return {
    ...input.details,
    seq,
    [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
    [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
      CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
    [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
    [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  };
}

function makeHarness(): Harness {
  const stateStorage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(stateStorage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("operator", identityEncKey, "passphrase");
  const store = new ObserveStore(stateStore, {
    identityId: storedIdentity.identity_id,
    encryptedPrivateKey: storedIdentity.encrypted_private_key,
    identityEncryptionKey: identityEncKey,
  });
  const harness: Harness = {
    auditLog: new AuditLog(new MemoryStorage(), masterKey),
    store,
    lock: inProcessRefreshLock(),
    masterKey,
    pinnedProducerKeyB64url: producerPubB64,
    resetAuditChain() {
      harness.auditLog = new AuditLog(new MemoryStorage(), masterKey);
    },
  };
  return harness;
}

/** Append the audit marker `runObserveDiscard` / promote write onto the same chain (the recompute mint-bound; refresh.ts guarantee 3). */
async function appendReviewMarker(
  auditLog: AuditLog,
  operation: "castle_wall_observe_discard" | "castle_wall_observe_promote",
): Promise<void> {
  await auditLog.appendCritical({
    layer: "l1",
    operation,
    identity_id: "operator",
    result: "success",
    details: { discarded_count: 1 },
  });
}

async function appendBlocked(
  auditLog: AuditLog,
  overrides: {
    host?: string | null;
    ip?: string;
    port?: number;
    protocol?: "tcp" | "udp";
    template?: string;
    timestamp?: string;
  } = {},
): Promise<void> {
  const timestamp = overrides.timestamp ?? new Date().toISOString();
  const details = {
    agent: { id: "agent-1", template: overrides.template ?? "claude-code" },
    destination: {
      ...(overrides.host !== undefined
        ? overrides.host === null
          ? {}
          : { host: overrides.host }
        : { host: "api.example.com" }),
      ip: overrides.ip ?? "203.0.113.5",
      port: overrides.port ?? 443,
      protocol: overrides.protocol ?? "tcp",
      hostname_source: "sni",
    },
  };
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "agent-1",
    result: "failure",
    timestamp,
    details: signedDetailsFor({
      timestamp,
      operation: "egress_blocked",
      identityId: "agent-1",
      result: "failure",
      details,
    }),
  });
}

/**
 * Append a Linux daemon FLAT-shape egress_blocked row (#897): flat `dest_*` +
 * `agent_*` + the daemon's unconditional `decision_provenance` fingerprint, as
 * `castle-wall-daemon/src/policy.rs` writes it. The adapter tags these
 * `provenance: "linux_daemon"`, so an `"unknown"` template here is a REAL,
 * suppressible template (unlike the macOS default-resolver sentinel).
 */
async function appendBlockedFlat(
  auditLog: AuditLog,
  overrides: {
    host?: string | null;
    ip?: string;
    port?: number;
    protocol?: "tcp" | "udp";
    template?: string;
  } = {},
): Promise<void> {
  const timestamp = new Date().toISOString();
  const details = {
    agent_id: "agent-1",
    agent_template: overrides.template ?? "claude-code",
    ...(overrides.host === null ? {} : { dest_host: overrides.host ?? "api.example.com" }),
    dest_ip: overrides.ip ?? "203.0.113.5",
    dest_port: overrides.port ?? 443,
    dest_protocol: overrides.protocol ?? "tcp",
    opaque: false,
    decision_provenance: "default_deny",
  };
  await auditLog.appendCritical({
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "agent-1",
    result: "failure",
    timestamp,
    details: signedDetailsFor({
      timestamp,
      operation: "egress_blocked",
      identityId: "agent-1",
      result: "failure",
      details,
    }),
  });
}

function allowRule(overrides: Partial<AllowlistRule["match"]> = {}): AllowlistRule {
  return {
    id: `rule-${JSON.stringify(overrides)}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-07-14T00:00:00.000Z",
    match: { host: ["api.example.com"], port: [443], protocol: "tcp", ...overrides },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
  };
}

function verifiedAllowlist(rules: AllowlistRule[] = []): () => Promise<RefreshAllowlistRead> {
  return async () => ({ status: "ok", rules });
}

async function refresh(harness: Harness, rules: AllowlistRule[] = []) {
  return refreshCandidatesFromAudit({
    auditLog: harness.auditLog,
    store: harness.store,
    readAllowlist: verifiedAllowlist(rules),
    lock: harness.lock,
    now: new Date("2026-07-14T12:00:00.000Z"),
    pinnedProducerKeyB64url: harness.pinnedProducerKeyB64url,
    subjectFortressId: "fortress:test",
  });
}

async function onlyCandidate(store: ObserveStore): Promise<CandidateObservation> {
  const listed = await store.listCandidates();
  expect(listed.size).toBe(1);
  return [...listed.values()][0]!;
}

describe("refresh idempotency (R3-1a: refresh-twice yields identical times_seen)", () => {
  it("the sweep's empirical probe: folding the same 2-event history through two refreshes keeps times_seen at 2, never 4", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);

    const first = await refresh(harness);
    expect(first.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);

    const second = await refresh(harness);
    expect(second.status).toBe("refreshed");
    expect(second.status === "refreshed" && second.folded_events).toBe(0);
    // The old engine rendered 4 here (the round-3 sweep's probe).
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("N extra refreshes over unchanged history leave every count and field byte-identical", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog, { host: "other.example.net", ip: "198.51.100.7", port: 8443 });

    await refresh(harness);
    const after1 = [...(await harness.store.listCandidates()).entries()];
    for (let i = 0; i < 3; i++) await refresh(harness);
    const after4 = [...(await harness.store.listCandidates()).entries()];
    expect(after4).toEqual(after1);
  });

  it("a genuinely NEW observation after a refresh increments the count by exactly one (incremental fold)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);

    await appendBlocked(harness.auditLog);
    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("incremental");
    expect(outcome.status === "refreshed" && outcome.folded_events).toBe(1);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(3);
  });
});

describe("promote/discard non-resurrection (R3-1b)", () => {
  it("promote-then-refresh does NOT resurrect the promoted destination (watermark leg: history is already folded)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);

    // Promote removes the candidate row (what runObservePromote does after a
    // successful promote) and the destination becomes a live allow rule.
    const candidate = await onlyCandidate(harness.store);
    await harness.store.removeCandidate(candidateKey(candidate));

    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status).toBe("refreshed");
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("promoted destination stays out even through a recompute heal (allowlist leg: the belt when the watermark cannot protect)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    // NO prior refresh: no watermark, so this refresh replays FULL history
    // (recompute) -- exactly the path where only the allowlist filter can
    // keep the promoted destination out.
    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("discard-then-refresh does not resurrect; a NEW observation re-mints with a RESTARTED count (the legend's semantics)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(3);

    // Discard drops the row (runObserveDiscard's removeCandidate).
    await harness.store.removeCandidate(candidateKey(await onlyCandidate(harness.store)));
    await refresh(harness);
    expect((await harness.store.listCandidates()).size).toBe(0);

    // One genuinely new denial re-mints the candidate at times_seen 1 -- not
    // at the historical 3 the old engine resurrected.
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });
});

describe("allowlist-aware fold + prune (R3-1b, chokepoint requirement 2)", () => {
  it("an already-allowed destination is never minted, while a not-allowed one still is", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog); // api.example.com -- allowed below
    await appendBlocked(harness.auditLog, { host: "blocked.example.net", ip: "198.51.100.9" });

    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    const remaining = await onlyCandidate(harness.store);
    expect(remaining.host).toBe("blocked.example.net");
  });

  it("a PERSISTED pending candidate whose destination the policy now permits is pruned on the next refresh", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await harness.store.listCandidates()).size).toBe(1);

    // Policy changes out-of-band (e.g. an operator-authored rule, or a
    // promote from another template's row): the next refresh reconciles.
    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.removed_now_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("protocol-aware: a udp allow rule suppresses a udp candidate (the CONNECT-proxy tcp matcher alone would miss it)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { protocol: "udp" });
    const outcome = await refresh(harness, [allowRule({ protocol: "udp" })]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("a udp candidate is NOT suppressed by a tcp-only rule for the same destination", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { protocol: "udp" });
    await refresh(harness, [allowRule({ protocol: "tcp" })]);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("a catch-all-destination allow (port/protocol only) suppresses -- every enforcer treats an absent destination axis as non-constraining", () => {
    const rules = [allowRule({ host: undefined, port: [443] })];
    expect(
      candidateCurrentlyAllowed(rules, {
        agent_id: "agent-1",
        agent_template: "claude-code",
        host: "api.example.com",
        ip: "203.0.113.5",
        port: 443,
        protocol: "tcp",
      }),
    ).toBe(true);
  });

  it("fail-closed toward KEEPING: a host-axis allow never matches a row with a different (even malformed) host", () => {
    const rules = [allowRule()]; // host: ["api.example.com"]
    expect(
      candidateCurrentlyAllowed(rules, {
        agent_id: "agent-1",
        agent_template: "claude-code",
        host: "bad host with spaces",
        ip: "",
        port: 443,
        protocol: "tcp",
      }),
    ).toBe(false);
  });

  it("round-3 HIGH: suppression is SCOPE-AWARE -- a rule promoted for template A neither suppresses nor prunes template B's identical destination", async () => {
    const harness = makeHarness();
    // Template B (ops-runner) is denied reaching the same destination a
    // claude-code-scoped rule allows. The daemon still denies ops-runner
    // (RuleScope::applies_to), so its candidate must be minted and stay.
    await appendBlocked(harness.auditLog, { template: "ops-runner" });
    const outcome = await refresh(harness, [allowRule()]); // scope: template_ids ["claude-code"]
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect(outcome.status === "refreshed" && outcome.removed_now_allowed).toBe(0);
    const row = await onlyCandidate(harness.store);
    expect(row.agent_template).toBe("ops-runner");

    // And it is not pruned on a later refresh either.
    await refresh(harness, [allowRule()]);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-3 HIGH counterpart: an EMPTY scope (all wrapped agents) suppresses any template, matching the daemon's applies_to", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { template: "ops-runner" });
    const allAgentsRule = { ...allowRule(), scope: {} };
    const outcome = await refresh(harness, [allAgentsRule]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("round-3 HIGH counterpart: an agent_ids scope suppresses exactly that instance", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog); // agent-1 / claude-code
    const instanceRule = { ...allowRule(), scope: { agent_ids: ["agent-1"] } };
    const outcome = await refresh(harness, [instanceRule]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("round-4 HIGH: a matching deny BEFORE an allow vetoes suppression (the daemon's first match denies; the flow keeps being recorded)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const denyFirst = [
      { ...allowRule(), id: "deny-first", disposition: "deny" as const },
      allowRule(),
    ];
    const outcome = await refresh(harness, denyFirst);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-6 HIGH: a matching deny AFTER an allow ALSO vetoes suppression (macOS deny-anywhere-wins would drop and record this flow)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const allowFirst = [
      allowRule(),
      { ...allowRule(), id: "deny-second", disposition: "deny" as const },
    ];
    const outcome = await refresh(harness, allowFirst);
    // The Linux daemon (first-match) would allow, but the macOS filter
    // drops on ANY matching deny -- so this flow can still be denied and
    // recorded on a shipped enforcer, and the candidate must stay.
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-6 HIGH: an exact-host allow never suppresses an IP-ONLY observation (OS enforcers cannot match a host axis against a raw-IP flow)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { host: null, ip: "203.0.113.10" });
    const hostRuleForIp = [allowRule({ host: ["203.0.113.10"] })];
    const outcome = await refresh(harness, hostRuleForIp);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);

    // The exact `ip` axis IS the agreed axis for an IP-only row.
    const ipRule = [allowRule({ host: undefined, ip: ["203.0.113.10"] })];
    const again = await refresh(harness, ipRule);
    expect(again.status === "refreshed" && again.removed_now_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("round-4: a first-matching PROMPT disposition does not suppress (the flow is not unconditionally allowed)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const promptFirst = [{ ...allowRule(), disposition: "prompt" as const }];
    await refresh(harness, promptFirst);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-4: a time_window allow is CONDITIONAL and never suppresses", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const windowed = [{ ...allowRule(), time_window: { start: "09:00", end: "17:00" } }];
    await refresh(harness, windowed);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-5 HIGH: a `*.suffix` host_pattern allow never suppresses (the Linux daemon treats that form as a defensive non-match and keeps denying)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog); // api.example.com
    const wildcardPattern = [
      { ...allowRule({ host: undefined, host_pattern: "*.example.com" }) },
    ];
    const outcome = await refresh(harness, wildcardPattern);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-5 HIGH counterpart: a `.suffix` host_pattern allow also never suppresses (the CONNECT-proxy family would not allow that form; suppression requires the enforcer INTERSECTION)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog); // api.example.com
    const dotPattern = [{ ...allowRule({ host: undefined, host_pattern: ".example.com" }) }];
    const outcome = await refresh(harness, dotPattern);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("round-5: an exact-host allow still suppresses (both enforcer legs agree)", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const outcome = await refresh(harness, [allowRule()]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("round-7 HIGH: the 'unknown' sentinel template (macOS default resolver -- may contain unattributed drops no allow can ever permit) is NEVER suppressed or pruned", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog, { template: "unknown" });
    const allAgentsRule = { ...allowRule(), scope: {} };
    const outcome = await refresh(harness, [allAgentsRule]);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(0);
    expect(outcome.status === "refreshed" && outcome.removed_now_allowed).toBe(0);
    expect((await harness.store.listCandidates()).size).toBe(1);
  });

  it("#897 finding 2: a Linux-daemon FLAT 'unknown'-template row IS folded AND IS suppressed by a covering allow rule scoped to 'unknown' (the exemption is macOS-only)", async () => {
    const harness = makeHarness();
    // A real NFQUEUE row: flat shape, agent_template "unknown", provenance linux_daemon.
    await appendBlockedFlat(harness.auditLog, { template: "unknown" });
    // Operator has allowed exactly this destination for template "unknown".
    const unknownScopedAllow = { ...allowRule(), scope: { template_ids: ["unknown"] } };
    const outcome = await refresh(harness, [unknownScopedAllow]);
    // Folded (finding 1) then suppressed (finding 2: NOT blanket-exempted).
    expect(outcome.status === "refreshed" && outcome.folded_events).toBe(1);
    expect(outcome.status === "refreshed" && outcome.suppressed_allowed).toBe(1);
    expect((await harness.store.listCandidates()).size).toBe(0);
  });

  it("#897 finding 2: a macOS default-resolver 'unknown' row and a Linux-daemon 'unknown' row diverge under the SAME allow rule (macOS stays pending, Linux is suppressed)", () => {
    const covering = [{ ...allowRule(), scope: { template_ids: ["unknown"] } }];
    const base = {
      agent_id: "agent-1",
      agent_template: "unknown",
      host: "api.example.com",
      ip: "203.0.113.5",
      port: 443,
      protocol: "tcp" as const,
    };
    // macOS default-resolver sentinel: unattributed, NEVER suppressed.
    expect(candidateCurrentlyAllowed(covering, { ...base, provenance: "macos" })).toBe(false);
    // undefined provenance (legacy/hand-built): conservative -> also exempt.
    expect(candidateCurrentlyAllowed(covering, { ...base, provenance: undefined })).toBe(false);
    // Linux daemon: "unknown" is a real, enforceable template -> suppressible.
    expect(candidateCurrentlyAllowed(covering, { ...base, provenance: "linux_daemon" })).toBe(true);
  });

  it("round-7 HIGH: the deny veto folds Unicode case (macOS caseInsensitiveCompare), not just ASCII", () => {
    const rules = [
      allowRule({ host: ["É.example"] }), // "É.example"
      {
        ...allowRule({ host: ["é.example"] }), // "é.example"
        id: "unicode-deny",
        disposition: "deny" as const,
      },
    ];
    expect(
      candidateCurrentlyAllowed(rules, {
        agent_id: "agent-1",
        agent_template: "claude-code",
        host: "É.example",
        ip: "",
        port: 443,
        protocol: "tcp",
      }),
    ).toBe(false);
  });

  it("an unverifiable allowlist aborts the refresh with NOTHING folded, written, or pruned", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const outcome = await refreshCandidatesFromAudit({
      auditLog: harness.auditLog,
      store: harness.store,
      readAllowlist: async () => ({ status: "unverified", reason: "bad signature" }),
      lock: harness.lock,
      now: new Date("2026-07-14T12:00:00.000Z"),
    });
    expect(outcome).toEqual({ status: "allowlist_unverified", reason: "bad signature" });
    expect((await harness.store.listCandidates()).size).toBe(0);
    expect(await harness.store.getFoldWatermark()).toBeNull();
  });
});

describe("recompute heal (pre-watermark stores and reset chains)", () => {
  it("a store the old additive engine inflated is healed to the true retained-history count on the first watermarkless refresh", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);

    // Simulate the pre-watermark engine having refreshed twice (times_seen
    // doubled to 4), with no watermark record.
    await harness.store.putCandidate({
      agent_id: "agent-1",
      agent_template: "claude-code",
      host: "api.example.com",
      ip: "203.0.113.5",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      times_seen: 4,
      first_seen: "2026-07-14T09:00:00.000Z",
      last_seen: "2026-07-14T09:00:01.000Z",
      would_be_disposition: "denied",
      exfil_risk: false,
    });

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("a candidate whose audit history aged out of retention is NOT dropped by a recompute (unreviewed candidates never vanish silently)", async () => {
    const harness = makeHarness();
    // Store holds a candidate, but the audit chain has no matching entries
    // (fully pruned): the recompute folds nothing and must leave it alone.
    await harness.store.putCandidate({
      agent_id: "agent-1",
      agent_template: "claude-code",
      host: "aged-out.example.com",
      ip: "203.0.113.77",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      times_seen: 5,
      first_seen: "2026-06-01T00:00:00.000Z",
      last_seen: "2026-06-02T00:00:00.000Z",
      would_be_disposition: "denied",
      exfil_risk: false,
    });

    const outcome = await refresh(harness);
    expect(outcome.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(5);
  });

  it("a watermark AHEAD of the surviving chain head (audit store reset) triggers a recompute instead of silently folding nothing forever", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    // A watermark from a previous audit-chain epoch, far past this chain.
    await harness.store.setFoldWatermark({
      folded_through_sequence: 999_999,
      entry_hash: "a-hash-from-a-previous-chain-epoch",
      updated_at: "2026-07-01T00:00:00.000Z",
    });

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);

    // And the watermark now tracks the REAL chain head: a further refresh is
    // an incremental no-op, not another recompute.
    const again = await refresh(harness);
    expect(again.status === "refreshed" && again.mode).toBe("incremental");
    expect(again.status === "refreshed" && again.folded_events).toBe(0);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });

  it("an empty chain refresh is a no-op that does not invent a watermark", async () => {
    const harness = makeHarness();
    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.folded_events).toBe(0);
    expect(await harness.store.getFoldWatermark()).toBeNull();
  });
});

describe("watermark round-trip (store surface)", () => {
  it("persists and re-reads the fold watermark; a malformed/hash-less record reads as absent (recompute, never inflate)", async () => {
    const harness = makeHarness();
    expect(await harness.store.getFoldWatermark()).toBeNull();
    await harness.store.setFoldWatermark({
      folded_through_sequence: 7,
      entry_hash: "abc123",
      updated_at: "2026-07-14T12:00:00.000Z",
    });
    expect(await harness.store.getFoldWatermark()).toEqual({
      folded_through_sequence: 7,
      entry_hash: "abc123",
      updated_at: "2026-07-14T12:00:00.000Z",
    });

    // A record missing the chain-identity hash (or otherwise malformed) is
    // treated as absent: the refresh then recomputes with replace semantics
    // rather than trusting a position it cannot bind to a chain.
    await harness.store.setFoldWatermark({
      folded_through_sequence: 9,
      updated_at: "2026-07-14T12:00:00.000Z",
    } as unknown as FoldWatermark);
    expect(await harness.store.getFoldWatermark()).toBeNull();
  });
});

describe("Codex-gate hardening (two-family gate fix round, 2026-07-14)", () => {
  it("BLOCKER: a concurrent refresh is refused by the lock -- the suffix is folded exactly once, never twice", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);

    const [first, second] = await Promise.all([refresh(harness), refresh(harness)]);
    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual(["refresh_in_progress", "refreshed"]);
    // The winning refresh folded the 2 events exactly once.
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);

    // And the lock is released: a later refresh runs normally.
    const later = await refresh(harness);
    expect(later.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("HIGH-1: a candidate discarded under the OLD engine (no watermark) is NOT resurrected by the migration recompute -- and a genuinely NEW denial re-mints it", async () => {
    const harness = makeHarness();
    // Old-engine history: two denials were folded into a candidate...
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    // ...which the operator then DISCARDED (runObserveDiscard removes the row
    // and appends the discard audit marker onto the same chain). No watermark
    // exists anywhere: this store predates the watermark engine.
    await appendReviewMarker(harness.auditLog, "castle_wall_observe_discard");

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    // The discarded candidate stays gone: the two events precede the chain's
    // last review marker, so the recompute may not mint from them.
    expect((await harness.store.listCandidates()).size).toBe(0);

    // A genuinely NEW denial (after the review marker) re-mints at count 1.
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });

  it("HIGH-1 counterpart: the migration recompute still HEALS a row that is present (not discarded), replacing its inflated count", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    await appendBlocked(harness.auditLog);
    // A review action happened (say, a different destination was discarded),
    // but THIS candidate is still present in the store with an old-engine
    // inflated count. Present rows heal from full retained history.
    await appendReviewMarker(harness.auditLog, "castle_wall_observe_discard");
    await harness.store.putCandidate({
      agent_id: "agent-1",
      agent_template: "claude-code",
      host: "api.example.com",
      ip: "203.0.113.5",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      times_seen: 6,
      first_seen: "2026-07-14T09:00:00.000Z",
      last_seen: "2026-07-14T09:00:01.000Z",
      would_be_disposition: "denied",
      exfil_risk: false,
    });

    const outcome = await refresh(harness);
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("round-2 MED: a watermark whose sequence was pruned off the surviving chain is NOT blindly honored -- it recomputes (identity unverifiable)", async () => {
    const harness = makeHarness();
    // Fake verified-chain source whose surviving suffix starts ABOVE the
    // persisted watermark's sequence (heavy FIFO pruning between refreshes,
    // or a reset chain that regrew and pruned past the old position -- the
    // two are indistinguishable, which is exactly why this must recompute).
    const prunedSource = {
      async streamVerifiedChain(consumer: {
        onEntry: (item: { sequence: number; entry_hash: string; entry: unknown }) => void;
      }): Promise<void> {
        for (const sequence of [6, 7]) {
          const timestamp = `2026-07-14T10:0${sequence}:00.000Z`;
          const details = {
            agent: { id: "agent-1", template: "claude-code" },
            destination: { host: "pruned.example.net", ip: "198.51.100.9", port: 443, protocol: "tcp", hostname_source: "sni" },
          };
          consumer.onEntry({
            sequence,
            entry_hash: `hash-${sequence}`,
            entry: {
              timestamp,
              layer: "l1",
              operation: "egress_blocked",
              identity_id: "agent-1",
              result: "failure",
              details: signedDetailsFor({
                timestamp,
                operation: "egress_blocked",
                identityId: "agent-1",
                result: "failure",
                details,
              }),
            },
          });
        }
      },
    };
    await harness.store.setFoldWatermark({
      folded_through_sequence: 5,
      entry_hash: "hash-from-an-unverifiable-past",
      updated_at: "2026-07-01T00:00:00.000Z",
    });

    const outcome = await refreshCandidatesFromAudit({
      auditLog: prunedSource as never,
      store: harness.store,
      readAllowlist: verifiedAllowlist([]),
      lock: harness.lock,
      now: new Date("2026-07-14T12:00:00.000Z"),
      pinnedProducerKeyB64url: harness.pinnedProducerKeyB64url,
      subjectFortressId: "fortress:test",
    });
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(2);
  });

  it("round-2 LOW: a throwing lock release never masks a completed refresh", async () => {
    const harness = makeHarness();
    await appendBlocked(harness.auditLog);
    const outcome = await refreshCandidatesFromAudit({
      auditLog: harness.auditLog,
      store: harness.store,
      readAllowlist: verifiedAllowlist([]),
      lock: {
        async acquire() {
          return async () => {
            throw new Error("release failed");
          };
        },
      },
      now: new Date("2026-07-14T12:00:00.000Z"),
      pinnedProducerKeyB64url: harness.pinnedProducerKeyB64url,
      subjectFortressId: "fortress:test",
    });
    expect(outcome.status).toBe("refreshed");
    expect((await onlyCandidate(harness.store)).times_seen).toBe(1);
  });

  it("HIGH-2: a RESET audit chain that regrew PAST the old watermark is detected by the hash binding -- recompute, never a silent prefix skip", async () => {
    const harness = makeHarness();
    // Chain epoch 1: one denial, refreshed -> watermark at (seq 1, hash-of-epoch-1).
    await appendBlocked(harness.auditLog);
    await refresh(harness);
    expect((await harness.store.listCandidates()).size).toBe(1);
    const watermark = await harness.store.getFoldWatermark();
    expect(watermark).not.toBeNull();

    // The audit store is reset/rebuilt and the NEW chain regrows past the old
    // watermark's sequence before the next refresh.
    harness.resetAuditChain();
    await appendBlocked(harness.auditLog, { host: "reset-a.example.net", ip: "198.51.100.1" });
    await appendBlocked(harness.auditLog, { host: "reset-b.example.net", ip: "198.51.100.2" });
    await appendBlocked(harness.auditLog, { host: "reset-c.example.net", ip: "198.51.100.3" });

    const outcome = await refresh(harness);
    // A bare-sequence watermark would have called this "incremental" and
    // folded only entries 2..3, permanently skipping the new chain's entry 1.
    expect(outcome.status === "refreshed" && outcome.mode).toBe("recompute");
    const hosts = [...(await harness.store.listCandidates()).values()].map((c) => c.host).sort();
    expect(hosts).toContain("reset-a.example.net");
    expect(hosts).toContain("reset-b.example.net");
    expect(hosts).toContain("reset-c.example.net");

    // The watermark now binds to the NEW chain: the next refresh is a plain
    // incremental no-op.
    const again = await refresh(harness);
    expect(again.status === "refreshed" && again.mode).toBe("incremental");
    expect(again.status === "refreshed" && again.folded_events).toBe(0);
  });
});
