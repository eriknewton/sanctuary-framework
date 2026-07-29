/**
 * Sanctuary Drill Harness — Folded-Board Approve/Deny e2e ("Item B").
 *
 * WHY THIS EXISTS
 * ---------------
 * The 2026-06-22 Erik-present Mini1 drill ("Item B") could not run the
 * folded-board approve/deny flow LIVE because no faithful test harness
 * existed. Approve/deny on the posture board only becomes decision-capable
 * (`decision_capable:true`) inside the REAL wrapped-agent MCP server boot:
 * a NON-standalone `DashboardApprovalChannel` wired via `setDependencies`
 * (server/src/index.ts:847). The other board boots (standalone
 * `sanctuary dashboard`, the `wrap` per-call dashboard, a bare channel)
 * all serve the approval area HONESTLY read-only (`decision_capable:false`).
 * That read-only honesty is the fold's safety invariant holding correctly,
 * but it means a faithful e2e must stand up the full co-located wiring and
 * drive a real Tier-1-gated MCP tool through the real approval gate. A
 * bare/channel-direct shortcut would test the WRONG surface (legacy board)
 * or bypass the gate that writes the signed audit, and report a false pass.
 *
 * WHAT THIS HARNESS BOOTS (the load-bearing wiring from index.ts, verbatim)
 * ------------------------------------------------------------------------
 *   real MemoryStorage (isolated, never ~/.sanctuary)
 *     -> real AuditLog (Ed25519-checkpointed, hash-chained at-rest)
 *     -> real DashboardApprovalChannel (co-located => decision_capable:true)
 *        + setDependencies()  (the index.ts:847 binding)
 *        + setAutoAuthLocalhost(true) (the real co-located boot ergonomics)
 *        + setApprovalAggregator() (the index.ts:1099 binding)
 *     -> real ApprovalAggregator
 *     -> real AggregatorBackedChannel wrapping the dashboard channel
 *        (index.ts:1076), redirect resolver reads the live policy
 *     -> real ApprovalGate (index.ts:1084) with the aggregator ingest
 *        callback (index.ts:1095)
 *     -> real MCP Server via createServer([state_export tool], { gate })
 *        (router.ts:83 — the SAME factory index.ts:1580 uses)
 *     -> real MCP Client over the MCP SDK's InMemoryTransport linked pair
 *        (the repo's own MCP plumbing; a faithful minimal client, no hand-
 *        rolled transport)
 *
 * The Tier-1 tool is the GENUINE `state_export` ToolDefinition produced by
 * `createCognitiveTools` (createL1Tools) — `state_export` is a canonical
 * `tier1_always_approve` operation (loader.ts DEFAULT_POLICY). The gate
 * classifies by tool NAME and fires BEFORE the handler body, so the
 * enforcement chokepoint under test (Tier-1 classification -> channel
 * round-trip -> signed-audit write) is exercised on the real tool; the
 * handler body is irrelevant to the approval surface and is never reached
 * on a deny.
 *
 * WHAT IS AUTOMATED HERE
 * ----------------------
 * Everything except the literal human mouse-click. The harness drives the
 * decision over real HTTP (POST /api/approve/:id and /api/deny/:id, and the
 * replace-mode /api/approval-inbox/:id/{approve,deny}) carrying the operator
 * bearer token — which is EXACTLY what the browser button does. It asserts:
 *   1. The co-located board reports decision_capable:true (not the read-only
 *      standalone surface), and the standalone board reports false.
 *   2. A real Tier-1 MCP tool call lands a genuine pending in the folded
 *      board's co-located inbox (visible at /api/pending).
 *   3. BOTH default-config and `replace`-config route a decision with no 404.
 *   4. A token-carrying APPROVE returns the correct gate result AND a
 *      gate-written signed-audit entry (`gate_approve:state_export`) lands in
 *      the tamper-evident hash chain with zero integrity findings.
 *   5. A token-carrying DENY returns the correct gate result AND a
 *      gate-written signed-audit entry (`gate_deny:state_export`).
 *   6. The session cookie minted by /api/session is `SameSite=Lax` (C1: lets a
 *      cross-host Fleet "Open Console" top-level navigation reuse a still-valid
 *      session; Lax still withholds the cookie on cross-site POSTs, so the
 *      approval-decision route stays CSRF-safe — proven by step 7's token lock).
 *   7. A TOKENLESS co-resident loopback attempt on the decision route is
 *      REJECTED (401) — a co-resident agent cannot self-approve, even though
 *      loopback auto-auth is enabled (requireToken:true defeats the shortcut).
 *   8. The approve/deny assertions repeat N>=3 (deterministic) so the same
 *      harness underpins a repeatable Erik-present manual drill.
 *
 * RESIDUAL MANUAL STEP (cannot be automated in CI)
 * ------------------------------------------------
 * The literal human click on the rendered board button is the ONLY step this
 * harness substitutes with a token-carrying programmatic POST. The POST hits
 * the identical route the button hits and carries the identical operator
 * credential, so every server-side invariant is proven; what is NOT proven
 * by CI is that a human, at a real signed+notarized build's GUI, sees the
 * pending card render and the button work end-to-end. That last mile is the
 * Erik-present manual drill this harness is designed to underpin: boot a real
 * fortress, trigger a Tier-1 op, approve one / deny one AT the board, N>=3,
 * and confirm the same gate-result + gate-written signed audit + SameSite
 * cookie + token-lock this harness asserts programmatically.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { ApprovalAggregator } from "../../src/principal-policy/approval-aggregator.js";
import type { ApprovalGateEvent } from "../../src/principal-policy/approval-aggregator.js";
import {
  AggregatorBackedChannel,
  makeRedirectResolverFromPolicySupplier,
} from "../../src/principal-policy/channels/aggregator-backed-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";

import { createServer } from "../../src/router.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

// ──────────────────────────────────────────────────────────────────────
// Fixture: stand up the REAL co-located wiring on an isolated state dir.
// ──────────────────────────────────────────────────────────────────────

const AUTH_TOKEN = "drill-operator-token-" + "0".repeat(32);
const FORTRESS_ID = "fortress_itemb_drill";
const IDENTITY_ID = "identity_itemb_drill";

interface FoldedBoardHarness {
  channel: DashboardApprovalChannel;
  gate: ApprovalGate;
  aggregator: ApprovalAggregator;
  auditLog: AuditLog;
  client: Client;
  port: number;
  /** Mutable so a test can flip approval_redirect to `replace` mid-life. */
  policy: PrincipalPolicy;
  stop: () => Promise<void>;
}

/**
 * Build the folded-board harness. `redirectMode` selects the approval-
 * routing config under test:
 *   - "default"  => approval_redirect disabled; decisions route to the
 *                   legacy co-located inbox (POST /api/approve|deny/:id).
 *   - "replace"  => approval_redirect enabled, mode "replace"; decisions
 *                   route to the cross-harness aggregator inbox
 *                   (POST /api/approval-inbox/:id/{approve,deny}).
 *
 * The redirect resolver reads `policy` live on every approval (exactly as
 * index.ts wires it via makeRedirectResolverFromPolicySupplier), so the
 * mode is set by the policy object the harness owns.
 */
async function makeHarness(
  redirectMode: "default" | "replace",
): Promise<FoldedBoardHarness> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);

  // Live policy object the redirect resolver reads on every approval.
  const policy: PrincipalPolicy = {
    ...DEFAULT_POLICY,
    approval_channel: {
      ...DEFAULT_POLICY.approval_channel,
      // Short timeout keeps any unresolved fail-closed path fast; every
      // assertion resolves the pending well before this fires.
      timeout_seconds: 5,
    },
    ...(redirectMode === "replace"
      ? { approval_redirect: { enabled: true, mode: "replace" as const } }
      : {}),
  };

  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();

  // Genuine Tier-1 tool: the real `state_export` ToolDefinition. It is a
  // canonical `tier1_always_approve` op, so the gate classifies it Tier-1
  // and routes it through the approval channel before its handler runs.
  const stateStore = new StateStore(storage, masterKey);
  const { tools } = createCognitiveTools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog,
  );
  const rawStateExportTool = tools.find((t) => t.name === "state_export");
  if (!rawStateExportTool) {
    throw new Error("harness setup: real state_export tool not found");
  }
  // index.ts classifies `state_export` as a "write" tool before registering it
  // (classifyMcpTools / WRITE_MCP_TOOLS). createServer's assertToolClasses
  // requires the class, so stamp the SAME class the real boot assigns. This
  // is the genuine classification, not a test shortcut.
  const stateExportTool = { ...rawStateExportTool, tool_class: "write" as const };

  // The real ApprovalAggregator (the folded board's cross-harness inbox).
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
  });

  let channel!: DashboardApprovalChannel;
  let port!: number;

  await bindWithRetry(async () => {
    port = randomTestPort();
    channel = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: policy.approval_channel.timeout_seconds,
      auth_token: AUTH_TOKEN,
      auto_open: false,
    });
    try {
      await channel.start();
    } catch (err) {
      // bindWithRetry retries on EADDRINUSE; surface other errors.
      await channel.stop().catch(() => {});
      throw err;
    }
  });

  // The index.ts:856 binding that makes the board co-located + decision-
  // capable. NOT calling setStandaloneMode(true) is exactly what the real
  // wrapped-agent boot does; standalone mode is the read-only path.
  channel.setDependencies({
    policy,
    baseline,
    auditLog,
  });
  // The real co-located boot enables loopback auto-auth ergonomics (the
  // browser opens pre-authenticated). The decision routes still demand the
  // token via requireToken:true — which assertion 7 proves.
  channel.setAutoAuthLocalhost(true);
  // index.ts:1099 — bind the aggregator so /api/approval-inbox/* routes are
  // live (the replace-mode decision surface).
  channel.setApprovalAggregator(aggregator);

  // index.ts:1076 — wrap the dashboard channel with the aggregator-backed
  // channel; the redirect resolver reads the live policy each call.
  const wrappedChannel = new AggregatorBackedChannel({
    underlying: channel,
    aggregator,
    resolveRedirect: makeRedirectResolverFromPolicySupplier(() => policy),
    replaceModeTimeoutMs: policy.approval_channel.timeout_seconds * 1000,
  });

  // index.ts:1084 — the real gate over the wrapped channel + real audit log.
  const gate = new ApprovalGate(
    policy,
    baseline,
    wrappedChannel,
    auditLog,
  );
  // index.ts:1095 — the gate's lifecycle events feed the aggregator, which
  // is what populates the folded board's inbox card in replace mode.
  gate.setApprovalEventCallback((event) => {
    void aggregator.ingest(event as unknown as ApprovalGateEvent);
  });

  // router.ts:83 — the SAME MCP server factory index.ts:1580 uses, with the
  // gate wired in. Every tool call routes through gate.evaluate().
  const server = createServer([stateExportTool], { gate, auditLog });

  // The repo's own MCP plumbing: a faithful minimal client over the SDK's
  // in-memory linked transport pair. No hand-rolled transport.
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "itemb-drill-client", version: "1.0.0" });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return {
    channel,
    gate,
    aggregator,
    auditLog,
    client,
    port,
    policy,
    stop: async () => {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
      await channel.stop().catch(() => {});
    },
  };
}

/**
 * Fire the genuine Tier-1 `state_export` MCP tool call through the real MCP
 * client. The call BLOCKS in the gate's approval round-trip until a decision
 * is posted to the board, so this returns the in-flight promise; the caller
 * resolves it by posting a decision and then awaits.
 *
 * A unique namespace per call gives each request a distinct args-binding so
 * concurrent/looped requests never collapse into one inbox card.
 */
function fireTier1ToolCall(
  client: Client,
  namespace: string,
): Promise<unknown> {
  return client.callTool({
    name: "state_export",
    arguments: { namespace, format: "json" },
  });
}

/** Read the co-located pending list off the live board (token-authed GET). */
async function fetchPending(
  port: number,
): Promise<Array<{ id: string; operation: string }>> {
  const res = await fetch(`http://127.0.0.1:${port}/api/pending`, {
    headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Array<{ id: string; operation: string }>;
}

/** Read the aggregator inbox (replace-mode card list) off the live board. */
async function fetchApprovalInbox(
  port: number,
): Promise<Array<{ aggregator_id: string }>> {
  const res = await fetch(`http://127.0.0.1:${port}/api/approval-inbox`, {
    headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    ok: boolean;
    data: { entries: Array<{ aggregator_id: string }> };
  };
  return body.data.entries;
}

/** Poll a producer until it yields a non-empty list (bounded). */
async function waitForNonEmpty<T>(
  producer: () => Promise<T[]>,
  label: string,
  timeoutMs = 4000,
): Promise<T[]> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const list = await producer();
    if (list.length > 0) return list;
    if (Date.now() > deadline) {
      throw new Error(`waitForNonEmpty timed out waiting for ${label}`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

/**
 * Count gate-written signed-audit entries for an operation+decision, and
 * assert the at-rest hash chain has ZERO integrity findings. The audit
 * chain is the cryptographic signing mechanism: each entry is hash-chained
 * (prev_hash/entry_hash) and the chain is Ed25519-checkpointed. A populated
 * `gate_<decision>:<op>` entry with no integrity findings is the
 * "gate-written signed audit entry" the drill must prove.
 */
async function assertGateAudit(
  auditLog: AuditLog,
  decision: "approve" | "deny",
  operation: string,
): Promise<void> {
  const { entries, integrity_findings } = await auditLog.query({ limit: 1000 });
  expect(integrity_findings).toEqual([]);
  const match = entries.filter(
    (e) => e.operation === `gate_${decision}:${operation}`,
  );
  expect(match.length).toBeGreaterThanOrEqual(1);
  // The gate stamps the decision result onto the entry: approve=success,
  // deny=failure. This proves the audit reflects the ACTUAL decision.
  expect(match[match.length - 1]!.result).toBe(
    decision === "approve" ? "success" : "failure",
  );
}

// ──────────────────────────────────────────────────────────────────────
// Drill: decision-capability honesty (co-located vs standalone).
// ──────────────────────────────────────────────────────────────────────

describe("Item B drill — folded board decision-capability honesty", () => {
  it("co-located board reports decision_capable:true; standalone reports false", async () => {
    const h = await makeHarness("default");
    try {
      const res = await fetch(`http://127.0.0.1:${h.port}/api/status`, {
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);
      const status = (await res.json()) as {
        standalone_mode: boolean;
        decision_capable: boolean;
      };
      // The board this harness boots is the REAL co-located surface.
      expect(status.standalone_mode).toBe(false);
      expect(status.decision_capable).toBe(true);
    } finally {
      await h.stop();
    }

    // Contrast: a standalone-mode board is honestly read-only. Same class,
    // setStandaloneMode(true) is the only difference — proving the harness
    // is on the decision-capable side, not the legacy read-only surface.
    await bindWithRetry(async () => {
      const port = randomTestPort();
      const standalone = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 5,
        auth_token: AUTH_TOKEN,
        auto_open: false,
      });
      try {
        await standalone.start();
        standalone.setStandaloneMode(true);
        const res = await fetch(`http://127.0.0.1:${port}/api/status`, {
          headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        });
        const status = (await res.json()) as {
          standalone_mode: boolean;
          decision_capable: boolean;
        };
        expect(status.standalone_mode).toBe(true);
        expect(status.decision_capable).toBe(false);
      } finally {
        await standalone.stop().catch(() => {});
      }
    });
  });
});

// ──────────────────────────────────────────────────────────────────────
// Drill: real Tier-1 MCP tool call lands a pending in the folded board.
// ──────────────────────────────────────────────────────────────────────

describe("Item B drill — real Tier-1 MCP call -> folded board inbox", () => {
  let h: FoldedBoardHarness;

  afterEach(async () => {
    if (h) await h.stop();
  });

  it("a real Tier-1 state_export call lands a pending in the co-located inbox (default mode)", async () => {
    h = await makeHarness("default");
    const callPromise = fireTier1ToolCall(h.client, "drill-pending-default");
    try {
      const pending = await waitForNonEmpty(
        () => fetchPending(h.port),
        "co-located pending",
      );
      expect(pending.some((p) => p.operation === "state_export")).toBe(true);
    } finally {
      // Resolve the in-flight call so the test does not leak a hung promise.
      const pending = await fetchPending(h.port);
      if (pending[0]) {
        await fetch(`http://127.0.0.1:${h.port}/api/deny/${pending[0].id}`, {
          method: "POST",
          headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        });
      }
      await callPromise.catch(() => {});
    }
  });

  it("a real Tier-1 state_export call lands a card in the aggregator inbox (replace mode)", async () => {
    h = await makeHarness("replace");
    const callPromise = fireTier1ToolCall(h.client, "drill-pending-replace");
    try {
      const inbox = await waitForNonEmpty(
        () => fetchApprovalInbox(h.port),
        "aggregator inbox card",
      );
      expect(inbox.length).toBeGreaterThanOrEqual(1);
    } finally {
      const inbox = await fetchApprovalInbox(h.port);
      if (inbox[0]) {
        await fetch(
          `http://127.0.0.1:${h.port}/api/approval-inbox/${inbox[0].aggregator_id}/deny`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
          },
        );
      }
      await callPromise.catch(() => {});
    }
  });
});

// ──────────────────────────────────────────────────────────────────────
// Drill: token-locked approve/deny over real HTTP, both modes, N>=3.
// Each iteration mirrors one Erik-present manual click at the board.
// ──────────────────────────────────────────────────────────────────────

const DRILL_ROUNDS = 3;

describe("Item B drill — token-locked approve/deny, default mode (legacy co-located inbox)", () => {
  let h: FoldedBoardHarness;

  beforeEach(async () => {
    h = await makeHarness("default");
  });
  afterEach(async () => {
    if (h) await h.stop();
  });

  for (let round = 1; round <= DRILL_ROUNDS; round++) {
    it(`round ${round}: APPROVE resolves the gate to allowed + writes a signed gate_approve audit`, async () => {
      const callPromise = fireTier1ToolCall(
        h.client,
        `drill-approve-default-${round}`,
      );
      const pending = await waitForNonEmpty(
        () => fetchPending(h.port),
        "pending",
      );
      const id = pending[0]!.id;

      // The token-carrying POST is what the browser button does.
      const res = await fetch(`http://127.0.0.1:${h.port}/api/approve/${id}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);

      // The MCP tool call returns; the gate allowed the op (the genuine
      // state_export handler runs after approval — its body is not the
      // surface under test, only the gate decision is).
      const result = (await callPromise) as { content: unknown[] };
      expect(result.content).toBeTruthy();

      await assertGateAudit(h.auditLog, "approve", "state_export");
    });

    it(`round ${round}: DENY resolves the gate to denied + writes a signed gate_deny audit`, async () => {
      const callPromise = fireTier1ToolCall(
        h.client,
        `drill-deny-default-${round}`,
      );
      const pending = await waitForNonEmpty(
        () => fetchPending(h.port),
        "pending",
      );
      const id = pending[0]!.id;

      const res = await fetch(`http://127.0.0.1:${h.port}/api/deny/${id}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      });
      expect(res.status).toBe(200);

      const result = (await callPromise) as { content: unknown[]; isError?: boolean };
      // A denied Tier-1 op returns the fixed coarse denial to the agent.
      expect(result.content).toBeTruthy();

      await assertGateAudit(h.auditLog, "deny", "state_export");
    });
  }
});

describe("Item B drill — token-locked approve/deny, replace mode (aggregator inbox)", () => {
  let h: FoldedBoardHarness;

  beforeEach(async () => {
    h = await makeHarness("replace");
  });
  afterEach(async () => {
    if (h) await h.stop();
  });

  for (let round = 1; round <= DRILL_ROUNDS; round++) {
    it(`round ${round}: APPROVE via aggregator inbox resolves the gate to allowed`, async () => {
      const callPromise = fireTier1ToolCall(
        h.client,
        `drill-approve-replace-${round}`,
      );
      const inbox = await waitForNonEmpty(
        () => fetchApprovalInbox(h.port),
        "aggregator card",
      );
      const id = inbox[0]!.aggregator_id;

      const res = await fetch(
        `http://127.0.0.1:${h.port}/api/approval-inbox/${id}/approve`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        },
      );
      // Must route with no 404 (chooseApprovalRows posts to whichever inbox
      // holds the request — the R2 invariant the drill writeup calls out).
      expect(res.status).not.toBe(404);
      expect(res.status).toBe(200);

      const result = (await callPromise) as { content: unknown[] };
      expect(result.content).toBeTruthy();

      await assertGateAudit(h.auditLog, "approve", "state_export");
    });

    it(`round ${round}: DENY via aggregator inbox resolves the gate to denied`, async () => {
      const callPromise = fireTier1ToolCall(
        h.client,
        `drill-deny-replace-${round}`,
      );
      const inbox = await waitForNonEmpty(
        () => fetchApprovalInbox(h.port),
        "aggregator card",
      );
      const id = inbox[0]!.aggregator_id;

      const res = await fetch(
        `http://127.0.0.1:${h.port}/api/approval-inbox/${id}/deny`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
        },
      );
      expect(res.status).not.toBe(404);
      expect(res.status).toBe(200);

      const result = (await callPromise) as { content: unknown[] };
      expect(result.content).toBeTruthy();

      await assertGateAudit(h.auditLog, "deny", "state_export");
    });
  }
});

// ──────────────────────────────────────────────────────────────────────
// Drill: a co-resident agent cannot self-approve. The decision routes are
// token-locked even on loopback with auto-auth enabled (requireToken:true).
// ──────────────────────────────────────────────────────────────────────

describe("Item B drill — co-resident agent cannot self-approve (token-locked decisions)", () => {
  let h: FoldedBoardHarness;

  afterEach(async () => {
    if (h) await h.stop();
  });

  it("tokenless loopback POST to /api/approve/:id is rejected (default mode)", async () => {
    h = await makeHarness("default");
    const callPromise = fireTier1ToolCall(h.client, "drill-selfapprove-default");
    const pending = await waitForNonEmpty(() => fetchPending(h.port), "pending");
    const id = pending[0]!.id;

    // Loopback request WITHOUT the operator token — the co-resident-agent
    // self-approval attempt. Auto-auth is ON, but requireToken:true on the
    // decision route defeats the loopback shortcut.
    const noToken = await fetch(`http://127.0.0.1:${h.port}/api/approve/${id}`, {
      method: "POST",
    });
    expect(noToken.status).toBe(401);

    // The pending is still pending (the tokenless attempt changed nothing).
    const stillPending = await fetchPending(h.port);
    expect(stillPending.some((p) => p.id === id)).toBe(true);

    // Clean up: the OPERATOR (with token) denies, releasing the call.
    const denied = await fetch(`http://127.0.0.1:${h.port}/api/deny/${id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(denied.status).toBe(200);
    await callPromise.catch(() => {});
  });

  it("tokenless loopback POST to /api/approval-inbox/:id/approve is rejected (replace mode)", async () => {
    h = await makeHarness("replace");
    const callPromise = fireTier1ToolCall(h.client, "drill-selfapprove-replace");
    const inbox = await waitForNonEmpty(
      () => fetchApprovalInbox(h.port),
      "aggregator card",
    );
    const id = inbox[0]!.aggregator_id;

    const noToken = await fetch(
      `http://127.0.0.1:${h.port}/api/approval-inbox/${id}/approve`,
      { method: "POST" },
    );
    expect(noToken.status).toBe(401);

    // Clean up via the token-carrying operator path.
    const denied = await fetch(
      `http://127.0.0.1:${h.port}/api/approval-inbox/${id}/deny`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
      },
    );
    expect(denied.status).toBe(200);
    await callPromise.catch(() => {});
  });
});

// ──────────────────────────────────────────────────────────────────────
// Drill: the operator session cookie is SameSite=Lax (R3 invariant).
// C1: Lax (not Strict) lets a cross-host Fleet "Open Console" top-level
// navigation reuse a still-valid session without re-prompting; Lax still
// withholds the cookie on cross-site POSTs, so the approval-decision route
// stays CSRF-safe (the token lock proven separately above is the teeth).
// ──────────────────────────────────────────────────────────────────────

describe("Item B drill — session cookie is SameSite=Lax", () => {
  let h: FoldedBoardHarness;

  afterEach(async () => {
    if (h) await h.stop();
  });

  it("POST /auth/session mints a SameSite=Lax session cookie", async () => {
    h = await makeHarness("default");
    const res = await fetch(`http://127.0.0.1:${h.port}/auth/session`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toContain("sanctuary_session=");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).not.toContain("SameSite=Strict");
  });
});
