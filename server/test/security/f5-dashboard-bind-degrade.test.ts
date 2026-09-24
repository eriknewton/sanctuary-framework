/**
 * F5 (dashboard-bind-degrade, 2026-09-24 dogfood finding): a second Claude
 * Code session starting the daily-fortress Sanctuary MCP server (stdio boot,
 * `src/index.ts`) while another session's server already holds the embedded
 * dashboard port hit EADDRINUSE and the WHOLE MCP server exited — the second
 * session had no Sanctuary tools at all.
 *
 * Wired-consumer test (AGENTS rule 4): drives the real stdio boot object
 * graph (`createSanctuaryServer`), with the dashboard port PRE-BOUND by this
 * test on an ephemeral port, and asserts:
 *   1. Boot completes (does not reject, does not exit).
 *   2. A Tier-1 gated tool call (`state_delete`) is denied with the SAME
 *      generic denial the gate already uses (AGENTS MUST-NEVER #7: no rule
 *      or tier revealed) — never a hang, never an auto-approve.
 *   3. An ungated Tier-3 tool call (`state_list`) still succeeds.
 *   4. A `dashboard_bind_unavailable` audit row is recorded, with the port
 *      number only (no secret, key, or path).
 *
 * Claim under test: "when the dashboard cannot bind, no approval-gated
 * operation can succeed in that process." The trace of every approval-channel
 * consumer this test exercises: `selectApprovalChannelByPolicy`
 * (channel-selection.ts, dashboard case) constructs the real
 * `DashboardApprovalChannel` and starts it with `exitCleanOnAddrInUse: true`
 * -> `index.ts`'s dashboard case checks `dashboard.addrInUse()` and swaps the
 * function-scoped `approvalChannel` to a `StderrApprovalChannel` BEFORE it is
 * captured by `AggregatorBackedChannel({ underlying: approvalChannel })` ->
 * that wrapper is the sole `channel` the one `ApprovalGate` instance holds ->
 * `router.ts`'s `CallToolRequestSchema` handler is the one dispatch site that
 * calls `gate.evaluate` for every tool call. No cached channel reference is
 * captured before the swap (the wrapper is constructed after it), and no
 * second `ApprovalGate` or approval-channel instance exists in the boot
 * graph.
 */

import { createServer, type Server as NetServer } from "node:net";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createSanctuaryServer } from "../../src/index.js";
import {
  StderrApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";
import { createTempFortress, type TempFortress } from "../helpers/temp-fortress.js";
import { bindWithRetry, randomTestPort } from "../util/port-collision-retry.js";

async function callTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {},
) {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, Function> }
  )._requestHandlers.get("tools/call");
  if (!handler) throw new Error("tools/call handler not registered");
  return await handler(
    { method: "tools/call" as const, params: { name, arguments: args } },
    {},
  );
}

function parseToolResult(result: {
  content: Array<{ type: string; text: string }>;
}) {
  return JSON.parse(result.content[0]!.text);
}

const DASHBOARD_ENV_KEYS = [
  "SANCTUARY_DASHBOARD_HOST",
  "SANCTUARY_DASHBOARD_PORT",
] as const;

describe("F5: a busy embedded-dashboard port degrades the MCP stdio boot instead of crashing it", () => {
  let fortress: TempFortress;
  let occupyingServer: NetServer;
  let dashboardPort: number;
  let restoreEnv: Map<string, string | undefined>;
  let boot: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;

  beforeEach(async () => {
    fortress = await createTempFortress("sanctuary-f5-dashbind");
    restoreEnv = new Map(DASHBOARD_ENV_KEYS.map((key) => [key, process.env[key]]));

    await mkdir(fortress.storagePath, { recursive: true, mode: 0o700 });
    await writeFile(
      join(fortress.storagePath, "principal-policy.yaml"),
      generateDefaultPolicyYaml().replace("type: stderr", "type: dashboard"),
      { mode: 0o600 },
    );

    // Occupy an ephemeral port BEFORE Sanctuary boots, simulating a second
    // session's dashboard already owning it. bindWithRetry only protects this
    // setup bind against an unrelated port collision (a third process); the
    // Sanctuary boot below is deliberately pointed at the SAME port and must
    // NOT retry -- a genuine EADDRINUSE is exactly what this test drives.
    await bindWithRetry(async () => {
      const port = randomTestPort();
      await new Promise<void>((resolve, reject) => {
        const srv = createServer();
        srv.once("error", reject);
        srv.listen(port, "127.0.0.1", () => {
          srv.off("error", reject);
          resolve();
        });
        occupyingServer = srv;
      });
      dashboardPort = port;
    });

    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    process.env.SANCTUARY_DASHBOARD_PORT = String(dashboardPort);
  });

  afterEach(async () => {
    await boot?.cleanup().catch(() => undefined);
    boot = undefined;
    await new Promise<void>((resolve) => occupyingServer.close(() => resolve()));
    for (const [key, value] of restoreEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fortress.cleanup();
  });

  it("boots with MCP tools live, denies a Tier-1 tool generically, allows a Tier-3 tool, and audits the degrade", async () => {
    // 1. Boot completes -- does not reject, does not exit the process.
    boot = await createSanctuaryServer();
    expect(boot.policy.approval_channel.type).toBe("dashboard");

    // 2. A Tier-1 gated call is denied with the SAME fixed, generic denial
    // shape the gate already returns for every policy-denied call (no rule,
    // tier, or "dashboard was busy" detail leaked to the agent -- MUST-NEVER
    // #7). It must NOT hang waiting on a dead dashboard listener.
    const denied = await callTool(boot.server, "state_delete", {
      namespace: "f5-test-ns",
      key: "f5-test-key",
    });
    expect(denied.isError).toBe(true);
    const deniedPayload = parseToolResult(denied);
    expect(deniedPayload.denied).toBe(true);

    // 3. An ungated (Tier-3) call still succeeds: the degrade is scoped to
    // approval-gated operations, not a blanket refusal. `identity_list`
    // (not `state_list`) is used deliberately: it carries no `namespace`
    // argument, so it cannot also trip the SEPARATE new-namespace-access
    // Tier-2 anomaly check (`gate.ts`'s `detectAnomaly`) on first access,
    // which would confound this assertion with a different gate path.
    const allowed = await callTool(boot.server, "identity_list", {});
    expect(allowed.isError).toBeFalsy();
    const allowedPayload = parseToolResult(allowed);
    expect(Array.isArray(allowedPayload.identities)).toBe(true);

    // 4. The degrade is audited: one dashboard_bind_unavailable row naming
    // the port only.
    const auditResult = await boot.auditLog.query({
      operation_type: "dashboard_bind_unavailable",
    });
    expect(auditResult.entries).toHaveLength(1);
    expect(auditResult.entries[0]!.result).toBe("failure");
    expect(auditResult.entries[0]!.details).toEqual({ port: dashboardPort });
  });
});

describe("F5 unit: StderrApprovalChannel is the deny-all channel the degrade swap constructs", () => {
  // The degrade site constructs `new StderrApprovalChannel(policy.approval_channel)`
  // -- a config whose `type` field is "dashboard" (the policy that selected the
  // now-unavailable dashboard channel), not "stderr". StderrApprovalChannel's
  // constructor and requestApproval() never read `config.type` (see
  // approval-channel.ts), so this must deny unconditionally regardless of what
  // config object it is handed. Existing SEC-016 coverage only ever
  // constructs it with a `{type: "stderr", ...}` config; this is the shape
  // the F5 swap site actually uses.
  const DASHBOARD_TYPED_CONFIG = {
    type: "dashboard" as const,
    timeout_seconds: 300,
  };

  const REQUESTS: ApprovalRequest[] = [
    {
      operation: "state_delete",
      tier: 1,
      reason: "F5 unit test — Tier 1 request",
      context: { namespace: "test" },
      timestamp: new Date().toISOString(),
    },
    {
      operation: "state_read",
      tier: 2,
      reason: "F5 unit test — Tier 2 anomaly request",
      context: { namespace: "test", anomaly: "frequency_spike" },
      timestamp: new Date().toISOString(),
    },
    {
      operation: "identity_rotate",
      tier: 1,
      reason: "F5 unit test — a second, differently-shaped Tier 1 request",
      context: {},
      timestamp: new Date().toISOString(),
    },
  ];

  it("denies every request type it can receive, even constructed with a dashboard-typed config", async () => {
    const channel = new StderrApprovalChannel(
      DASHBOARD_TYPED_CONFIG as unknown as ConstructorParameters<
        typeof StderrApprovalChannel
      >[0],
    );
    for (const request of REQUESTS) {
      const response = await channel.requestApproval(request);
      expect(response.decision).toBe("deny");
      expect(response.decided_by).toBe("stderr:non-interactive");
    }
  });
});
