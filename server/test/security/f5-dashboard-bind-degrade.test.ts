/**
 * F5 (dashboard-bind-degrade, 2026-09-24 dogfood finding): a second Claude
 * Code session starting the daily-fortress Sanctuary MCP server (stdio boot,
 * `src/index.ts`) while another session's server already holds the embedded
 * dashboard port hit EADDRINUSE and the WHOLE MCP server exited. The second
 * session had no Sanctuary tools at all.
 *
 * Wired-consumer test (AGENTS rule 4): drives the real stdio boot object
 * graph (`createSanctuaryServer`), with the dashboard port PRE-BOUND by this
 * test on an ephemeral port, and asserts:
 *   1. Boot completes (does not reject, does not exit).
 *   2. A Tier-1 gated tool call (`state_delete`) is denied with the EXACT
 *      fixed generic denial payload the gate returns on every policy denial
 *      (AGENTS MUST-NEVER #7: no rule or tier revealed), and the matching
 *      `gate_deny:state_delete` audit row lands. It must NOT hang waiting
 *      on a dead dashboard listener.
 *   3. An ungated Tier-3 tool call (`identity_list`) still succeeds.
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
 * calls `gate.evaluate` for every tool call. There is exactly one
 * `ApprovalGate` in the boot graph; the `AggregatorBackedChannel` wrapper it
 * holds is constructed AFTER the swap, so it wraps the post-swap
 * `StderrApprovalChannel`, not a cached reference to the dead dashboard.
 *
 * BOUND (not exercised here): under `policy.approval_redirect.enabled: true`
 * with mode "replace", `AggregatorBackedChannel` never calls the underlying
 * channel at all, so the swap is inert and every gated call falls back to a
 * per-call timeout-then-deny wait instead of an immediate denial. Default
 * policy has `approval_redirect.enabled: false` (loader.ts), which is what
 * this test's fixture policy carries.
 */

import { createServer, type Server as NetServer } from "node:net";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fixedDenial } from "../../src/agent-native/safety-base.js";
import { createSanctuaryServer } from "../../src/index.js";
import {
  StderrApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import { refuseDashboardBindRace } from "../../src/principal-policy/channel-selection.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import {
  DEFAULT_POLICY,
  generateDefaultPolicyYaml,
} from "../../src/principal-policy/loader.js";
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

// A163 fix round 1 (Claude minor 6): SANCTUARY_DASHBOARD_ENABLED is included
// here even though `explicitDashboardRequested` (index.ts) no longer reads
// it -- this keeps the F5 (implicit-case) suite below env-insensitive: with
// that var exported ambiently, the F5 suite must still boot the #1458
// degrade, not the A163 refusal, since the refusal now keys off the boot
// option this suite never sets, not the env var.
const DASHBOARD_ENV_KEYS = [
  "SANCTUARY_DASHBOARD_HOST",
  "SANCTUARY_DASHBOARD_PORT",
  "SANCTUARY_DASHBOARD_ENABLED",
] as const;

// Must match `GENERIC_GATE_DENIAL_REMEDIATION` in router.ts (not exported):
// the fixed remediation class every gate denial returns to the caller,
// regardless of which policy rule or tier fired.
const GENERIC_GATE_DENIAL_REMEDIATION = "unavailable";

describe("F5: a busy embedded-dashboard port degrades the MCP stdio boot instead of crashing it", () => {
  let fortress: TempFortress;
  let occupyingServer: NetServer | undefined;
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
    // session's dashboard (or any other local process) already owning it.
    // bindWithRetry only protects THIS setup bind against an unrelated port
    // collision (a third process); the Sanctuary boot below is deliberately
    // pointed at the SAME port and must NOT retry -- a genuine EADDRINUSE is
    // exactly what this test drives. `occupyingServer` is assigned only on a
    // successful bind; a failed attempt's listener is closed before the
    // retry so bindWithRetry never leaks a half-bound socket across
    // attempts.
    await bindWithRetry(async () => {
      const port = randomTestPort();
      await new Promise<void>((resolve, reject) => {
        const srv = createServer();
        const onSetupError = (err: Error): void => {
          srv.close(() => reject(err));
        };
        srv.once("error", onSetupError);
        srv.listen(port, "127.0.0.1", () => {
          srv.off("error", onSetupError);
          occupyingServer = srv;
          resolve();
        });
      });
      dashboardPort = port;
    });

    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    process.env.SANCTUARY_DASHBOARD_PORT = String(dashboardPort);
  });

  afterEach(async () => {
    try {
      await boot?.cleanup().catch(() => undefined);
    } finally {
      boot = undefined;
      try {
        if (occupyingServer) {
          await new Promise<void>((resolve) => occupyingServer!.close(() => resolve()));
        }
      } finally {
        occupyingServer = undefined;
        for (const [key, value] of restoreEnv) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
        await fortress.cleanup();
      }
    }
  });

  it("boots with MCP tools live, denies a Tier-1 tool with the exact fixed payload, allows a Tier-3 tool, and audits the degrade", async () => {
    // 1. Boot completes -- does not reject, does not exit the process.
    boot = await createSanctuaryServer();
    expect(boot.policy.approval_channel.type).toBe("dashboard");

    // 2. A Tier-1 gated call is denied with the EXACT fixed, generic denial
    // payload the gate returns for every policy-denied call (no rule, tier,
    // or "port busy" detail leaked to the agent -- MUST-NEVER #7). Comparing
    // the whole payload, not just `denied === true`, rules out a denial for
    // an unrelated reason (schema validation, an unknown tool) passing this
    // assertion by coincidence.
    const denied = await callTool(boot.server, "state_delete", {
      namespace: "f5-test-ns",
      key: "f5-test-key",
    });
    expect(denied.isError).toBe(true);
    const deniedPayload = parseToolResult(denied);
    expect(deniedPayload).toEqual(
      fixedDenial("audit:gate:state_delete", GENERIC_GATE_DENIAL_REMEDIATION, null),
    );
    const deniedText = JSON.stringify(deniedPayload).toLowerCase();
    expect(deniedText).not.toContain("port");
    expect(deniedText).not.toContain("tier");
    expect(deniedText).not.toContain("busy");
    expect(deniedText).not.toContain("dashboard");

    // The gate's own audit trail for this exact call: `gate_deny:<operation>`
    // (gate.ts's requestApproval, the response.decision === "deny" branch).
    const gateDenyAudit = await boot.auditLog.query({
      operation_type: "gate_deny:state_delete",
    });
    expect(gateDenyAudit.entries).toHaveLength(1);
    expect(gateDenyAudit.entries[0]!.result).toBe("failure");
    expect(gateDenyAudit.entries[0]!.details?.decided_by).toBe(
      "stderr:non-interactive",
    );

    // 3. An ungated (Tier-3) call still succeeds: the degrade is scoped to
    // approval-gated operations, not a blanket refusal. `identity_list`
    // (not `state_list`) is used deliberately: it carries no `namespace`
    // argument, so it cannot also trip the SEPARATE new-namespace-access
    // Tier-2 anomaly check (`gate.ts`'s `detectAnomaly`, which runs BEFORE
    // the tier-3 allowlist check) on first access, which would confound this
    // assertion with a different gate path.
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

describe("A163: an explicitly requested dashboard refuses startup on a busy port instead of degrading", () => {
  // Fix round 1 (code-gate 2026-09-27, Claude-2/Grok-1 blocking): the signal
  // is now the boot-local `explicitDashboardRequested` option on
  // `createSanctuaryServer`, set ONLY by cli.ts's `--dashboard` argv parse --
  // never `SANCTUARY_DASHBOARD_ENABLED` / `config.dashboard.enabled`, both of
  // which persist past the process that set them (`saveConfig`, `wrap`) and
  // so read as "some earlier setup asked" on every later boot, not "this
  // operator asked now". `DASHBOARD_ENV_KEYS` above already restores
  // `SANCTUARY_DASHBOARD_ENABLED` around every test in this file so the F5
  // suite stays env-insensitive; this suite does not set that env var at all
  // and instead passes the boot option directly.
  //
  // Fail-before note (Claude-5 minor correction): on unmodified `origin/main`
  // (no `explicitDashboardRequested` branch and no preflight), `boot` rejects
  // nothing -- `createSanctuaryServer()` RESOLVES, degrading like the F5
  // path. `expect(promise).rejects.toThrow(...)` against a resolving promise
  // fails immediately with "promise resolved instead of rejecting", not a
  // timeout; that is the actual fail-before witness for this suite.
  let fortress: TempFortress;
  let occupyingServer: NetServer | undefined;
  let dashboardPort: number;
  let restoreEnv: Map<string, string | undefined>;
  let boot: Awaited<ReturnType<typeof createSanctuaryServer>> | undefined;

  beforeEach(async () => {
    fortress = await createTempFortress("sanctuary-a163-dashbind");
    restoreEnv = new Map(DASHBOARD_ENV_KEYS.map((key) => [key, process.env[key]]));

    await bindWithRetry(async () => {
      const port = randomTestPort();
      await new Promise<void>((resolve, reject) => {
        const srv = createServer();
        const onSetupError = (err: Error): void => {
          srv.close(() => reject(err));
        };
        srv.once("error", onSetupError);
        srv.listen(port, "127.0.0.1", () => {
          srv.off("error", onSetupError);
          occupyingServer = srv;
          resolve();
        });
      });
      dashboardPort = port;
    });

    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    process.env.SANCTUARY_DASHBOARD_PORT = String(dashboardPort);
  });

  afterEach(async () => {
    try {
      await boot?.cleanup().catch(() => undefined);
    } finally {
      boot = undefined;
      try {
        if (occupyingServer) {
          await new Promise<void>((resolve) => occupyingServer!.close(() => resolve()));
        }
      } finally {
        occupyingServer = undefined;
        for (const [key, value] of restoreEnv) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
        await fortress.cleanup();
      }
    }
  });

  it("virgin fortress: refuses before any fortress write, naming the port", async () => {
    // No mkdir, no principal-policy.yaml, no prior boot: this fortress has
    // never been touched. The preflight probe (`refuseIfDashboardPortUnavailable`
    // in index.ts) runs immediately after `loadConfig`, before the storage-dir
    // mkdir, before `establishMaster`'s custody envelope, before
    // `loadPrincipalPolicy`'s ENOENT-triggered default-policy write.
    await expect(
      createSanctuaryServer({ explicitDashboardRequested: true }),
    ).rejects.toThrow(
      new RegExp(`dashboard.*explicitly requested.*${dashboardPort}.*already in use`, "is"),
    );
    boot = undefined;

    // Nothing was written: the whole fortress directory (custody envelope,
    // config file, principal-policy.yaml, audit log) never came into being.
    expect(existsSync(fortress.storagePath)).toBe(false);
  });

  it("does NOT refuse an implicit boot on the same busy port (explicitDashboardRequested omitted)", async () => {
    // Sanity check that the new option, not ambient state, gates the
    // refusal: same busy port, same fortress shape, but this call never
    // opts in, so `loadPrincipalPolicy`'s ENOENT default (type: stderr)
    // means the dashboard branch is never reached at all and boot completes
    // normally.
    boot = await createSanctuaryServer();
    expect(boot.policy.approval_channel.type).toBe("stderr");
  });

  it("race path: after custody exists, a lost bind race is audited and the channel is stopped through its real stop()", async () => {
    // Reproducing the actual bind-timing race (preflight sees the port free,
    // the real `dashboard.start()` loses it moments later) deterministically
    // through the full boot is not practical; `refuseDashboardBindRace` is
    // exported from `channel-selection.ts` (not re-exported from
    // `src/index.ts`, so it never touches the public-surface-snapshot guard)
    // specifically so this path is testable directly against REAL objects
    // instead of being left uncovered. This is the
    // "passphrase-established fortress" case Grok-2 named: custody already
    // exists (this boot's own `createTempFortress` pins `SANCTUARY_PASSPHRASE`),
    // so the audit row and the channel-stop side effect are the only things
    // under test, not the preflight (which is covered by the first `it`).
    boot = await createSanctuaryServer();
    const { auditLog } = boot;

    // Observe the REAL `setInterval`/`clearInterval` calls without replacing
    // real timer scheduling (no `vi.useFakeTimers`, which would risk hanging
    // the dashboard's real HTTP bind/close I/O below). `setIntervalSpy` calls
    // through to the genuine implementation; it only lets this test see the
    // handle `DashboardApprovalChannel`'s constructor arms unconditionally
    // (`dashboard.ts`'s `sessionCleanupTimer`, before any bind attempt).
    const setIntervalSpy = vi.spyOn(global, "setInterval");
    const dashboard = new DashboardApprovalChannel({
      port: dashboardPort,
      host: "127.0.0.1",
      timeout_seconds: DEFAULT_POLICY.approval_channel.timeout_seconds,
      auth_token: "a163-race-test-token",
    });
    const sessionCleanupTimerHandle = setIntervalSpy.mock.results.at(-1)?.value;
    setIntervalSpy.mockRestore();
    expect(sessionCleanupTimerHandle).toBeDefined();

    // The occupying server (bound in beforeEach) makes this `start()` lose
    // the race exactly as the real dashboard case's `start()` would.
    await dashboard.start({ exitCleanOnAddrInUse: true, silentAddrInUse: true });
    expect(dashboard.addrInUse()).toBe(true);

    const clearIntervalSpy = vi.spyOn(global, "clearInterval");
    const err = await refuseDashboardBindRace(
      dashboard,
      auditLog,
      boot.config.storage_path,
      dashboardPort,
    );
    expect(err.message).toContain(String(dashboardPort));
    expect(err.message).toContain("already in use");

    // stop() was reached through the REAL channel: the exact timer handle
    // its constructor armed was cleared, not a substitute or a mock.
    expect(clearIntervalSpy).toHaveBeenCalledWith(sessionCleanupTimerHandle);
    clearIntervalSpy.mockRestore();

    // The fortress's own trail records why: same shape as the #1458 degrade
    // path's audit row.
    const auditResult = await auditLog.query({
      operation_type: "dashboard_bind_unavailable",
    });
    expect(auditResult.entries).toHaveLength(1);
    expect(auditResult.entries[0]!.result).toBe("failure");
    expect(auditResult.entries[0]!.details).toEqual({ port: dashboardPort });
  });
});

describe("F5 unit: StderrApprovalChannel is the deny-all channel the degrade swap constructs", () => {
  // The degrade site constructs `new StderrApprovalChannel(policy.approval_channel)`,
  // a config whose `type` field is "dashboard" (the policy that selected the
  // now-unavailable dashboard channel), not "stderr". StderrApprovalChannel's
  // constructor and requestApproval() never read `config.type` (see
  // approval-channel.ts), so this must deny unconditionally regardless of what
  // config object it is handed. Existing SEC-016 coverage only ever
  // constructs it with a `{type: "stderr", ...}` config; this is the shape
  // the F5 swap site actually uses.
  const DASHBOARD_TYPED_CONFIG = {
    type: "dashboard" as const,
    // Derived, not a bare literal: the same default timeout the production
    // swap site's config carries (policy.approval_channel.timeout_seconds).
    // StderrApprovalChannel never reads this field either way.
    timeout_seconds: DEFAULT_POLICY.approval_channel.timeout_seconds,
  };

  const REQUESTS: ApprovalRequest[] = [
    {
      operation: "state_delete",
      tier: 1,
      reason: "F5 unit test, Tier 1 request",
      context: { namespace: "test" },
      timestamp: new Date().toISOString(),
    },
    {
      operation: "state_read",
      tier: 2,
      reason: "F5 unit test, Tier 2 anomaly request",
      context: { namespace: "test", anomaly: "frequency_spike" },
      timestamp: new Date().toISOString(),
    },
    {
      operation: "identity_rotate",
      tier: 1,
      reason: "F5 unit test, a second, differently shaped Tier 1 request",
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
