/**
 * Federation PR-A1 — `sanctuary status` CLI verb, end-to-end on loopback.
 *
 * The first API-backed Wave 1 MVP command: boots a real dashboard,
 * runs the full RFC v7 ceremony through the #432 dashboard-request seam,
 * and renders GET /v1/status. Asserts the catalog exit-code contract
 * (0 success / 1 user error / 2 daemon unavailable / 3 auth failure) and
 * that no output mode ever contains key material.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { randomBytes } from "node:crypto";

import { ed25519 } from "@noble/curves/ed25519";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { renderTable, runStatusCommand, toYaml } from "../../src/cli/status.js";
import { toBase64url } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  stop: () => Promise<void>;
}

async function startRig(): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `status-cli-test-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });
  await dashboard.start();

  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    stop: async () => {
      await dashboard.stop();
    },
  };
}

// retry:2 - these CLI subprocess tests touch real host state (daemon
// reachability, loopback ports) and are flaky under full-suite parallel load;
// retry re-runs the test, so a genuine regression still fails all attempts
// (distinct from filename-based flake-skipping, which masks regressions).
describe("sanctuary status (CLI, /v1-backed)", { retry: 2 }, () => {
  let rig: TestRig;
  let savedToken: string | undefined;
  let savedUrl: string | undefined;

  beforeEach(async () => {
    rig = await startRig();
    savedToken = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    savedUrl = process.env.SANCTUARY_DASHBOARD_URL;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = rig.authToken;
    delete process.env.SANCTUARY_DASHBOARD_URL;
  });

  afterEach(async () => {
    await rig.stop();
    if (savedToken === undefined) delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    else process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = savedToken;
    if (savedUrl === undefined) delete process.env.SANCTUARY_DASHBOARD_URL;
    else process.env.SANCTUARY_DASHBOARD_URL = savedUrl;
  });

  it("exit 0 + human table by default", async () => {
    const out = new Capture();
    const err = new Capture();
    const code = await runStatusCommand({
      argv: [],
      out,
      err,
      dashboardUrl: rig.baseUrl,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("Sanctuary daemon status");
    expect(out.text).toContain("federation:   disabled");
    expect(err.text).toBe("");
  });

  it("--output json emits the catalog schema and no key material", async () => {
    const out = new Capture();
    const code = await runStatusCommand({
      argv: ["--output", "json"],
      out,
      err: new Capture(),
      dashboardUrl: rig.baseUrl,
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text) as Record<string, unknown>;
    for (const key of [
      "ok",
      "version",
      "daemon",
      "listener",
      "federation",
      "identity",
      "castle_wall",
    ]) {
      expect(parsed).toHaveProperty(key);
    }
    expect(out.text).not.toContain("private_key");
    expect(out.text).not.toContain(rig.authToken);
  });

  it("--output yaml renders the document", async () => {
    const out = new Capture();
    const code = await runStatusCommand({
      argv: ["--output=yaml"],
      out,
      err: new Capture(),
      dashboardUrl: rig.baseUrl,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("ok: true");
    expect(out.text).toContain("federation:");
    expect(out.text).toContain("enabled: false");
  });

  it("exit 1 on invalid arguments", async () => {
    const err = new Capture();
    expect(
      await runStatusCommand({
        argv: ["--output", "xml"],
        out: new Capture(),
        err,
        dashboardUrl: rig.baseUrl,
      }),
    ).toBe(1);
    expect(err.text).toContain("--output must be");

    expect(
      await runStatusCommand({
        argv: ["--no-such-flag"],
        out: new Capture(),
        err: new Capture(),
        dashboardUrl: rig.baseUrl,
      }),
    ).toBe(1);
  });

  it("exit 2 when the daemon is unreachable", async () => {
    const err = new Capture();
    const code = await runStatusCommand({
      argv: [],
      out: new Capture(),
      err,
      // Connection-refused port: nothing listens here.
      dashboardUrl: "http://127.0.0.1:9",
    });
    expect(code).toBe(2);
    expect(err.text).toContain("daemon unavailable");
  });

  it("exit 3 when the ceremony is denied (operator identity required, no credential presentable)", async () => {
    // PR-A3: the bearer-token attestation path is gone. A daemon WITH an
    // operator identity configured (so it is not in auth-disabled dev mode)
    // and WITHOUT loopback auto-auth requires a durable operator attestation
    // the bare `sanctuary status` CLI cannot produce → the ceremony is denied.
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    const port = await getFreePort();
    const operatorPub = ed25519.getPublicKey(randomBytes(32));
    const dashboard = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auth_token: `status-cli-test-${randomBytes(8).toString("hex")}`,
      auto_open: false,
    });
    dashboard.setDependencies({
      policy: {
        version: 1,
        tier1_always_approve: [],
        tier3_auto_allow: [],
        anomaly_thresholds: {
          new_namespace: true,
          unfamiliar_counterparty_window_days: 7,
          frequency_spike_multiplier: 5,
        },
        approval_channel: { type: "stderr", timeout_seconds: 30 },
      } as never,
      baseline: { load: async () => {}, save: async () => {} } as never,
      auditLog,
      identityManager: {
        getDefault: () => ({
          identity_id: "op-1",
          label: "operator",
          did: "did:key:test",
          public_key: toBase64url(operatorPub),
          created_at: "2026-06-01T00:00:00.000Z",
          key_type: "ed25519",
          key_protection: "passphrase",
        }),
        getPrimaryIdentityId: () => "op-1",
        get: () => undefined,
      } as never,
    });
    await dashboard.start();
    try {
      const err = new Capture();
      const code = await runStatusCommand({
        argv: [],
        out: new Capture(),
        err,
        dashboardUrl: `http://127.0.0.1:${port}`,
      });
      expect(code).toBe(3);
      expect(err.text).toContain("session ceremony denied");
      // The denial must stay generic: no hint about WHICH check failed.
      expect(err.text).not.toContain("attestation");
      expect(err.text).not.toContain("challenge");
    } finally {
      await dashboard.stop();
    }
  });

  it("succeeds without an env token when loopback auto-auth is enabled", async () => {
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    rig.dashboard.setAutoAuthLocalhost(true);
    const out = new Capture();
    const code = await runStatusCommand({
      argv: [],
      out,
      err: new Capture(),
      dashboardUrl: rig.baseUrl,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("Sanctuary daemon status");
  });

  it("--help exits 0 and documents the exit codes", async () => {
    const out = new Capture();
    const code = await runStatusCommand({ argv: ["--help"], out, err: new Capture() });
    expect(code).toBe(0);
    expect(out.text).toContain("Exit codes");
  });
});

describe("renderTable castle-wall line", () => {
  // Regression: the default table line must read the honest evidence-gated
  // `arm_state` field that /v1/status now returns (a full CastleWallPosture),
  // NOT the dead `.status` placeholder the document carried before this PR.
  // Reading the wrong field silently pinned the line to "unknown" regardless
  // of the real arm-state, defeating the human-readable honesty path.
  function lineFor(castleWall: unknown): string {
    const table = renderTable({ castle_wall: castleWall });
    const line = table
      .split("\n")
      .find((l) => l.includes("castle wall:"));
    expect(line, "table must include a castle wall: line").toBeDefined();
    return line!;
  }

  it("renders the honest arm_state, not the dead .status field", () => {
    expect(lineFor({ arm_state: "armed", status: "unknown" })).toContain(
      "castle wall:  armed",
    );
    expect(lineFor({ arm_state: "degraded" })).toContain(
      "castle wall:  degraded",
    );
    expect(lineFor({ arm_state: "not_installed" })).toContain(
      "castle wall:  not_installed",
    );
  });

  it("renders unknown for the honest unknown arm_state and for an absent castle_wall", () => {
    expect(lineFor({ arm_state: "unknown" })).toContain("castle wall:  unknown");
    // No castle_wall object at all (locked/absent) ⇒ honestly unknown.
    const table = renderTable({});
    const line = table.split("\n").find((l) => l.includes("castle wall:"));
    expect(line).toContain("castle wall:  unknown");
  });

  it("renders enforcement_unavailable as a loud reason line, not bare degraded only", () => {
    const table = renderTable({
      castle_wall: {
        arm_state: "degraded",
        evidence_basis: "enforcement_unavailable",
      },
    });
    expect(table).toContain("castle wall:  degraded");
    expect(table).toContain(
      "castle wall reason: enforcement_unavailable (manifest loaded, arm lease missing)",
    );
  });
});

describe("toYaml", () => {
  it("renders nested objects, arrays, and quoted scalars", () => {
    const doc = {
      ok: true,
      version: "1.3.3",
      list: [1, "two", { three: 3 }],
      nested: { a: null, b: "needs: quoting" },
    };
    const text = toYaml(doc);
    expect(text).toContain("ok: true");
    // Version-like strings are quoted defensively (could parse as a
    // YAML number otherwise).
    expect(text).toContain('version: "1.3.3"');
    expect(text).toContain("- 1");
    expect(text).toContain('"needs: quoting"');
    expect(text).toContain("a: null");
  });
});
