import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runInboxCommand } from "../../src/cli/inbox.js";
import { writeLockdownStatus } from "../../src/lockdown/status.js";
import { writeTenantRuntime } from "../../src/cli/agents/runtime.js";

class StringWritable extends Writable {
  chunks: string[] = [];

  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }

  get text(): string {
    return this.chunks.join("");
  }
}

interface MockInboxItem {
  version: "1.1";
  item_id: string;
  kind: string;
  created_at: string;
  agent_id?: string;
  identity_id: string;
  display_template_id: string;
  display_template_args: Array<{ kind: string; value: string | number }>;
  resolved: boolean;
  resolved_at?: string;
  tier?: string;
  operation_category?: string;
}

const pendingItem = (id: string): MockInboxItem => ({
  version: "1.1",
  item_id: id,
  kind: "approval_pending",
  created_at: "2026-05-15T12:00:00.000Z",
  agent_id: "agent-b",
  identity_id: "operator-1",
  display_template_id: "approval_pending.tier1.state_export",
  display_template_args: [
    { kind: "agent_id", value: "agent-b" },
    { kind: "identity_id", value: "operator-1" },
  ],
  resolved: false,
  tier: "tier1",
  operation_category: "state_export",
});

function okJson(payload: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  } as Response;
}

async function run(argv: string[]): Promise<{
  code: number;
  out: StringWritable;
  err: StringWritable;
}> {
  const out = new StringWritable();
  const err = new StringWritable();
  const code = await runInboxCommand({ argv, out, err });
  return { code, out, err };
}

describe("sanctuary inbox approvals CLI", () => {
  let originalFetch: typeof globalThis.fetch;
  let originalDashboardUrl: string | undefined;
  let originalOperatorId: string | undefined;
  let originalStoragePath: string | undefined;
  let fortressPath: string;
  let items: MockInboxItem[];
  let auditEvents: Array<{ action: string; approval_id: string }>;

  beforeEach(async () => {
    originalFetch = globalThis.fetch;
    originalDashboardUrl = process.env.SANCTUARY_DASHBOARD_URL;
    originalOperatorId = process.env.SANCTUARY_OPERATOR_ID;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-inbox-lockdown-"));
    process.env.SANCTUARY_DASHBOARD_URL = "http://127.0.0.1:3909";
    process.env.SANCTUARY_OPERATOR_ID = "operator-test";
    process.env.SANCTUARY_STORAGE_PATH = fortressPath;
    const blocked = pendingItem("blocked-1");
    blocked.kind = "blocked_egress";
    delete blocked.operation_category;
    items = [
      pendingItem("approval-1"),
      { ...pendingItem("approval-resolved"), resolved: true },
      blocked,
    ];
    auditEvents = [];
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    if (originalDashboardUrl === undefined) {
      delete process.env.SANCTUARY_DASHBOARD_URL;
    } else {
      process.env.SANCTUARY_DASHBOARD_URL = originalDashboardUrl;
    }
    if (originalOperatorId === undefined) {
      delete process.env.SANCTUARY_OPERATOR_ID;
    } else {
      process.env.SANCTUARY_OPERATOR_ID = originalOperatorId;
    }
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    await rm(fortressPath, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function installInboxFetch(): ReturnType<typeof vi.fn> {
    const fetchSpy = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const target = String(url);
      if (target === "http://127.0.0.1:3909/api/hub/inbox") {
        return okJson({ ok: true, data: { items } });
      }
      const match = /^http:\/\/127\.0\.0\.1:3909\/api\/hub\/inbox\/([^/]+)\/approve$/.exec(
        target,
      );
      if (match && init?.method === "POST") {
        const id = decodeURIComponent(match[1]!);
        const item = items.find((entry) => entry.item_id === id);
        if (!item) {
          return okJson({ ok: false, error: "not_found" }, 404);
        }
        if (item.resolved) {
          return okJson({ ok: false, error: "already_resolved" }, 409);
        }
        item.resolved = true;
        item.resolved_at = "2026-05-15T12:01:00.000Z";
        auditEvents.push({ action: "approval-receipt", approval_id: id });
        return okJson({ ok: true, data: { item } });
      }
      return okJson({ ok: false, error: "unexpected_route" }, 500);
    });
    globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;
    return fetchSpy;
  }

  it("approvals list returns the pending approval set", async () => {
    installInboxFetch();

    const { code, out, err } = await run(["approvals", "list"]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    expect(out.text).toContain("ID");
    expect(out.text).toContain("approval-1");
    expect(out.text).toContain("operator-1");
    expect(out.text).toContain("agent-b");
    expect(out.text).toContain("state_export");
    expect(out.text).not.toContain("approval-resolved");
    expect(out.text).not.toContain("blocked-1");
  });

  it("approvals list --json returns items with lockdown_status", async () => {
    installInboxFetch();

    const { code, out, err } = await run(["approvals", "list", "--json"]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    const parsed = JSON.parse(out.text);
    expect(parsed.lockdown_status).toMatchObject({ active: false });
    expect(parsed.items.map((item: MockInboxItem) => item.item_id)).toEqual([
      "approval-1",
    ]);
  });

  it("routes --fortress=<path> through that fortress runtime", async () => {
    const scopedFortress = await mkdtemp(join(tmpdir(), "sanctuary-inbox-scoped-"));
    try {
      await writeTenantRuntime(scopedFortress, {
        version: "test",
        pid: process.pid,
        started_at: new Date().toISOString(),
        dashboard_host: "127.0.0.1",
        dashboard_port: 3910,
        mode: "standalone",
      });
      const fetchSpy = vi.fn(async (url: string | URL) => {
        expect(String(url)).toBe("http://127.0.0.1:3910/api/hub/inbox");
        return okJson({ ok: true, data: { items } });
      });
      globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;

      const { code, err } = await run([
        "approvals",
        "list",
        "--json",
        `--fortress=${scopedFortress}`,
      ]);

      expect(code).toBe(0);
      expect(err.text).toBe("");
      expect(fetchSpy).toHaveBeenCalledOnce();
    } finally {
      await rm(scopedFortress, { recursive: true, force: true });
    }
  });

  it("approvals approve <id> transitions the item out of pending approval", async () => {
    installInboxFetch();

    const approved = await run(["approvals", "approve", "approval-1"]);
    const listed = await run(["approvals", "list", "--json"]);

    expect(approved.code).toBe(0);
    expect(approved.out.text).toBe("approval: approval-1 approved by operator-test\n");
    expect(items.find((item) => item.item_id === "approval-1")?.resolved).toBe(true);
    expect(JSON.parse(listed.out.text).items).toEqual([]);
  });

  it("approvals list prints a lockdown banner when the fortress is locked", async () => {
    installInboxFetch();
    await writeLockdownStatus(fortressPath, {
      active: true,
      activated_at: "2026-05-19T12:00:00.000Z",
      reason: "operator_lockdown",
    });

    const { code, out } = await run(["approvals", "list"]);

    expect(code).toBe(0);
    expect(out.text).toContain(
      "Fortress lockdown status is ACTIVE (since 2026-05-19T12:00:00.000Z). CLI status only; writes are not blocked by this flag.",
    );
    expect(out.text).toContain("approval-1");
  });

  it("approvals approve <id> emits the existing approval receipt through the approve route", async () => {
    const fetchSpy = installInboxFetch();

    const { code } = await run(["approvals", "approve", "approval-1"]);

    expect(code).toBe(0);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:3909/api/hub/inbox/approval-1/approve",
      expect.objectContaining({ method: "POST" }),
    );
    expect(auditEvents).toEqual([
      { action: "approval-receipt", approval_id: "approval-1" },
    ]);
  });

  it("approvals approve <bogus-id> exits nonzero", async () => {
    installInboxFetch();

    const { code, out, err } = await run(["approvals", "approve", "bogus-id"]);

    expect(code).toBe(1);
    expect(out.text).toBe("");
    expect(err.text).toContain("sanctuary inbox: endpoint not implemented in this build (HTTP 404): not_found");
  });

  it("approvals list names network/connection failures with a remediation hint", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") });
    }) as unknown as typeof globalThis.fetch;

    const { code, out, err } = await run(["approvals", "list"]);

    expect(code).toBe(1);
    expect(out.text).toBe("");
    expect(err.text).toContain("sanctuary inbox: network/connection failure: fetch failed");
    expect(err.text).toContain("ECONNREFUSED");
    expect(err.text).toContain("Hint: start the Sanctuary dashboard");
  });

  it.each([
    [
      "404",
      404,
      { ok: false, error: "route missing" },
      "endpoint not implemented in this build (HTTP 404): route missing",
      "verify the dashboard exposes /api/hub/inbox",
    ],
    [
      "401",
      401,
      { ok: false, error: "unauthorized" },
      "auth/policy denied (HTTP 401): unauthorized",
      "check SANCTUARY_DASHBOARD_AUTH_TOKEN",
    ],
    [
      "403",
      403,
      { ok: false, error: "policy denied" },
      "auth/policy denied (HTTP 403): policy denied",
      "operator authorization",
    ],
    [
      "500",
      500,
      { ok: false, error: "boom" },
      "server error (HTTP 500): boom",
      "inspect the dashboard logs",
    ],
  ])(
    "approvals list names HTTP %s failure class",
    async (_label, status, payload, expectedClass, expectedHint) => {
      globalThis.fetch = vi.fn(async () => okJson(payload, status)) as unknown as typeof globalThis.fetch;

      const { code, out, err } = await run(["approvals", "list"]);

      expect(code).toBe(1);
      expect(out.text).toBe("");
      expect(err.text).toContain(`sanctuary inbox: ${expectedClass}`);
      expect(err.text).toContain(expectedHint);
    },
  );

  it("documents the approvals subcommands in help", async () => {
    const { code, out, err } = await run(["--help"]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    expect(out.text).toContain("approvals list [--json]");
    expect(out.text).toContain("approvals approve <entry_id> [--json]");
  });

  it("documents each approvals subcommand help surface", async () => {
    const list = await run(["approvals", "list", "--help"]);
    const approve = await run(["approvals", "approve", "--help"]);

    expect(list.code).toBe(0);
    expect(list.out.text).toContain(
      "Usage: sanctuary inbox approvals list [--json] [--fortress <path>]",
    );
    expect(approve.code).toBe(0);
    expect(approve.out.text).toContain(
      "Usage: sanctuary inbox approvals approve <entry_id> [--json] [--fortress <path>]",
    );
  });
});
