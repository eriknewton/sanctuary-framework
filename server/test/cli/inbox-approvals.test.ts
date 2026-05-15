import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Writable } from "node:stream";

import { runInboxCommand } from "../../src/cli/inbox.js";

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
  let items: MockInboxItem[];
  let auditEvents: Array<{ action: string; approval_id: string }>;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    originalDashboardUrl = process.env.SANCTUARY_DASHBOARD_URL;
    originalOperatorId = process.env.SANCTUARY_OPERATOR_ID;
    process.env.SANCTUARY_DASHBOARD_URL = "http://127.0.0.1:3909";
    process.env.SANCTUARY_OPERATOR_ID = "operator-test";
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

  afterEach(() => {
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

  it("approvals list --json returns a parseable array", async () => {
    installInboxFetch();

    const { code, out, err } = await run(["approvals", "list", "--json"]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    const parsed = JSON.parse(out.text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.map((item: MockInboxItem) => item.item_id)).toEqual([
      "approval-1",
    ]);
  });

  it("approvals approve <id> transitions the item out of pending approval", async () => {
    installInboxFetch();

    const approved = await run(["approvals", "approve", "approval-1"]);
    const listed = await run(["approvals", "list", "--json"]);

    expect(approved.code).toBe(0);
    expect(approved.out.text).toBe("approval: approval-1 approved by operator-test\n");
    expect(items.find((item) => item.item_id === "approval-1")?.resolved).toBe(true);
    expect(JSON.parse(listed.out.text)).toEqual([]);
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
    expect(err.text).toContain("sanctuary inbox: not_found");
  });

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
