/**
 * Unit tests for the multi-tenant HTML renderer.
 *
 * Validates: (1) empty-state copy, (2) row escaping + deep-link
 * construction, (3) status-pill classification, (4) the embedded snapshot
 * JSON is well-formed so a future client-side live view can parse it, and
 * (5) HTML entity escaping for adversarial tenant names.
 */

import { describe, it, expect } from "vitest";
import { renderMultiAgentHTML } from "../../src/dashboard/multi-html.js";
import type { MultiTenantSnapshot } from "../../src/dashboard/multi-aggregator.js";

function snapshot(
  tenants: MultiTenantSnapshot["tenants"] = []
): MultiTenantSnapshot {
  return {
    version: 1,
    generated_at: "2026-04-17T12:00:00.000Z",
    tenant_count: tenants.length,
    running_count: tenants.filter((t) => t.running).length,
    tenants,
  };
}

describe("renderMultiAgentHTML", () => {
  it("renders an empty-state when no tenants exist", () => {
    const html = renderMultiAgentHTML({ snapshot: snapshot() });
    expect(html).toContain("Multi-Agent Overview");
    expect(html).toContain("No tenants found");
    expect(html).toContain("sanctuary wrap");
  });

  it("renders a running tenant with a deep-link to its dashboard", () => {
    const html = renderMultiAgentHTML({
      snapshot: snapshot([
        {
          name: "nsa",
          storage_path: "/home/e/.sanctuary/nsa",
          initialized: true,
          passphrase_status: "keychain",
          keychain_service: "sanctuary-passphrase-aaaaaaaaaaaaaaaa",
          dashboard_url: "http://127.0.0.1:3501",
          dashboard_port: 3501,
          webhook_callback_port: 3511,
          pid: 99001,
          started_at: "2026-04-17T11:59:00.000Z",
          mode: "wrap",
          running: true,
          probe_reason: null,
          last_activity: "2026-04-17T11:59:50.000Z",
        },
      ]),
    });
    expect(html).toContain('href="http://127.0.0.1:3501"');
    expect(html).toContain("pill-running");
    expect(html).toContain(">running<");
    expect(html).toContain(">nsa<");
    expect(html).toContain("Keychain");
  });

  it("renders a stopped tenant without a deep-link (no runtime)", () => {
    const html = renderMultiAgentHTML({
      snapshot: snapshot([
        {
          name: "standards",
          storage_path: "/home/e/.sanctuary/standards",
          initialized: true,
          passphrase_status: "fallback-file",
          keychain_service: "sanctuary-passphrase-bbbbbbbbbbbbbbbb",
          dashboard_url: null,
          dashboard_port: null,
          webhook_callback_port: null,
          pid: null,
          started_at: null,
          mode: null,
          running: false,
          probe_reason: "no runtime.json",
          last_activity: null,
        },
      ]),
    });
    expect(html).toContain("pill-stopped");
    expect(html).toContain(">stopped<");
    expect(html).toContain("Fallback file");
    expect(html).not.toContain("http://127.0.0.1");
  });

  it("escapes adversarial tenant names / storage paths into HTML entities", () => {
    const html = renderMultiAgentHTML({
      snapshot: snapshot([
        {
          name: "<img src=x onerror=alert(1)>",
          storage_path: "/tmp/<script>/",
          initialized: true,
          passphrase_status: "keychain",
          keychain_service: "sanctuary-passphrase-cccccccccccccccc",
          dashboard_url: null,
          dashboard_port: null,
          webhook_callback_port: null,
          pid: null,
          started_at: null,
          mode: null,
          running: false,
          probe_reason: null,
          last_activity: null,
        },
      ]),
    });
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;script&gt;");
  });

  it("embeds a parseable snapshot JSON block", () => {
    const snap = snapshot([
      {
        name: "t1",
        storage_path: "/x",
        initialized: true,
        passphrase_status: "keychain",
        keychain_service: "sanctuary-passphrase-dddddddddddddddd",
        dashboard_url: "http://127.0.0.1:3502",
        dashboard_port: 3502,
        webhook_callback_port: 3512,
        pid: 1,
        started_at: "2026-04-17T11:00:00.000Z",
        mode: "wrap",
        running: true,
        probe_reason: null,
        last_activity: "2026-04-17T11:59:00.000Z",
      },
    ]);
    const html = renderMultiAgentHTML({ snapshot: snap });
    const match = /<script id="snapshot-data" type="application\/json">([\s\S]*?)<\/script>/.exec(
      html
    );
    expect(match).not.toBeNull();
    // Unescape the u003c hack before parsing.
    const raw = match![1]!.replace(/\\u003c/g, "<");
    const parsed = JSON.parse(raw);
    expect(parsed.tenants[0].name).toBe("t1");
    expect(parsed.running_count).toBe(1);
  });

  it("uses pill-empty for an uninitialized tenant", () => {
    const html = renderMultiAgentHTML({
      snapshot: snapshot([
        {
          name: "fresh",
          storage_path: "/x/fresh",
          initialized: false,
          passphrase_status: "not-initialized",
          keychain_service: "sanctuary-passphrase-eeeeeeeeeeeeeeee",
          dashboard_url: null,
          dashboard_port: null,
          webhook_callback_port: null,
          pid: null,
          started_at: null,
          mode: null,
          running: false,
          probe_reason: "no runtime.json",
          last_activity: null,
        },
      ]),
    });
    expect(html).toContain("pill-empty");
    expect(html).toContain(">empty<");
    expect(html).toContain("Not initialized");
  });

  it("pluralizes 'tenants' correctly in the header", () => {
    const html1 = renderMultiAgentHTML({
      snapshot: snapshot([
        {
          name: "only",
          storage_path: "/x",
          initialized: true,
          passphrase_status: "keychain",
          keychain_service: "sanctuary-passphrase-ffffffffffffffff",
          dashboard_url: null,
          dashboard_port: null,
          webhook_callback_port: null,
          pid: null,
          started_at: null,
          mode: null,
          running: false,
          probe_reason: null,
          last_activity: null,
        },
      ]),
    });
    expect(html1).toContain("1 tenant discovered");

    const html2 = renderMultiAgentHTML({ snapshot: snapshot() });
    expect(html2).toContain("0 tenants discovered");
  });
});
