/**
 * Sanctuary v1.1 Dashboard - honesty regressions.
 *
 * NF-01: the Health page must not expose a button wired to an absent hub route.
 * NF-02: per-agent policy cells must render real data or an honest empty state,
 * never invented policy numbers.
 */

import { describe, expect, it } from "vitest";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";

function liftDashboardRenderers(): {
  renderHealth: (state: unknown) => string;
  renderPolicy: (state: unknown) => string;
} {
  const src = getClientScript();
  const end = src.indexOf("// ── Render: exit drill");
  let chunk = src.slice(0, end);
  chunk = chunk.replace(/const\s+state\s*=/, "var state =");
  const wrapper = `
    var document = { getElementById: () => null };
    var window = { matchMedia: () => null };
    var sessionStorage = { getItem: () => null, setItem: () => null };
    var location = { hash: "", host: "test" };
    ${chunk}
    return {
      renderHealth: function (s) { state = s; return renderHealthPage(); },
      renderPolicy: function (s) { state = s; return renderPolicyCenter(); }
    };
  `;
  // eslint-disable-next-line no-new-func
  const factory = new Function(wrapper) as () => {
    renderHealth: (state: unknown) => string;
    renderPolicy: (state: unknown) => string;
  };
  return factory();
}

function fakeState(extras: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agents: [],
    activity: [],
    policyView: { view: null, loadError: null, loading: false },
    templateBinding: { agentId: null, selectedTemplateId: null, pendingItemId: null, error: null },
    ...extras,
  };
}

describe("v1.1 dashboard honesty", () => {
  const { renderHealth, renderPolicy } = liftDashboardRenderers();

  it("NF-01 removes the dead full-audit button and handler", () => {
    const script = getClientScript();

    expect(script).not.toContain('data-action="run-full-audit"');
    expect(script).not.toContain("async function onRunFullAudit()");
    expect(script).not.toContain('action === "run-full-audit"');
    expect(script).not.toContain('api("/audit-chain/verify"');

    const html = renderHealth(fakeState());
    expect(html).toContain("Audit-chain verification is not available from this dashboard in this build");
    expect(html).not.toContain("Run full audit");
  });

  it("NF-02 renders real template and budget data without fabricated policy detail", () => {
    const html = renderPolicy(
      fakeState({
        agents: [
          {
            version: "1.1",
            agent_id: "agent-alpha",
            identity_id: "operator-1",
            harness: "claude-code",
            model_provider: { vendor: "anthropic", model_id: "claude-test" },
            policy_id: "policy-default",
            channel_template_id: "request-approve-act",
            status: "active",
            budget_summary: {
              daily: { unit: "usd", cap: 7.5, used: 0 },
              last_refreshed_at: "2026-08-08T00:00:00.000Z",
            },
            last_activity_at: "2026-08-08T00:00:00.000Z",
            wrapped_at: "2026-08-08T00:00:00.000Z",
            capabilities: {
              can_pause: true,
              can_resume: true,
              can_restart: true,
              can_unwrap: true,
              can_lockdown: true,
              can_chat: true,
              can_change_template: true,
            },
          },
        ],
      }),
    );

    expect(html).toContain("agent-alpha");
    expect(html).toContain("request-approve-act");
    expect(html).toContain("$7.5/day");
    expect(html.match(/Not available yet/g)?.length).toBe(4);
    expect(html).not.toContain('class="allow-count">12</span>');
    expect(html).not.toContain('class="block-count">3</span>');
    expect(html).not.toContain("<td>30 d</td>");
    expect(html).not.toContain("<td>T1, T2</td>");
    expect(html).not.toContain('class="toggle-on" aria-label="enabled"');
  });
});
