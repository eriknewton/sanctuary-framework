/**
 * Slice 2 shell: every hash route still reaches a screen.
 *
 * The rail folded fourteen destinations into eight plus a Configure group.
 * The thirteen older hash ids are frozen surfaces (bookmarks, deep links,
 * links inside other screens), so each must still render its own screen when
 * navigated directly, and the five new ids must render theirs. This walks
 * every id through the client's real route switch (renderMain, run in a
 * minimal DOM) and fails on the switch's "Route not found." fallback. It also
 * pins the rail: exactly eight destinations in the buyer's words, in order,
 * then Integrations and Settings under Configure, and nothing else.
 */
import { describe, expect, it } from "vitest";
import { createContext, runInContext } from "node:vm";
import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { renderDashboardV11Html } from "../../../src/dashboard/v1_1/html.js";

// The thirteen route ids that shipped before the slice 2 rail.
const FROZEN_ROUTE_IDS = [
  "posture", "agents", "policy", "activity", "dashboard", "attestation", "health",
  "auto-trigger", "intelligence", "privacy", "honeypot", "coordination", "exit-drill",
];
// The hash ids the slice 2 rail adds.
const NEW_ROUTE_IDS = ["approvals", "enforcement", "findings", "integrations", "settings"];
// Reached by clicking an agent, never from the rail; walked so it cannot rot.
const INTERNAL_ROUTE_IDS = ["agent-detail"];

function clientInMinimalDom() {
  const main = { innerHTML: "", querySelector: () => null, querySelectorAll: () => [] };
  const fortress = { innerHTML: "" };
  const appClasses = new Set<string>();
  const app = {
    setAttribute() {},
    classList: { add: (c: string) => appClasses.add(c), remove: (c: string) => appClasses.delete(c) },
  };
  const pending = () => new Promise<never>(() => {});
  const context = createContext({
    document: {
      getElementById: (id: string) => (id === "main" ? main : id === "fortress" ? fortress : id === "app" ? app : id === "dashboard-config" ? { textContent: "{}" } : null),
      addEventListener() {}, querySelectorAll: () => [],
      documentElement: { setAttribute() {}, removeAttribute() {} },
    },
    window: { addEventListener() {} }, location: { hash: "", search: "", origin: "http://fixture" },
    sessionStorage: { getItem: () => null }, URLSearchParams, URL, AbortController, Date,
    Element: class {}, setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    EventSource: class { addEventListener() {} close() {} },
    // Reads never settle: every screen renders its honest not-loaded state.
    fetch: pending,
  });
  runInContext(getClientScript(), context);
  return { main, context, appClasses };
}

describe("slice 2 shell route walk", () => {
  it.each([...FROZEN_ROUTE_IDS, ...NEW_ROUTE_IDS, ...INTERNAL_ROUTE_IDS])(
    "#%s resolves to a renderer in the client's route switch",
    (id) => {
      const { main, context } = clientInMinimalDom();
      runInContext(`state.route = ${JSON.stringify(id)}; renderMain();`, context);
      expect(main.innerHTML.length).toBeGreaterThan(0);
      expect(main.innerHTML).not.toContain("Route not found.");
    },
  );

  // The fortress column (the queue and ambient posture beside the concierge)
  // shows only beside Talk's full page; every other route is route-full, so
  // sibling screens (the Settings tabs among them) never re-open it.
  it.each([...FROZEN_ROUTE_IDS, ...NEW_ROUTE_IDS, ...INTERNAL_ROUTE_IDS])(
    "#%s is route-full unless it is Talk's full page",
    (id) => {
      const { context, appClasses } = clientInMinimalDom();
      runInContext(`setRoute(${JSON.stringify(id)});`, context);
      expect(appClasses.has("route-full")).toBe(id !== "dashboard");
    },
  );

  it("walks all thirteen frozen ids and the five new ones", () => {
    expect(FROZEN_ROUTE_IDS).toHaveLength(13);
    expect(NEW_ROUTE_IDS).toHaveLength(5);
    expect(new Set([...FROZEN_ROUTE_IDS, ...NEW_ROUTE_IDS]).size).toBe(18);
  });

  it("every folded route lights a rail item that the rendered rail carries", () => {
    const html = renderDashboardV11Html({ embedClient: false });
    const nav = html.match(/<nav id="sidebar-nav"[^>]*>([\s\S]*?)<\/nav>/)![1]!;
    const railIds = [...nav.matchAll(/data-route="([^"]+)"/g)].map((m) => m[1]);
    const { context } = clientInMinimalDom();
    const parents = runInContext("ROUTE_RAIL_PARENT", context) as Record<string, string | null>;
    for (const id of [...FROZEN_ROUTE_IDS, ...NEW_ROUTE_IDS, ...INTERNAL_ROUTE_IDS]) {
      expect(Object.prototype.hasOwnProperty.call(parents, id), id).toBe(true);
      const parent = parents[id];
      // Talk is a top-bar button, so it lights no rail item.
      if (id === "dashboard") expect(parent).toBeNull();
      else expect(railIds, id).toContain(parent);
    }
  });

  it("the rail is exactly eight destinations, then Integrations and Settings under Configure", () => {
    const html = renderDashboardV11Html({ embedClient: false });
    const nav = html.match(/<nav id="sidebar-nav"[^>]*>([\s\S]*?)<\/nav>/)![1]!;
    const entries = [...nav.matchAll(/<a href="([^"]+)"[^>]*>[\s\S]*?<span class="rail-label">([^<]+)<\/span>|<div class="nav-group-label">([^<]+)<\/div>/g)]
      .map((m) => (m[3] ? `group:${m[3]}` : `${m[2]} ${m[1]}`));
    expect(entries).toEqual([
      "Overview #posture",
      "Approvals #approvals",
      "Agents #agents",
      "Machines /fleet",
      "Enforcement #enforcement",
      "Findings #findings",
      "Evidence #activity",
      "Policies #policy",
      "group:Configure",
      "Integrations #integrations",
      "Settings #settings",
    ]);
    // Nothing else is a rail destination: every link in the nav is one of the ten.
    expect([...nav.matchAll(/<a /g)]).toHaveLength(10);
  });
});
