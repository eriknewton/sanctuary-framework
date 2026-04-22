/**
 * HTML surface tests — AC1 (six primary surfaces land) + AC5 (badges render
 * with deterministic class names) + AC7 (reserved v1.x surfaces appear as
 * disabled affordances, never as active nav).
 *
 * The HTML renderer takes a MeshConsoleClient snapshot and produces a single
 * document that both the browser and the Electron shell consume. These tests
 * assert on the document's shape so regressions in either shell show up
 * here first.
 */

import { afterEach, describe, expect, it } from "vitest";

import { bootThreeModeDrill, type ThreeModeDrillHandle } from "../acceptance/three-mode-drill/harness.js";
import {
  MeshConsoleClient,
  renderConsoleHTML,
  renderConsoleHTMLBytes,
  RESERVED_V1X_SURFACES,
  CONSOLE_SURFACES,
} from "../../src/console/index.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

function consoleForNodeA(drill: ThreeModeDrillHandle): MeshConsoleClient {
  return new MeshConsoleClient({
    node: drill.nodeA,
    pinnedMaster: drill.master_public,
    rootPrincipalCert: drill.root_principal_cert,
    rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
    nodePrivateKey: drill.nodeKpA.privateKey,
  });
}

describe("WP-MVP-2 console HTML — six primary surfaces (AC1)", () => {
  it(
    "renders every active surface as a <section> and every reserved v1.x surface as a disabled nav item",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);

      const html = renderConsoleHTML(client);

      // AC1: each active surface has its own <section id="..."> block.
      for (const surface of CONSOLE_SURFACES) {
        expect(html).toContain(`id="${surface}"`);
      }

      // AC7 / MSP reservation: every reserved v1.x surface appears in nav as
      // a disabled affordance (data-reserved="true") — NOT as an active
      // section.
      for (const reserved of RESERVED_V1X_SURFACES) {
        expect(html).toContain(`data-surface="${reserved}"`);
        // Ensure it is NOT emitted as an active <section>.
        expect(html).not.toContain(`<section id="${reserved}" class="surface">`);
      }
    },
    40_000
  );

  it(
    "renders the three-layer attestation badges with deterministic class names (AC5)",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);

      // Seed one agent with each of the five states so the HTML exercises the
      // full state spectrum on the per-agent + per-action layers.
      const states = ["verified", "pending", "degraded", "failed", "unknown"] as const;
      for (let i = 0; i < states.length; i++) {
        client.recordAttestationResult({
          agent_id: `agent-${i}`,
          state: states[i]!,
          action_state: states[i]!,
          policy_version: i + 1,
        });
      }

      const html = renderConsoleHTML(client);

      // Per-agent + per-action classes for each state must be present.
      for (const state of states) {
        expect(html).toContain(`att-per-agent-${state}`);
        expect(html).toContain(`att-per-action-${state}`);
      }
      // Global badge is always rendered in the fortress header.
      expect(html).toMatch(/att-global-(verified|pending|degraded|failed|unknown)/);
      // Custody-provenance v1.x stub is rendered as a reserved-class badge.
      expect(html).toContain("att-custody-provenance-stub");
      expect(html).toContain("att-v1x-reserved");
    },
    40_000
  );

  it(
    "HTML is non-trivial — bytes > 4 KB (rough sanity; catches empty render regressions)",
    async () => {
      active = await bootThreeModeDrill();
      const client = consoleForNodeA(active);

      const bytes = renderConsoleHTMLBytes(client);
      expect(bytes).toBeGreaterThan(4_000);
    },
    40_000
  );

  it("does not name any competitor product in the rendered HTML (naming-discipline)", async () => {
    active = await bootThreeModeDrill();
    const client = consoleForNodeA(active);
    const html = renderConsoleHTML(client);

    // We don't enumerate every competitor; these are the ones the
    // naming-discipline rule explicitly flags in the priority queue.
    const forbidden = ["Coze", "Dust", "Hermes", "MoltBridge", "AgentGraph", "HiveTrust"];
    for (const name of forbidden) {
      expect(html).not.toContain(name);
    }
  }, 40_000);

  it("does not contain em-dashes in the rendered HTML (no-em-dash rule)", async () => {
    active = await bootThreeModeDrill();
    const client = consoleForNodeA(active);
    const html = renderConsoleHTML(client);
    expect(html.includes("\u2014")).toBe(false);
  }, 40_000);
});
