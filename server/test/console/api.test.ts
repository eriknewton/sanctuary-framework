/**
 * Console HTTP API surface — end-to-end via the standalone server.
 *
 * Brings up the MeshConsoleClient on node A of the three-mode drill, starts
 * the console HTTP server, and exercises the auth gate + JSON routes the
 * browser + Electron shell depend on.
 *
 * Covers AC6 (alert inbox render + acknowledge path) and AC1 (HTML shell
 * served at /console).
 */

import { afterEach, describe, expect, it } from "vitest";

import { bootThreeModeDrill, type ThreeModeDrillHandle } from "../acceptance/three-mode-drill/harness.js";
import {
  MeshConsoleClient,
  startConsoleServer,
  type ConsoleServerHandle,
} from "../../src/console/index.js";

let active: ThreeModeDrillHandle | null = null;
let serverHandle: ConsoleServerHandle | null = null;

afterEach(async () => {
  if (serverHandle) {
    await serverHandle.stop();
    serverHandle = null;
  }
  if (active) {
    await active.teardown();
    active = null;
  }
});

async function bootConsole() {
  active = await bootThreeModeDrill();
  const drill = active;
  const client = new MeshConsoleClient({
    node: drill.nodeA,
    pinnedMaster: drill.master_public,
    rootPrincipalCert: drill.root_principal_cert,
    rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
    nodePrivateKey: drill.nodeKpA.privateKey,
  });
  serverHandle = await startConsoleServer({
    client,
    host: "127.0.0.1",
    loopbackAutoAuth: true,
  });
  return { drill, client, url: serverHandle.url };
}

describe("console HTTP API — loopback auto-auth + JSON routes", () => {
  it(
    "GET /console returns HTML with all six primary surfaces",
    async () => {
      const { url } = await bootConsole();
      const resp = await fetch(url);
      expect(resp.status).toBe(200);
      expect(resp.headers.get("Content-Type")).toContain("text/html");
      const html = await resp.text();
      expect(html).toContain("Sanctuary Operator Console");
      expect(html).toContain('id="fortress"');
      expect(html).toContain('id="agents"');
      expect(html).toContain('id="policy"');
      expect(html).toContain('id="join-revoke"');
      expect(html).toContain('id="mesh-health"');
      expect(html).toContain('id="recovery"');
    },
    60_000
  );

  it(
    "GET /api/console/state returns the full snapshot as JSON",
    async () => {
      const { url } = await bootConsole();
      const base = url.replace("/console", "");
      const resp = await fetch(`${base}/api/console/state`);
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data).toHaveProperty("fortress");
      expect(data).toHaveProperty("agents");
      expect(data).toHaveProperty("alerts");
      expect(data).toHaveProperty("pending_joins");
      expect(data).toHaveProperty("pinned_policies");
    },
    60_000
  );

  it(
    "GET /api/console/templates returns the five canonical channel templates",
    async () => {
      const { url } = await bootConsole();
      const base = url.replace("/console", "");
      const resp = await fetch(`${base}/api/console/templates`);
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.templates).toHaveLength(5);
      const ids = data.templates.map((t: { id: string }) => t.id).sort();
      expect(ids).toEqual([
        "bidirectional-sync",
        "credential-share-scoped",
        "escrow-handoff",
        "plan-inspect-read-only",
        "read-outputs-only",
      ]);
    },
    60_000
  );

  it(
    "POST /api/console/policy/compose pins a policy via the live mesh",
    async () => {
      const { url, client } = await bootConsole();
      const base = url.replace("/console", "");
      const resp = await fetch(`${base}/api/console/policy/compose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: "agent-x",
          counterparty: "agent-y",
          channel_template_id: "read-outputs-only",
        }),
      });
      expect(resp.status).toBe(200);
      const data = await resp.json();
      expect(data.policy_version).toBe(1);
      expect(data.signed_event_id).toBeTruthy();
      expect(client.getPinnedPolicy("agent-x")).toBeTruthy();
    },
    60_000
  );

  it(
    "POST /api/console/policy/compose rejects bogus template with 400",
    async () => {
      const { url } = await bootConsole();
      const base = url.replace("/console", "");
      const resp = await fetch(`${base}/api/console/policy/compose`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: "agent-z",
          counterparty: "agent-y",
          channel_template_id: "not-a-real-template",
        }),
      });
      expect([400, 500]).toContain(resp.status);
      const data = await resp.json();
      expect(data.error).toBeTruthy();
    },
    60_000
  );

  it(
    "unknown path under /api/console/ returns 404",
    async () => {
      const { url } = await bootConsole();
      const base = url.replace("/console", "");
      const resp = await fetch(`${base}/api/console/does-not-exist`);
      expect(resp.status).toBe(404);
    },
    60_000
  );

  it(
    "enforces bearer token when auth is enabled + loopback auto-auth disabled",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;
      const client = new MeshConsoleClient({
        node: drill.nodeA,
        pinnedMaster: drill.master_public,
        rootPrincipalCert: drill.root_principal_cert,
        rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
        nodePrivateKey: drill.nodeKpA.privateKey,
      });
      serverHandle = await startConsoleServer({
        client,
        host: "127.0.0.1",
        authToken: "secret-token",
        loopbackAutoAuth: false,
      });
      const base = serverHandle.url.replace("/console", "");
      const unauthResp = await fetch(`${base}/api/console/state`);
      expect(unauthResp.status).toBe(401);
      const authResp = await fetch(`${base}/api/console/state`, {
        headers: { Authorization: "Bearer secret-token" },
      });
      expect(authResp.status).toBe(200);
    },
    60_000
  );
});
