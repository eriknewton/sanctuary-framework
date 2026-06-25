/**
 * Slice S5 end-to-end test — the reference blocklist plugin against the real egress
 * decision path.
 *
 * This drives the ACTUAL plugin process (a spawned `node bin/blocklist.mjs`) through
 * the real `FramedJsonPluginClient` ↔ `PluginSupervisor` ↔ `decideEgressProxyConnect`
 * wiring. It proves the two demo-bearing facts the design (§7, S5 acceptance) calls
 * for:
 *   1. A blocklisted domain is DENIED, attributed to the plugin via PluginContribution.
 *   2. A plugin that CRASHES mid-stream leaves egress STILL DENIED (fail-closed).
 *
 * The plugin is integrity-verified against its committed first-party signature before
 * it is ever spawned — a bundle that does not verify never runs.
 *
 * Confinement is NOT exercised here (that is the Linux hostile-probe drill); this is
 * the wire-contract + attribution + fail-closed proof, which is platform-independent.
 */

import { afterEach, describe, expect, it } from "vitest";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import {
  decideEgressProxyConnect,
  type EgressProxyResolver,
} from "../../../src/castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import {
  PluginSupervisor,
  loadBundledReferenceBlocklist,
  spawnReferencePlugin,
  type SpawnedPlugin,
} from "../../../src/substrate/index.js";

function allowHost(host: string, port = 443): AllowlistRule {
  return {
    id: `allow-${host}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-06-24T00:00:00.000Z",
    match: { host, port, protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function resolverReturning(addresses: string[]): EgressProxyResolver {
  return {
    async resolve(): Promise<string[]> {
      return addresses;
    },
  };
}

const spawned: SpawnedPlugin[] = [];

afterEach(() => {
  while (spawned.length > 0) spawned.pop()?.close();
});

async function supervisorWithRealPlugin(): Promise<PluginSupervisor> {
  const loaded = await loadBundledReferenceBlocklist();
  const plugin = spawnReferencePlugin(loaded.entryPath);
  spawned.push(plugin);
  const supervisor = new PluginSupervisor();
  await supervisor.adoptRunningPlugin({
    governance: loaded.governance,
    descriptor: loaded.descriptor,
    bundleHash: loaded.bundleHash,
    instanceId: "inst-e2e",
    client: plugin.client,
    requestTimeoutMs: 500,
  });
  return supervisor;
}

describe("S5 reference blocklist plugin — end to end", () => {
  it("integrity-verifies the bundled plugin before it can run", async () => {
    const loaded = await loadBundledReferenceBlocklist();
    expect(loaded.governance.plugin_id).toBe("ai.sanctuary.blocklist");
    expect(loaded.governance.hooks[0]?.hook_class).toBe("egress_decision");
    expect(loaded.governance.hooks[0]?.fail_mode).toBe("deny");
    expect(loaded.bundleHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("DENIES a blocklisted domain on an otherwise-allowed egress, attributed to the plugin", async () => {
    const supervisor = await supervisorWithRealPlugin();

    // Host would ALLOW evil.example.com:443 (it is on the allowlist); the plugin's
    // deny must override the host permit. This is the headline: a plugin can tighten
    // a host allow, never loosen a host deny.
    const decision = await decideEgressProxyConnect("evil.example.com:443", {
      rules: [allowHost("evil.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    expect(decision.disposition).toBe("deny");
    expect(decision.contributors).toBeDefined();
    const contribution = decision.contributors?.[0];
    expect(contribution).toMatchObject({
      plugin_id: "ai.sanctuary.blocklist",
      hook_class: "egress_decision",
      verdict: "deny",
      instance_id: "inst-e2e",
    });
    expect(contribution?.rationale).toContain("evil.example.com");
    expect(contribution?.bundle_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("lets a clean domain through (host allow + plugin no_objection = allow)", async () => {
    const supervisor = await supervisorWithRealPlugin();
    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });
    expect(decision.disposition).toBe("allow");
    expect(decision.contributors?.[0]).toMatchObject({
      plugin_id: "ai.sanctuary.blocklist",
      verdict: "no_objection",
    });
  });

  it("denies a blocklisted SUBDOMAIN (label-boundary suffix match)", async () => {
    const supervisor = await supervisorWithRealPlugin();
    const decision = await decideEgressProxyConnect("api.exfil.test:443", {
      rules: [allowHost("api.exfil.test")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });
    expect(decision.disposition).toBe("deny");
    expect(decision.contributors?.[0]).toMatchObject({ verdict: "deny" });
  });

  it("FAIL-CLOSED: a plugin killed mid-stream leaves egress DENIED", async () => {
    const loaded = await loadBundledReferenceBlocklist();
    const plugin = spawnReferencePlugin(loaded.entryPath);
    spawned.push(plugin);
    const supervisor = new PluginSupervisor();
    await supervisor.adoptRunningPlugin({
      governance: loaded.governance,
      descriptor: loaded.descriptor,
      bundleHash: loaded.bundleHash,
      instanceId: "inst-crash",
      client: plugin.client,
      requestTimeoutMs: 500,
    });

    // Kill the plugin process AND close its client so the next consultation cannot
    // get a verdict. The host must mint a failure and apply the egress fail-mode
    // (deny) — a dead detector means MORE blocking, never less.
    plugin.close();
    // Give the close a tick to propagate to the client.
    await new Promise((r) => setTimeout(r, 20));

    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    expect(decision.disposition).toBe("deny");
    expect(decision.contributors?.[0]?.verdict).toMatch(/fail_mode_applied|timeout/);
  });
});
