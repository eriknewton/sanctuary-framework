import { describe, expect, it, vi } from "vitest";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import { decideEgressProxyConnect, type EgressProxyResolver } from "../../src/castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  PluginInvocationError,
  PluginSupervisor,
  type Governance,
  type PluginRuntimeClient,
  type PluginSupervisorOptions,
  type PluginVerdict,
} from "../../src/substrate/index.js";
import { buildValidBundle } from "./helpers.js";

function allowHost(host: string, port = 443): AllowlistRule {
  return {
    id: `allow-${host}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-06-23T00:00:00.000Z",
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

function governance(fields = ["egress.host", "egress.port", "egress.protocol"]): Governance {
  return {
    plugin_id: "ai.example.blocklist",
    version: "1.0.0",
    channel: "stable",
    entry: "bin/blocklist",
    hooks: [{ hook_class: "egress_decision", fields, fail_mode: "deny" }],
    endpoints: [],
    signal_keys: ["score"],
  };
}

class ScriptedClient implements PluginRuntimeClient {
  readonly payloads: Record<string, unknown>[] = [];

  constructor(
    private readonly handler: (
      payload: Record<string, unknown>,
      expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
    ) => Promise<PluginVerdict> | PluginVerdict,
  ) {}

  async request(
    payload: Record<string, unknown>,
    expected: { request_id: string; nonce: string; declaredSignalKeys: readonly string[] },
  ): Promise<PluginVerdict> {
    this.payloads.push(payload);
    return this.handler(payload, expected);
  }
}

async function supervisorWithClient(
  client: PluginRuntimeClient,
  options?: PluginSupervisorOptions,
  fields?: string[],
): Promise<PluginSupervisor> {
  const bundle = buildValidBundle();
  const supervisor = new PluginSupervisor(options);
  await supervisor.adoptRunningPlugin({
    governance: governance(fields),
    descriptor: bundle.descriptor,
    bundleHash: "sha256:bundle",
    instanceId: "inst-test",
    client,
  });
  return supervisor;
}

describe("plugin-host S4 supervisor and egress consultation", () => {
  it("does not let plugin no_objection flip a host-denied egress to allow", async () => {
    const client = new ScriptedClient((_payload, expected) => ({
      decision: "no_objection",
      request_id: expected.request_id,
      nonce: expected.nonce,
      rationale: "no objection",
      confidence: 0.99,
    }));
    const supervisor = await supervisorWithClient(client);

    const decision = await decideEgressProxyConnect("blocked.example:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    expect(decision.disposition).toBe("deny");
    expect(decision).toMatchObject({
      reason: "allowlist_miss",
      contributors: [{ plugin_id: "ai.example.blocklist", verdict: "no_objection" }],
    });
  });

  it("applies egress fail-mode deny when a plugin crashes mid-request", async () => {
    const client = new ScriptedClient(() => {
      throw new PluginInvocationError("crash", "boom");
    });
    const supervisor = await supervisorWithClient(client);

    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    expect(decision.disposition).toBe("deny");
    expect(decision).toMatchObject({
      reason: "plugin_decision",
      contributors: [{ verdict: "fail_mode_applied", rationale: "plugin invocation failed" }],
    });
  });

  it("rejects a replayed request nonce and fails closed for egress", async () => {
    const client = new ScriptedClient((_payload, expected) => ({
      decision: "no_objection",
      request_id: expected.request_id,
      nonce: expected.nonce,
      rationale: "ok",
    }));
    const supervisor = await supervisorWithClient(client, { nonceSource: () => "replayed-nonce" });
    const options = {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    };

    const first = await decideEgressProxyConnect("api.example.com:443", options);
    const second = await decideEgressProxyConnect("api.example.com:443", options);

    expect(first.disposition).toBe("allow");
    expect(second.disposition).toBe("deny");
    expect(second).toMatchObject({
      reason: "plugin_decision",
      contributors: [{ verdict: "fail_mode_applied", rationale: "replayed request nonce rejected" }],
    });
  });

  it("marshals only declared egress fields to the plugin", async () => {
    const client = new ScriptedClient((_payload, expected) => ({
      decision: "no_objection",
      request_id: expected.request_id,
      nonce: expected.nonce,
      rationale: "ok",
    }));
    const supervisor = await supervisorWithClient(client, undefined, ["egress.host"]);

    await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });

    expect(client.payloads).toHaveLength(1);
    expect(client.payloads[0]).toMatchObject({
      request_id: expect.any(String),
      nonce: expect.any(String),
      hook_class: "egress_decision",
      host: "api.example.com",
    });
    expect(client.payloads[0]).not.toHaveProperty("port");
    expect(client.payloads[0]).not.toHaveProperty("protocol");
    expect(client.payloads[0]).not.toHaveProperty("origin");
    expect(client.payloads[0]).not.toHaveProperty("agent_id");
    expect(client.payloads[0]).not.toHaveProperty("session_id");
    expect(client.payloads[0]).not.toHaveProperty("timestamp");
  });

  it("keeps audit-chain verification green over entries carrying contributors", async () => {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey(), { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_decision",
      identity_id: "system",
      result: "failure",
      details: { authority: "api.example.com:443", reason: "plugin_decision" },
      contributors: [
        {
          plugin_id: "ai.example.blocklist",
          bundle_hash: "sha256:bundle",
          instance_id: "inst-test",
          hook_class: "egress_decision",
          verdict: "deny",
          confidence: 0.88,
          rationale: "blocked",
          latency_ms: 7,
        },
      ],
    });

    const query = await auditLog.query({ limit: 10 });
    expect(query.integrity_findings).toEqual([]);
    expect(query.entries[0]?.contributors?.[0]).toMatchObject({
      plugin_id: "ai.example.blocklist",
      verdict: "deny",
    });
    const verified = await auditLog.verifiedChainView();
    expect(verified).toHaveLength(1);
    expect(verified[0]!.entry.contributors?.[0]?.plugin_id).toBe("ai.example.blocklist");
  });

  it("auto-suspends a deny-flooding plugin, audits the valve, then falls back to the host decision", async () => {
    const auditSink = { appendCritical: vi.fn(async () => {}) };
    const client = new ScriptedClient((_payload, expected) => ({
      decision: "deny",
      request_id: expected.request_id,
      nonce: expected.nonce,
      rationale: "deny everything",
    }));
    const supervisor = await supervisorWithClient(
      client,
      { auditSink, denyFlood: { minEvaluations: 3, windowSize: 3, denyRate: 1 } },
    );
    const options = {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    };

    await decideEgressProxyConnect("api.example.com:443", options);
    await decideEgressProxyConnect("api.example.com:443", options);
    const third = await decideEgressProxyConnect("api.example.com:443", options);
    const afterSuspend = await decideEgressProxyConnect("api.example.com:443", options);

    expect(third.disposition).toBe("deny");
    expect(afterSuspend.disposition).toBe("allow");
    expect(afterSuspend.contributors?.[0]).toMatchObject({ verdict: "unhealthy_skipped" });
    expect(auditSink.appendCritical).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "plugin_suspend",
        details: expect.objectContaining({ reason: "deny_flood", suspension_reason: "deny_flood" }),
      }),
    );
  });
});
