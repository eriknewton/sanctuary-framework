/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-4 credential honeypot regression suite.
 */

import { describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { TrapRegistry } from "../../src/honeypot/trap-registry.js";
import { compileHoneypot } from "../../src/honeypot/honeypot-compiler.js";
import { CredentialTrapRuntime } from "../../src/honeypot/credential-trap-runtime.js";
import {
  HONEYPOT_API_PREFIX,
  handleHoneypotRoute,
  handleHoneypotTriggerIfMatch,
} from "../../src/honeypot/runtime-trap-handler.js";
import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  type CredentialType,
  type TrapSpec,
} from "../../src/honeypot/types.js";
import { runHoneypotCli } from "../../src/honeypot/cli.ts";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_pi4";

interface Rig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: TrapRegistry;
  runtime: CredentialTrapRuntime;
}

async function makeRig(opts?: {
  fortressId?: string;
  now?: () => Date;
}): Promise<Rig> {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const registry = new TrapRegistry();
  const runtime = new CredentialTrapRuntime({
    registry,
    findingStore,
    auditLog,
    operatorId: OPERATOR,
    fortressId,
    ...(opts?.now ? { now: opts.now } : {}),
  });
  return { storage, masterKey, auditLog, findingStore, registry, runtime };
}

function mkCredentialSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  return {
    trap_id: overrides.trap_id ?? "cred-trap-1",
    trap_class: "credential",
    trigger: overrides.trigger ?? {
      kind: "credential",
      fake_credential_name: "stripe_prod_secret",
      fake_credential_type: "api_key",
      fake_credential_value: "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
      visibility: "all_wrapped_agents",
      emission_paths: ["secret_broker"],
      fake_response_on_use:
        "HTTP/1.1 401 Unauthorized\n{\"error\":\"invalid_api_key\"}",
      monitored_target_hosts: ["api.stripe.com"],
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text:
      overrides.english_text ??
      "Deploy a fake stripe_prod_secret API key visible to all agents.",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date().toISOString(),
  };
}

describe("WP-V1.3-5 Pi-4 compiler: credential class", () => {
  for (const fixture of [
    {
      type: "api_key" as CredentialType,
      value: "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
      name: "stripe_prod_secret",
    },
    {
      type: "password" as CredentialType,
      value: "Ridge-Atlas-91-Velvet",
      name: "admin_db_password",
    },
    {
      type: "oauth_refresh" as CredentialType,
      value: "1//0gXyZpQ9mN7bVcD4eF6hJ8kL2rT5wA3sE",
      name: "google_refresh_token",
    },
  ]) {
    it(`LLM Path A parses credential TrapSpec for ${fixture.type}`, async () => {
      const selector = makeStubSelector({
        capability: { summarize: true, classify: false, redact: false },
        summarize: async () => ({
          body: {
            kind: "summarize",
            text: JSON.stringify({
              trap_class: "credential",
              fake_credential_name: fixture.name,
              fake_credential_type: fixture.type,
              fake_credential_value: fixture.value,
              visibility: "all_wrapped_agents",
              emission_paths: ["secret_broker"],
              fake_response_on_use:
                "HTTP/1.1 401 Unauthorized\n{\"error\":\"invalid_api_key\"}",
              monitored_target_hosts: ["api.example.com"],
              finding_severity: "alert",
              explanation_paragraph: "Fake credential catches secret probes.",
            }),
          },
        }),
      });
      const result = await compileHoneypot(
        {
          english_text: `Deploy a fake ${fixture.name} credential.`,
          operator_id: OPERATOR,
          observed_at: new Date().toISOString(),
        },
        { selector },
      );
      expect(result.source).toBe("llm");
      expect(result.spec.trap_class).toBe("credential");
      expect(result.spec.trigger.kind).toBe("credential");
      if (result.spec.trigger.kind === "credential") {
        expect(result.spec.trigger.fake_credential_type).toBe(fixture.type);
        expect(result.spec.trigger.fake_credential_name).toBe(fixture.name);
      }
    });
  }

  it("LLM Path A rejects implausible credential values and falls back", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "credential",
            fake_credential_name: "stripe_prod_secret",
            fake_credential_type: "api_key",
            fake_credential_value: "fake",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text:
          "Deploy a fake stripe_prod_secret API key visible through the secret broker.",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("heuristic");
    expect(result.warnings.some((w) => /invalid_fake_credential_value/.test(w))).toBe(true);
    expect(result.spec.trap_class).toBe("credential");
  });

  it("heuristic Path B compiles English credential bait", async () => {
    const result = await compileHoneypot({
      english_text:
        "Deploy a fake stripe_prod_secret API key visible to all agents via secret broker; if used against api.stripe.com, audit the attempt.",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.source).toBe("heuristic");
    expect(result.spec.trap_class).toBe("credential");
    if (result.spec.trigger.kind === "credential") {
      expect(result.spec.trigger.fake_credential_name).toBe("stripe_prod_secret");
      expect(result.spec.trigger.monitored_target_hosts).toEqual([
        "api.stripe.com",
      ]);
    }
  });
});

describe("WP-V1.3-5 Pi-4 runtime credential deployment", () => {
  it("secret broker emission lists and returns a visible fake credential", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    expect(rig.runtime.listVisibleCredentials("cline", "secret_broker")).toEqual([
      {
        name: "stripe_prod_secret",
        type: "api_key",
        emission_path: "secret_broker",
      },
    ]);
    const read = await rig.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    expect(read.handled).toBe(true);
    if (read.handled) expect(read.value).toMatch(/^ak_live_/);
  });

  it("env var emission exports a stable variable name for visible agents", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkCredentialSpec({
        trigger: {
          kind: "credential",
          fake_credential_name: "admin_api_key",
          fake_credential_type: "api_key",
          fake_credential_value: "ak_live_91N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
          visibility: "all_wrapped_agents",
          emission_paths: ["env_var_export"],
        },
      }),
    );
    expect(rig.runtime.envExportsForAgent("cline")).toEqual({
      ADMIN_API_KEY: "ak_live_91N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
    });
  });

  it("config file emission preserves per-agent visibility", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkCredentialSpec({
        trigger: {
          kind: "credential",
          fake_credential_name: "billing_session_token",
          fake_credential_type: "session_token",
          fake_credential_value: "sess_liv_7HnF2qKp9TzM4xRb6WcY8vLs3Ea",
          visibility: "specific_agents",
          visible_to_agents: ["cline"],
          emission_paths: ["config_file"],
        },
      }),
    );
    expect(rig.runtime.configEntriesForAgent("cline")).toHaveProperty(
      "billing_session_token",
    );
    expect(rig.runtime.configEntriesForAgent("other")).toEqual({});
  });
});

describe("WP-V1.3-5 Pi-4 trap activation on credential read", () => {
  it("emits sentinel finding and returns the fake value", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    const read = await rig.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    expect(read.handled).toBe(true);
    const findings = await rig.findingStore.listFindings({ limit: 100 });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.sentinel_id).toBe(
      `${HONEYPOT_SENTINEL_ID_PREFIX}cred-trap-1`,
    );
    expect(JSON.stringify(findings[0])).not.toContain(
      "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
    );
  });

  it("audit emission includes caller, emission path, access pattern, and timestamped finding", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    await rig.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    const entries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    const trigger = entries.find((e) => e.operation === HONEYPOT_AUDIT_OPS.TRIGGERED);
    expect(trigger).toBeDefined();
    expect(trigger!.details?.caller_identity).toBe("agent:cline");
    expect(trigger!.details?.emission_path).toBe("secret_broker");
    expect(trigger!.details?.access_pattern).toBe("read");
    expect(trigger!.details?.credential_value_hash).toMatch(/^[a-f0-9]{32}$/);
  });

  it("read attempts outside visibility do not fire", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkCredentialSpec({
        trigger: {
          kind: "credential",
          fake_credential_name: "admin_db_password",
          fake_credential_type: "password",
          fake_credential_value: "Ridge-Atlas-91-Velvet",
          visibility: "specific_agents",
          visible_to_agents: ["cline"],
          emission_paths: ["secret_broker"],
        },
      }),
    );
    const read = await rig.runtime.readCredential(
      "admin_db_password",
      "agent:other",
      "secret_broker",
    );
    expect(read.handled).toBe(false);
    expect((await rig.findingStore.listFindings({ limit: 100 }))).toHaveLength(0);
  });
});

describe("WP-V1.3-5 Pi-4 credential use attempts", () => {
  it("records second finding and Castle Wall blocked-egress audit when the fake credential is used", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    await rig.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    const attempt = await rig.runtime.recordUseAttempt({
      credentialValue: "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
      callerIdentity: "agent:cline",
      targetHost: "api.stripe.com",
      targetPath: "/v1/charges",
    });
    expect(attempt.handled).toBe(true);
    if (attempt.handled) {
      expect(attempt.statusCode).toBe(401);
      expect(attempt.responseBody).toContain("invalid_api_key");
      expect(attempt.responseBody).not.toMatch(/honeypot|trap|fake/i);
    }
    const findings = await rig.findingStore.listFindings({ limit: 100 });
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.details.usage_attempted === true)).toBe(true);
    const audit = (await rig.auditLog.query({ layer: "l1", limit: 100 })).entries;
    expect(audit.some((e) => e.operation === "egress_blocked")).toBe(true);
  });

  it("front-of-dispatch hook blocks HTTP use attempts with a plausible 401", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotTriggerIfMatch(
        {
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: FORTRESS_A,
          credentialRuntime: rig.runtime,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(204).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    try {
      const res = await fetch(`http://127.0.0.1:${addr.port}/v1/charges`, {
        method: "POST",
        headers: {
          "x-sanctuary-agent": "cline",
          "x-sanctuary-upstream-host": "api.stripe.com",
          "x-api-key": "ak_live_51N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
        },
      });
      expect(res.status).toBe(401);
      expect(await res.text()).toContain("invalid_api_key");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("WP-V1.3-5 Pi-4 stats, API, CLI, isolation", () => {
  it("multi-emission-path traps surface across broker, env, and config paths", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkCredentialSpec({
        trigger: {
          kind: "credential",
          fake_credential_name: "admin_api_key",
          fake_credential_type: "api_key",
          fake_credential_value: "ak_live_81N7bVcD4eF6hJ8kL2rT5wA3sE9xQ",
          visibility: "all_wrapped_agents",
          emission_paths: ["secret_broker", "env_var_export", "config_file"],
        },
      }),
    );
    expect(rig.runtime.listVisibleCredentials("cline", "secret_broker")).toHaveLength(1);
    expect(rig.runtime.envExportsForAgent("cline")).toHaveProperty("ADMIN_API_KEY");
    expect(rig.runtime.configEntriesForAgent("cline")).toHaveProperty("admin_api_key");
  });

  it("management route exposes credential-trap stats for dashboard drilldown", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    await rig.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: FORTRESS_A,
          credentialRuntime: rig.runtime,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    try {
      const res = await fetch(
        `http://127.0.0.1:${addr.port}${HONEYPOT_API_PREFIX}/credential-traps`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: { traps: Array<{ read_count: number }> } };
      expect(body.data.traps[0]!.read_count).toBe(1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("CLI credential-traps list surfaces deployed credential traps", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    const streams = captureStreams();
    const exit = await runHoneypotCli(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
        credentialTrapStats: () => rig.runtime.stats(),
      },
      {
        argv: ["credential-traps", "list"],
        out: streams.out as unknown as NodeJS.WritableStream,
        err: streams.err as unknown as NodeJS.WritableStream,
      },
    );
    expect(exit).toBe(0);
    expect(streams.out.text).toContain("stripe_prod_secret");
  });

  it("multi-fortress isolation keeps credential findings scoped", async () => {
    const rigA = await makeRig({ fortressId: FORTRESS_A });
    const rigB = await makeRig({ fortressId: FORTRESS_B });
    rigA.registry.deploy(mkCredentialSpec());
    rigB.registry.deploy(mkCredentialSpec({ trap_id: "cred-trap-b" }));
    await rigA.runtime.readCredential(
      "stripe_prod_secret",
      "agent:cline",
      "secret_broker",
    );
    expect((await rigA.findingStore.listFindings({ limit: 100 }))).toHaveLength(1);
    expect((await rigB.findingStore.listFindings({ limit: 100 }))).toHaveLength(0);
  });

  it("castle-walking: credential deployment is server-local and does not create outbound selector calls", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkCredentialSpec());
    expect(rig.runtime.listVisibleCredentials("cline")).toHaveLength(1);
    const entries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    expect(entries).toHaveLength(0);
  });
});

interface StubSelectorOpts {
  capability: { summarize: boolean; classify: boolean; redact: boolean };
  summarize?: () => Promise<{ body: { kind: "summarize"; text: string } }>;
}

function makeStubSelector(opts: StubSelectorOpts): any {
  const summarizeImpl =
    opts.summarize ??
    (async () => ({ body: { kind: "summarize", text: "{}" } }));
  return {
    getSubstrate: async () => ({
      surface: "template-suggestion",
      substrate: "local",
      capability: opts.capability,
      badge: {
        surface: "template-suggestion",
        substrate: "local",
        labelKey: "test",
        tradeoffKey: "test",
        status: "green",
      },
      displayLabel: "Test",
    }),
    invokeSummarize: async () => {
      const r = await summarizeImpl();
      return {
        servedBy: "local",
        failureClass: null,
        body: r.body,
        completedAt: new Date().toISOString(),
        latencyMs: 1,
      };
    },
  };
}

function captureStreams(): {
  out: { write: (s: string) => boolean; text: string };
  err: { write: (s: string) => boolean; text: string };
} {
  let outText = "";
  let errText = "";
  return {
    out: {
      write: (s: string) => {
        outText += s;
        return true;
      },
      get text() {
        return outText;
      },
    },
    err: {
      write: (s: string) => {
        errText += s;
        return true;
      },
      get text() {
        return errText;
      },
    },
  };
}
