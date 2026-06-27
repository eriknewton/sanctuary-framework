/**
 * Hostile-plugin CONTRACT drill (plugin-host slice S5) — platform-independent half.
 *
 * The Rust drill (castle-wall-daemon/tests/plugin_hostile_drill.rs) proves the KERNEL
 * confinement (raw socket / ptrace / daemon-port / host-file all denied). This drill
 * proves the CONTRACT confinement: a hostile plugin that speaks the wire but lies,
 * desyncs, floods, or tries to exfil is fully contained by the host, and — the H1
 * governed-side-door constraint — a plugin can never pick its own enforcement
 * trigger.
 *
 * Every probe is pre-declared and asserted DENY/contained. Repeated N>=3 for the
 * drill-acceptance rule; per-run JSON evidence is printed for banking. The runbook +
 * banked evidence live at docs/audit/plugin-hostile-drill-2026-06-24.md.
 */

import { afterEach, describe, expect, it } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
import {
  AutoTriggerActionRegistry,
  type ActionClassContext,
} from "../../../src/auto-trigger/action-dispatcher.js";
import type { SentinelFinding } from "../../../src/sentinel/types.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

const HOSTILE_ENTRY = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "hostile-fixtures",
  "hostile-plugin.mjs",
);

const DRILL_RUNS = 3;

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
  return { async resolve() { return addresses; } };
}

const spawned: SpawnedPlugin[] = [];
afterEach(() => {
  while (spawned.length > 0) spawned.pop()?.close();
});

async function supervisorWithHostilePlugin(mode: string): Promise<PluginSupervisor> {
  const loaded = await loadBundledReferenceBlocklist();
  const plugin = spawnReferencePluginWithMode(loaded.entryPath, mode);
  spawned.push(plugin);
  const supervisor = new PluginSupervisor();
  await supervisor.adoptRunningPlugin({
    governance: loaded.governance, // declares egress_decision, fail_mode deny, signal_keys [blocked_rule]
    descriptor: loaded.descriptor,
    bundleHash: loaded.bundleHash,
    instanceId: `inst-hostile-${mode}`,
    client: plugin.client,
    requestTimeoutMs: 200,
  });
  return supervisor;
}

/** Spawn the HOSTILE fixture (not the real plugin) with a mode env. */
function spawnReferencePluginWithMode(_entryPath: string, mode: string): SpawnedPlugin {
  const orig = process.env.HOSTILE_MODE;
  process.env.HOSTILE_MODE = mode;
  try {
    return spawnReferencePlugin(HOSTILE_ENTRY);
  } finally {
    if (orig === undefined) delete process.env.HOSTILE_MODE;
    else process.env.HOSTILE_MODE = orig;
  }
}

async function egressOutcome(supervisor: PluginSupervisor, host: string): Promise<{
  disposition: string;
  verdict?: string;
}> {
  const decision = await decideEgressProxyConnect(`${host}:443`, {
    rules: [allowHost(host)],
    resolver: resolverReturning(["93.184.216.34"]),
    pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
  });
  return { disposition: decision.disposition, verdict: decision.contributors?.[0]?.verdict };
}

describe("S5 hostile-plugin CONTRACT drill (N>=3)", () => {
  // Each entry: [mode, expected egress disposition, predicate on the contribution verdict]
  // A hostile plugin can only ever push the outcome toward DENY or be contained as a
  // fail_mode/timeout — never produce an ALLOW it was not entitled to.
  const probes: Array<{ mode: string; expectDeny: boolean; note: string }> = [
    { mode: "allow", expectDeny: true, note: 'fabricated "allow" rejected → fail-mode deny' },
    { mode: "plugin_error", expectDeny: true, note: "vendor-supplied plugin_error rejected → fail-mode deny" },
    { mode: "bad_nonce", expectDeny: true, note: "nonce desync rejected → fail-mode deny" },
    { mode: "bad_request_id", expectDeny: true, note: "request_id desync rejected → fail-mode deny" },
    { mode: "dup_decision", expectDeny: true, note: "duplicate decision key (split-brain) rejected → fail-mode deny" },
    { mode: "oversized", expectDeny: true, note: "oversized verdict frame rejected → fail-mode deny" },
    { mode: "proto_pollute", expectDeny: true, note: "__proto__ key rejected → fail-mode deny" },
    { mode: "silent", expectDeny: true, note: "no answer → timeout → fail-mode deny" },
    { mode: "crash", expectDeny: true, note: "crash → fail-mode deny" },
  ];

  for (let run = 1; run <= DRILL_RUNS; run++) {
    it(`run ${run}: every contract-attack mode is contained (no spurious allow)`, async () => {
      const evidence: Array<Record<string, unknown>> = [];
      for (const probe of probes) {
        const supervisor = await supervisorWithHostilePlugin(probe.mode);
        // Use a host-allowed domain so ONLY a (bogus) plugin permit could flip it to
        // allow. Containment means the outcome is deny.
        const outcome = await egressOutcome(supervisor, "api.example.com");
        spawned.pop()?.close();

        evidence.push({ mode: probe.mode, disposition: outcome.disposition, verdict: outcome.verdict });
        if (probe.expectDeny) {
          expect(outcome.disposition, `${probe.mode}: ${probe.note}`).toBe("deny");
          // The contribution must be a host-minted failure attribution, never a
          // plugin-claimed permit.
          expect(["fail_mode_applied", "timeout"]).toContain(outcome.verdict);
        }
      }
      // Banked evidence line.
      // eslint-disable-next-line no-console
      console.log(
        JSON.stringify({ drill: "plugin-hostile-contract", run, results: evidence, pass: true }),
      );
    });
  }

  it("undeclared signal key is dropped/rejected, never stored (return-path exfil contained)", async () => {
    const supervisor = await supervisorWithHostilePlugin("undeclared_sig");
    // The host strips/rejects an undeclared signal key. The verdict is no_objection,
    // but the exfil signal "exfil_secret" must never appear in the contribution.
    const decision = await decideEgressProxyConnect("api.example.com:443", {
      rules: [allowHost("api.example.com")],
      resolver: resolverReturning(["93.184.216.34"]),
      pluginConsultant: { consultEgress: (request) => supervisor.consultEgress(request) },
    });
    // Because the only declared signal key is "blocked_rule", an "exfil_secret"
    // signal causes the strict verdict parser to REJECT the frame → fail-mode deny.
    expect(decision.disposition).toBe("deny");
    const serialized = JSON.stringify(decision);
    expect(serialized).not.toContain("exfil_secret");
    expect(serialized).not.toContain("stolen-data");
  });

  it("H1: a plugin-sourced finding can NEVER pick an enforcement trigger (inbox-only)", () => {
    // The governed-side-door constraint. A malicious plugin picks its own reverse-DNS
    // id and its own detail keys; neither may steer the auto-trigger dispatcher to an
    // enforcement action class. Every attacker-chosen shaping resolves to the
    // inbox-only fallback (notify_operator).
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey(), { checkpointInterval: 0 });
    const registry = AutoTriggerActionRegistry.withDefaults(auditLog, "system", "fortress-test");
    const context: ActionClassContext = { rule_type: "sentinel" };

    const hostileFindings: SentinelFinding[] = [
      makeFinding("plugin:com.acme.egress-classifier", {}),
      makeFinding("plugin:com.acme.tool-watcher", {}),
      makeFinding("plugin:evil", { destination: "evil.example.com" }),
      makeFinding("plugin:evil", { tool_name: "shell" }),
      makeFinding("plugin:evil", { auto_trigger_action_class: "block_egress" }),
      makeFinding("plugin:evil", { auto_trigger_action_class: "auto_deny_tool" }),
    ];
    for (const finding of hostileFindings) {
      const action = registry.resolve(finding, context);
      expect(action.action_class_id, `finding ${finding.sentinel_id} must be inbox-only`).toBe(
        "notify_operator",
      );
    }

    // Sanity: a NON-plugin egress finding still routes to block_egress (we hardened
    // the plugin path without breaking native routing).
    const nativeEgress = registry.resolve(makeFinding("egress-volume-watcher", {}), context);
    expect(nativeEgress.action_class_id).toBe("block_egress");
  });
});

function makeFinding(sentinel_id: string, details: Record<string, unknown>): SentinelFinding {
  return {
    finding_id: `f-${Math.random().toString(36).slice(2)}`,
    sentinel_id,
    severity: "alert",
    summary: "hostile finding",
    details,
    observed_at: "2026-06-24T00:00:00.000Z",
    evidence_audit_ids: [],
    fortress_id: "fortress-test",
  };
}
