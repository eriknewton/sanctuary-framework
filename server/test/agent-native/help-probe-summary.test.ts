// fail-before-exempt: live probe-key generation imports the new classifier module; cadence and unbound assertions are witnessed with the cooperative surface restored to base and the classifier retained.
/** Help probe summaries retain bounded state and reserve audit rows synchronously. */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as surface from "../../src/agent-native/cooperative-surface.js";
import { classifyIntent, HELP_NEEDLES, HELP_INTENT_MAX_CHARS, HELP_MAX_VARIANTS } from "../../src/agent-native/intent-classifier.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";

// A minute contains sixty thousand milliseconds, the audit summary interval.
const interval = surface.HELP_PROBE_ROW_INTERVAL_MS ?? 60_000;
// The next power of two above the closed set of thirty-eight probe keys.
const cap = surface.HELP_PROBE_MAX_KEYS ?? 64;
const OPERATION = "sanctuary_help_probe_summary";
afterEach(() => vi.restoreAllMocks());
function setup() {
  const storage = new MemoryStorage();
  const key = generateRandomKey();
  const auditLog = new AuditLog(storage, key);
  let binding: SessionBinding | undefined;
  let now = 0;
  const setOrigin = (identityId?: string) => {
    binding = identityId === undefined ? undefined : {
      identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId),
    };
  };
  setOrigin("origin-one");
  const { tools, identityManager, namespaceRegistry } = createL1Tools(new StateStore(storage, key), storage, key, "recovery-key", auditLog);
  const help = surface.createAgentNativeCooperativeTools({ identityManager, namespaceRegistry, auditLog,
    primitiveTools: tools, currentSessionBinding: () => binding, now: () => now,
  }).tools.find(tool => tool.name === "sanctuary_help")!;
  const call = async (intent: string) => JSON.parse((await help.handler({ intent })).content[0]!.text);
  // Three origins worth of rows cover eviction and both interval rounds.
  const rows = async () => (await auditLog.query({ operation_type: OPERATION, limit: cap * 3 })).entries;
  return { auditLog, call, rows, setOrigin, advance: (ms: number) => { now += ms; } };
}
const probeIntents = [...HELP_NEEDLES, "hmm", "save and hmm", "read and save", "x".repeat(HELP_INTENT_MAX_CHARS + 1),
  Array.from({ length: HELP_MAX_VARIANTS + 1 }, (_, i) => `%61${i}x`).join(" ")];
const uniqueIntents = [...new Map(probeIntents.map(intent => [classifyIntent(intent).probe_key, intent])).values()];

describe("help probe summaries", () => {
  it("bounds one thousand distinct probe intents to one row per key per minute", async () => {
    const env = setup();
    const keys = new Set<string | undefined>();
    // One thousand variations exercise retained state beyond the closed probe-key set.
    for (let i = 0; i < 1000; i += 1) {
      const intent = `${probeIntents[i % probeIntents.length]} z${i}`;
      keys.add(classifyIntent(intent).probe_key);
      await env.call(intent);
    }
    expect(keys.size).toBeLessThanOrEqual(cap);
    expect(await env.rows()).toHaveLength(keys.size);
    for (const row of await env.rows()) expect(row.details?.samples).toHaveLength(1);
    env.advance(interval);
    for (let i = 0; i < 1000; i += 1) await env.call(`${probeIntents[i % probeIntents.length]} z${i}`);
    expect(await env.rows()).toHaveLength(keys.size * 2);
    for (const row of await env.rows()) {
      expect(row.details).toBeDefined();
      const samples = row.details!.samples as string[];
      // Each key keeps the established three samples of at most one hundred twenty characters.
      expect(samples.length).toBeLessThanOrEqual(3);
      for (const sample of samples) expect(sample.length).toBeLessThanOrEqual(120);
    }
  });
  it("evicts the key seen longest ago when the map reaches its cap", async () => {
    const env = setup();
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent })));
    expect(entries.length).toBeGreaterThan(cap);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      await env.call(entries[index]!.intent);
    };
    for (let i = 0; i < cap; i += 1) { await probe(i); env.advance(1); }
    expect(await env.rows()).toHaveLength(cap);
    await probe(0);
    env.advance(1);
    await probe(cap);
    expect(await env.rows()).toHaveLength(cap + 1);
    await probe(0);
    expect(await env.rows()).toHaveLength(cap + 1);
    await probe(1);
    expect(await env.rows()).toHaveLength(cap + 2);
  });
  it("reserves one row for fifty concurrent probes of a key", async () => {
    const env = setup();
    await Promise.all(Array.from({ length: 50 }, () => env.call("export the note")));
    expect(await env.rows()).toHaveLength(1);
  });
  it("retains a reserved row slot after an append rejects", async () => {
    const env = setup();
    const append = env.auditLog.appendCritical.bind(env.auditLog);
    let attempts = 0;
    vi.spyOn(env.auditLog, "appendCritical").mockImplementation(async entry => {
      if (entry.operation === OPERATION) { attempts += 1; throw new Error("append unavailable"); }
      return append(entry);
    });
    expect(await env.call("export the note")).toMatchObject({ denied: true, remediation_class: "wait", audit_ref: "audit:sanctuary_help" });
    for (let i = 0; i < 50; i += 1) expect(await env.call("export the note")).toHaveProperty("safety_class", "gated");
    expect(attempts).toBe(1);
    env.advance(interval);
    await env.call("export the note");
    expect(attempts).toBe(2);
  });
  it("answers gated probes without an identity and uses a distinct unbound origin", async () => {
    const env = setup();
    await env.call("export the note");
    env.setOrigin();
    const answer = await env.call("export the note");
    expect(answer).toMatchObject({ safety_class: "gated", tool: null });
    for (const field of ["error", "denied", "status", "probe_key"]) expect(answer).not.toHaveProperty(field);
    await env.call("export the note");
    expect(await env.rows()).toHaveLength(2);
    expect((await env.rows()).at(-1)).toHaveProperty("identity_id", "system");
  });
});
