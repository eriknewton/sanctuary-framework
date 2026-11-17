// One insert at a time per bridge process: while a completed-turn capture is still being written, including after its
// caller gave up, a deliberate remember is answered unavailable at once, and a remember after the capture settles is saved.
// The real provider, client, shim class and bridge run against temporary storage; only Python's standard library is used.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RECALL_PREFETCH_BUDGET_MS } from "../../src/hermes-memory-bridge/recall.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { startFixture, type Fixture } from "./harness/fixture.js";

const captureFact = "The Porto review moved to Monday at 9am.";
const deliberateNote = "A deliberate note while the capture is held.";
const laterNote = "A deliberate note after the capture settled.";
const unavailable = { outcome: "unavailable", message: "Sanctuary could not take this request right now; nothing was done." };
const saved = { outcome: "saved", message: "Saved." };
// Must match CAPTURE_DEADLINE_MS in hermes-plugin/sanctuary_memory/__init__.py, which is RECALL_PREFETCH_BUDGET_MS.
const captureDeadlineMs = RECALL_PREFETCH_BUDGET_MS;

// The bridge's storage, held from arm() until release(): the insert started while it is armed stays in flight.
// Every call from arm() on is tracked, so settled() can tell when the held insert has finished with storage.
function holdableStorage() {
  let armed = false;
  let tracking = false;
  let held = 0;
  const pending = new Set<Promise<unknown>>();
  let release!: () => void;
  const gate = new Promise<void>(resolveGate => { release = resolveGate; });
  const track = (call: () => unknown) => {
    const result = call();
    if (!tracking || !(result instanceof Promise)) return result;
    pending.add(result);
    void result.then(() => pending.delete(result), () => pending.delete(result));
    return result;
  };
  const wrap = (storage: StorageBackend): StorageBackend => new Proxy(storage, {
    get(target, key) {
      const value = Reflect.get(target, key, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => track(() => {
        if (!armed) return value.apply(target, args);
        held += 1;
        return gate.then(() => value.apply(target, args));
      });
    },
  });
  // The refusal path after the last storage call uses no timer, so once no tracked call is pending across a full
  // macrotask turn the bridge has settled the entry and freed its slot.
  const settled = async () => {
    do {
      await Promise.allSettled([...pending]);
      await new Promise(resolveTurn => setImmediate(resolveTurn));
    } while (pending.size > 0);
  };
  return { wrap, settled, held: () => held,
    arm: () => { armed = true; tracking = true; },
    release: () => { armed = false; release(); } };
}

// Drives the shipped provider with Hermes's memory-provider base stubbed; each stdin line is one step, each stdout line one report.
const driver = String.raw`
import importlib.util, json, sys, time, types
plugin, command = sys.argv[1], json.loads(sys.argv[2])
memory = types.ModuleType("agent.memory_provider")
memory.MemoryProvider = type("MemoryProvider", (), {})
sys.modules["agent"] = types.ModuleType("agent")
sys.modules["agent.memory_provider"] = memory
spec = importlib.util.spec_from_file_location("sanctuary_memory_witness", plugin + "/sanctuary_memory/__init__.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module._shared.resolve_command = lambda: command
provider = module.SanctuaryMemory()
provider.initialize("witness", platform="telegram", agent_context="primary")
# A provider without a capture client still reports ready, so each assertion below stays reachable on it.
capture = getattr(module, "capture_client", None)
ready = module._shared.get_client().ready.wait(30) and (capture is None or capture().ready.wait(30))
print(json.dumps({"ready": bool(ready)}), flush=True)
for line in sys.stdin:
    step = json.loads(line)
    started = time.monotonic()
    if step["do"] == "capture":
        provider.sync_turn(step["text"], "assistant reply", session_id="witness", messages=[])
        report = {"unsaved": getattr(provider, "_capture_unsaved", None)}
    else:
        report = {"result": json.loads(provider.handle_tool_call("remember", {"text": step["text"]}))}
    report["ms"] = (time.monotonic() - started) * 1000
    print(json.dumps(report), flush=True)
`;

describe("capture and remember share the bridge's single insert slot", () => {
  const storage = holdableStorage();
  let fixture: Fixture;
  beforeAll(async () => { fixture = await startFixture({ wrapStorage: storage.wrap }); });
  afterAll(async () => { storage.release(); await fixture?.close(); });

  it("answers a remember unavailable while a capture insert is held, then saves one once the slot frees", async () => {
    // The shim's last argument is its log path; this witness reads the bridge audit instead, so the log is discarded.
    const shim = fixture.shimCommand(resolve(".")).slice(0, -1).concat("/dev/null");
    const child = spawn("python3", ["-I", "-B", "-c", driver, resolve("../hermes-plugin"), JSON.stringify(shim)],
      { cwd: resolve("."), stdio: ["pipe", "pipe", "inherit"] });
    const lines = createInterface({ input: child.stdout! })[Symbol.asyncIterator]();
    const next = async () => JSON.parse(String((await lines.next()).value));
    const step = async (value: Record<string, string>) => { child.stdin!.write(JSON.stringify(value) + "\n"); return next(); };
    try {
      expect(await next()).toEqual({ ready: true });
      const audit = async () => (await fixture.audit()).filter(row => String(row.details?.kind).startsWith("insert_"));
      const before = (await audit()).length;

      // The capture's insert reaches the bridge and is held there; its caller gives up at its own deadline, unsaved.
      storage.arm();
      const capture = await step({ do: "capture", text: captureFact });
      expect(storage.held()).toBeGreaterThan(0);
      expect(capture.unsaved).toBe(true);
      expect(capture.ms).toBeGreaterThanOrEqual(captureDeadlineMs);

      // The held insert still occupies the slot, so a deliberate remember is told at once that nothing was done.
      const refused = await step({ do: "remember", text: deliberateNote });
      expect(refused.result).toEqual(unavailable);
      expect(refused.ms).toBeLessThan(captureDeadlineMs);

      // Once the held insert settles, the slot is free and the next remember is saved.
      storage.release();
      await storage.settled();
      const later = await step({ do: "remember", text: laterNote });
      expect(later.result).toEqual(saved);

      const rows = (await audit()).slice(before);
      const admitted = (text: string) => rows.filter(row => row.details?.kind === "insert_admitted" &&
        row.details?.text_sha256 === hermesBridgePassageTextDigest(text));
      // The refused remember never reached the adapter. The capture's connection was gone before its commit check, so
      // the bridge refused it before admission; it was never resent, so it is not saved at all, and never twice.
      expect(rows.filter(row => row.details?.text_sha256 === hermesBridgePassageTextDigest(deliberateNote))).toEqual([]);
      expect(admitted(captureFact)).toEqual([]);
      expect(admitted(laterNote)).toHaveLength(1);
    } finally {
      child.stdin!.end();
      child.kill();
    }
  }, 90_000); // Two connections' startup, one five-second capture window and the settle wait share a ninety-second bound.
});
