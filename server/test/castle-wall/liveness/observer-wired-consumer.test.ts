/**
 * The observer is a wired consumer: the LaunchAgent's own ProgramArguments
 * reach run-watch through the real CLI dispatcher, the production composition
 * builds the observer with every collector, the sampler, the publisher and the
 * clock, a missing one fails at construction, and 100 production cycles over
 * modelled children never reach the credential store.
 */
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmdirSync, unlinkSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { OBSERVER_PERIOD } from "../../../src/castle-wall/liveness/constants.js";
import { CensusSampler, CensusSeries } from "../../../src/castle-wall/liveness/census-sampler.js";
import { LivenessObserver, type LivenessObserverDeps } from "../../../src/castle-wall/liveness/observer.js";
import { LivenessRecordPublisher } from "../../../src/castle-wall/liveness/record-store.js";
import { parseObserverRecord } from "../../../src/castle-wall/liveness/schema.js";
import * as watch from "../../../src/cli/castle-wall-watch.js";
import { BoundedChildRunner, type WatchChild, type WatchSpawn } from "../../../src/cli/castle-wall-watch-collectors.js";
import { inMemoryKeychainCalls } from "../../setup/keychain-memory-store.js";

vi.mock("../../../src/cli/castle-wall-watch.js", async importOriginal => {
  const original = await importOriginal<typeof import("../../../src/cli/castle-wall-watch.js")>();
  return { ...original, runRunWatch: vi.fn(original.runRunWatch) };
});

const UID = process.getuid!();
const FIX = join(__dirname, "fixtures");
const GOLDEN = readFileSync(join(FIX, "observer.golden.plist"), "utf8");
const PRINTS = JSON.parse(readFileSync(join(FIX, "launchctl-print.json"), "utf8")).entries as Record<string, { code: number; stdout: string; stderr: string }>;
const PS_TEXT = (JSON.parse(readFileSync(join(FIX, "process-census.json"), "utf8")) as { text: string }).text;
const NETSTAT = readFileSync(join(FIX, "census", "netstat-anv-macos26.txt"), "utf8");
const goldenArguments = (): string[] => [...(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(GOLDEN)![1]!).matchAll(/<string>([^<]*)<\/string>/g)].map(m => m[1]!);

// The shared in-memory credential store logs every call it serves; no verb may reach it.

/** Modelled children for every command a production cycle spawns. */
function modelledSpawn(argv: string[][]): WatchSpawn {
  return (file, args) => {
    argv.push([file, ...args]);
    const child = Object.assign(new EventEmitter(), { pid: 8000 + argv.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter };
    child.kill = () => true;
    const stdout = file === "/usr/sbin/sysctl" ? "boot-fixture-current\n"
      : file === "/bin/ps" ? PS_TEXT
        : file === "/usr/sbin/netstat" ? NETSTAT
          : file === "/bin/launchctl" ? PRINTS.full_agent_gui!.stdout : "";
    queueMicrotask(() => { child.stdout.emit("data", Buffer.from(stdout)); child.emit("exit", 0, null); child.emit("close", 0, null); });
    return child;
  };
}
/** Real timers scaled down a thousandfold, so the cycle's deadlines and re-read gaps keep their order without wall-clock waits. */
const TIME_SCALE = 1000;
const scaledTimers = {
  setTimeout: (fire: () => void, ms: number) => setTimeout(fire, Math.ceil(ms / TIME_SCALE)),
  clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout),
  setInterval: (fire: () => void, ms: number) => setInterval(fire, Math.ceil(ms / TIME_SCALE)),
  clearInterval: (h: unknown) => clearInterval(h as NodeJS.Timeout),
};

describe("CLI dispatch", () => {
  it("routes the golden LaunchAgent ProgramArguments to run-watch through the real dispatcher", async () => {
    const args = goldenArguments();
    expect(args.slice(2, 4)).toEqual(["castle-wall", "run-watch"]);
    const runRunWatch = vi.mocked(watch.runRunWatch);
    runRunWatch.mockImplementationOnce(async () => 0);
    const exits: number[] = [];
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code: number) => { exits.push(code); }) as never);
    const original = process.argv;
    const originalExitCode = process.exitCode;
    process.argv = [process.execPath, resolve("src/cli.ts"), ...args.slice(2)];
    try {
      await (await import("../../../src/cli.js")).cliEntryInvocation;
      // The dispatcher exits from the stdout drain callback, after the entry promise settles.
      for (let i = 0; i < 100 && exits.length === 0; i++) await new Promise<void>(done => setImmediate(done));
    } finally { process.argv = original; exitSpy.mockRestore(); process.exitCode = originalExitCode; }
    expect(runRunWatch).toHaveBeenCalledTimes(1);
    expect(runRunWatch.mock.calls[0]![0]).toEqual(args.slice(4));
    expect(exits).toEqual([0]);
  });
});

describe("production composition", () => {
  function compose() {
    const argv: string[][] = [];
    const runner = new BoundedChildRunner({ spawn: modelledSpawn(argv), timers: scaledTimers });
    const clock = { nowMs: () => Date.now(), uptimeMs: () => 36_000_000 };
    const root = mkdtempSync(join(tmpdir(), "lv-wired-"));
    const composition = watch.composeProductionWatch({ fortressPath: root, operatorUid: UID, runner, timers: scaledTimers, clock, hostname: "fixture-host" });
    return { composition, clock, root, argv };
  }

  it("constructs the observer with every collector, the sampler, the publisher and the host clock", () => {
    const { composition, clock, root } = compose();
    const deps = composition.deps;
    for (const name of ["readRecords", "readBootId", "queryAvailability", "printFullAgent", "readFullAgentState", "readProcesses", "printHarness", "collectCanaryFacts"] as const) {
      expect(typeof deps.collectors[name], name).toBe("function");
    }
    expect(deps.sampler).toBeInstanceOf(CensusSampler);
    expect(composition.sampler).toBe(deps.sampler);
    expect(deps.series).toBeInstanceOf(CensusSeries);
    expect(deps.publisher).toBeInstanceOf(LivenessRecordPublisher);
    expect(deps.clock).toBe(clock);
    expect(deps.timers).toBe(scaledTimers);
    expect(deps.operatorUid).toBe(UID);
    expect(deps.hostId).toMatch(/^host-[0-9a-f]{16}$/);
    expect(composition.observer).toBeInstanceOf(LivenessObserver);
    rmdirSync(root);
  });

  it("fails at construction when any dependency, collector or sampler input is missing", () => {
    const { composition, root } = compose();
    const deps = composition.deps;
    for (const key of ["fortressId", "hostId", "operatorUid", "collectors", "sampler", "series", "publisher", "clock", "timers"] as const) {
      expect(() => new LivenessObserver({ ...deps, [key]: undefined } as unknown as LivenessObserverDeps), key).toThrow(/requires/);
    }
    for (const name of Object.keys(deps.collectors)) {
      if (name === "runNetstat") continue;
      const collectors = { ...deps.collectors, [name]: undefined };
      expect(() => new LivenessObserver({ ...deps, collectors } as unknown as LivenessObserverDeps), name).toThrow(/requires collector/);
    }
    const samplerDeps = { series: new CensusSeries(), runNetstat: async () => ({ status: "failed" as const }), context: () => ({ gateway: null, gatewayAlive: false, ipv4Set: null, bootId: null }), clock: { nowMs: () => 0, uptimeMs: () => 0 }, timers: scaledTimers };
    for (const key of Object.keys(samplerDeps)) {
      expect(() => new CensusSampler({ ...samplerDeps, [key]: undefined } as never), key).toThrow(/requires/);
    }
    rmdirSync(root);
  });

  it("run-watch with darwin injected and an injected fortress does not refuse, and 100 production cycles reach no credential store", async () => {
    const argv: string[][] = [];
    const runner = new BoundedChildRunner({ spawn: modelledSpawn(argv), timers: scaledTimers });
    const root = mkdtempSync(join(tmpdir(), "lv-wired-"));
    // Track every publish so cleanup waits for the last write, which may outlive the scaled stop deadline.
    const publishes: Promise<void>[] = [];
    const originalPublish = LivenessRecordPublisher.prototype.publish;
    const publishSpy = vi.spyOn(LivenessRecordPublisher.prototype, "publish").mockImplementation(function (this: LivenessRecordPublisher, record: unknown) {
      const p = originalPublish.call(this, record);
      publishes.push(p.catch(() => undefined));
      return p;
    });
    let built: ReturnType<typeof watch.composeProductionWatch> | null = null;
    const out: string[] = [];
    const sink = { write: (text: string) => { out.push(text); return true; } } as unknown as NodeJS.WritableStream;
    const code = await watch.runRunWatch(["--fortress", root, "--launch-agent"], {
      platform: "darwin", euid: UID, runner, timers: scaledTimers, out: sink as never, err: sink as never, sleep: ms => new Promise(done => setTimeout(done, Math.ceil(ms / TIME_SCALE))),
      compose: input => { built = watch.composeProductionWatch(input); return built; },
      waitForStop: async () => { for (let i = 0; i < 300 && built!.observer.stats().cycles < 100; i++) await built!.observer.tick(); },
    });
    await Promise.all(publishes);
    publishSpy.mockRestore();
    expect(code).toBe(0);
    expect(out).toEqual([]);
    expect(publishes.length).toBeGreaterThanOrEqual(100);
    const observer = built!.observer;
    expect(observer.stats().cycles).toBeGreaterThanOrEqual(100);
    expect(inMemoryKeychainCalls()).toEqual([]);
    const recordPath = join(root, "liveness", "observer.json");
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    expect(parseObserverRecord(record).ok).toBe(true);
    expect(record.observer_period_ms).toBe(OBSERVER_PERIOD);
    for (const call of argv) expect(["/usr/sbin/sysctl", "/bin/launchctl", "/bin/ps", "/usr/sbin/netstat"]).toContain(call[0]);
    for (const call of argv.filter(c => c[0] === "/bin/launchctl")) expect(call[1]).toBe("print");
    // The publication fence leaves only the record and its current-publisher claim; no lock or temp survives.
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(["observer.json", "observer.json.publisher"]);
    unlinkSync(recordPath);
    unlinkSync(`${recordPath}.publisher`);
    rmdirSync(join(root, "liveness"));
    rmdirSync(root);
  });

  // Through compiled dist/cli.js only on a host that is not macOS: on darwin this would start a real observer, so it is NOT_RUN there.
  it.skipIf(process.platform === "darwin")("compiled run-watch refuses a non-darwin host with exit 1 and the platform text", () => {
    const dist = resolve("dist/cli.js");
    expect(existsSync(dist)).toBe(true);
    const root = mkdtempSync(join(tmpdir(), "lv-wired-"));
    mkdirSync(join(root, "unused"), { mode: 0o700 });
    const result = spawnSync(process.execPath, [dist, "castle-wall", "run-watch", "--fortress", root], { encoding: "utf8", timeout: 60_000, env: { ...process.env, HOME: root } });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("run-watch refused: unsupported_adapter (the observer runs on macOS only).");
    rmdirSync(join(root, "unused"));
    rmdirSync(root);
  });
});
