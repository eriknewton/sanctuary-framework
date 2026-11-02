// fail-before-exempt: new module full-supervision ledger and classifier, no base symbol to fail against
import * as fs from "node:fs/promises";
import * as syncFs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  FullSupervisionLedger, FULL_SUPERVISION_REFUSAL_LINE, FULL_SUPERVISION_CLOCK_SKEW_MS,
  FULL_SUPERVISION_WINDOW_SECONDS, type FullSupervisionFs,
} from "../../../src/castle-wall/runtime/full-supervision-state.js";
import { charge, classification, dependencies, ledger, successful, TEST_WALL, TEST_MONOTONIC } from "../../fixtures/full-supervision/support.js";

vi.mock("node:fs", async (original) => ({
  ...await original<typeof import("node:fs")>(), writeSync: vi.fn(() => 0),
}));

let root: string;
beforeEach(async () => { root = await fs.mkdtemp(join(tmpdir(), "supervision-state-")); });
afterEach(async () => { vi.useRealTimers(); vi.restoreAllMocks(); await fs.rm(root, { recursive: true, force: true }); });
const refusal = (reason: string) => ({ ok: false, reason });
function deferred() { let resolve!: () => void; const promise = new Promise<void>((r) => { resolve = r; }); return { promise, resolve }; }

it("retains the budget across fresh objects and healthy completions", async () => {
  for (let index = 0; index < 5; index++) {
    const charged = await charge(root, `crash-${index}`);
    expect(charged.charges).toHaveLength(index + 1);
    if (index < 4) {
      const fresh = ledger(root);
      successful(await fresh.admit(`clean-${index}`));
      const clean = successful(await fresh.settle(`clean-${index}`, classification(`clean-${index}`, {
        exit: { code: 0 }, completion: { attemptId: `clean-${index}`, cleanup: "ok" },
      })));
      expect(clean.charges).toHaveLength(index + 1);
    }
  }
  expect(await ledger(root).admit("sixth")).toEqual(refusal("latched"));
});

it("keeps the latch through nonzero replay, boot change and wall advancement", async () => {
  await charge(root, "first", { budget: 1 });
  const next = ledger(root, { budget: 1, bootIdentity: async () => "next-boot", wallClock: () => TEST_WALL + FULL_SUPERVISION_WINDOW_SECONDS * 1000 * 2 });
  expect(successful(await next.settle("first", classification("first"))).state).toBe("state_LATCHED");
  expect(await next.admit("second")).toEqual(refusal("latched"));
});

it("never ignores unidentified pending when reopened", async () => {
  expect(successful(await ledger(root).admit("first"))).toMatchObject({ admitted: true, state: "state_PENDING_UNIDENTIFIED" });
  expect(await ledger(root).admit("second")).toEqual(refusal("unidentified_attempt"));
});

it("replays proven dead identity exactly once and refuses live or unknown children", async () => {
  const first = ledger(root, { budget: 1 });
  successful(await first.admit("first"));
  successful(await first.recordIdentity("first", process.pid, "test-start"));
  for (const live of ["alive", "unknown"] as const) {
    expect(await ledger(root, { budget: 1, processLiveness: async () => live }).admit("next")).toEqual(refusal(live === "alive" ? "child_alive" : "child_unknown"));
  }
  for (let replay = 0; replay < 2; replay++) {
    expect(await ledger(root, { budget: 1 }).admit("next")).toEqual(refusal("latched"));
    expect(successful(await ledger(root, { budget: 1 }).status()).charges.map((c) => c.attemptId)).toEqual(["first"]);
  }
});

it("requires observed start-token identity and a matched settlement", async () => {
  const instance = ledger(root, { processStartToken: async () => "actual" });
  successful(await instance.admit("first"));
  expect(await instance.recordIdentity("first", process.pid, "claimed")).toEqual(refusal("child_unknown"));
  expect(await instance.settle("other", classification("other"))).toEqual(refusal("invalid_attempt"));
  expect(await instance.settle("first", classification("other"))).toEqual(refusal("invalid_attempt"));
  expect(successful(await instance.status()).state).toBe("state_PENDING_UNIDENTIFIED");
});

it("clock rollback cannot age out charges or grant another admission", async () => {
  await charge(root, "charged");
  expect(await ledger(root, { wallClock: () => TEST_WALL - FULL_SUPERVISION_CLOCK_SKEW_MS - 1 }).admit("rollback")).toEqual(refusal("clock_rollback"));
  expect(await ledger(root, { monotonicClock: () => TEST_MONOTONIC - 1 }).admit("mono-rollback")).toEqual(refusal("clock_rollback"));
  expect(await ledger(root, { bootIdentity: async () => "new-boot", wallClock: () => TEST_WALL - FULL_SUPERVISION_CLOCK_SKEW_MS - 1 }).admit("boot-rollback")).toEqual(refusal("clock_rollback"));
  expect(successful(await ledger(root).status()).charges).toHaveLength(1);
});

it("keeps a high-water floor across repeated tolerated clock adjustments", async () => {
  await charge(root, "charged");
  const tolerated = ledger(root, { wallClock: () => TEST_WALL - FULL_SUPERVISION_CLOCK_SKEW_MS });
  successful(await tolerated.admit("clean"));
  successful(await tolerated.settle("clean", classification("clean", { exit: { code: 0 }, completion: { attemptId: "clean", cleanup: "ok" } })));
  expect(await ledger(root, { wallClock: () => TEST_WALL - 2 * FULL_SUPERVISION_CLOCK_SKEW_MS }).admit("lower")).toEqual(refusal("clock_rollback"));
});

it("refuses unknown clock provenance before enrollment", async () => {
  for (const overrides of [
    { bootIdentity: async () => null }, { wallClock: () => null }, { monotonicClock: () => null },
    { wallClock: () => NaN }, { bootIdentity: async () => { throw new Error("unknown"); } },
  ]) expect(await ledger(root, overrides).admit("first")).toEqual(refusal("unknown_clock_provenance"));
  expect(await fs.readdir(root)).toEqual([]);
});

it("bounds retention and per-call reads across adversarial spaced failures", async () => {
  const iterations = 50; // Ten complete K=5 waves.
  const windowMs = FULL_SUPERVISION_WINDOW_SECONDS * 1000;
  for (let index = 0; index < iterations; index++) {
    const instance = ledger(root, { wallClock: () => TEST_WALL + index * (windowMs + 1) });
    successful(await instance.admit(`spaced-${index}`));
    const state = successful(await instance.settle(`spaced-${index}`, classification(`spaced-${index}`)));
    expect(state.charges).toHaveLength(1);
    expect(state.state).toBe("state_IDLE");
    expect((await fs.stat(join(root, "ledger.json"))).size).toBeLessThanOrEqual(instance.readCapBytes);
  }
  expect((await fs.readdir(root)).sort()).toEqual(["enrolled.json", "ledger.json"]);
  const originalOpen = fs.open;
  let maxRead = 0;
  let reads = 0;
  const facade = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await originalOpen(...args);
    const read = handle.read.bind(handle);
    handle.read = (async (...readArgs: any[]) => { maxRead = Math.max(maxRead, readArgs[0].length); reads++; return (read as any)(...readArgs); }) as typeof handle.read;
    return handle;
  } };
  const instance = ledger(root, { fs: facade, wallClock: () => TEST_WALL + iterations * (windowMs + 1) });
  successful(await instance.status());
  expect(maxRead).toBe(instance.readCapBytes + 1);
  expect(reads).toBeLessThanOrEqual(4); // Two bounded files, one data read and one EOF read each.
});

it("has an inclusive window boundary and an injectable throttle", async () => {
  await charge(root, "first", { budget: 2 });
  const atBoundary = ledger(root, { budget: 2, wallClock: () => TEST_WALL + FULL_SUPERVISION_WINDOW_SECONDS * 1000 });
  successful(await atBoundary.admit("second"));
  expect(successful(await atBoundary.settle("second", classification("second"))).state).toBe("state_LATCHED");
  const fresh = await fs.mkdtemp(join(root, "throttle-"));
  await charge(fresh, "first", { throttleSeconds: 5 });
  expect(await ledger(fresh, { throttleSeconds: 5 }).admit("second")).toEqual(refusal("throttled"));
  expect(successful(await ledger(fresh, { throttleSeconds: 5, wallClock: () => TEST_WALL + 5 * 1000 }).admit("second")).admitted).toBe(true);
});

it("allows only explicit reset and never discards pending during reset", async () => {
  const instance = ledger(root, { budget: 1 });
  successful(await instance.admit("first"));
  expect(await instance.resetLatch("operator-recovery")).toEqual(refusal("unidentified_attempt"));
  successful(await instance.settle("first", classification("first")));
  expect(successful(await instance.resetLatch("operator-recovery")).state).toBe("state_IDLE");
  expect(successful(await instance.admit("second")).admitted).toBe(true);
});

it("terminal settlement latches without permitting an automatic retry", async () => {
  const instance = ledger(root);
  successful(await instance.admit("first"));
  successful(await instance.settle("first", { kind: "terminal", reason: "parse_refusal", decidedBy: classification("first").decidedBy }));
  expect(await ledger(root).admit("second")).toEqual(refusal("latched"));
});

it("enrollment interruption or deletion cannot replenish the budget", async () => {
  const failLedger: FullSupervisionFs = { ...fs, rename: async (from, to) => {
    if (String(to).endsWith("ledger.json")) throw new Error("injected interruption");
    return fs.rename(from, to);
  } };
  expect((await ledger(root, { fs: failLedger }).admit("first")).ok).toBe(false);
  expect(await ledger(root).admit("second")).toEqual(refusal("enrolled_ledger_missing"));
  const separate = await fs.mkdtemp(join(root, "deleted-"));
  await charge(separate, "first");
  await fs.unlink(join(separate, "ledger.json"));
  expect(await ledger(separate).admit("second")).toEqual(refusal("enrolled_ledger_missing"));
});

it("refuses unreadable enrolled ledgers without treating them as fresh", async () => {
  await charge(root, "first");
  const facade: FullSupervisionFs = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]).endsWith("ledger.json")) throw Object.assign(new Error("unreadable"), { code: "EACCES" });
    return fs.open(...args);
  } };
  expect(await ledger(root, { fs: facade }).admit("second")).toEqual(refusal("enrolled_ledger_missing"));
});

describe("state validation", () => {
  it("rejects unsafe directory permissions, ownership and symlinks", async () => {
    await fs.chmod(root, 0o777);
    expect(await ledger(root).admit("first")).toEqual(refusal("unsafe_state_dir"));
    await fs.chmod(root, 0o700);
    const facade = { ...fs, lstat: async (...args: Parameters<typeof fs.lstat>) => {
      const stat = await fs.lstat(...args); return Object.assign(stat, { uid: process.getuid!() + 1 });
    } } as FullSupervisionFs;
    expect(await ledger(root, { fs: facade }).admit("first")).toEqual(refusal("unsafe_state_dir"));
    const link = join(root, "link"); await fs.symlink(root, link);
    expect(await ledger(link).admit("first")).toEqual(refusal("unsafe_state_dir"));
  });
  it.each(["json", "schema", "oversize", "symlink", "owner", "mode", "settings", "latched-pending"])("refuses %s state", async (kind) => {
    await charge(root, "first");
    const path = join(root, "ledger.json");
    let facade: FullSupervisionFs = fs;
    if (kind === "json") await fs.writeFile(path, "{");
    if (kind === "schema") await fs.writeFile(path, JSON.stringify({ version: 1, charges: [null] }));
    if (kind === "oversize") await fs.writeFile(path, " ".repeat(ledger(root).readCapBytes + 1));
    if (kind === "symlink") { await fs.rename(path, join(root, "real.json")); await fs.symlink(join(root, "real.json"), path); }
    if (kind === "mode") await fs.chmod(path, 0o666);
    if (kind === "settings") {
      const data = JSON.parse(await fs.readFile(path, "utf8")); data.settings.budget++; await fs.writeFile(path, JSON.stringify(data));
    }
    if (kind === "latched-pending") {
      const data = JSON.parse(await fs.readFile(path, "utf8"));
      data.latched = true;
      data.pending = { attemptId: "impossible", identity: { pid: process.pid, startToken: "test-start" }, clock: data.lastClock };
      await fs.writeFile(path, JSON.stringify(data));
    }
    if (kind === "owner") facade = { ...fs, open: async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      if (String(args[0]) === path) { const stat = handle.stat.bind(handle); handle.stat = (async () => Object.assign(await stat(), { uid: process.getuid!() + 1 })) as typeof handle.stat; }
      return handle;
    } };
    expect(await ledger(root, { fs: facade }).admit("second")).toEqual(refusal("corrupt_state"));
  });
});

it("late completing writes never admit through repeated deadline waves", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const stderr = vi.mocked(syncFs.writeSync);
  stderr.mockClear();
  const waves = 10; // Twice the default crash budget; each wave leaves an independent refused pending attempt.
  for (let wave = 0; wave < waves; wave++) {
    const directory = await fs.mkdtemp(join(root, "wave-"));
    const reached = deferred(); const release = deferred(); const unlocked = deferred();
    let renames = 0;
    const facade: FullSupervisionFs = { ...fs,
      rename: async (from, to) => {
        if (String(to).endsWith("ledger.json")) { renames++; reached.resolve(); await release.promise; }
        return fs.rename(from, to);
      },
      unlink: async (path) => { await fs.unlink(path); if (String(path).endsWith("writer.lock")) unlocked.resolve(); },
    };
    const instance = ledger(directory, { fs: facade, writeDeadlineMs: 1 });
    const admitting = instance.admit("timed-out");
    await reached.promise;
    try {
      await vi.advanceTimersByTimeAsync(1);
      expect(await admitting).toEqual(refusal("ledger_write_stalled"));
      expect(stderr).toHaveBeenLastCalledWith(2, FULL_SUPERVISION_REFUSAL_LINE);
      for (let retry = 0; retry < 5; retry++) {
        expect(await instance.admit(`busy-${retry}`)).toEqual(refusal("ledger_busy"));
        expect(await ledger(directory).admit(`other-${retry}`)).toEqual(refusal("ledger_busy"));
      }
    } finally { release.resolve(); await unlocked.promise; }
    expect(await ledger(directory).admit("after-late-write")).toEqual(refusal("unidentified_attempt"));
    expect(successful(await ledger(directory).status()).state).toBe("state_PENDING_UNIDENTIFIED");
    expect(renames).toBe(1);
  }
  expect(stderr.mock.calls.every(([fd, line]) => fd === 2 && line === FULL_SUPERVISION_REFUSAL_LINE)).toBe(true);
});

it("serializes competing admissions without retaining a queue", async () => {
  const instances = Array.from({ length: 50 }, () => new FullSupervisionLedger(dependencies(root)));
  const results = await Promise.all(instances.map((instance, index) => instance.admit(`racer-${index}`)));
  expect(results.filter((result) => result.ok && result.admitted)).toHaveLength(1);
  expect(results.filter((result) => !result.ok)).toHaveLength(instances.length - 1);
});
