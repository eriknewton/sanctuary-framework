import { createRequire } from "node:module";
import { spawn, type ChildProcess } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, rm, unlink } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const fixture = fileURLToPath(new URL("../fixtures/lock-teardown-child.ts", import.meta.url));
// Must match test/fixtures/lock-teardown-child.ts: one command and response per role.
type Command = "RELEASE" | "CHECK" | "EXIT" | "EXPIRE" | "CONTINUE";
type Message = { identitiesPreserved?: boolean; directory?: string; overflowDenied?: boolean; denied?: number; queue?: number; writes?: number; spent?: number; expectedSpent?: number; boundaryLosses?: number; live?: number; before?: number; afterResult?: number; afterEvent?: number; pendingBefore?: boolean; afterEventPending?: boolean; closeCalls?: number; firstKind?: string; firstFailed?: boolean; sameRepeat?: boolean; sameConcurrent?: boolean; delivered?: number; aborts?: number; unregistered?: boolean; successorIntact?: boolean; reacquired?: number; exists?: boolean; primaryPreserved?: boolean; guardInCatch?: number; sameLockCallbacks?: number; sameLockKind?: string; otherCallbacks?: number; contendingCallbacks?: number; refusals?: number; heldStats?: number; readOnly?: number; inert?: number; reached?: boolean; available?: boolean; originalCause?: boolean; closes?: number; closeEvents?: number; observed?: string; phase: string; path?: string; held?: boolean; errors?: Array<{ kind?: string; message: string }>; guardAtUnref?: number; callbackCount?: number;
  losses?: number; refused?: number; callbacks?: number; unexpected?: number; artifacts?: number; binds?: number; retained?: number; guards?: number; exportedBudget?: number;
  typedRefusal?: boolean; releaseErrors?: Array<{ kind?: string; message: string }>; guardsBefore?: number; retainedBefore?: number; records?: number };
const STDERR_CAP_BYTES = 16_384; // 16 KiB, 1024 bytes per KiB.
const LINE_BUFFER_CAP_BYTES = 65_536; // 64 KiB, 1024 bytes per KiB.
const STEP_TIMEOUT_MS = 15_000; // One lifecycle fixture RPC budget.
const TEST_TIMEOUT_MS = STEP_TIMEOUT_MS * 10; // Two imports plus eight protocol steps.
const owned: Array<{ child: ChildProcess; done: Promise<{ code: number | null; signal: string | null }> }> = [];
const roots: string[] = [];

async function launch(root: string, role: string, shape = "numeric0", implementation = process.env.LK1_T3_IMPLEMENTATION ?? "source", extraEnv: Record<string, string> = {}) {
  const home = join(root, role);
  await mkdir(home, { mode: 0o700 });
  const child = spawn(process.execPath, ["--unhandled-rejections=throw", "--import", "tsx", fixture, role, shape, implementation], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe", "ipc"],
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, VITEST: "true",
      SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "locks"), SANCTUARY_STORAGE_PATH: join(home, "fortress"),
      SANCTUARY_NO_UPDATE_CHECK: "1", LK1_TARGET: join(root, "state"), ...extraEnv },
  });
  let stderr = "", stdout = "";
  let failure: Error | undefined;
  let receiver: { phase: string; resolve: (message: Message) => void; reject: (error: Error) => void } | undefined;
  const queued: Message[] = [];
  child.stderr!.on("data", (data: Buffer) => { stderr = (stderr + data.toString()).slice(-STDERR_CAP_BYTES); });
  child.stdout!.on("data", (data: Buffer) => {
    stdout += data.toString();
    if (Buffer.byteLength(stdout) > LINE_BUFFER_CAP_BYTES) fail(new Error("fixture stdout overflow"));
  });
  function fail(error: Error) { failure = error; receiver?.reject(error); }
  child.on("message", (message: Message) => {
    if (receiver) {
      const current = receiver; receiver = undefined;
      if (message.phase === current.phase) current.resolve(message);
      else current.reject(new Error(`expected ${current.phase}, received ${message.phase}`));
    } else {
      if (queued.length >= 2) fail(new Error("fixture message overflow")); // READY and HELD may arrive before observation.
      else queued.push(message);
    }
  });
  const done = new Promise<{ code: number | null; signal: string | null }>((resolve, reject) => {
    child.once("error", error => { fail(error); reject(error); });
    child.once("close", (code, signal) => {
      if (receiver) fail(new Error(`fixture exited before ${receiver.phase}: ${stderr}`));
      resolve({ code, signal });
    });
  });
  owned.push({ child, done });
  function phase(name: string): Promise<Message> {
    if (failure) return Promise.reject(failure);
    const message = queued.shift();
    if (message) return message.phase === name ? Promise.resolve(message) : Promise.reject(new Error(`unexpected ${message.phase}`));
    if (receiver) return Promise.reject(new Error("duplicate fixture observer"));
    let timer: ReturnType<typeof setTimeout>;
    return new Promise<Message>((resolve, reject) => {
      timer = setTimeout(() => { receiver = undefined; reject(new Error(`fixture phase timeout ${name}: ${stderr}`)); }, STEP_TIMEOUT_MS);
      receiver = { phase: name, resolve, reject };
    }).finally(() => clearTimeout(timer));
  }
  function command(value: Command) { child.send(value); }
  return { child, done, phase, command, stderr: () => stderr, stdout: () => stdout };
}

afterEach(async () => {
  for (const { child, done } of owned.splice(0)) {
    if (child.exitCode === null && child.signalCode === null && child.pid) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    }
    await done;
  }
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function connectable(path: string): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect(path);
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => { socket.destroy(); resolve(false); });
    socket.setTimeout(STEP_TIMEOUT_MS, () => { socket.destroy(); resolve(false); });
  });
}

describe.runIf(process.platform === "linux" || process.platform === "darwin")("lock teardown ownership", () => {
  for (const shape of ["ordinary", "exclusive"] as const) {
    it(`L1 R: ${shape} callback requires fresh admission`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "callback-admission", shape, "source", {
        SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "ancestor", "locks"),
      });
      await holder.phase("READY");
      const fault = await holder.phase("FAULT_REACHED");
      expect(fault.reached).toBe(true);
      if (shape === "exclusive") expect(fault.identitiesPreserved).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.callbackCount, "fresh admission refuses callback effects").toBe(0);
      expect(result.errors?.some(error => error.kind === (shape === "ordinary" ? "holder-lost" : "scaffold-integrity"))).toBe(true);
      expect(result).toMatchObject({ closes: 0, retained: 1, guardAtUnref: 1 });
      holder.command("EXIT"); await holder.phase("RETURNED");
      expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["healthy", "failed-release"] as const) {
    it(`L5 R: assertHeld after ${shape} path release refuses without changing retention`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "released-lease", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.errors, "a released lease refuses the next protected step").toEqual([expect.objectContaining({ kind: "holder-lost" })]);
      expect(result.typedRefusal).toBe(true);
      expect(result.releaseErrors).toEqual(shape === "healthy" ? [] : [expect.objectContaining({ kind: "holder-lost" })]);
      const retained = shape === "healthy" ? 0 : 1; // Only failed disposal retains its one acquired listener.
      expect(result).toMatchObject({ guardsBefore: retained, guards: retained, retainedBefore: retained, retained, records: retained });
      holder.command("EXIT"); await holder.phase("RETURNED");
      expect(await holder.done).toEqual({ code: 0, signal: null });
      expect(holder.stderr()).toBe("");
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["ordinary", "reader", "exclusive"] as const) {
    it(`T2a E HEALTHY-LOCK: ${shape} exclusion and reacquisition`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "healthy-family", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result).toMatchObject({ callbacks: 2, contendingCallbacks: 0, refusals: 2, guards: 0 });
      expect(result.closeEvents).toBe(shape === "exclusive" ? 4 : 6); // Two rounds, counting each transient probe separately.
      expect(result.heldStats).toBe(shape === "ordinary" ? 2 : shape === "reader" ? 6 : 0);
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }
  it("T2c E EXISTING-MODES: unsupported and pre-bind environmental modes remain available", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "modes");
    await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
    expect(await holder.phase("DISPOSAL_SETTLED")).toMatchObject({ callbacks: 1, readOnly: 2, inert: 2, guards: 0 });
    holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);

  for (const shape of ["healthy", "prebind", "postbind"] as const) {
    it(`T2b ${shape === "postbind" ? "R" : "E"}: probe ${shape} disposal and install observation`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "probe", shape);
      await holder.phase("READY");
      expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      if (shape === "postbind") {
        expect(result.errors, "post-bind failure throws typed io").toEqual([expect.objectContaining({ kind: "io" })]);
        expect(result.originalCause).toBe(true);
        expect(result.observed).toBe("unknown");
      } else {
        expect(result.errors).toEqual([]);
        expect(result.available).toBe(shape === "healthy");
        expect(result.observed).toBe(shape === "healthy" ? "available" : "unavailable");
      }
      expect(result.closes).toBe(shape === "prebind" ? 0 : 2); // One direct probe and one real install observation.
      expect(result.closeEvents).toBe(result.closes);
      holder.command("EXIT"); await holder.phase("RETURNED");
      expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const fault of ["EACCES", "EIO", "unexpected"] as const) {
    it(`T4b R: ${fault} keeps its typed cause and still-owned listener`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "stat-fault", fault);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.errors?.some(error => error.kind === "io"), "unreadable ownership is typed io before drain").toBe(true);
      expect(result).toMatchObject({ originalCause: true, primaryPreserved: true, guardInCatch: 1, guardAtUnref: 1,
        sameLockCallbacks: 0, sameLockKind: "contention", otherCallbacks: 1 });
      expect(result.errors).toHaveLength(2);
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["mode", "uid", "file", "symlink", "owner-read"] as const) {
    it(`T4c ${shape === "owner-read" ? "N SECURED-MODE" : "E INVALID-SHAPE"}: ${shape} retains without closing`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "invalid-shape", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.errors?.some(error => error.kind === (shape === "file" || shape === "symlink" ? "holder-lost" : "io"))).toBe(true);
      expect(result).toMatchObject({ closes: 0, guardInCatch: 1, guardAtUnref: 1 });
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["preabort", "contention"] as const) {
    it(`T5d E NODE-DISPOSED-LISTEN: ${shape} refunds without an unsafe close`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "listen-refund", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.errors).toEqual([expect.objectContaining({ kind: shape === "preabort" ? "operation_aborted" : "contention" })]);
      expect(result.callbacks).toBe(0);
      expect(result.binds).toBe(shape === "preabort" ? 0 : 2);
      expect(result.closes).toBe(shape === "preabort" ? 0 : 1);
      expect(result.afterResult).toBe(result.before);
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["chmod", "unknown"] as const) {
    it(`T5b ${shape === "chmod" ? "E OWNED-CHMOD-CLEANUP" : "N UNKNOWN-CAPTURE"}: ${shape}`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "capture-fault", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.callbackCount).toBe(0);
      expect(result.errors?.length).toBeGreaterThan(0);
      expect(result).toMatchObject(shape === "chmod" ? { closes: 2, reacquired: 1, guards: 0, exists: false }
        : { closes: 0, reacquired: 0, guards: 1, exists: true });
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["healthy", "replace"] as const) {
    it(`T5c ${shape === "replace" ? "R EVICTION-RETURN" : "E"}: reader ${shape}`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "reader-eviction", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.delivered, "late validation precedes lease delivery").toBe(shape === "replace" ? 0 : 1);
      expect(result).toMatchObject({ aborts: 1, unregistered: true, successorIntact: true });
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  it("T6c N PROBE-FALLBACK: same inode cleanup has serialized authority", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "fallback");
    await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
    expect(await holder.phase("DISPOSAL_SETTLED")).toMatchObject({ closes: 1, errors: [], exists: false });
    holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);
  for (const shape of ["healthy", "hook-throws", "no-pid"] as const) {
    it(`T5b N HELPER-REAP: ${shape} settles after helper close`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "helper", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result).toMatchObject({ closedAtSettlement: true, callbacks: shape === "healthy" ? 1 : 0 });
      expect(result.errors?.length).toBe(shape === "healthy" ? 0 : 1);
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }
  for (const shape of ["timeout", "callback-error", "throw", "event-first", "callback-first"] as const) {
    it(`T6 ${shape === "timeout" || shape === "callback-error" ? "R REPEAT" : "N ORDER"}: stub ${shape}`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "close-order", shape);
      await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
      const result = await holder.phase("DISPOSAL_SETTLED");
      const failed = ["timeout", "callback-error", "throw"].includes(shape);
      expect(result.firstFailed).toBe(failed);
      expect(result.sameRepeat, "repeat release preserves the settled result").toBe(true);
      expect(result.sameConcurrent).toBe(true);
      expect(result.closeCalls).toBe(1);
      expect(result.guards).toBe(0);
      expect(result.before).toBe(1);
      expect(result.afterResult).toBe(shape === "timeout" || shape === "event-first" ? 0 : 1);
      expect(result.afterEvent).toBe(0);
      if (shape === "event-first") expect(result.afterEventPending).toBe(true);
      if (shape !== "throw") expect(result.pendingBefore).toBe(true);
      if (shape === "callback-error" || shape === "throw") expect(result.originalCause).toBe(true);
      holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }

  for (const shape of ["retained", "live"] as const) {
  it(`T7 R CAP: ${shape} budget refuses every kernel family before setup`, async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "budget", shape);
    await holder.phase("READY");
    // Must match the six-family inventory and policy headroom in storage/cross-process-lock.ts.
    const budget = 2 ** Math.ceil(Math.log2(6 * 8));
    const reached = await holder.phase("FAULT_REACHED");
    expect(shape === "live" ? reached.live : reached.losses).toBe(budget);
    const result = await holder.phase("DISPOSAL_SETTLED").catch(error => {
      if (holder.child.exitCode === 0) return { phase: "UNEXPECTED_EXIT" } as Message;
      throw error;
    });
    expect(result.phase, "capacity refusal preserves live IPC").toBe("DISPOSAL_SETTLED");
    expect(result.refused, "all post-cap public admissions refuse poisoned").toBe(budget * 2);
    expect(result).toMatchObject({ callbacks: 0, unexpected: 0, artifacts: 0, binds: 0, retained: budget, guards: shape === "live" ? 0 : 1, exportedBudget: budget });
    expect(holder.stderr().split("Kernel lock retention limit reached;").length - 1).toBe(1);
    expect(holder.stdout()).toBe("");
    holder.command("EXIT");
    await holder.phase("RETURNED");
    expect(await holder.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);

  }

  it("T7 N: malformed process registry refuses before setup", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "malformed");
    await holder.phase("READY"); expect((await holder.phase("FAULT_REACHED")).reached).toBe(true);
    const result = await holder.phase("DISPOSAL_SETTLED");
    expect(result).toMatchObject({ callbacks: 0, artifacts: 0 });
    expect(result.errors).toEqual([expect.objectContaining({ kind: "poisoned" })]);
    holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);

  it("T8 R: late quota waves preserve their successors and reject at the lock boundary", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "quota-waves");
    await holder.phase("READY");
    for (let wave = 0; wave < 3; wave++) {
      const paused = await holder.phase("WRITE_PAUSED");
      expect(paused.overflowDenied).toBe(true);
      await unlink(paused.path!);
      await expect(lstat(paused.path!)).rejects.toMatchObject({ code: "ENOENT" });
      const peerRoot = join(root, `wave-${wave}`); await mkdir(peerRoot, { mode: 0o700 });
      const successor = await launch(peerRoot, "successor", "numeric0", "source", {
        LK1_TARGET: paused.directory!, LK1_DIRECT_LOCK: "own-scope-save-quota.lock", SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "locks"),
      });
      await successor.phase("READY"); expect((await successor.phase("HELD")).path).toBe(paused.path);
      const identity = await lstat(paused.path!, { bigint: true });
      holder.command("EXPIRE");
      const expired = await holder.phase("EXPIRED"); expect(expired.denied).toBe(expired.queue! + 1);
      holder.command("RELEASE");
      const result = await holder.phase("DISPOSAL_SETTLED");
      expect(result.writes).toBe(wave + 1);
      expect(result.spent).toBe(result.expectedSpent);
      expect(result.boundaryLosses, "actual lock boundary rejects each late disposal").toBe(wave + 1);
      if (wave === 2) {
        holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
      }
      expect((await lstat(paused.path!, { bigint: true }).catch(() => null))?.ino, "quota successor survives late release and drain").toBe(identity.ino);
      successor.command("CHECK"); expect((await successor.phase("CHECKED")).held).toBe(true);
      successor.command("RELEASE"); expect((await successor.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
      successor.command("EXIT"); await successor.phase("RETURNED"); expect(await successor.done).toEqual({ code: 0, signal: null });
      if (wave !== 2) holder.command("CONTINUE");
    }
  }, TEST_TIMEOUT_MS);

  it("T5a R: post-bind substitution refuses callback admission", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "postbind-holder");
    await holder.phase("READY");
    const { path } = await holder.phase("FAULT_REACHED");
    await unlink(path!);
    await expect(lstat(path!)).rejects.toMatchObject({ code: "ENOENT" });
    const successor = await launch(root, "successor");
    await successor.phase("READY");
    expect((await successor.phase("HELD")).path).toBe(path);
    const identity = await lstat(path!, { bigint: true });
    holder.command("RELEASE");
    const result = await holder.phase("DISPOSAL_SETTLED");
    expect(result.callbackCount, "post-bind ownership loss refuses callback").toBe(0);
    expect(result.errors?.some(error => error.kind === "holder-lost")).toBe(true);
    expect(result.guardAtUnref).toBe(1);
    expect((await lstat(path!, { bigint: true }).catch(() => null))?.ino, "post-bind successor identity is preserved").toBe(identity.ino);
    holder.command("EXIT");
    await holder.phase("RETURNED");
    expect(await holder.done).toEqual({ code: 0, signal: null });
    successor.command("CHECK");
    expect((await successor.phase("CHECKED")).held).toBe(true);
    successor.command("RELEASE");
    expect((await successor.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
    successor.command("EXIT");
    await successor.phase("RETURNED");
    expect(await successor.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);

  it("T4a R: missing path protection remains armed when a successor arrives later", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    const holder = await launch(root, "holder");
    await holder.phase("READY"); const { path } = await holder.phase("HELD");
    await unlink(path!); await expect(lstat(path!)).rejects.toMatchObject({ code: "ENOENT" });
    holder.command("RELEASE"); const result = await holder.phase("DISPOSAL_SETTLED");
    expect(result.errors?.some(error => error.kind === "holder-lost")).toBe(true);
    expect(result.guardAtUnref, "missing path installs protection before unref").toBe(1);
    const successor = await launch(root, "successor");
    await successor.phase("READY"); expect((await successor.phase("HELD")).path).toBe(path);
    const identity = await lstat(path!, { bigint: true });
    holder.command("EXIT"); await holder.phase("RETURNED"); expect(await holder.done).toEqual({ code: 0, signal: null });
    expect((await lstat(path!, { bigint: true }).catch(() => null))?.ino, "late successor survives missing-path retention").toBe(identity.ino);
    successor.command("CHECK"); expect((await successor.phase("CHECKED")).held).toBe(true);
    successor.command("RELEASE"); expect((await successor.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
    successor.command("EXIT"); await successor.phase("RETURNED"); expect(await successor.done).toEqual({ code: 0, signal: null });
  }, TEST_TIMEOUT_MS);

  it("T2a E HEALTHY-LOCK: owned release permits a new holder", async () => {
    const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
    for (const role of ["holder", "contender-after"]) {
      const holder = await launch(root, role);
      await holder.phase("READY");
      const { path } = await holder.phase("HELD");
      holder.command("RELEASE");
      expect((await holder.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
      await expect(lstat(path!)).rejects.toMatchObject({ code: "ENOENT" });
      holder.command("EXIT");
      await holder.phase("RETURNED");
      expect(await holder.done).toEqual({ code: 0, signal: null });
    }
  }, TEST_TIMEOUT_MS);

  for (const [shape, code, classification] of [
    ["sync-loss", 0, "R"], ["numeric0", 0, "R"], ["numeric1", 1, "R"], ["numeric7", 7, "R"],
    ["string1", 1, "R"], ["string7", 7, "R"],
    ["handled-term", 0, "R"], ["handled-int", 0, "R"], ["cleanup-reject", 1, "R"],
    ["explicit", 0, "E EXPLICIT"], ["fatal", 1, "E FATAL"], ["rejection", 1, "E FATAL"],
  ] as const) {
    it(`${shape === "sync-loss" ? "T4a" : "T3"} ${classification}: successor survives ${shape}`, async () => {
      const root = await mkdtemp(join(tmpdir(), "lk1-")); roots.push(root);
      const holder = await launch(root, "holder", shape);
      await holder.phase("READY");
      const { path } = await holder.phase("HELD");
      expect(path).toBeDefined();
      await unlink(path!);
      await expect(lstat(path!)).rejects.toMatchObject({ code: "ENOENT" });
      const successor = await launch(root, "successor");
      await successor.phase("READY");
      expect((await successor.phase("HELD")).path).toBe(path);
      const identity = await lstat(path!, { bigint: true });
      expect(await connectable(path!)).toBe(true);
      holder.command("RELEASE");
      const disposal = await holder.phase("DISPOSAL_SETTLED");
      expect(disposal.errors?.some(error => error.kind === "holder-lost")).toBe(true);
      if (shape === "sync-loss") expect(disposal).toMatchObject({ guardInCatch: 1, guardAtUnref: 1 });
      holder.command("EXIT");
      if (shape.startsWith("handled-") || shape === "cleanup-reject") await holder.phase("CLEANUP_DONE");
      await holder.phase("RETURNED");
      expect(await holder.done).toEqual({ code, signal: null });
      if (shape.startsWith("handled-") || shape === "cleanup-reject") expect(await readFile(join(root, "holder", "lk1-cleanup"), "utf8")).toBe("completed");
      expect(holder.stderr()).not.toContain("forcing");
      const after = await lstat(path!, { bigint: true }).catch(() => null);
      expect(after?.ino, "successor identity survives holder EXIT").toBe(identity.ino);
      expect(after?.dev).toBe(identity.dev);
      expect(await connectable(path!)).toBe(true);
      successor.command("CHECK");
      expect((await successor.phase("CHECKED")).held).toBe(true);
      const contender = await launch(root, "contender");
      await contender.phase("READY");
      const contention = await contender.phase("DISPOSAL_SETTLED");
      expect(contention.callbackCount).toBe(0);
      expect(contention.errors?.some(error => error.kind === "contention")).toBe(true);
      contender.command("EXIT");
      await contender.phase("RETURNED");
      expect(await contender.done).toEqual({ code: 0, signal: null });
      successor.command("RELEASE");
      expect((await successor.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
      successor.command("EXIT");
      await successor.phase("RETURNED");
      expect(await successor.done).toEqual({ code: 0, signal: null });
    }, TEST_TIMEOUT_MS);
  }
});

it("T2 N inventory: every kernel bind and close uses the ownership record", async () => {
  const ts: typeof import("typescript") = createRequire(import.meta.url)("typescript");
  const text = await readFile(new URL("../../src/storage/cross-process-lock.ts", import.meta.url), "utf8");
  const source = ts.createSourceFile("locks.ts", text, ts.ScriptTarget.Latest, true);
  const binds: string[] = [], closes: string[] = [];
  function visit(node: import("typescript").Node, owner = "") {
    if (ts.isFunctionDeclaration(node)) owner = node.name?.text ?? owner;
    if (ts.isCallExpression(node)) {
      const call = node.expression.getText(source);
      if (call === "listenOnSocket") binds.push(owner);
      if (call === "acquired.server.close" || call === "server.close") closes.push(owner);
    }
    ts.forEachChild(node, child => visit(child, owner));
  }
  visit(source);
  expect(binds.sort()).toEqual(["acquireKernelLock", "acquireMasterWriteBarrier", "probeKernelBackedCrossProcessLockCapability"]);
  expect(closes.filter(name => name !== "withLifetimeProfileLock")).toEqual(["releaseKernelLock"]);
});
