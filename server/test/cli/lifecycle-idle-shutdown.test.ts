// fail-before-exempt: bounds one lifecycle harness retry to clean or signaled early exits and adds capped diagnostics; assertions and production behavior are unchanged (CAP-READY-01).
/** Real CLI/dashboard and fault injection into production lifecycle code. */
import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstat, mkdtemp, mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { createServer, connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { decrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";

const fixture = fileURLToPath(new URL("../fixtures/lifecycle-idle-child.ts", import.meta.url));
const owned: Array<{ child: ChildProcess; root: string; done: Promise<unknown> }> = [];
const pause = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
// The full suite runs more than a thousand files in parallel. Starting the
// real tsx child can approach the old 15-second ready ceiling even in an
// isolated run, so timing pressure must not masquerade as a lifecycle defect.
const CHILD_DEADLINE_MS = 75_000;
const READY_TIMEOUT_MS = 60_000;
const RPC_TIMEOUT_MS = 15_000;
const TEST_TIMEOUT_MS = 150_000;
async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}
function killOwned(child: ChildProcess): void {
  if (child.pid && child.exitCode === null && child.signalCode === null) {
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
  }
}
async function launch(mode: string) {
  const port = await unusedPort();
  const root = await mkdtemp(join(tmpdir(), "sanctuary-lifecycle-"));
  const fortress = join(root, "fortress");
  await mkdir(fortress, { mode: 0o700 });
  const key = randomBytes(32);
  await writeFile(join(root, "fixture-key"), key, { mode: 0o600 });
  const child = spawn(process.execPath, ["--import", "tsx", fixture, mode], {
    detached: true, stdio: ["pipe", "pipe", "pipe"],
    env: { PATH: process.env.PATH, HOME: root, TMPDIR: root, VITEST: "true",
      SANCTUARY_STORAGE_PATH: fortress, SANCTUARY_NO_UPDATE_CHECK: "1",
      SANCTUARY_DASHBOARD_ENABLED: "true", SANCTUARY_DASHBOARD_PORT: String(port),
      SANCTUARY_DASHBOARD_AUTO_OPEN: "false" },
  });
  let stderr = "", pending = "";
  const messages: Array<{ id?: number; result?: unknown; error?: unknown }> = [];
  child.stderr!.on("data", (chunk: Buffer) => { stderr = (stderr + chunk.toString()).slice(-1_000_000); });
  child.stdout!.on("data", (chunk: Buffer) => {
    pending += chunk.toString();
    for (;;) {
      const end = pending.indexOf("\n"); if (end < 0) break;
      const line = pending.slice(0, end); pending = pending.slice(end + 1);
      try { messages.push(JSON.parse(line)); } catch { /* RPC will fail closed. */ }
    }
  });
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; killOwned(child); }, CHILD_DEADLINE_MS);
  const done = new Promise<{ code: number | null; signal: string | null; stderr: string; timedOut: boolean }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => { clearTimeout(deadline); resolve({ code, signal, stderr, timedOut }); });
  });
  owned.push({ child, root, done });
  async function until(check: () => boolean, ms = READY_TIMEOUT_MS): Promise<void> {
    const limit = Date.now() + ms;
    while (!check()) {
      const stopped = child.exitCode !== null || child.signalCode !== null;
      if (stopped || Date.now() > limit) {
        await writeFile(join(root, "child-stderr.log"), stderr, { mode: 0o600 });
        const reason = stopped
          ? `child-exit:${child.exitCode ?? "null"}:${child.signalCode ?? "none"}`
          : "observation-timeout";
        const stderrTail = stderr.trim().slice(-2_000);
        throw new Error(
          `Lifecycle observation failed (${mode}:${reason}); private fixture ${root}` +
          (stderrTail ? `; stderr tail: ${stderrTail}` : ""),
        );
      }
      await pause(20);
    }
  }
  async function rpc(id: number, method: string, params: unknown): Promise<unknown> {
    child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    await until(() => messages.some(message => message.id === id), RPC_TIMEOUT_MS);
    const message = messages.find(message => message.id === id)!;
    expect(message.error).toBeUndefined(); return message.result;
  }
  async function dispose(): Promise<void> {
    const index = owned.findIndex(item => item.child === child);
    if (index >= 0) owned.splice(index, 1);
    killOwned(child);
    await Promise.race([done.catch(() => {}), pause(1000)]);
    await rm(root, { recursive: true, force: true });
  }
  return { root, fortress, key, port, child, done, rpc, dispose,
    stderr: () => stderr,
    ready: () => until(() => stderr.includes(mode === "cli" ? "Tools: all registered" : "LIFECYCLE:READY")) };
}
async function launchReady(mode: string) {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    const run = await launch(mode);
    try {
      await run.ready();
      return run;
    } catch (error) {
      lastError = error;
      const portRace = /EADDRINUSE|already (?:owned|in use)/i.test(run.stderr());
      const schedulingTimeout = error instanceof Error &&
        error.message.includes(":observation-timeout)");
      // A clean early exit is the dashboard's benign single-owner stand-down;
      // a signal is host scheduling/resource pressure. Retry either once, but
      // never retry a numeric non-zero exit: that is a real CLI failure.
      const retryableChildExit = run.child.exitCode === 0 || run.child.signalCode !== null;
      if (attempt === 1 || (!portRace && !schedulingTimeout && !retryableChildExit)) throw error;
      await run.dispose();
    }
  }
  throw lastError;
}
afterEach(async () => {
  for (const item of owned.splice(0)) {
    killOwned(item.child);
    await Promise.race([item.done.catch(() => {}), pause(1000)]);
    await rm(item.root, { recursive: true, force: true });
  }
});
async function expectListenerGone(port: number): Promise<void> {
  const result = await new Promise<string>(resolve => {
    const socket = connect(port, "127.0.0.1");
    socket.once("connect", () => { socket.destroy(); resolve("open"); });
    socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "unknown"));
    socket.setTimeout(500, () => { socket.destroy(); resolve("timeout"); });
  });
  expect(result).toBe("ECONNREFUSED");
}
async function persisted(fortress: string, key: Uint8Array) {
  const storage = new FilesystemStorage(join(fortress, "state"));
  const raw = await storage.read("_principal", "session-baseline");
  expect(raw).not.toBeNull();
  const profile = JSON.parse(new TextDecoder().decode(decrypt(JSON.parse(new TextDecoder().decode(raw!)), derivePurposeKey(key, "principal-baseline")))) as { saved_at: string; tool_call_counts: Record<string, number> };
  expect(Number.isFinite(Date.parse(profile.saved_at))).toBe(true);
  // New reader after child exit cannot flush the child's in-memory queue.
  const audit = await new AuditLog(storage, key).query({ limit: 1000 });
  expect(audit.integrity_findings).toEqual([]);
  expect(audit.entries.length).toBeGreaterThan(0);
  return { profile, audit };
}
describe("production idle lifecycle", () => {
  for (const trigger of ["EOF", "SIGTERM", "SIGINT"] as const) {
    it(`actual CLI/dashboard persist and exit on ${trigger}`, async () => {
      const run = await launchReady("cli");
      const response = await fetch(`http://127.0.0.1:${run.port}/`, { signal: AbortSignal.timeout(2000) });
      expect(response.status).toBe(200);
      expect((await response.text()).toLowerCase().includes("sanctuary")).toBe(true);
      await run.rpc(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "lifecycle-test", version: "1" } });
      run.child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      expect(await run.rpc(2, "tools/call", { name: "state_read", arguments: { namespace: "lifecycle", key: "absent" } })).toBeDefined();
      const stopping = Date.now();
      if (trigger === "EOF") run.child.stdin!.end(); else run.child.kill(trigger);
      const outcome = await run.done;
      expect(outcome.timedOut).toBe(false); expect(outcome.signal).toBeNull(); expect(outcome.code).toBe(0);
      expect(Date.now() - stopping).toBeLessThan(8000);
      const { profile } = await persisted(run.fortress, run.key);
      expect(profile.tool_call_counts.state_read).toBeGreaterThan(0);
      await expectListenerGone(run.port);
    }, TEST_TIMEOUT_MS);
  }
  it("actual CLI catches stdin that ended before transport connection", async () => {
    const run = await launch("cli-preended");
    run.child.stdin!.end();
    const outcome = await run.done;
    expect(outcome.timedOut).toBe(false);
    expect(outcome.code).toBe(0);
    expect(outcome.signal).toBeNull();
    await persisted(run.fortress, run.key);
    await expectListenerGone(run.port);
  }, TEST_TIMEOUT_MS);
  it("real composition awaits close, survives rejection, stops producers, and caches cleanup permanently", async () => {
    const run = await launch("graph-reject"); const outcome = await run.done;
    expect(outcome.timedOut).toBe(false); expect(outcome.code).toBe(1); expect(outcome.signal).toBeNull();
    const obs = JSON.parse(await readFile(join(run.root, "observations.json"), "utf8")) as { trace: string[]; same: boolean; rejected: boolean; keyStillHeld: boolean };
    expect(obs.same).toBe(true); expect(obs.rejected).toBe(true); expect(obs.keyStillHeld).toBe(true);
    const trace = obs.trace;
    const producers = ["inbox-stop", "suggester-stop", "sentinel-dispose", "anomaly-dispose", "actions-dispose", "dashboard-stop"];
    for (const label of ["close-start", "close-end", ...producers, "inbox-flush", "baseline-save", "audit-flush"]) expect(trace.filter(item => item === label)).toHaveLength(1);
    expect(trace.indexOf("close-end")).toBeLessThan(trace.indexOf("inbox-stop"));
    for (const label of producers) expect(trace.indexOf(label)).toBeLessThan(trace.indexOf("inbox-flush"));
    expect(trace.indexOf("inbox-flush")).toBeLessThan(trace.indexOf("baseline-save"));
    expect(trace.at(-1)).toBe("audit-flush");
    const { audit } = await persisted(run.fortress, run.key);
    expect(audit.entries.some(entry => entry.operation === "lifecycle_final_append")).toBe(true);
    await expectListenerGone(run.port);
  }, TEST_TIMEOUT_MS);
  for (const [mode, code] of [["reject", 1], ["prior", 42], ["stray", 1], ["pending", 1]] as const) {
    it(`production CLI helper handles ${mode}`, async () => {
      const run = await launch(`helper-${mode}`); await run.ready(); run.child.stdin!.end();
      const outcome = await run.done;
      expect(outcome.timedOut).toBe(false); expect(outcome.signal).toBeNull(); expect(outcome.code).toBe(code);
      if (mode === "stray" || mode === "pending") expect(outcome.stderr.includes("forcing exit")).toBe(true);
      if (mode === "reject") expect(outcome.stderr.includes("shutdown error")).toBe(true);
    }, TEST_TIMEOUT_MS);
  }
  it("production CLI helper caches simultaneous, reentrant and post-completion shutdown", async () => {
    const run = await launch("helper-reentry"); const outcome = await run.done;
    expect(outcome.timedOut).toBe(false); expect(outcome.code).toBe(0);
    expect(JSON.parse(await readFile(join(run.root, "observations.json"), "utf8"))).toEqual({ calls: 1, same: true });
  }, TEST_TIMEOUT_MS);
});

// Must match the IPC phases and commands in fixtures/lifecycle-idle-child.ts.
type LK1Message = { recoveryCalls?: number; importCalls?: number; floorReached?: boolean; durableLoads?: number; phase: string; path?: string; directory?: string; request_id?: string; reason?: string; context?: { cause_class?: string }; errors?: Array<{ kind?: string }>; held?: boolean; callbackCount?: number };
const LK1_STDERR_CAP_BYTES = 16_384; // 16 KiB with 1024 bytes per KiB.
const LK1_LINE_BUFFER_CAP_BYTES = 65_536; // 64 KiB with 1024 bytes per KiB.
function lk1Observe(child: ChildProcess) {
  let stderr = "", buffer = "";
  const waiting = new Map<string, { resolve: (value: any) => void; reject: (error: Error) => void }>();
  const messages = new Map<string, unknown>();
  let stopped = false;
  function deliver(name: string, value: unknown) {
    const waiter = waiting.get(name);
    if (waiter) { waiting.delete(name); waiter.resolve(value); }
    else {
      if (messages.has(name)) throw new Error(`duplicate LK1 phase ${name}`);
      messages.set(name, value);
    }
  }
  child.stderr!.on("data", (data: Buffer) => {
    const wasReady = stderr.includes("Tools: all registered");
    stderr = (stderr + data.toString()).slice(-LK1_STDERR_CAP_BYTES);
    if (!wasReady && stderr.includes("Tools: all registered")) deliver("READY", {});
  });
  child.stdout!.on("data", (data: Buffer) => {
    buffer += data.toString();
    if (Buffer.byteLength(buffer) > LK1_LINE_BUFFER_CAP_BYTES) throw new Error("LK1 RPC line overflow");
    for (;;) {
      const end = buffer.indexOf("\n"); if (end < 0) break;
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      const message = JSON.parse(line);
      if (message.id !== undefined) deliver(`rpc:${message.id}`, message);
    }
  });
  child.on("message", (message: LK1Message) => deliver(message.phase, message));
  const done = new Promise<{ code: number | null; signal: string | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      stopped = true;
      for (const waiter of waiting.values()) waiter.reject(new Error(`LK1 child exited ${code}/${signal}: ${stderr}`));
      waiting.clear(); resolve({ code, signal });
    });
  });
  function phase<T = LK1Message>(name: string, timeoutMs = READY_TIMEOUT_MS): Promise<T> {
    if (messages.has(name)) { const value = messages.get(name); messages.delete(name); return Promise.resolve(value as T); }
    if (stopped) return Promise.reject(new Error(`LK1 child stopped before ${name}: ${stderr}`));
    if (waiting.has(name)) return Promise.reject(new Error(`duplicate LK1 observer ${name}`));
    let timer: ReturnType<typeof setTimeout>;
    return new Promise<T>((resolve, reject) => {
      timer = setTimeout(() => { waiting.delete(name); reject(new Error(`LK1 phase ceiling ${name}: ${stderr}`)); }, timeoutMs);
      waiting.set(name, { resolve, reject });
    }).finally(() => clearTimeout(timer));
  }
  return { phase, done, stderr: () => stderr,
    command: (command: string, identity?: string) => child.send({ command, identity }),
    rpc: async (id: number, name: string, args: unknown) => {
      child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } })}\n`);
      const response = await phase<{ error?: unknown; result: any }>(`rpc:${id}`, RPC_TIMEOUT_MS);
      expect(response.error).toBeUndefined(); return response.result;
    },
  };
}

describe.runIf(process.platform === "linux" || process.platform === "darwin")("LK1 real CLI quota ownership", () => {
  for (const trigger of ["EOF", "SIGTERM", "SIGINT", "ALIVE", "CLAIM", "IDENTITY", "IMPORT"] as const) {
    it(`${trigger === "CLAIM" ? "T9" : trigger === "IDENTITY" || trigger === "IMPORT" ? "T10" : "T1"} R: completed CLI ${trigger} cleanup preserves its successor`, async () => {
      const root = await mkdtemp(join(tmpdir(), "l-"));
      const fortress = join(root, "fortress");
      await mkdir(fortress, { mode: 0o700 });
      const key = randomBytes(32);
      await writeFile(join(root, "fixture-key"), key, { mode: 0o600 });
      const port = await unusedPort();
      const token = randomBytes(32).toString("hex");
      const child = spawn(process.execPath, ["--import", "tsx", fixture, trigger === "CLAIM" ? "cli-lk1-claim" : trigger === "IDENTITY" ? "cli-lk1-identity" : trigger === "IMPORT" ? "cli-lk1-import" : "cli-lk1"], {
        detached: true, stdio: ["pipe", "pipe", "pipe", "ipc"],
        env: { PATH: process.env.PATH, HOME: root, TMPDIR: root, VITEST: "true",
          SANCTUARY_STORAGE_PATH: fortress, SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "k"), SANCTUARY_NO_UPDATE_CHECK: "1",
          SANCTUARY_DASHBOARD_ENABLED: "true", SANCTUARY_DASHBOARD_PORT: String(port),
          SANCTUARY_DASHBOARD_AUTO_OPEN: "false", SANCTUARY_DASHBOARD_AUTH_TOKEN: token },
      });
      const run = lk1Observe(child);
      const children: Array<{ child: ChildProcess; done: Promise<unknown> }> = [{ child, done: run.done }];
      try {
        await run.phase("READY");
        child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "lk1", version: "1" } } })}\n`);
        await run.phase("rpc:1");
        child.stdin!.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
        const created = await run.rpc(2, "identity_create", { label: "lk1" });
        expect(created.isError).not.toBe(true);
        const identity = JSON.parse(created.content[0].text).identity_id;
        expect(identity).toEqual(expect.any(String));
        run.command("BIND", identity); await run.phase("BOUND");
        if (trigger !== "CLAIM" && trigger !== "IDENTITY" && trigger !== "IMPORT") {
          const warm = await run.rpc(3, "sanctuary_remember", { key: "warm", value: "warm" });
          expect(warm.isError).not.toBe(true);
          expect(JSON.stringify(warm)).not.toContain('"denied":true');
        }
        const approve = async (pending: Promise<any>, decision: "approve" | "deny") => {
          const hold = await Promise.race([run.phase("HOLD"), pending.then((): LK1Message => ({ phase: "OP_SETTLED" }))]);
          expect(hold.phase, "Tier 1 approval precedes import effects").toBe("HOLD");
          const response = await fetch(`http://127.0.0.1:${port}/api/${decision}/${hold.request_id}`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
          expect(response.status).toBe(200);
          return pending;
        };
        let bundle: string | undefined;
        if (trigger === "IMPORT") {
          const exported = await approve(run.rpc(8, "reputation_export", { identity_id: identity }), "approve");
          expect(exported.isError).not.toBe(true);
          bundle = JSON.parse(exported.content[0].text).bundle;
          expect(bundle).toEqual(expect.any(String));
          const healthy = await approve(run.rpc(9, "reputation_import", { bundle }), "approve");
          expect(healthy.isError).not.toBe(true);
          expect(JSON.parse(healthy.content[0].text).error).toBeUndefined();
          expect(JSON.parse(healthy.content[0].text).completeness_verification).not.toBe("failed");
          run.command("COUNTS"); expect(await run.phase("RECOVERY_COUNTS")).toMatchObject({ importCalls: 1, recoveryCalls: 0 });
        }
        run.command("ARM"); await run.phase("ARMED");
        if (trigger === "IMPORT") {
          const denied = run.rpc(10, "reputation_import", { bundle });
          const hold = await Promise.race([run.phase("HOLD"), denied.then((): LK1Message => ({ phase: "OP_SETTLED" }))]);
          expect(hold.phase, "unapproved import remains held").toBe("HOLD");
          run.command("COUNTS"); expect(await run.phase("RECOVERY_COUNTS")).toMatchObject({ importCalls: 1, recoveryCalls: 0 });
          const response = await fetch(`http://127.0.0.1:${port}/api/deny/${hold.request_id}`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
          expect(response.status).toBe(200); expect(JSON.stringify(await denied)).toMatch(/denied|refused/i);
          run.command("COUNTS"); expect(await run.phase("RECOVERY_COUNTS")).toMatchObject({ importCalls: 1, recoveryCalls: 0 });
        }
        const saving = trigger === "IDENTITY" ? run.rpc(4, "identity_create", { label: "runtime" })
          : trigger === "IMPORT" ? run.rpc(4, "reputation_import", { bundle })
          : run.rpc(4, "sanctuary_remember", { key: "refused", value: "refused" });
        void saving.catch(() => {});
        if (trigger === "IMPORT") {
          const hold = await run.phase("HOLD");
          const response = await fetch(`http://127.0.0.1:${port}/api/approve/${hold.request_id}`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
          expect(response.status).toBe(200);
        }
        const pausePhase = trigger === "CLAIM" ? "CLAIM_PAUSED" : trigger === "IDENTITY" || trigger === "IMPORT" ? "RECOVERY_PAUSED" : "READ_PAUSED";
        const paused = await Promise.race([run.phase(pausePhase), saving.then((result): LK1Message => ({ phase: "OP_SETTLED", result } as LK1Message))]);
        expect(paused.phase, `real consumer reaches the required lock pause: ${JSON.stringify(paused)}`).toBe(pausePhase);
        if (trigger === "IDENTITY" || trigger === "IMPORT") expect(paused.floorReached).toBe(true);
        await unlink(paused.path!);
        await expect(lstat(paused.path!)).rejects.toMatchObject({ code: "ENOENT" });
        async function launchPeer(role: string) {
          const home = join(root, role); await mkdir(home, { mode: 0o700 });
          const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../fixtures/lock-teardown-child.ts", import.meta.url)), role, "numeric0", "source"], {
            detached: true, stdio: ["ignore", "pipe", "pipe", "ipc"],
            env: { PATH: process.env.PATH, HOME: home, TMPDIR: home, VITEST: "true",
              SANCTUARY_STORAGE_PATH: join(home, "fortress"), SANCTUARY_CUSTODY_LOCK_ROOT: join(root, "k"),
              SANCTUARY_NO_UPDATE_CHECK: "1", LK1_TARGET: paused.directory, LK1_DIRECT_LOCK: trigger === "CLAIM" ? ".memory-handles.lock" : trigger === "IDENTITY" || trigger === "IMPORT" ? "custody-master.lock" : "own-scope-save-quota.lock" },
          });
          const observation = lk1Observe(child);
          children.push({ child, done: observation.done });
          return { child, ...observation };
        }
        const peer = await launchPeer("successor");
        const successor = peer.child;
        await peer.phase("READY");
        expect((await peer.phase("HELD")).path).toBe(paused.path);
        const heldIdentity = await lstat(paused.path!, { bigint: true });
        run.command("RESUME");
        if (trigger === "IMPORT") {
          const refusal = JSON.parse((await saving).content[0].text);
          expect(refusal).toMatchObject({ imported_attestations: 0, completeness_verification: "failed" });
          expect(refusal.error).toEqual(expect.any(String));
        } else if (trigger === "CLAIM" || trigger === "IDENTITY") {
          expect((await saving).isError).toBe(true);
        } else {
        const hold = await run.phase("HOLD");
        expect(hold.reason).toBe("memory save quota unavailable");
        expect(["deadline", "lock"]).toContain(hold.context?.cause_class);
        const denial = await fetch(`http://127.0.0.1:${port}/api/deny/${hold.request_id}`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
        expect(denial.status).toBe(200);
        expect(JSON.stringify(await saving)).toMatch(/denied|refused/i);
        }
        await run.phase("DISPOSAL_SETTLED");
        expect(await run.rpc(5, "state_read", { namespace: "lifecycle", key: "absent" })).toBeDefined();
        if (trigger === "CLAIM") {
          run.command("LOADS"); const before = (await run.phase("CACHE_STATE")).durableLoads!;
          const retried = await run.rpc(6, "sanctuary_remember", { key: "retried", value: "retried" });
          expect(retried.isError).not.toBe(true);
          run.command("LOADS"); const after = (await run.phase("CACHE_STATE")).durableLoads!;
          expect(after, "retry loads the durable first-use claim").toBeGreaterThan(before);
          const warm = await run.rpc(7, "sanctuary_remember", { key: "cached", value: "cached" });
          expect(warm.isError).not.toBe(true);
          run.command("LOADS"); expect((await run.phase("CACHE_STATE")).durableLoads).toBe(after);
        }
        const assertConnectable = async () => {
          await new Promise<void>((resolve, reject) => {
            const socket = connect(paused.path!);
            socket.once("connect", () => { socket.destroy(); resolve(); });
            socket.once("error", reject);
            socket.setTimeout(RPC_TIMEOUT_MS, () => { socket.destroy(); reject(new Error("quota connection ceiling")); });
          });
        };
        await assertConnectable();
        if (trigger === "ALIVE") {
          successor.send("CHECK"); expect((await peer.phase("CHECKED")).held).toBe(true);
          successor.send("RELEASE"); expect((await peer.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
          successor.send("EXIT"); await peer.phase("RETURNED");
          expect(await peer.done).toEqual({ code: 0, signal: null });
          expect(child.exitCode).toBeNull();
          const fresh = await run.rpc(6, "sanctuary_remember", { key: "continued", value: "continued" });
          expect(fresh.isError).not.toBe(true);
          expect(JSON.stringify(fresh)).not.toMatch(/"denied":true|"refused":true/);
        }
        run.command("STOPPING"); await run.phase("STOPPING");
        if (trigger === "EOF" || trigger === "ALIVE" || trigger === "CLAIM" || trigger === "IDENTITY" || trigger === "IMPORT") child.stdin!.end(); else child.kill(trigger);
        await run.phase("FLUSH_DONE");
        expect(await run.done).toEqual({ code: 0, signal: null });
        expect(run.stderr()).not.toContain("forcing");
        expect(JSON.parse(await readFile(join(root, "lk1-flush.json"), "utf8")).sort()).toEqual(["audit", "baseline", "inbox"]);
        const { profile } = await persisted(fortress, key);
        expect(profile.tool_call_counts.state_read ?? 0, "shutdown persists the final live read").toBeGreaterThan(0);
        if (trigger === "ALIVE") return;
        const after = await lstat(paused.path!, { bigint: true }).catch(() => null);
        expect(after?.ino, "quota successor survives actual CLI shutdown").toBe(heldIdentity.ino);
        expect(after?.dev).toBe(heldIdentity.dev);
        await assertConnectable();
        successor.send("CHECK"); expect((await peer.phase("CHECKED")).held).toBe(true);
        const contender = await launchPeer("contender");
        await contender.phase("READY");
        const blocked = await contender.phase("DISPOSAL_SETTLED");
        expect(blocked.callbackCount).toBe(0);
        expect(blocked.errors?.some(error => error.kind === "contention")).toBe(true);
        contender.child.send("EXIT"); await contender.phase("RETURNED");
        expect(await contender.done).toEqual({ code: 0, signal: null });
        successor.send("RELEASE"); expect((await peer.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
        successor.send("EXIT"); await peer.phase("RETURNED");
        expect(await peer.done).toEqual({ code: 0, signal: null });
        const reacquired = await launchPeer("contender-after");
        await reacquired.phase("READY");
        expect((await reacquired.phase("HELD")).path).toBe(paused.path);
        reacquired.child.send("RELEASE");
        expect((await reacquired.phase("DISPOSAL_SETTLED")).errors).toEqual([]);
        reacquired.child.send("EXIT"); await reacquired.phase("RETURNED");
        expect(await reacquired.done).toEqual({ code: 0, signal: null });
      } finally {
        for (const item of children) { killOwned(item.child); await item.done; }
        await rm(root, { recursive: true, force: true });
      }
    }, TEST_TIMEOUT_MS);
  }
});
