/** Real CLI/dashboard and fault injection into production lifecycle code. */
import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
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
        const reason = stopped ? "child-exit" : "observation-timeout";
        throw new Error(`Lifecycle observation failed (${mode}:${reason}); private fixture ${root}`);
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
      if (attempt === 1 || (!portRace && !schedulingTimeout)) throw error;
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
