// Item 3 exemption: platform gating only; a Darwin start-token reader and S0 drill are owed.
import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, expect, it } from "vitest";
import { ledger, successful, classification, linuxStartToken, realLiveness } from "../../fixtures/full-supervision/support.js";
import type { FullSupervisionResult } from "../../../src/castle-wall/runtime/full-supervision-state.js";

interface Message { cut?: string; admission?: FullSupervisionResult; status?: FullSupervisionResult; holding?: boolean; error?: string }
interface Running {
  child: ChildProcess;
  messages: Message[];
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  holding: Promise<void>;
}
let root: string;
const children: Running[] = [];
let cancelled = false;
let spawningLoop: Promise<void> | undefined;
beforeEach(async () => {
  cancelled = false;
  spawningLoop = undefined;
  root = await mkdtemp(join(tmpdir(), "supervision-process-"));
});
afterEach(async () => {
  try {
    // Timeout does not cancel the test body: close admission before any exit can resume its loop.
    cancelled = true;
    for (const { child } of children) {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
    await Promise.allSettled(spawningLoop ? [spawningLoop] : []);
    const reaped = await Promise.allSettled(children.splice(0).map(async ({ child, exited }) => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await exited;
    }));
    const failed = reaped.find((result) => result.status === "rejected");
    if (failed?.status === "rejected") throw failed.reason;
  } finally { await rm(root, { recursive: true, force: true }); }
});
function start(cut: string, attemptId: string, budget = 5, mode = "cut", bootId = "test-boot"): Running {
  if (cancelled) throw new Error("process test cancelled before spawn");
  // Reuse test/operational/audit-log-two-process-tail.test.ts's resolved tsx import pattern.
  const child = spawn(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"),
    fileURLToPath(new URL("../../fixtures/full-supervision/child.ts", import.meta.url)), root, mode, cut, attemptId, String(budget), bootId],
  { stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env, HOME: root } });
  const messages: Message[] = [];
  let resolveHold!: () => void;
  const holding = new Promise<void>((resolve) => { resolveHold = resolve; });
  child.on("message", (message: Message) => { messages.push(message); if (message.holding) resolveHold(); });
  let stderr = "";
  child.stderr!.on("data", (data: Buffer) => { stderr += String(data); });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code !== null && code !== 0) reject(new Error(`fixture exited ${code}: ${stderr} ${JSON.stringify(messages)}`));
      else resolve({ code, signal });
    });
  });
  const running = { child, messages, exited, holding }; children.push(running); return running;
}
const cuts = ["before_pending_write", "after_pending_write", "after_identity_write", "before_settle", "after_settle"];
for (const cut of cuts) {
  // Identity cuts require the owed Darwin start-token reader; pre-identity cuts remain portable.
  const identityDependent = !["before_pending_write", "after_pending_write"].includes(cut);
  const test = identityDependent ? it.skipIf(process.platform !== "linux") : it;
  test(`real SIGKILL at ${cut} preserves admission and replay accounting`, async () => {
    const child = start(cut, "first", 1);
    expect((await child.exited).signal).toBe("SIGKILL");
    expect(child.messages.some((message) => message.cut === cut)).toBe(true);
    const instance = ledger(root, { budget: 1, processLiveness: realLiveness, processStartToken: linuxStartToken });
    if (cut === "before_pending_write") {
      expect(successful(await instance.status()).charges).toHaveLength(0);
      expect(successful(await instance.admit("next")).admitted).toBe(true);
    } else if (cut === "after_pending_write") {
      expect(await instance.admit("next")).toEqual({ ok: false, reason: "unidentified_attempt" });
      expect(successful(await instance.status()).state).toBe("state_PENDING_UNIDENTIFIED");
    } else {
      expect(await realLiveness(child.child.pid!)).toBe("dead");
      for (let replay = 0; replay < 2; replay++) {
        expect(await instance.admit("next")).toEqual({ ok: false, reason: "latched" });
        expect(successful(await instance.status()).charges.map((charge) => charge.attemptId)).toEqual(["first"]);
      }
    }
  });
}

it.skipIf(process.platform !== "linux")("refuses a recorded child that remains alive or has unknown liveness", async () => {
  const child = start("none", "live", 5, "hold");
  await Promise.race([child.holding, child.exited.then(() => { throw new Error("child exited before hold"); })]);
  expect(await realLiveness(child.child.pid!)).toBe("alive");
  expect(await ledger(root, { processLiveness: realLiveness, processStartToken: linuxStartToken }).admit("other")).toEqual({ ok: false, reason: "child_alive" });
  expect(await ledger(root, { processLiveness: async () => "unknown", processStartToken: linuxStartToken }).admit("other")).toEqual({ ok: false, reason: "child_unknown" });
});

it.skipIf(process.platform !== "linux")("admits at most K across 50 mixed crash iterations and preserves latch across boot and process restart", async () => {
  spawningLoop = (async () => {
    const schedule = cuts;
    let admissions = 0;
    const attempts = 50; // Ten K=5 waves, including attempted starts long after the latch.
    for (let iteration = 0; iteration < attempts; iteration++) {
      if (cancelled) return;
      const cut = schedule[iteration % schedule.length]!;
      const child = start(cut, `attempt-${iteration}`);
      await child.exited;
      if (cancelled) return;
      admissions += child.messages.filter((message) => message.admission?.ok && message.admission.admitted).length;
      expect(admissions).toBeLessThanOrEqual(5);
      if (cut === "after_pending_write" && child.messages.some((message) => message.admission?.ok)) {
        const reopened = ledger(root);
        expect(await reopened.admit("unidentified-retry")).toEqual({ ok: false, reason: "unidentified_attempt" });
        // The parent observed this exact child's SIGKILL and reaped it. Explicit
        // settlement uses that exit evidence; opening alone cannot resolve the identity gap.
        expect(await realLiveness(child.child.pid!)).toBe("dead");
        successful(await reopened.settle(`attempt-${iteration}`, classification(`attempt-${iteration}`, { exit: { signal: "SIGKILL" } })));
      }
    }
    expect(admissions).toBe(5);
    const state = successful(await ledger(root).status());
    expect(state.state).toBe("state_LATCHED");
    expect(state.charges).toHaveLength(5);
    expect(new Set(state.charges.map((charge) => charge.attemptId)).size).toBe(5);
    if (cancelled) return;
    const rebooted = start("none", "sixth", 5, "cut", "changed-boot");
    await rebooted.exited;
    expect(rebooted.messages).toContainEqual({ admission: { ok: false, reason: "latched" } });
    if (cancelled) return;
    const restarted = start("none", "inspect", 5, "inspect", "changed-boot");
    await restarted.exited;
    expect(restarted.messages).toContainEqual({ status: { ...state, admitted: false } });
  })();
  await spawningLoop;
}, 60_000); // Fifty real TS loader starts receive a minute; no timers drive the crash schedule.
