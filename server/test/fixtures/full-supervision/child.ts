import { ledger, classification, linuxStartToken, realLiveness, successful } from "./support.js";

const [directory, mode, cut, attemptId, budgetText, bootId] = process.argv.slice(2);
const instance = ledger(directory!, {
  budget: Number(budgetText), bootIdentity: async () => bootId!,
  processLiveness: realLiveness, processStartToken: linuxStartToken,
});
async function send(value: unknown): Promise<void> {
  await new Promise<void>((resolve, reject) => process.send!(value as object, (error) => error ? reject(error) : resolve()));
}
async function step(name: string): Promise<void> {
  if (name !== cut) return;
  await send({ cut: name });
  process.kill(process.pid, "SIGKILL");
  // No work follows a crash cut, even if a platform failed to deliver the signal.
  await new Promise<never>(() => {});
}
async function run() {
  if (mode === "inspect") { await send({ status: await instance.status() }); return; }
  await step("before_pending_write");
  const admission = await instance.admit(attemptId!);
  await send({ admission });
  if (!admission.ok) return;
  await step("after_pending_write");
  const start = await linuxStartToken(process.pid);
  if (!start) throw new Error("test child start token unavailable");
  successful(await instance.recordIdentity(attemptId!, process.pid, start));
  if (mode === "hold") {
    await send({ holding: true });
    await new Promise<void>((resolve) => process.once("message", () => resolve()));
    return;
  }
  await step("after_identity_write");
  await step("before_settle");
  successful(await instance.settle(attemptId!, classification(attemptId!)));
  await step("after_settle");
}
try { await run(); process.disconnect?.(); }
catch (error) { await send({ error: String(error) }); process.exitCode = 1; process.disconnect?.(); }
