/**
 * The Hermes owner verbs as shipped: each verb reached from the real cli.ts
 * dispatcher in a child process, real signals delivered to a delete in
 * flight, and the real bridge child saving, recalling and (after an owner
 * delete) no longer recalling a passage.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";

import { HERMES_MEMORY_OWNER_DELETE_OPERATION } from "../../src/cli/hermes-memory.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import {
  CHILD_PREAMBLE, FIXTURE_AGENT_ID, auditEntries, ownerFortress, observeChild, runCleanups, runCli, runVerb, seedPassage,
  startBridge, type Cleanup, type OwnerFortress,
} from "../helpers/hermes-owner-fortress.js";

const stack: Cleanup[] = [];
afterEach(async () => { await runCleanups(stack); });

const PACKAGE_VERSION = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;
const CLOSING = "The Hermes memory relay is still stopped. Start it with: launchctl kickstart";
// A run that stops before reading the audit log cannot rule out an earlier unconfirmed delete.
const CLOSING_BEFORE_AUDIT_READ = "The Hermes memory relay is still stopped. The audit record could not be checked. Leave it stopped until the coordinator has read a memory-report.";
const source = (path: string) => new URL(path, import.meta.url).href;
const OWNER_MODULE = source("../../src/cli/hermes-memory.ts");
const ADAPTER_MODULE = source("../../src/sdw/adapters/sdw-memory-backend.ts");
const HELPER_MODULE = source("../helpers/hermes-owner-fortress.ts");
// A delivered signal is handled within one event-loop turn; 300 ms leaves a slow CI host ample margin before the resume.
const SIGNAL_SETTLE_MS = 300;
// Bound for one child to pause inside the delete or exit after resuming.
const CHILD_STEP_MS = 30_000;

describe("sanctuary hermes routing from cli.ts", () => {
  it("routes memory-report to its handler and prints the report", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "routed passage");
    const run = await runCli(f, ["hermes", "memory-report", "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, "--since", f.since], stack);
    expect(run.code, run.err).toBe(0);
    expect(JSON.parse(run.out)).toMatchObject({ report: "sanctuary hermes memory-report", owner_scope_passage_count: 1 });
    // cli.ts passes its own package version; the header carries it exactly, never a placeholder.
    expect(JSON.parse(run.out).provenance.package_version).toBe(PACKAGE_VERSION);
    expect(run.err.trimEnd().split("\n").at(-1)).toContain(CLOSING);
  });

  it.each(["memory-show", "memory-delete"])("routes %s to its handler, which refuses a non-terminal child", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "routed passage");
    const run = await runCli(f, ["hermes", verb, "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, "--passage", "p1"], stack);
    expect(run.code).toBe(1);
    expect(run.err).toContain("needs a terminal for both input and output");
    expect(run.err.trimEnd().split("\n").at(-1)!.startsWith(CLOSING_BEFORE_AUDIT_READ)).toBe(true);
    expect(run.out).not.toContain("routed passage");
  });

  it("routes recover-save to its handler, which opens the fortress with host-local custody", async () => {
    const f = await ownerFortress(stack);
    const run = await runCli(f, ["hermes", "recover-save", "--fortress", f.fortress], stack);
    expect(run, JSON.stringify(run)).toMatchObject({ code: 0, out: "nothing to recover\n" });
  });

  it("routes a mistyped hermes command to the hermes usage and the closing line, never to recover-save", async () => {
    const f = await ownerFortress(stack);
    const run = await runCli(f, ["hermes", "memory-reprot", "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID], stack);
    expect(run.code).toBe(2);
    expect(run.err).toContain("Run \"sanctuary hermes <command> --help\" for each command's rules.");
    expect(run.err).not.toContain("Usage: sanctuary hermes recover-save");
    expect(run.err.trimEnd().split("\n").at(-1)!.startsWith(CLOSING_BEFORE_AUDIT_READ)).toBe(true);
    // Positive control: recover-save itself still reaches its own help.
    const recover = await runCli(f, ["hermes", "recover-save", "--help"], stack);
    expect(recover.out).toContain("Usage: sanctuary hermes recover-save");
  });

  it("names the Hermes memory relay, never a private agent name, in sanctuary --help and the hermes help", async () => {
    const f = await ownerFortress(stack);
    const top = await runCli(f, ["--help"], stack);
    expect(top.code, top.err).toBe(0);
    expect(top.out).toContain("run with the Hermes memory relay stopped");
    expect(top.out).not.toMatch(/\bCoS\b/u);
    const recover = await runCli(f, ["hermes", "recover-save", "--help"], stack);
    expect(recover.out + recover.err).not.toMatch(/\bCoS\b/u);
    expect(recover.out + recover.err).toContain("recover-save");
  });

  it("lists all four hermes commands in hermes help and each verb's own help", async () => {
    const f = await ownerFortress(stack);
    const help = await runCli(f, ["hermes", "--help"], stack);
    expect(help.code).toBe(0);
    for (const verb of ["recover-save", "memory-report", "memory-show", "memory-delete"]) expect(help.out).toContain(`hermes ${verb}`);
    for (const verb of ["memory-report", "memory-show", "memory-delete"]) {
      const own = await runCli(f, ["hermes", verb, "--help"], stack);
      expect(own.code).toBe(0);
      expect(own.out).toContain(`Usage: sanctuary hermes ${verb}`);
    }
  });
});

/** Run memory-delete in a child that pauses inside deletePassage until the parent resumes it. */
async function deleteInChild(f: OwnerFortress, ignoreSignals: boolean) {
  const script = `${CHILD_PREAMBLE}
    const { runHermesMemory } = await import(${JSON.stringify(OWNER_MODULE)});
    const { SdwMemoryBackendAdapter } = await import(${JSON.stringify(ADAPTER_MODULE)});
    const { TerminalInput, TerminalSink } = await import(${JSON.stringify(HELPER_MODULE)});
    const real = SdwMemoryBackendAdapter.prototype.deletePassage;
    SdwMemoryBackendAdapter.prototype.deletePassage = async function(id) {
      process.send("paused");
      await new Promise(resume => process.once("message", resume));
      return real.call(this, id);
    };
    const stdout = new TerminalSink();
    const stderr = new TerminalSink();
    const stdin = new TerminalInput();
    let answered = false;
    stdout.on("data", () => { if (!answered && stdout.text.includes("Type DELETE")) { answered = true; stdin.write("DELETE\\n"); } });
    const code = await runHermesMemory({ argv: ["memory-delete", "--fortress", ${JSON.stringify(f.fortress)}, "--agent-id", ${JSON.stringify(FIXTURE_AGENT_ID)}, "--passage", "p1"],
      env: { HOME: ${JSON.stringify(f.home)} }, stdout, stderr, stdin, packageVersion: "0.0.0-owner-child", packageRoot: ${JSON.stringify(f.root)}, invokedEntry: undefined,
      ${ignoreSignals ? "" : "signals: { on() {}, off() {} },"} });
    process.stdout.write(JSON.stringify({ code, out: stdout.text, err: stderr.text }));
    process.disconnect();
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
    { detached: true, stdio: ["ignore", "pipe", "pipe", "ipc"], env: { ...process.env, HOME: f.home, VITEST: "true" } });
  const observed = observeChild(child, stack);
  await Promise.race([
    new Promise<void>(resolve => child.once("message", () => resolve())),
    observed.exit.then(() => { throw new Error(`child exited before the delete: ${observed.stderr()}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("child never reached the delete")), CHILD_STEP_MS)),
  ]);
  return observed;
}

describe("memory-delete signal window", () => {
  it.each(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGTSTP"] as const)("a %s after DELETE does not interrupt the delete", async signal => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "signal window passage");
    const observed = await deleteInChild(f, true);
    process.kill(observed.child.pid!, signal);
    await new Promise(resolve => setTimeout(resolve, SIGNAL_SETTLE_MS));
    expect(observed.child.exitCode).toBeNull();
    expect(observed.child.signalCode).toBeNull();
    observed.child.send("resume");
    const exit = await Promise.race([observed.exit,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`child did not finish after ${signal}`)), CHILD_STEP_MS))]);
    expect(exit, observed.stderr()).toEqual({ code: 0, signal: null });
    expect(JSON.parse(observed.stdout())).toMatchObject({ code: 0, out: expect.stringContaining("deleted\n") });
    expect((await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION)).map(entry => entry.details?.outcome)).toEqual(["intent", "deleted"]);
    expect(await f.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${FIXTURE_AGENT_ID}.p1`)).toBeNull();
  });

  it("control: without the ignore handlers the same SIGTERM kills the delete mid-flight, leaving an interrupted intent", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "signal window passage");
    const observed = await deleteInChild(f, false);
    process.kill(observed.child.pid!, "SIGTERM");
    expect(await observed.exit).toEqual({ code: null, signal: "SIGTERM" });
    expect((await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION)).map(entry => entry.details?.outcome)).toEqual(["intent"]);
    const next = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(next.code).toBe(1);
    expect(next.err).toContain("interrupted");
  });
});

describe("owner verbs against the real bridge", () => {
  it("witnesses a save and its recall without the words, then a delete that recall no longer returns", async () => {
    const f = await ownerFortress(stack);
    const token = "mauve-lantern-5c09e1";
    const text = `My library card number ends in ${token}.`;
    const first = startBridge(f, stack);
    expect(await first.next()).toEqual({ type: "ready" });
    expect(await first.call("memory_insert", { text, taint: "user_content", passage_id: "card", tags: ["turn-capture"] }))
      .toMatchObject({ outcome: "saved" });
    expect(JSON.stringify(await first.call("memory_recall", { query: token }))).toContain(token);
    await first.stop();

    const before = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(before.code, before.err).toBe(0);
    expect(before.out).not.toContain(token);
    expect(before.out).not.toContain("query_sha256");
    const parsed = JSON.parse(before.out);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(parsed.rows.find((row: Record<string, unknown>) => row.kind === "insert_admitted")).toMatchObject({
      passage_id: "card", present: "present", digest_matches: true, later_failure: false, resaved: false, tags: ["turn-capture"] });
    expect(parsed.rows.find((row: Record<string, unknown>) => row.kind === "memory_recall")).toMatchObject({
      passage_ids: ["card"], truncated: false });

    const deleted = await runVerb(f, ["memory-delete", "--passage", "card"], { answer: "DELETE\n" });
    expect(deleted.code, deleted.err).toBe(0);

    const second = startBridge(f, stack);
    expect(await second.next()).toEqual({ type: "ready" });
    const recall = await second.call("memory_recall", { query: token });
    expect(JSON.stringify(recall)).not.toContain(token);
    await second.stop();

    const after = JSON.parse((await runVerb(f, ["memory-report", "--since", f.since])).out);
    expect(after.rows.find((row: Record<string, unknown>) => row.kind === "insert_admitted")).toMatchObject({ present: "absent", resaved: false });
    const recalls = after.rows.filter((row: Record<string, unknown>) => row.kind === "memory_recall");
    expect(recalls.at(-1)).toMatchObject({ passage_ids: [], truncated: false });
    expect(after.owner_deletes[0].attempts).toEqual([expect.objectContaining({ outcome: "deleted" })]);
    expect(JSON.stringify(after)).not.toContain(token);
  }, 120_000);
});
