/** The pure canary integrity checker over collected facts, and the production fact collector over fixtures. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkCanaryIntegrity, type CanaryIntegrityFacts } from "../../../src/castle-wall/liveness/canary-integrity.js";
import { CHILD_READ_DEADLINE } from "../../../src/castle-wall/liveness/constants.js";
import { CANARY_PLIST_BYTES, generateCanaryPlist, parseSystemJobPrint } from "../../../src/castle-wall/liveness/launchd-plists.js";
import { BoundedChildRunner, createWatchCollectors, type WatchChild, type WatchSpawn } from "../../../src/cli/castle-wall-watch-collectors.js";
import { EventEmitter } from "node:events";

const NAME = "sanctuary-agent-fixture";
const AGENT_UID = 502;
const NOW = 1_794_225_600_000;
const PRINTS = JSON.parse(readFileSync(join(__dirname, "fixtures", "launchctl-print.json"), "utf8")) as {
  entries: Record<string, { code: number; stdout: string; stderr: string }>;
};
const bytes = Buffer.from(generateCanaryPlist(NAME));

function good(): CanaryIntegrityFacts {
  return {
    agentUid: AGENT_UID,
    plistStat: { status: "ok", value: { isFile: true, isSymbolicLink: false, uid: 0, gid: 0, mode: 0o100644, size: bytes.byteLength } },
    plistBytes: { status: "ok", value: bytes },
    account: { status: "ok", value: { name: NAME, reverseUid: AGENT_UID } },
    print: { status: "ok", value: parseSystemJobPrint(PRINTS.entries.canary_system!.stdout) },
  };
}
type Edit = (facts: CanaryIntegrityFacts) => void;
const stat = (facts: CanaryIntegrityFacts) => (facts.plistStat as unknown as { value: Record<string, unknown> }).value;
const print = (facts: CanaryIntegrityFacts) => (facts.print as unknown as { value: { arguments: string[]; username: string | null; program: string | null; valid: boolean } }).value;

describe("canary integrity conjunction", () => {
  it("passes with every conjunct and stamps this cycle's time", () => {
    expect(checkCanaryIntegrity(good(), NOW)).toEqual({ passed: true, checked_at_ms: NOW });
    expect(checkCanaryIntegrity(good(), NOW + 1)!.checked_at_ms).toBe(NOW + 1);
  });

  it.each<[string, Edit]>([
    ["owner not root (the suite runner's uid)", f => { stat(f).uid = process.getuid!() === 0 ? 1 : process.getuid!(); }],
    ["group not wheel", f => { stat(f).gid = 20; }],
    ["mode 0664", f => { stat(f).mode = 0o100664; }],
    ["mode 0600", f => { stat(f).mode = 0o100600; }],
    ["a symlink", f => { stat(f).isSymbolicLink = true; }],
    ["not a regular file", f => { stat(f).isFile = false; }],
    ["size over the cap", f => { stat(f).size = CANARY_PLIST_BYTES + 1; }],
    ["one byte changed", f => { const b = Buffer.from(bytes); b[b.length - 2] = 0x41; f.plistBytes = { status: "ok", value: b }; }],
    ["bytes over the cap", f => { f.plistBytes = { status: "ok", value: Buffer.alloc(CANARY_PLIST_BYTES + 1) }; }],
    ["file absent", f => { f.plistStat = { status: "failed" }; }],
    ["bytes unreadable", f => { f.plistBytes = { status: "failed" }; }],
    ["print absent", f => { f.print = { status: "ok", value: parseSystemJobPrint("") }; }],
    ["a refused system print read", f => { f.print = { status: "failed" }; }],
    ["print arguments differ", f => { print(f).arguments = print(f).arguments.slice(0, -1); }],
    ["print argument edited", f => { print(f).arguments = print(f).arguments.map(a => (a === "-q" ? "-v" : a)); }],
    ["print program differs", f => { print(f).program = "/bin/sh"; }],
    ["print user differs", f => { print(f).username = "root"; }],
    ["reverse uid differs", f => { f.account = { status: "ok", value: { name: NAME, reverseUid: AGENT_UID + 1 } }; }],
    ["an id failure", f => { f.account = { status: "failed" }; }],
    ["an invalid account name", f => { f.account = { status: "ok", value: { name: "bad name", reverseUid: AGENT_UID } }; }],
    ["bytes generated for another account", f => { f.plistBytes = { status: "ok", value: Buffer.from(generateCanaryPlist("other-agent")) }; }],
  ])("fails on %s", (_case, edit) => {
    const facts = good();
    edit(facts);
    expect(checkCanaryIntegrity(facts, NOW)).toEqual({ passed: false, checked_at_ms: NOW });
  });

  it("is null with no account to check", () => {
    expect(checkCanaryIntegrity({ ...good(), agentUid: null }, NOW)).toBeNull();
  });
});

/** A fake child that answers one argv with a fixed result, or never exits. */
function scriptedSpawn(answers: (args: readonly string[]) => { code: number; stdout: string; stderr?: string } | "hang"): { spawn: WatchSpawn; argv: string[][] } {
  const argv: string[][] = [];
  const spawn: WatchSpawn = (file, args) => {
    argv.push([file, ...args]);
    const child = new EventEmitter() as EventEmitter & WatchChild & { stdout: EventEmitter; stderr: EventEmitter };
    Object.assign(child, { pid: 1000 + argv.length, stdout: new EventEmitter(), stderr: new EventEmitter() });
    child.kill = () => { queueMicrotask(() => { child.emit("exit", null, "SIGTERM"); child.emit("close", null, "SIGTERM"); }); return true; };
    const answer = answers(args);
    if (answer !== "hang") {
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from(answer.stdout));
        if (answer.stderr) child.stderr.emit("data", Buffer.from(answer.stderr));
        child.emit("exit", answer.code, null);
        child.emit("close", answer.code, null);
      });
    }
    return child;
  };
  return { spawn, argv };
}

describe("canary fact collector", () => {
  const timers = { setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) };
  const fakeFs = (mode = 0o100644) => ({
    lstatSync: () => ({ isFile: () => true, isSymbolicLink: () => false, uid: 0, gid: 0, mode, size: bytes.byteLength }) as never,
    openSync: () => 7,
    readSync: (_fd: number, buffer: Uint8Array, offset: number) => { if (offset >= bytes.byteLength) return 0; buffer.set(bytes, offset); return bytes.byteLength; },
    closeSync: () => undefined,
  });

  it("collects facts that pass, through id -un, id -u and the system print", async () => {
    const { spawn, argv } = scriptedSpawn(args => {
      if (args[0] === "-un") return { code: 0, stdout: `${NAME}\n` };
      if (args[0] === "-u") return { code: 0, stdout: `${AGENT_UID}\n` };
      return { code: 0, stdout: PRINTS.entries.canary_system!.stdout };
    });
    const runner = new BoundedChildRunner({ spawn, timers });
    const collectors = createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501, fs: fakeFs() });
    const facts = await collectors.collectCanaryFacts(AGENT_UID);
    expect(checkCanaryIntegrity({ agentUid: AGENT_UID, ...facts }, NOW)!.passed).toBe(true);
    expect(argv).toEqual([
      ["/usr/bin/id", "-un", String(AGENT_UID)],
      ["/usr/bin/id", "-u", NAME],
      ["/bin/launchctl", "print", "system/ai.sanctuaryprotocol.castle-wall.canary"],
    ]);
  });

  it("fails when the id chain exceeds its one shared deadline", async () => {
    let clock = 0;
    const { spawn } = scriptedSpawn(args => {
      if (args[0] === "-un") { clock += CHILD_READ_DEADLINE; return { code: 0, stdout: `${NAME}\n` }; }
      if (args[0] === "-u") return { code: 0, stdout: `${AGENT_UID}\n` };
      return { code: 0, stdout: PRINTS.entries.canary_system!.stdout };
    });
    const runner = new BoundedChildRunner({ spawn, timers });
    const collectors = createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501, fs: fakeFs(), nowMs: () => clock });
    const facts = await collectors.collectCanaryFacts(AGENT_UID);
    expect(facts.account.status).toBe("failed");
    expect(checkCanaryIntegrity({ agentUid: AGENT_UID, ...facts }, NOW)!.passed).toBe(false);
  });

  it("fails on a refused system print and on a non-zero id", async () => {
    for (const refuse of ["print", "id"] as const) {
      const { spawn } = scriptedSpawn(args => {
        if (args[0] === "-un") return refuse === "id" ? { code: 1, stdout: "" } : { code: 0, stdout: `${NAME}\n` };
        if (args[0] === "-u") return { code: 0, stdout: `${AGENT_UID}\n` };
        return refuse === "print" ? { code: 1, stdout: "", stderr: "Operation not permitted\n" } : { code: 0, stdout: PRINTS.entries.canary_system!.stdout };
      });
      const runner = new BoundedChildRunner({ spawn, timers });
      const facts = await createWatchCollectors({ runner, timers, fortressPath: "/nonexistent-fixture", operatorUid: 501, fs: fakeFs() }).collectCanaryFacts(AGENT_UID);
      expect(checkCanaryIntegrity({ agentUid: AGENT_UID, ...facts }, NOW)!.passed, refuse).toBe(false);
    }
  });
});
