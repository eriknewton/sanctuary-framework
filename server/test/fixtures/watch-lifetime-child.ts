/**
 * Child process for the observer lifetime witnesses. It runs `run-watch` or
 * `install-watch` with the PRODUCTION timers (the context passes no timers and
 * no sleep, so `realRunnerTimers` is used), over modelled children and temp
 * directories, and prints one `RETURNED <code>` line when the verb's promise
 * settles. A verb that lets the process exit early never prints it.
 *
 * Nothing here runs launchctl, id, ps, sysctl or netstat: every child is a
 * modelled event emitter answering the closed command enum.
 *
 * Usage: watch-lifetime-child.ts run-watch <fortress>
 *        watch-lifetime-child.ts install-watch <fortress> <home>
 */
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Writable } from "node:stream";
import { CANARY_LABEL } from "../../src/castle-wall/liveness/constants.js";
import { generateCanaryPlist, parseSystemJobPrint } from "../../src/castle-wall/liveness/launchd-plists.js";
import { runInstallWatch, runRunWatch } from "../../src/cli/castle-wall-watch.js";
import { BoundedChildRunner, realRunnerTimers, type WatchChild, type WatchSpawn } from "../../src/cli/castle-wall-watch-collectors.js";

const FIX = fileURLToPath(new URL("../castle-wall/liveness/fixtures", import.meta.url));
const PRINTS = JSON.parse(readFileSync(join(FIX, "launchctl-print.json"), "utf8")).entries as Record<string, { code: number; stdout: string; stderr: string }>;
const PS_TEXT = (JSON.parse(readFileSync(join(FIX, "process-census.json"), "utf8")) as { text: string }).text;
const NETSTAT = readFileSync(join(FIX, "census", "netstat-anv-macos26.txt"), "utf8");
const BASE_CONFIG = (JSON.parse(readFileSync(join(FIX, "states.json"), "utf8")).base.config.value) as Record<string, unknown>;
const UID = process.getuid!();
/** The fixture agent account; any uid other than the runner's. */
const AGENT_UID = UID + 1;
const NAME = "sanctuary-agent-fixture";

type Answer = { code: number; stdout: string };
/** Modelled children that answer on a later turn of the event loop, as a real child's output would arrive. */
function modelledSpawn(answer: (file: string, args: readonly string[]) => Answer, calls: string[][]): WatchSpawn {
  return (file, args) => {
    calls.push([file, ...args]);
    // Fixture pids only: 9000 plus the call index keeps each modelled child distinct.
    const child = Object.assign(new EventEmitter(), { pid: 9000 + calls.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter };
    child.kill = () => { setImmediate(() => { child.emit("exit", null, "SIGTERM"); child.emit("close", null, "SIGTERM"); }); return true; };
    const { code, stdout } = answer(file, args);
    setImmediate(() => { if (stdout) child.stdout.emit("data", Buffer.from(stdout)); child.emit("exit", code, null); child.emit("close", code, null); });
    return child;
  };
}

class Sink extends Writable {
  text = "";
  override _write(chunk: Buffer, _enc: string, done: () => void): void { this.text += chunk.toString(); done(); }
}

const [mode, fortress, home] = process.argv.slice(2);
const calls: string[][] = [];
const report = (code: number, out: string, err: string): void => {
  process.stdout.write(`${JSON.stringify({ out, err, calls })}\nRETURNED ${code}\n`);
};

if (mode === "run-watch") {
  const answer = (file: string): Answer => {
    if (file === "/usr/sbin/sysctl") return { code: 0, stdout: "boot-fixture-current\n" };
    if (file === "/bin/ps") return { code: 0, stdout: PS_TEXT };
    if (file === "/usr/sbin/netstat") return { code: 0, stdout: NETSTAT };
    if (file === "/bin/launchctl") return { code: 0, stdout: PRINTS.full_agent_gui!.stdout };
    return { code: 1, stdout: "" };
  };
  const runner = new BoundedChildRunner({ spawn: modelledSpawn(answer, calls), timers: realRunnerTimers });
  const out = new Sink();
  const err = new Sink();
  void runRunWatch(["--fortress", fortress!, "--launch-agent"], { platform: "darwin", runner, out, err }).then(code => report(code, out.text, err.text));
} else if (mode === "install-watch") {
  let observerLoaded = false;
  const answer = (file: string, args: readonly string[]): Answer => {
    if (file === "/usr/bin/id") return args[0] === "-un" ? { code: 0, stdout: `${NAME}\n` } : { code: 0, stdout: `${AGENT_UID}\n` };
    if (file !== "/bin/launchctl") return { code: 1, stdout: "" };
    if (args[0] === "print" && args[1]!.startsWith("gui/")) return observerLoaded ? PRINTS.observer_gui! : PRINTS.gui_not_found!;
    if (args[0] === "print" && args[1] === `system/${CANARY_LABEL}`) return PRINTS.canary_system!;
    if (args[0] === "bootstrap") { observerLoaded = true; return { code: 0, stdout: "" }; }
    if (args[0] === "bootout") { observerLoaded = false; return { code: 0, stdout: "" }; }
    return { code: 1, stdout: "" };
  };
  const runner = new BoundedChildRunner({ spawn: modelledSpawn(answer, calls), timers: realRunnerTimers });
  const bytes = Buffer.from(generateCanaryPlist(NAME));
  const out = new Sink();
  const err = new Sink();
  void runInstallWatch(["--fortress", fortress!], {
    platform: "darwin", home: home!, runner, out, err,
    stableRuntime: () => ({ ok: true, node: "/opt/homebrew/opt/node/bin/node", cli: "/opt/homebrew/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js", nodeVersion: "v22.0.0" }),
    readConfig: async () => ({ status: "present", value: { ...structuredClone(BASE_CONFIG), agent_uid: AGENT_UID } }),
    // The installed-plist facts are modelled: this child never reads /Library/LaunchDaemons.
    collectCanaryFacts: async () => ({
      plistStat: { status: "ok", value: { isFile: true, isSymbolicLink: false, uid: 0, gid: 0, mode: 0o100644, size: bytes.byteLength } },
      plistBytes: { status: "ok", value: bytes },
      account: { status: "ok", value: { name: NAME, reverseUid: AGENT_UID } },
      print: { status: "ok", value: parseSystemJobPrint(PRINTS.canary_system!.stdout) },
    }),
  }).then(code => report(code, out.text, err.text));
} else {
  process.stderr.write("unknown mode\n");
  // 64 = EX_USAGE in sysexits.h, distinct from every verb exit so a mistyped mode cannot read as a verb result.
  process.exitCode = 64;
}
