/**
 * The results and local verbs are reached through the compiled CLI and are
 * listed for shell completion. Runs dist/cli.js, so the build must be current.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { runCompletionCommand } from "../../src/cli/completion.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

const run = promisify(execFile);
const CLI = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
// Must match the first lines of RESULTS_USAGE and LOCAL_USAGE in src/cli/local-results.ts.
const VERBS: Array<[verb: string, argv: string[], usage: string]> = [
  ["results", ["results", "--help"], "Usage: sanctuary results <command> [options]"],
  ["results", ["results"], "Usage: sanctuary results <command> [options]"],
  ["local", ["local", "--help"], "Usage: sanctuary local log <command> [options]"],
  ["local", ["local"], "Usage: sanctuary local log <command> [options]"],
];
// The CLI waits on nothing for a help form; this bounds a hang.
const CLI_TIMEOUT_MS = 60_000;

const temps: string[] = [];
afterEach(async () => {
  for (const path of temps.splice(0)) await rm(path, { recursive: true, force: true });
});

describe("the results and local verbs in the built CLI", () => {
  it.each(VERBS)("%s is dispatched to its own command (%j)", async (_verb, argv, usage) => {
    const home = await mkdtemp(join(tmpdir(), "local-verbs-"));
    temps.push(home);
    const env = { PATH: process.env.PATH ?? "", HOME: home, SANCTUARY_STORAGE_PATH: join(home, ".sanctuary"), NO_COLOR: "1" };
    const result = await run(process.execPath, [CLI, ...argv], { env, timeout: CLI_TIMEOUT_MS }).catch((error: { stdout?: string; stderr?: string; code?: number }) => error);
    expect(result.stdout ?? "").toContain(usage);
    expect(`${result.stdout ?? ""}${result.stderr ?? ""}`).not.toMatch(/unknown command/i);
  });

  it("both verbs are listed and completed", async () => {
    expect(TOP_LEVEL_SUBCOMMANDS as readonly string[]).toEqual(expect.arrayContaining(["results", "local"]));
    let text = "";
    const out = new Writable({ write(chunk, _encoding, done) { text += String(chunk); done(); } });
    expect(await runCompletionCommand({ argv: ["bash"], out })).toBe(0);
    const words = /compgen -W "([^"]*)"/.exec(text)?.[1]?.split(" ") ?? [];
    expect(words).toEqual(expect.arrayContaining(["results", "local"]));
  });
});
