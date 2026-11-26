/**
 * Wired consumer: the production `cli.ts` dispatch routes `verify-release` to
 * its handler, which produces `verified` and `refused` from the orchestration
 * witness's wiring (synthetic release, test-key manifest, provenance stub).
 * The handler is wrapped only to add those injected dependencies; the argv
 * and entry module URL it receives are the dispatcher's own.
 */
import { Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as handler from "../../src/cli/verify-release.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";
import { denyAllNetwork } from "./helpers.js";
import { cleanupTempRoots, deps, install, release } from "./synthetic.js";

vi.mock("../../src/cli/verify-release.js", async importOriginal => {
  const original = await importOriginal<typeof import("../../src/cli/verify-release.js")>();
  return { ...original, runVerifyReleaseCommand: vi.fn(original.runVerifyReleaseCommand) };
});

denyAllNetwork();
afterEach(cleanupTempRoots);

async function dispatch(argv: string[], wiring: Parameters<typeof handler.runVerifyReleaseCommand>[0]["deps"]) {
  const run = vi.mocked(handler.runVerifyReleaseCommand);
  const original = (await vi.importActual<typeof import("../../src/cli/verify-release.js")>("../../src/cli/verify-release.js")).runVerifyReleaseCommand;
  const chunks: string[] = [];
  const out = new Writable({ write(chunk, _enc, done) { chunks.push(String(chunk)); done(); } });
  run.mockImplementationOnce(args => original({ ...args, out, deps: wiring }));
  const exits: number[] = [];
  const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code: number) => { exits.push(code); }) as never);
  const savedArgv = process.argv;
  const savedExitCode = process.exitCode;
  process.argv = [process.execPath, "/usr/local/bin/sanctuary", ...argv];
  try {
    vi.resetModules();
    await (await import("../../src/cli.js")).cliEntryInvocation;
    for (let i = 0; i < 100 && exits.length === 0; i++) await new Promise<void>(done => setImmediate(done));
  } finally {
    process.argv = savedArgv;
    exitSpy.mockRestore();
    process.exitCode = savedExitCode;
  }
  return { run, exits, output: chunks.join("") };
}

describe("cli.ts dispatch of verify-release", () => {
  it("the verb is in the subcommand registry", () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("verify-release");
  });

  it("reaches the handler with the dispatcher's argv and cli.ts's own module URL, and produces verified (exit 0)", async () => {
    const r = release();
    const root = install(r.files);
    const { run, exits, output } = await dispatch(["verify-release", "--target", root, "--json"], deps(r));
    expect(run).toHaveBeenCalledTimes(1);
    expect(run.mock.calls[0]![0].argv).toEqual(["--target", root, "--json"]);
    expect(run.mock.calls[0]![0].entryModuleUrl).toMatch(/\/src\/cli\.ts$/);
    expect(JSON.parse(output)).toMatchObject({ verdict: "verified", target: root });
    expect(exits).toEqual([0]);
  });

  it("produces refused (exit 3) through the same dispatch", async () => {
    const r = release();
    const root = install({ ...r.files, "README.md": "changed" });
    const { exits, output } = await dispatch(["verify-release", "--target", root, "--json"], deps(r));
    expect(JSON.parse(output)).toMatchObject({ verdict: "refused", reason: "installed-file-differs:README.md" });
    expect(exits).toEqual([3]);
  });
});
