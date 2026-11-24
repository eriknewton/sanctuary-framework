// The results and local log verbs: export rows before files, whole pages, option values, and a clean environment.
import { open, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runLocalCommand, runResultsCommand } from "../../src/cli/local-results.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { operatorFixture, type OperatorFixture } from "./helpers/operator-fixture.js";

// Only host custody is replaced; the stores, the lock root and the files are real.
vi.mock("../../src/core/master-custody.js", async (original) => ({
  ...await original<typeof import("../../src/core/master-custody.js")>(),
  resolveCliMasterKey: vi.fn(),
}));

const USAGE_EXIT = 2;
const fixtures: OperatorFixture[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const fixture of fixtures.splice(0)) await fixture.close();
});

function capture() {
  let text = "";
  const stream = new Writable({ write(chunk, _encoding, done) { text += chunk.toString(); done(); } });
  return { stream, text: () => text };
}

async function setup(): Promise<OperatorFixture> {
  const fixture = await operatorFixture();
  fixtures.push(fixture);
  vi.stubEnv("SANCTUARY_STORAGE_PATH", fixture.path);
  vi.mocked(resolveCliMasterKey).mockClear();
  vi.mocked(resolveCliMasterKey).mockImplementation(async () => ({
    masterKey: Uint8Array.from(fixture.masterKey),
    masterWriteBarrier: { filesystemBacked: false, assertSessionHeld: () => {}, assertHeld: () => {}, release: async () => {}, signal: new AbortController().signal },
  }));
  return fixture;
}

type Runner = typeof runResultsCommand;
async function run(runner: Runner, argv: string[], env: NodeJS.ProcessEnv = { SANCTUARY_PASSPHRASE: "isolated-test-custody" }) {
  const out = capture();
  const err = capture();
  const code = await runner({ argv, out: out.stream, err: err.stream, env, input: new PassThrough() });
  return { code, out: out.text(), err: err.text() };
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(() => true, () => false);
}

describe("export rows come before export files", () => {
  it("a results export whose file cannot be created after its row leaves the row and no file", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const path = join(f.path, "missing-directory", "result.json");
    const result = await run(runResultsCommand, ["export", id, "--out", path]);
    expect(result.code).toBe(1);
    expect(await exists(path)).toBe(false);
    expect((await f.rows()).at(-1)).toMatchObject({ kind: "operator_export", body: { request_id: id } });
  });

  it("a log export whose file cannot be created after its row leaves the row and no file", async () => {
    const f = await setup();
    const path = join(f.path, "missing-directory", "log.jsonl");
    const result = await run(runLocalCommand, ["log", "export", "--out", path]);
    expect(result.code).toBe(1);
    expect(await exists(path)).toBe(false);
    expect((await f.rows()).at(-1)?.kind).toBe("oplog_exported");
  });

  it("an export to an existing path writes no row and leaves the path untouched", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    for (const [runner, argv] of [[runResultsCommand, ["export", id]], [runLocalCommand, ["log", "export"]]] as Array<[Runner, string[]]>) {
      const path = join(f.path, `existing-${argv[0]}.txt`);
      await (await open(path, "wx", 0o600)).writeFile("keep me", "utf8"); // Owner-only scratch file.
      const before = await f.rows();
      const result = await run(runner, [...argv, "--out", path]);
      expect(result.code).toBe(1);
      expect(result.err).toContain("already exists");
      expect(await readFile(path, "utf8")).toBe("keep me");
      expect(await f.rows()).toEqual(before);
    }
  });
});

describe("local log export writes the whole page", () => {
  it("every row reaches the file even when the file handle writes short", async () => {
    const f = await setup();
    for (let n = 1; n <= 5; n += 1) await f.seed(n, `summary ${n}`);
    // A handle whose single write call takes only half of what it is given.
    const probe = await open(join(f.path, "probe.bin"), "w", 0o600);
    const prototype = Object.getPrototypeOf(probe) as { write: (...args: unknown[]) => Promise<unknown> };
    await probe.close();
    const original = prototype.write;
    vi.spyOn(prototype, "write").mockImplementation(function (this: unknown, data: unknown, ...rest: unknown[]) {
      const half = typeof data === "string" ? data.slice(0, Math.ceil(data.length / 2)) : data;
      return original.call(this, half, ...rest);
    });
    const path = join(f.path, "log.jsonl");
    const result = await run(runLocalCommand, ["log", "export", "--out", path]);
    expect(result.code, result.err).toBe(0);
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    const rows = lines.map((line) => JSON.parse(line) as { seq: number; kind: string });
    expect(rows.at(-1)?.kind).toBe("oplog_exported");
    expect(rows.map((row) => row.seq)).toEqual(rows.map((_, index) => rows[0]!.seq + index));
  });
});

describe("option values are never read as a request id", () => {
  it("results show --fortress <path> <id> finds the result in that fortress", async () => {
    const f = await setup();
    const id = await f.seed(1, "the fortress summary");
    vi.stubEnv("SANCTUARY_STORAGE_PATH", join(f.path, "not-this-one"));
    const result = await run(runResultsCommand, ["show", "--fortress", f.path, id]);
    expect(result.code, result.err).toBe(0);
    expect(result.out).toContain("the fortress summary");
  });

  it("results show --fortress <path> with no id exits with usage before unlocking", async () => {
    const f = await setup();
    const result = await run(runResultsCommand, ["show", "--fortress", f.path]);
    expect(result.code).toBe(USAGE_EXIT);
    expect(resolveCliMasterKey).not.toHaveBeenCalled();
  });
});

describe("the verbs read their own environment", () => {
  it("a --fortress run leaves the process environment as it found it", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const elsewhere = join(f.path, "elsewhere");
    vi.stubEnv("SANCTUARY_STORAGE_PATH", elsewhere);
    const result = await run(runResultsCommand, ["show", "--fortress", f.path, id]);
    expect(result.code, result.err).toBe(0);
    expect(process.env.SANCTUARY_STORAGE_PATH).toBe(elsewhere);
  });

  it("the lock root comes from the command's environment: an override there that cannot be used refuses", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const result = await run(runResultsCommand, ["show", id], { SANCTUARY_PASSPHRASE: "isolated-test-custody", SANCTUARY_CUSTODY_LOCK_ROOT: "relative/lock-root" });
    expect(result.code).toBe(1);
    expect(result.err).toContain("custody lock root");
    expect(resolveCliMasterKey).not.toHaveBeenCalled();
  });

  it("the storage path comes from the command's environment when no --fortress is given", async () => {
    const f = await setup();
    const id = await f.seed(1, "from the command environment");
    vi.stubEnv("SANCTUARY_STORAGE_PATH", join(f.path, "not-this-one"));
    const result = await run(runResultsCommand, ["show", id], { SANCTUARY_PASSPHRASE: "isolated-test-custody", SANCTUARY_STORAGE_PATH: f.path });
    expect(result.code, result.err).toBe(0);
    expect(result.out).toContain("from the command environment");
  });
});

describe("sanctuary local log without a session", () => {
  it.each([[["log", "show"]], [["log", "export", "--out", "unused.jsonl"]]])("local %j refuses without a passphrase or recovery key", async (argv) => {
    const f = await setup();
    const before = await f.rows();
    const result = await run(runLocalCommand, argv, {});
    expect(result.code).toBe(1);
    expect(result.err).toContain("requires SANCTUARY_PASSPHRASE");
    expect(resolveCliMasterKey).not.toHaveBeenCalled();
    expect(await f.rows()).toEqual(before);
    expect(await exists("unused.jsonl")).toBe(false);
  });
});
