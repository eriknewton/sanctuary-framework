// fail-before-exempt: the results and local verbs and their module are new; base has no such commands.
import { open, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DELETE_ALL_CONFIRMATION, runLocalCommand, runResultsCommand } from "../../src/cli/local-results.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { oplogRowKey } from "../../src/local-recompile/oplog.js";
import { LOCAL_OPLOG_NAMESPACE } from "../../src/local-recompile/store-record.js";
import { operatorFixture, requestId, type OperatorFixture } from "./helpers/operator-fixture.js";

// Only host custody is replaced; the stores, the lock root and the files are real.
vi.mock("../../src/core/master-custody.js", async (original) => ({
  ...await original<typeof import("../../src/core/master-custody.js")>(),
  resolveCliMasterKey: vi.fn(),
}));

// Owner read and write only; must match EXPORT_FILE_MODE in src/cli/local-results.ts.
const OWNER_ONLY = 0o600;
const PERMISSION_BITS = 0o777;

/** Mode and text of one file, both read through a single descriptor so they describe the same file. */
async function readOwnedFile(path: string): Promise<{ mode: number; text: string }> {
  const handle = await open(path, "r");
  try {
    return { mode: (await handle.stat()).mode, text: await handle.readFile("utf8") };
  } finally {
    await handle.close();
  }
}
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
async function run(runner: Runner, argv: string[], options: { env?: NodeJS.ProcessEnv; input?: string } = {}) {
  const out = capture();
  const err = capture();
  const input = new PassThrough();
  if (options.input !== undefined) input.end(options.input);
  const code = await runner({ argv, out: out.stream, err: err.stream, env: options.env ?? { SANCTUARY_PASSPHRASE: "isolated-test-custody" }, input });
  return { code, out: out.text(), err: err.text() };
}

async function kinds(fixture: OperatorFixture): Promise<string[]> {
  return (await fixture.rows()).map((row) => row.kind);
}

describe("sanctuary results", () => {
  it("lists results newest first", async () => {
    const f = await setup();
    const older = await f.seed(1, "first summary");
    const newer = await f.seed(2, "second summary");
    const result = await run(runResultsCommand, ["list"]);
    expect(result.code, result.err).toBe(0);
    expect(result.out.indexOf(newer)).toBeLessThan(result.out.indexOf(older));
    expect(result.out).toContain("committed");
  });

  it("shows a summary and its sources and records the view first", async () => {
    const f = await setup();
    const id = await f.seed(1, "the main points");
    const result = await run(runResultsCommand, ["show", id]);
    expect(result.code, result.err).toBe(0);
    expect(result.out).toContain("the main points");
    expect(result.out).toContain('"namespace":"notes"');
    expect((await kinds(f)).at(-1)).toBe("operator_render");
  });

  it("terminal control characters in a summary are neutralised on show", async () => {
    const f = await setup();
    const id = await f.seed(1, "a\u001b[2Jb\u0007c\u009bd\nline two\tend");
    const result = await run(runResultsCommand, ["show", id]);
    expect(result.code, result.err).toBe(0);
    expect(result.out).toContain("a�[2Jb�c�d\nline two\tend");
    for (const control of ["\u001b", "\u0007", "\u009b"]) expect(result.out).not.toContain(control);
  });

  it("exports one result as a new owner-only file and records the export", async () => {
    const f = await setup();
    const id = await f.seed(1, "exported text");
    const path = join(f.path, "export.json");
    const result = await run(runResultsCommand, ["export", id, "--out", path]);
    expect(result.code, result.err).toBe(0);
    const exported = await readOwnedFile(path);
    expect(exported.mode & PERMISSION_BITS).toBe(OWNER_ONLY);
    expect(JSON.parse(exported.text).body.summary).toBe("exported text");
    expect((await kinds(f)).at(-1)).toBe("operator_export");
  });

  it("refuses an existing export path and writes no row", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const path = join(f.path, "taken.json");
    await writeFile(path, "keep", { mode: OWNER_ONLY });
    const before = (await f.rows()).length;
    const result = await run(runResultsCommand, ["export", id, "--out", path]);
    expect(result.code).toBe(1);
    expect(result.err).toContain("already exists");
    expect(await readFile(path, "utf8")).toBe("keep");
    expect((await f.rows()).length).toBe(before);
  });

  it("deletes one result after its row", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const result = await run(runResultsCommand, ["delete", id]);
    expect(result.code, result.err).toBe(0);
    expect(await f.hasResult(id)).toBe(false);
    expect((await kinds(f)).at(-1)).toBe("result_deleted");
  });

  it("delete all asks for the typed word and deletes nothing without it", async () => {
    const f = await setup();
    const one = await f.seed(1, "one");
    const two = await f.seed(2, "two");
    const refused = await run(runResultsCommand, ["delete", "--all"], { input: "yes\n" });
    expect(refused.code).toBe(1);
    expect(await f.hasResult(one)).toBe(true);
    const confirmed = await run(runResultsCommand, ["delete", "--all"], { input: `${DELETE_ALL_CONFIRMATION}\n` });
    expect(confirmed.code, confirmed.err).toBe(0);
    expect(await f.hasResult(one)).toBe(false);
    expect(await f.hasResult(two)).toBe(false);
  });

  it("delete all with --yes skips the question", async () => {
    const f = await setup();
    const one = await f.seed(1, "one");
    const result = await run(runResultsCommand, ["delete", "--all", "--yes"]);
    expect(result.code, result.err).toBe(0);
    expect(await f.hasResult(one)).toBe(false);
  });

  it("an unknown id is reported without a row", async () => {
    const f = await setup();
    const before = (await f.rows()).length;
    const result = await run(runResultsCommand, ["show", requestId(99)]);
    expect(result.code).toBe(1);
    expect((await f.rows()).length).toBe(before);
  });

  it.each([
    ["list"],
    ["show", requestId(1)],
    ["export", requestId(1), "--out", "/nonexistent/never-written.json"],
    ["delete", requestId(1)],
  ])("refuses %s without an unlocked fortress", async (...argv) => {
    const f = await setup();
    const id = await f.seed(1, "text");
    const result = await run(runResultsCommand, argv, { env: {} });
    expect(result.code).toBe(1);
    expect(result.err).toContain("requires SANCTUARY_PASSPHRASE");
    expect(resolveCliMasterKey).not.toHaveBeenCalled();
    expect(await f.hasResult(id)).toBe(true);
  });

  it("export and delete write their log row first, and do nothing when the row fails", async () => {
    const f = await setup();
    const id = await f.seed(1, "text");
    // An unreadable head makes every append refuse.
    await f.storage.write(LOCAL_OPLOG_NAMESPACE, "head", new TextEncoder().encode("not a sealed record"));
    const path = join(f.path, "never.json");
    const exported = await run(runResultsCommand, ["export", id, "--out", path]);
    expect(exported.code).toBe(1);
    await expect(stat(path)).rejects.toThrow();
    const deleted = await run(runResultsCommand, ["delete", id]);
    expect(deleted.code).toBe(1);
    expect(await f.hasResult(id)).toBe(true);
  });

  it("prints usage with no arguments and needs no unlock", async () => {
    const result = await run(runResultsCommand, [], { env: {} });
    expect(result.code).toBe(0);
    expect(result.out).toContain("Usage: sanctuary results");
  });
});

describe("sanctuary local log", () => {
  it("shows verified rows from a sequence number", async () => {
    const f = await setup();
    await f.seed(1, "text");
    const result = await run(runLocalCommand, ["log", "show", "--since", "1"]);
    expect(result.code, result.err).toBe(0);
    const rows = result.out.trim().split("\n").map((line) => JSON.parse(line) as { seq: number; kind: string });
    expect(rows[0]!.seq).toBe(1);
    expect(rows.map((row) => row.kind)).toContain("result_committed");
  });

  it("exports every row as an owner-only file and records the export", async () => {
    const f = await setup();
    await f.seed(1, "text");
    const path = join(f.path, "log.jsonl");
    const result = await run(runLocalCommand, ["log", "export", "--out", path]);
    expect(result.code, result.err).toBe(0);
    const exported = await readOwnedFile(path);
    expect(exported.mode & PERMISSION_BITS).toBe(OWNER_ONLY);
    const lines = exported.text.trim().split("\n").map((line) => JSON.parse(line) as { kind: string });
    expect(lines[0]!.kind).toBe("genesis");
    expect(lines.at(-1)!.kind).toBe("oplog_exported");
  });

  it("a broken log chain is reported and the command exits non-zero", async () => {
    const f = await setup();
    await f.seed(1, "text");
    await f.storage.delete(LOCAL_OPLOG_NAMESPACE, oplogRowKey(1));
    const shown = await run(runLocalCommand, ["log", "show"]);
    expect(shown.code).toBe(1);
    expect(shown.err).toContain("chain is broken at row 1");
    const path = join(f.path, "broken.jsonl");
    const exported = await run(runLocalCommand, ["log", "export", "--out", path]);
    expect(exported.code).toBe(1);
    await expect(stat(path)).rejects.toThrow();
  });

  it("prints usage with no arguments and needs no unlock", async () => {
    const result = await run(runLocalCommand, [], { env: {} });
    expect(result.code).toBe(0);
    expect(result.out).toContain("Usage: sanctuary local log");
  });
});
