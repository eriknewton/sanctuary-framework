/**
 * `sanctuary memory_ingest` / `sanctuary memory_emit` CLI tests.
 *
 * Covers what the MCP-handler tests cannot reach: argument parsing and its exit
 * codes, the master-key bootstrap gate, the argv-passphrase warning and the
 * stdin alternative, the audit ordering (write-ahead INTENT, then an outcome
 * record carrying what actually landed), and the partial-mirror warning.
 *
 * Isolation: every run points at a throwaway fortress created in a temp dir and
 * unlocked with a passphrase supplied through env or stdin, so the operator's
 * real login keychain and real ~/.sanctuary are never touched.
 */

import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  PASSPHRASE_ARGV_WARNING,
  runMemoryEmitCommand,
  runMemoryIngestCommand,
} from "../../src/cli/memory-file.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const PASSPHRASE = "memory-file-cli-test-passphrase-v1";

function makeSink(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
  return { stream, text: () => chunks.join("") };
}

const cleanupTasks: Array<() => Promise<void>> = [];

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `${prefix}-`));
  cleanupTasks.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function copyFixtureSet(name: string, prefix: string): Promise<string> {
  const source = join(FIXTURE_ROOT, name);
  const target = await tempDir(prefix);
  for (const filename of (await readdir(source)).filter((f) => f.endsWith(".md"))) {
    await writeFile(join(target, filename), await readFile(join(source, filename)));
  }
  return target;
}

describe("memory file CLI: argument parsing", () => {
  afterEach(async () => {
    while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
  });

  it("--help prints usage and exits 0 without touching a fortress", async () => {
    for (const run of [runMemoryIngestCommand, runMemoryEmitCommand]) {
      const out = makeSink();
      const err = makeSink();
      const code = await run({ argv: ["--help"], out: out.stream, err: err.stream, env: {} });
      expect(code).toBe(0);
      expect(out.text()).toContain("--harness=claude-code");
      expect(err.text()).toBe("");
    }
  });

  it("refuses a non-claude-code harness with the usage exit code", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "codex", "--dir", "/tmp/whatever"],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain('--harness must be "claude-code"');
    expect(out.text()).toBe("");
  });

  it("refuses a missing --dir with the usage exit code", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryEmitCommand({
      argv: ["--harness", "claude-code"],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain("--dir is required");
  });
});

describe("memory file CLI: credential gate", () => {
  let prevStoragePath: string | undefined;

  beforeEach(() => {
    prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  });

  afterEach(async () => {
    if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
    while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
  });

  it("refuses (exit 1) when no passphrase or recovery key is supplied", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", join(FIXTURE_ROOT, "basic")],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("require SANCTUARY_PASSPHRASE");
    expect(out.text()).toBe("");
  });

  it("warns that --passphrase leaks the secret into argv", async () => {
    const out = makeSink();
    const err = makeSink();
    // Exits non-zero (that fortress is not unlocked); the assertion here is
    // that the warning fires on the argv form at all.
    const code = await runMemoryIngestCommand({
      argv: [
        "--harness",
        "claude-code",
        "--dir",
        join(FIXTURE_ROOT, "basic"),
        "--fortress",
        join(await tempDir("memfile-warn"), "nope"),
        "--passphrase",
        PASSPHRASE,
      ],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain(PASSPHRASE_ARGV_WARNING.trim());
    expect(err.text()).toContain("could not unlock the fortress");
    // The warning must not echo the secret it is warning about.
    expect(err.text()).not.toContain(PASSPHRASE);
  });
});

describe("memory file CLI: fortress-backed round trip", () => {
  let fortress: string;
  let prevStoragePath: string | undefined;

  beforeEach(async () => {
    prevStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    fortress = join(await tempDir("memfile-cli"), ".sanctuary");
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    // Bootstrap a real passphrase-mode fortress so the CLI's unbootstrapped
    // resolveCliMasterKey unlocks an existing custody envelope. Failure mode if
    // this is skipped: the command fails on unlock, which looks like a CLI bug.
    await resolveCliMasterKey(new FilesystemStorage(join(fortress, "state")), {
      passphrase: PASSPHRASE,
      bootstrap: true,
      storagePathHint: fortress,
    });
  });

  afterEach(async () => {
    if (prevStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = prevStoragePath;
    while (cleanupTasks.length > 0) await cleanupTasks.pop()!();
  });

  async function auditEntries(): Promise<
    Array<{ operation: string; details: Record<string, unknown> }>
  > {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      passphrase: PASSPHRASE,
      storagePathHint: fortress,
    });
    const result = await new AuditLog(storage, masterKey).query({ limit: 1000 });
    return result.entries.map((entry) => ({
      operation: entry.operation,
      details: (entry.details ?? {}) as Record<string, unknown>,
    }));
  }

  async function auditOperations(): Promise<string[]> {
    return (await auditEntries()).map((entry) => entry.operation);
  }

  it("ingests, emits, and records the intent BEFORE and the outcome AFTER each operation", async () => {
    const source = await copyFixtureSet("basic", "memfile-cli-source");
    const output = await tempDir("memfile-cli-output");

    const ingestOut = makeSink();
    const ingestErr = makeSink();
    const ingestCode = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: ingestOut.stream,
      err: ingestErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(ingestCode).toBe(0);
    expect(ingestOut.text()).toContain("ingested 3 of 3 Claude Code memory files");
    expect(ingestErr.text()).not.toContain("WARNING");

    const emitOut = makeSink();
    const emitErr = makeSink();
    const emitCode = await runMemoryEmitCommand({
      argv: ["--harness", "claude-code", "--dir", output, "--fortress", fortress],
      out: emitOut.stream,
      err: emitErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(emitCode).toBe(0);
    expect(emitOut.text()).toContain("emitted 3 Claude Code memory files");
    expect(emitOut.text()).toContain("index_present: yes");

    // Byte-faithful round trip through the encrypted vault.
    expect((await readdir(output)).filter((f) => f.endsWith(".md")).sort()).toEqual(
      (await readdir(source)).filter((f) => f.endsWith(".md")).sort(),
    );
    for (const filename of (await readdir(source)).filter((f) => f.endsWith(".md"))) {
      expect(await readFile(join(output, filename))).toEqual(
        await readFile(join(source, filename)),
      );
    }

    const entries = await auditEntries();
    // Order matters: the intent record precedes the work, and the record that
    // asserts the work happened comes after it.
    const relevant = entries.filter((entry) => entry.operation.startsWith("memory_"));
    expect(relevant.map((entry) => entry.operation)).toEqual([
      "memory_ingest_started",
      "memory_ingest",
      "memory_emit_started",
      "memory_emit",
    ]);
    expect(relevant.find((entry) => entry.operation === "memory_emit")!.details).toMatchObject({
      emitted_file_count: 3,
      index_present: true,
    });
  }, 60_000);

  it("accepts the passphrase on stdin instead of argv", async () => {
    const source = await copyFixtureSet("empty-body", "memfile-cli-stdin-source");
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: [
        "--harness",
        "claude-code",
        "--dir",
        source,
        "--fortress",
        fortress,
        "--passphrase-stdin",
      ],
      out: out.stream,
      err: err.stream,
      env: {},
      stdin: Readable.from([`${PASSPHRASE}\n`]),
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("ingested 2 of 2 Claude Code memory files");
    // No argv warning: the secret never entered the process argument list.
    expect(err.text()).not.toContain("--passphrase puts the fortress passphrase");
  }, 60_000);

  it("ingests security prose without reporting a partial mirror", async () => {
    const source = await copyFixtureSet("basic", "memfile-cli-security-prose-source");
    await writeFile(
      join(source, "security-notes.md"),
      "# Security notes\n\nThe principal policy and recovery key are stored offline.\n",
    );
    const out = makeSink();
    const err = makeSink();

    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("ingested 4 of 4 Claude Code memory files");
    expect(err.text()).not.toContain("the mirror is INCOMPLETE");
  }, 60_000);

  it("warns loudly and names every file when the classifier makes the mirror partial", async () => {
    const source = await copyFixtureSet("basic", "memfile-cli-skip-source");
    await writeFile(
      join(source, "note-with-secret.md"),
      "# Ops note\n\nSANCTUARY_RECOVERY_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
    );

    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });

    // Exit 0: the mirror of the acceptable files succeeded. The operator learns
    // it is partial from a warning that names the file, not from a bare count.
    expect(code).toBe(0);
    expect(out.text()).toContain("ingested 3 of 4 Claude Code memory files");
    expect(err.text()).toContain("the mirror is INCOMPLETE");
    expect(err.text()).toContain("note-with-secret.md (classifier_reject)");

    const operations = await auditOperations();
    expect(operations.filter((op) => op.startsWith("memory_ingest"))).toEqual([
      "memory_ingest_started",
      "memory_ingest",
    ]);
  }, 60_000);

  it("warns when emit cannot produce a re-ingestable Claude Code memory tree", async () => {
    const source = await copyFixtureSet("basic", "memfile-cli-index-skip-source");
    await writeFile(
      join(source, "MEMORY.md"),
      "# Memory index\n\nSANCTUARY_RECOVERY_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE\n",
    );
    const output = await tempDir("memfile-cli-index-output");

    const ingestOut = makeSink();
    const ingestErr = makeSink();
    const ingestCode = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: ingestOut.stream,
      err: ingestErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(ingestCode).toBe(0);
    expect(ingestErr.text()).toContain("MEMORY.md (classifier_reject)");

    const emitOut = makeSink();
    const emitErr = makeSink();
    const emitCode = await runMemoryEmitCommand({
      argv: ["--harness", "claude-code", "--dir", output, "--fortress", fortress],
      out: emitOut.stream,
      err: emitErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });

    expect(emitCode).toBe(0);
    expect(emitOut.text()).toContain("index_present: no");
    expect(emitErr.text()).toContain("missing MEMORY.md");
    expect((await readdir(output)).filter((name) => name.endsWith(".md")).sort())
      .not.toContain("MEMORY.md");
    expect((await auditEntries()).find((entry) => entry.operation === "memory_emit")!.details)
      .toMatchObject({
        emitted_file_count: 2,
        index_present: false,
      });
  }, 60_000);

  it("fails closed with a denial record when the source directory does not exist", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: [
        "--harness",
        "claude-code",
        "--dir",
        join(fortress, "no-such-memory-dir"),
        "--fortress",
        fortress,
      ],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("memory_ingest failed");
    const operations = await auditOperations();
    // No success-labelled outcome record for an ingest that never ran.
    expect(operations).toContain("memory_ingest_denied");
    expect(operations).not.toContain("memory_ingest");
  }, 60_000);
});
