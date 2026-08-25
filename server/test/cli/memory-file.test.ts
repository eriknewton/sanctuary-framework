// fail-before-exempt: C3 fixture-wiring only — this existing CLI suite supplies the newly required durable memory-integrity-state resolver, but changes no assertion; C3 behavior is covered by memory-provenance-attachment, memory-provenance-migration, memory-provenance-migration-tools, memory-integrity-tier1, policy-loader, loader-required-keys, and the migration contract suite, all of which fail against pre-C3 source.
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
  runMemoryTranscodeCommand,
  runMemoryTranscodeRestoreCommand,
} from "../../src/cli/memory-file.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { fortressIdFromStoragePath } from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { createPrimaryMemoryProvenancePublicKeyResolver, createPrimaryMemoryProvenanceSigningHandleResolver } from "../../src/sdw/memory-provenance-signing.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/claude-code-memory/", import.meta.url),
);
const CODEX_FIXTURE_ROOT = fileURLToPath(
  new URL("../../src/sdw/__fixtures__/codex-memory/", import.meta.url),
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
    for (const run of [
      runMemoryIngestCommand,
      runMemoryEmitCommand,
      runMemoryTranscodeCommand,
      runMemoryTranscodeRestoreCommand,
    ]) {
      const out = makeSink();
      const err = makeSink();
      const code = await run({ argv: ["--help"], out: out.stream, err: err.stream, env: {} });
      expect(code).toBe(0);
      expect(out.text()).toContain("Usage: sanctuary memory_");
      expect(err.text()).toBe("");
    }
  });

  it("refuses an unsupported harness with the usage exit code", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      // Deliberately nonexistent and outside the OS temp namespace. The
      // unsupported harness must be rejected before any directory inspection;
      // a temp-dir literal here also creates a false source-to-open dataflow in
      // CodeQL even though this branch returns before bootstrap or file I/O.
      argv: ["--harness", "hermes", "--dir", "/operator/not-opened"],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain('--harness must be "claude-code" or "codex"');
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

  it("requires distinct harnesses and the exact reversible mode", async () => {
    const out = makeSink();
    const err = makeSink();
    expect(await runMemoryTranscodeCommand({
      argv: [
        "--from-harness", "codex",
        "--to-harness", "codex",
        "--mode", "lossy",
        "--dir", "/operator/not-opened",
      ],
      out: out.stream,
      err: err.stream,
      env: {},
    })).toBe(2);
    expect(err.text()).toContain("must name different values");
  });

  it("refuses a trailing bare --allow-file with the usage exit code, instead of silently dropping the waiver", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", "/operator/not-opened", "--allow-file"],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain("--allow-file requires a value");
    expect(out.text()).toBe("");
  });

  it("refuses --allow-file immediately followed by another flag, instead of silently consuming it as the path", async () => {
    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      // Without required-value parsing, "--dir" here would be consumed as
      // the allow-listed path AND would vanish as a flag, so the real --dir
      // that follows would be read as a second, unexpected positional value.
      argv: [
        "--harness", "claude-code",
        "--allow-file", "--dir",
        "--dir", "/operator/not-opened",
      ],
      out: out.stream,
      err: err.stream,
      env: {},
    });
    expect(code).toBe(2);
    expect(err.text()).toContain("--allow-file requires a value");
    expect(out.text()).toBe("");
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
    const storage = new FilesystemStorage(join(fortress, "state"));
    const masterKey = await resolveCliMasterKey(storage, {
      passphrase: PASSPHRASE,
      bootstrap: true,
      storagePathHint: fortress,
    });
    const identities = new IdentityManager(storage, masterKey);
    const { storedIdentity } = createIdentity(
      "memory-file-cli-test",
      derivePurposeKey(masterKey, "identity-encryption"),
      "passphrase",
    );
    await identities.save(storedIdentity);
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

  it("accepts a Codex home and round-trips only its three curated memory files", async () => {
    const codexHome = await tempDir("memory-file-cli-codex-home");
    const memories = join(codexHome, "memories");
    await mkdir(memories, { recursive: true });
    for (const filename of ["MEMORY.md", "memory_summary.md", "raw_memories.md"]) {
      await writeFile(
        join(memories, filename),
        await readFile(join(CODEX_FIXTURE_ROOT, "unicode", filename)),
      );
    }
    await writeFile(join(codexHome, "state_5.sqlite"), Buffer.from([0, 255, 0, 255]));
    await writeFile(join(codexHome, "history.jsonl"), "not curated memory\n");
    const output = await tempDir("memory-file-cli-codex-output");

    const ingestOut = makeSink();
    const ingestErr = makeSink();
    expect(await runMemoryIngestCommand({
      argv: ["--harness", "codex", "--dir", codexHome, "--fortress", fortress],
      out: ingestOut.stream,
      err: ingestErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    })).toBe(0);
    expect(ingestOut.text()).toContain("ingested 3 of 3 Codex memory files");
    expect(ingestErr.text()).toBe("");

    const emitOut = makeSink();
    const emitErr = makeSink();
    expect(await runMemoryEmitCommand({
      argv: ["--harness", "codex", "--dir", output, "--fortress", fortress],
      out: emitOut.stream,
      err: emitErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    })).toBe(0);
    expect(emitOut.text()).toContain("emitted 3 Codex memory files");
    expect(emitErr.text()).toBe("");
    expect((await readdir(output)).sort()).toEqual([
      "MEMORY.md",
      "memory_summary.md",
      "raw_memories.md",
    ]);
    for (const filename of await readdir(output)) {
      expect(await readFile(join(output, filename))).toEqual(
        await readFile(join(memories, filename)),
      );
    }
  }, 60_000);

  it("manually transcodes and restores exact source files with ordered audit receipts", async () => {
    const source = await copyFixtureSet("unicode", "memfile-cli-transcode-source");
    const projection = await tempDir("memfile-cli-transcode-projection");
    const restored = await tempDir("memfile-cli-transcode-restored");
    expect(await runMemoryIngestCommand({
      argv: ["--harness", "claude-code", "--dir", source, "--fortress", fortress],
      out: makeSink().stream,
      err: makeSink().stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    })).toBe(0);

    const transcodeOut = makeSink();
    const transcodeErr = makeSink();
    expect(await runMemoryTranscodeCommand({
      argv: [
        "--from-harness", "claude-code",
        "--to-harness", "codex",
        "--mode", "reversible",
        "--dir", projection,
        "--fortress", fortress,
      ],
      out: transcodeOut.stream,
      err: transcodeErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    })).toBe(0);
    expect(transcodeErr.text()).toBe("");
    const archiveId = /archive_id ([a-f0-9]+)/.exec(transcodeOut.text())?.[1];
    expect(archiveId).toMatch(/^[a-f0-9]+$/);
    expect((await readdir(projection)).sort()).toEqual([
      "MEMORY.md",
      "memory_summary.md",
      "raw_memories.md",
    ]);

    const restoreOut = makeSink();
    const restoreErr = makeSink();
    expect(await runMemoryTranscodeRestoreCommand({
      argv: [
        "--archive-id", archiveId!,
        "--dir", restored,
        "--fortress", fortress,
      ],
      out: restoreOut.stream,
      err: restoreErr.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    })).toBe(0);
    expect(restoreErr.text()).toBe("");
    expect(restoreOut.text()).toContain("restored 2 exact Claude Code source files");
    for (const filename of await readdir(source)) {
      expect(await readFile(join(restored, filename))).toEqual(await readFile(join(source, filename)));
    }

    expect((await auditOperations()).filter((operation) =>
      operation.startsWith("memory_transcode")
    )).toEqual([
      "memory_transcode_started",
      "memory_transcode",
      "memory_transcode_restore_started",
      "memory_transcode_restore",
    ]);
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
    // F2: names the detector and line, never the matched content.
    expect(err.text()).toContain(
      "refused note-with-secret.md: looks like a labeled Sanctuary recovery key value (line 3)",
    );
    expect(out.text()).not.toContain("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE");
    expect(err.text()).not.toContain("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE");

    const operations = await auditOperations();
    expect(operations.filter((op) => op.startsWith("memory_ingest"))).toEqual([
      "memory_ingest_started",
      "memory_ingest",
    ]);
  }, 60_000);

  describe("Rung-1 point 3: --allow-file classifier override", () => {
    const SECRET_VALUE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE";

    async function refusedFixture(prefix: string): Promise<string> {
      const source = await copyFixtureSet("basic", prefix);
      await writeFile(
        join(source, "note-with-secret.md"),
        `# Ops note\n\nSANCTUARY_RECOVERY_KEY=${SECRET_VALUE}\n`,
      );
      return source;
    }

    it("refuses without the flag and ingests with it, naming the audited override", async () => {
      const refusedSource = await refusedFixture("memfile-cli-allow-file-baseline");
      const refusedOut = makeSink();
      const refusedErr = makeSink();
      const refusedCode = await runMemoryIngestCommand({
        argv: ["--harness", "claude-code", "--dir", refusedSource, "--fortress", fortress],
        out: refusedOut.stream,
        err: refusedErr.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });
      expect(refusedCode).toBe(0);
      expect(refusedOut.text()).toContain("ingested 3 of 4 Claude Code memory files");
      expect(refusedErr.text()).toContain("the mirror is INCOMPLETE");

      const overriddenSource = await refusedFixture("memfile-cli-allow-file-overridden");
      const out = makeSink();
      const err = makeSink();
      const code = await runMemoryIngestCommand({
        argv: [
          "--harness", "claude-code",
          "--dir", overriddenSource,
          "--fortress", fortress,
          "--allow-file", "note-with-secret.md",
        ],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });

      expect(code).toBe(0);
      expect(out.text()).toContain("ingested 4 of 4 Claude Code memory files");
      // Reported as overridden, never as a refusal, and the mirror is complete.
      expect(err.text()).not.toContain("the mirror is INCOMPLETE");
      expect(out.text()).toContain("1 file(s) were overridden");
      expect(out.text()).toContain(
        "overridden note-with-secret.md: looks like a labeled Sanctuary recovery key value (line 3)",
      );
      // F2/MUST-NEVER #9 discipline: the secret never appears anywhere printed.
      expect(out.text()).not.toContain(SECRET_VALUE);
      expect(err.text()).not.toContain(SECRET_VALUE);

      const entries = await auditEntries();
      const overrideEntry = entries.find(
        (entry) => entry.operation === "memory_ingest_classifier_override",
      );
      expect(overrideEntry).toBeDefined();
      expect(overrideEntry!.details).toMatchObject({
        harness: "claude-code",
        source_path: "note-with-secret.md",
        reason: "classifier_reject",
        detector: "labeled_recovery_key",
        line: 3,
      });
      expect(JSON.stringify(entries)).not.toContain(SECRET_VALUE);

      const outcomeEntry = entries.find((entry) => entry.operation === "memory_ingest" && entry.details.source_dir === overriddenSource)!;
      expect(outcomeEntry.details).toMatchObject({
        committed_file_count: 4,
        skipped_file_count: 0,
        overridden_file_count: 1,
        unused_allow_files: [],
        complete: true,
      });
    }, 60_000);

    it("reports an allow-listed path the classifier never refused as unused", async () => {
      const source = await copyFixtureSet("basic", "memfile-cli-allow-file-unused");
      const out = makeSink();
      const err = makeSink();
      const code = await runMemoryIngestCommand({
        argv: [
          "--harness", "claude-code",
          "--dir", source,
          "--fortress", fortress,
          "--allow-file", "concise-updates.md",
        ],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });

      expect(code).toBe(0);
      expect(err.text()).toContain(
        "--allow-file named 1 path(s) the classifier never refused (nothing was waived): concise-updates.md",
      );
      const entries = await auditEntries();
      expect(
        entries.some((entry) => entry.operation === "memory_ingest_classifier_override"),
      ).toBe(false);
    }, 60_000);

    it("fails closed with a denial when an allow-listed path is absent from the source directory", async () => {
      const source = await copyFixtureSet("basic", "memfile-cli-allow-file-unknown");
      const out = makeSink();
      const err = makeSink();
      const code = await runMemoryIngestCommand({
        argv: [
          "--harness", "claude-code",
          "--dir", source,
          "--fortress", fortress,
          "--allow-file", "does-not-exist.md",
        ],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });

      expect(code).toBe(1);
      expect(err.text()).toContain("memory_ingest failed");
      expect(out.text()).toBe("");
      const operations = (await auditOperations()).filter((op) => op.startsWith("memory_ingest"));
      expect(operations).toContain("memory_ingest_denied");
      expect(operations).not.toContain("memory_ingest_classifier_override");
    }, 60_000);

    async function fortressAdapterForCheckOnly(): Promise<SdwMemoryBackendAdapter> {
      const storage = new FilesystemStorage(join(fortress, "state"));
      const masterKey = await resolveCliMasterKey(storage, {
        passphrase: PASSPHRASE,
        storagePathHint: fortress,
      });
      const identities = new IdentityManager(storage, masterKey);
      await identities.load();
      return new SdwMemoryBackendAdapter({
        storage,
        masterKey,
        fortressId: fortressIdFromStoragePath(fortress),
        ownerRef: "fleet-self",
        resolvePrimarySigningHandle: createPrimaryMemoryProvenanceSigningHandleResolver(identities, masterKey),
        resolveSignerPublicKey: createPrimaryMemoryProvenancePublicKeyResolver(identities),
        resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      });
    }

    it("writes the override audit record BEFORE the first corpus write, even when the corpus write then fails", async () => {
      const source = await refusedFixture("memfile-cli-high-c2-source");
      // Pre-occupy the corpus namespace as a plain FILE instead of a
      // directory: every corpus write inside it fails (ENOTDIR/EEXIST-class),
      // while the SEPARATE _audit namespace directory is untouched, so audit
      // writes still land normally. This fails EVERY corpus write, a
      // strictly stronger injection than "only the first" and still proves
      // the required property: the override record is durable even though
      // the commit phase never lands anything.
      await writeFile(join(fortress, "state", "_sdw_document_corpus"), "occupied");

      const out = makeSink();
      const err = makeSink();
      const code = await runMemoryIngestCommand({
        argv: [
          "--harness", "claude-code",
          "--dir", source,
          "--fortress", fortress,
          "--allow-file", "note-with-secret.md",
        ],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });

      expect(code).toBe(1);
      expect(err.text()).toContain("memory_ingest failed");

      const entries = await auditEntries();
      const overrideIndex = entries.findIndex(
        (entry) => entry.operation === "memory_ingest_classifier_override",
      );
      const denialIndex = entries.findIndex((entry) => entry.operation === "memory_ingest_denied");
      expect(overrideIndex).toBeGreaterThanOrEqual(0);
      expect(entries[overrideIndex]!.details).toMatchObject({
        source_path: "note-with-secret.md",
        detector: "labeled_recovery_key",
      });
      expect(denialIndex).toBeGreaterThan(overrideIndex);
      expect(JSON.stringify(entries)).not.toContain(SECRET_VALUE);
    }, 60_000);

    it("a throwing audit log commits NOTHING to the vault, on the CLI surface", async () => {
      const source = await refusedFixture("memfile-cli-audit-throws-source");
      // Pre-occupy the _audit namespace as a file: every audit write fails
      // from the very first one (memory_ingest_started), so the command must
      // deny before ever reaching the commit phase.
      await writeFile(join(fortress, "state", "_audit"), "occupied");

      const out = makeSink();
      const err = makeSink();
      const code = await runMemoryIngestCommand({
        argv: [
          "--harness", "claude-code",
          "--dir", source,
          "--fortress", fortress,
          "--allow-file", "note-with-secret.md",
        ],
        out: out.stream,
        err: err.stream,
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      });

      // The command itself fails closed (it cannot even durably record the
      // attempt); nothing reaches the vault.
      expect(code).not.toBe(0);
      await rm(join(fortress, "state", "_audit"), { force: true });
      const adapter = await fortressAdapterForCheckOnly();
      expect(await adapter.listPassages()).toEqual([]);
    }, 60_000);
  });

  it("names the bare_high_entropy_credential detector for Claude Code, without leaking the value (Rung-1 fix-round-2)", async () => {
    const BARE_CREDENTIAL_VALUE = "Rk2Nc9Wp5Ju1Vd8Sy3Ma6Ib0Ge7Tn4Ox1Cl9Aq3Fy6Un8x";
    const source = await copyFixtureSet("basic", "memfile-cli-bare-cred-source");
    await writeFile(
      join(source, "note-with-bare-id.md"),
      `# Notes

Unrelated identifier: ${BARE_CREDENTIAL_VALUE}
`,
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
    expect(err.text()).toContain(
      "refused note-with-bare-id.md: a high-entropy value elsewhere in the file looks like a raw credential (line 3)",
    );
    expect(out.text()).not.toContain(BARE_CREDENTIAL_VALUE);
    expect(err.text()).not.toContain(BARE_CREDENTIAL_VALUE);
  }, 60_000);

  it("names the bare_high_entropy_credential detector for Codex, without leaking the value (Rung-1 fix-round-2)", async () => {
    const BARE_CREDENTIAL_VALUE = "Bt3Qm7Xd1Kj5Rw9Vc2Ny6Ha0If4Ge8Ou1Sp3Lz6Wk9Tr2x";
    const codexHome = await tempDir("memfile-cli-bare-cred-codex-home");
    const memories = join(codexHome, "memories");
    await mkdir(memories, { recursive: true });
    for (const filename of ["MEMORY.md", "memory_summary.md", "raw_memories.md"]) {
      await writeFile(
        join(memories, filename),
        await readFile(join(CODEX_FIXTURE_ROOT, "unicode", filename)),
      );
    }
    await writeFile(
      join(memories, "raw_memories.md"),
      `# Raw Memories

Unrelated identifier: ${BARE_CREDENTIAL_VALUE}
`,
    );

    const out = makeSink();
    const err = makeSink();
    const code = await runMemoryIngestCommand({
      argv: ["--harness", "codex", "--dir", codexHome, "--fortress", fortress],
      out: out.stream,
      err: err.stream,
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(err.text()).toContain(
      "refused raw_memories.md: a high-entropy value elsewhere in the file looks like a raw credential (line 3)",
    );
    expect(out.text()).not.toContain(BARE_CREDENTIAL_VALUE);
    expect(err.text()).not.toContain(BARE_CREDENTIAL_VALUE);
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
    expect(ingestErr.text()).toContain(
      "refused MEMORY.md: looks like a labeled Sanctuary recovery key value (line 3)",
    );

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
