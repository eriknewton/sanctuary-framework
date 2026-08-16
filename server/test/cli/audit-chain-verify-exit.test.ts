import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  computeAuditEntryHash,
} from "../../src/audit/chain.js";
import type { EntryExportRecord } from "../../src/cli/audit-chain-verify.js";
import {
  CLI_PATH,
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  isolateChildFortress,
  runCli,
} from "./helpers/run-cli.js";

const ZERO_HASH = "0".repeat(64);
const BAD_HASH = "1".repeat(64);

describe("sanctuary audit-chain verify process behavior", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function writeFixture(name: string, content: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-audit-chain-cli-"));
    tempDirs.push(dir);
    const file = join(dir, name);
    await writeFile(file, content);
    return file;
  }

  function payload(seq: number): string {
    return Buffer.from(`payload-${seq}`).toString("base64url");
  }

  function cleanEntries(count: number): EntryExportRecord[] {
    const entries: EntryExportRecord[] = [];
    let prevHash = AUDIT_CHAIN_GENESIS;
    for (let seq = 1; seq <= count; seq++) {
      const timestamp = new Date(Date.UTC(2026, 0, 1, 0, 0, seq)).toISOString();
      const encryptedPayloadBytes = payload(seq);
      const entryHash = computeAuditEntryHash({
        sequence: seq,
        prev_hash: prevHash,
        timestamp,
        encrypted_payload_bytes: encryptedPayloadBytes,
        schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
      });
      entries.push({
        type: "entry",
        seq,
        schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
        prev_hash: prevHash,
        entry_hash: entryHash,
        timestamp,
        encrypted_payload_bytes: encryptedPayloadBytes,
      });
      prevHash = entryHash;
    }
    return entries;
  }

  function asJsonl(records: readonly unknown[]): string {
    return records.map((record) => JSON.stringify(record)).join("\n") + "\n";
  }

  function tamperedEntries(): EntryExportRecord[] {
    const entries = cleanEntries(3);
    entries[1] = {
      ...entries[1]!,
      encrypted_payload_bytes: Buffer.from("tampered").toString("base64url"),
    };
    return entries;
  }

  function largeFindingEntries(count: number): EntryExportRecord[] {
    return Array.from({ length: count }, (_, index) => {
      const seq = index + 1;
      return {
        type: "entry",
        seq,
        schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
        prev_hash: seq === 1 ? AUDIT_CHAIN_GENESIS : ZERO_HASH,
        entry_hash: BAD_HASH,
        timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, seq)).toISOString(),
        encrypted_payload_bytes: payload(seq),
      };
    });
  }

  it("returns observed process exits 0, 1, and 10 for verifier outcomes", async () => {
    const clean = await writeFixture("clean.jsonl", asJsonl(cleanEntries(3)));
    const tampered = await writeFixture("tampered.jsonl", asJsonl(tamperedEntries()));

    const pass = await runCli("audit-chain", "verify", "--input", clean);
    expect(pass.code).toBe(0);
    expect(JSON.parse(pass.stdout)).toMatchObject({ verdict: "PASS" });

    const strictFindings = await runCli("audit-chain", "verify", "--input", tampered);
    expect(strictFindings.code).toBe(1);
    expect(JSON.parse(strictFindings.stdout)).toMatchObject({ verdict: "FAIL" });

    const relaxedFindings = await runCli(
      "audit-chain",
      "verify",
      "--input",
      tampered,
      "--no-strict",
    );
    expect(relaxedFindings.code).toBe(10);
    expect(JSON.parse(relaxedFindings.stdout)).toMatchObject({ verdict: "FAIL" });
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("keeps a piped large findings report parseable", async () => {
    const input = await writeFixture("large.jsonl", asJsonl(largeFindingEntries(1_200)));

    const result = await runCliWithStdoutPipedThroughCat([
      "audit-chain",
      "verify",
      "--input",
      input,
      "--no-strict",
    ]);

    expect(result.code).toBe(10);
    expect(result.catCode).toBe(0);
    expect(result.stdout.length).toBeGreaterThan(65_536);
    const report = JSON.parse(result.stdout) as { verdict: string; findings: unknown[] };
    expect(report.verdict).toBe("FAIL");
    expect(report.findings.length).toBeGreaterThan(1_000);
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});

async function runCliWithStdoutPipedThroughCat(args: string[]): Promise<{
  code: number | null;
  catCode: number | null;
  stdout: string;
  stderr: string;
}> {
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_NO_WARNINGS: "1" };
  delete env.SANCTUARY_PASSPHRASE;
  const cleanup = await isolateChildFortress(env);

  const cli = spawn(process.execPath, [CLI_PATH, ...args], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const cat = spawn("cat", [], {
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  cli.stdout.setEncoding("utf8");
  cli.stderr.setEncoding("utf8");
  cat.stdout.setEncoding("utf8");
  cat.stderr.setEncoding("utf8");
  cat.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  cli.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  cat.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  cli.stdout.pipe(cat.stdin);

  const timeout = setTimeout(() => {
    cli.kill("SIGTERM");
    cat.kill("SIGTERM");
  }, 30_000);

  try {
    const [cliClose, catClose] = await Promise.all([waitForClose(cli), waitForClose(cat)]);
    return {
      code: cliClose.code,
      catCode: catClose.code,
      stdout,
      stderr,
    };
  } finally {
    clearTimeout(timeout);
    await cleanup();
  }
}

async function waitForClose(child: ChildProcess): Promise<{
  code: number | null;
  signal: NodeJS.Signals | null;
}> {
  const [code, signal] = (await once(child, "close")) as [number | null, NodeJS.Signals | null];
  return { code, signal };
}
