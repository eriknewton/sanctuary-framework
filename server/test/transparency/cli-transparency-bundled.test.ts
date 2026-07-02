/**
 * Bundled-binary round-trip drill for `sanctuary transparency`.
 *
 * WHY a separate subprocess test exists: cli-transparency.test.ts runs the
 * command handlers IN PROCESS (vitest against src/), where
 * `require("../../package.json")` resolved correctly from src/ and the bug was
 * invisible. The defect only manifests in the BUNDLED binary: once tsup emits
 * server/dist/cli.js, that relative path resolved to the repo-root
 * package.json (which has no `version`), the persisted checkpoint dropped its
 * daemon.version, and the NEXT read rejected the whole chain as
 * "malformed (store corrupted or tampered)". This test drives the real
 * `node dist/cli.js` binary as separate subprocesses so the bundled path is
 * exercised and a future regression of the same shape fails here.
 *
 * It never boots a server and never touches the operator's ~/.sanctuary or the
 * macOS keychain: a keychain-free temp fortress is seeded with a local
 * castle-pinned key and a derived-key params file, and every command runs with
 * SANCTUARY_PASSPHRASE + --local-sign against that fortress.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";

const execFileAsync = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
// test/transparency/ -> server/dist/cli.js
const DIST_CLI = join(HERE, "..", "..", "dist", "cli.js");
const PASSPHRASE = "transparency-bundled-passphrase";

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * F5 (v1.6.1 stdio stdout purity): the audit-log's one-time file-locking
 * announcement is an operator-facing diagnostic that now correctly lands on
 * STDERR (stdout is the JSON-RPC / payload channel and must stay pure).
 * Strip that known diagnostic before asserting stderr silence, so the
 * assertions still catch real error output.
 */
function nonDiagnosticStderr(stderr: string): string {
  return stderr
    .split("\n")
    .filter(
      (line) =>
        !line.startsWith("[audit-log] cross-process file locking enabled")
    )
    .join("\n")
    .trim();
}

async function runCli(
  args: string[],
  env: NodeJS.ProcessEnv
): Promise<RunResult> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [DIST_CLI, ...args], {
      env: { ...process.env, ...env },
      maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return {
      code: typeof e.code === "number" ? e.code : 1,
      stdout: e.stdout ?? "",
      stderr: e.stderr ?? "",
    };
  }
}

describe("sanctuary transparency (bundled binary round-trip)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function makeFortress(): Promise<{
    fortress: string;
    publicKey: Uint8Array;
    binaryPath: string;
  }> {
    const fortress = await mkdtemp(
      join(tmpdir(), "sanctuary-transparency-bundled-")
    );
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(PASSPHRASE);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params))
    );

    // Local castle-pinned signing key (the --local-sign dev/test custody path).
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), publicKey);
    await writeFile(
      join(fortress, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(privateKey, derived.key))
    );

    // Castle Wall policy + a stand-in binary to hash.
    const rulesDir = join(fortress, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(
      join(rulesDir, "allow-github.json"),
      JSON.stringify({ rule_id: "allow-github" })
    );
    const binaryPath = join(fortress, "fake-binary.js");
    await writeFile(binaryPath, "exit(0)");

    // Seed enforcement history.
    const auditLog = new AuditLog(storage, derived.key, {
      checkpointInterval: 0,
    });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-cli",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: "fortress-cli",
      result: "success",
      details: { rule_id: "allow-github" },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return { fortress, publicKey, binaryPath };
  }

  // Unit-only runs (no build) stay green: skip with a clear message when the
  // bundle is absent. The coordinator's gate runs `npm run build` first, so the
  // regression assertion is exercised on every full CI run.
  const maybe = existsSync(DIST_CLI) ? it : it.skip;

  maybe(
    "checkpoint -> checkpoint -> export round-trips through dist/cli.js (daemon.version survives)",
    async () => {
      const { fortress, publicKey, binaryPath } = await makeFortress();
      const env = { SANCTUARY_PASSPHRASE: PASSPHRASE };
      const checkpointArgs = [
        "transparency",
        "checkpoint",
        "--fortress",
        fortress,
        "--local-sign",
        "--binary",
        binaryPath,
      ];

      // (1) First checkpoint.
      const c1 = await runCli(checkpointArgs, env);
      expect(nonDiagnosticStderr(c1.stderr)).toBe("");
      expect(c1.code).toBe(0);
      expect(c1.stdout).toContain("Enforcement checkpoint 1 emitted");

      // (2) Second checkpoint. BEFORE the fix this read of the persisted
      // genesis checkpoint failed because its daemon.version was dropped by
      // the bundled binary, producing "malformed (store corrupted or
      // tampered)". This is the regression assertion.
      const c2 = await runCli(checkpointArgs, env);
      expect(c2.stdout + c2.stderr).not.toContain("malformed");
      expect(nonDiagnosticStderr(c2.stderr)).toBe("");
      expect(c2.code).toBe(0);
      expect(c2.stdout).toContain("Enforcement checkpoint 2 emitted");

      // (3) Export a publishable bundle.
      const bundlePath = join(fortress, "bundle.json");
      const ex = await runCli(
        ["transparency", "export", "--fortress", fortress, "--output", bundlePath],
        env
      );
      expect(ex.stdout + ex.stderr).not.toContain("malformed");
      expect(ex.code).toBe(0);
      expect(ex.stderr).toContain("Exported 2 checkpoint(s)");

      // The exported bundle parses and every checkpoint carries a non-empty
      // string daemon.version (the invariant the reader's isDaemon enforces).
      const bundle = JSON.parse(await readFile(bundlePath, "utf8")) as {
        checkpoints: Array<{ daemon?: { version?: unknown } }>;
      };
      expect(bundle.checkpoints).toHaveLength(2);
      for (const checkpoint of bundle.checkpoints) {
        expect(typeof checkpoint.daemon?.version).toBe("string");
        expect((checkpoint.daemon?.version as string).length).toBeGreaterThan(0);
      }

      // (4) Offline verification through the bundled binary returns PASS,
      // confirming the round-trip is verifiable, not merely re-readable.
      const keyPath = join(fortress, "verify-key.bin");
      await writeFile(keyPath, publicKey);
      const vr = await runCli(
        [
          "verify-transparency",
          "--input",
          bundlePath,
          "--public-key-file",
          keyPath,
        ],
        env
      );
      expect(vr.code).toBe(0);
      expect(vr.stdout).toContain("Verdict: PASS");
      expect(vr.stdout).toContain("counters 1..2");
    },
    120_000
  );
});
