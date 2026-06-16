/**
 * Auditor-pack synthetic drill fixtures.
 *
 * Pre-declared pass criteria for the later coordinator-run cross-host drill:
 *
 * 1. Clean bundle verifies offline with only the exported bundle and the
 *    operator-published Ed25519 public key. Expected: PASS, exit 0.
 * 2. A truncated in-chain bundle fails with a specific reason code. Expected:
 *    FAIL, exit 1, finding kind `counter_gap`.
 * 3. Host-side audit-log tail truncation is caught by `--against-log`.
 *    Expected: FAIL, exit 1, finding kind `log_head_behind_checkpoint`.
 *
 * These are synthetic fixtures only: no network, no wall-clock soak, no
 * production signer dependency. The subprocess test pins both the Node binary
 * (`process.execPath`) and the verifier artifact path (`dist/verify-transparency.js`).
 */

import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, describe, expect, it } from "vitest";

import {
  runTransparencyCommand,
  runVerifyTransparencyCommand,
} from "../../src/cli/transparency.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { randomBytes } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const execFileAsync = promisify(execFile);
const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const STANDALONE_VERIFIER = join(TEST_DIR, "../../dist/verify-transparency.js");
const PASSPHRASE = "auditor-pack-drill-passphrase";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _enc: BufferEncoding,
    cb: (err?: Error | null) => void
  ): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("transparency auditor-pack drill fixtures", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("documents standalone verifier options, exit codes, and host-mode boundary", async () => {
    const help = await execFileAsync(process.execPath, [
      STANDALONE_VERIFIER,
      "--help",
    ]);
    expect(help.stdout).toContain(
      "Usage: node verify-transparency.js --input <path> [options]"
    );
    expect(help.stdout).toContain("--public-key-file <path>");
    expect(help.stdout).toContain("--allow-partial");
    expect(help.stdout).toContain("Exit codes: 0 PASS");
    expect(help.stdout).toContain("10 PARTIAL");
    expect(help.stdout).toContain("1 FAIL");
    expect(help.stdout).toContain("2 usage error");
    expect(help.stdout).toContain("offline-only");
    expect(help.stdout).toContain("sanctuary verify-transparency");
    expect(help.stdout).toContain("--against-log");
  });

  async function makeFortress(): Promise<{
    fortress: string;
    publicKey: Uint8Array;
    binaryPath: string;
  }> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-auditor-pack-"));
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(PASSPHRASE);
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(derived.params))
    );

    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), publicKey);
    await writeFile(
      join(fortress, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(privateKey, derived.key))
    );

    const rulesDir = join(fortress, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(
      join(rulesDir, "allow-docs.json"),
      JSON.stringify({ rule_id: "allow-docs" })
    );
    const binaryPath = join(fortress, "fake-binary.js");
    await writeFile(binaryPath, "process.exit(0)\n");

    const auditLog = new AuditLog(storage, derived.key, {
      checkpointInterval: 0,
    });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: "auditor-pack",
      result: "success",
      details: { rule_id: "allow-docs" },
    });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "auditor-pack",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return { fortress, publicKey, binaryPath };
  }

  async function emitCheckpoints(
    fortress: string,
    binaryPath: string,
    count: number
  ): Promise<string> {
    for (let i = 0; i < count; i++) {
      const code = await runTransparencyCommand({
        argv: [
          "checkpoint",
          "--fortress",
          fortress,
          "--passphrase",
          PASSPHRASE,
          "--local-sign",
          "--binary",
          binaryPath,
        ],
        out: new Capture(),
        err: new Capture(),
        env: {},
      });
      expect(code).toBe(0);
    }

    const bundlePath = join(fortress, "bundle.json");
    const exportCode = await runTransparencyCommand({
      argv: ["export", "--fortress", fortress, "--output", bundlePath],
      out: new Capture(),
      err: new Capture(),
      env: {},
    });
    expect(exportCode).toBe(0);
    return bundlePath;
  }

  it("runs the three PR-1 auditor-pack drill legs against synthetic fixtures", async () => {
    const { fortress, publicKey, binaryPath } = await makeFortress();
    const bundlePath = await emitCheckpoints(fortress, binaryPath, 3);
    const keyPath = join(fortress, "published-key.bin");
    await writeFile(keyPath, publicKey);

    const clean = await execFileAsync(process.execPath, [
      STANDALONE_VERIFIER,
      "--input",
      bundlePath,
      "--public-key-file",
      keyPath,
    ]);
    expect(clean.stdout).toContain("Verdict: PASS");
    expect(clean.stdout).toContain("Signature basis: pinned key");

    const bundle = JSON.parse(await readFile(bundlePath, "utf8")) as {
      checkpoints: Array<{ counter: number }>;
    };
    bundle.checkpoints = bundle.checkpoints.filter(
      (checkpoint) => checkpoint.counter !== 2
    );
    const truncatedPath = join(fortress, "bundle-truncated-gap.json");
    await writeFile(truncatedPath, JSON.stringify(bundle, null, 2));

    await expect(
      execFileAsync(process.execPath, [
        STANDALONE_VERIFIER,
        "--input",
        truncatedPath,
        "--public-key-file",
        keyPath,
      ])
    ).rejects.toMatchObject({
      code: 1,
      stdout: expect.stringContaining("counter_gap"),
    });

    const storage = new FilesystemStorage(join(fortress, "state"));
    const keys = (await storage.list("_audit", "entry-")).map((meta) => meta.key);
    await storage.delete("_audit", keys.at(-1)!);
    await storage.delete("_audit", keys.at(-2)!);

    const hostOut = new Capture();
    const hostCode = await runVerifyTransparencyCommand({
      argv: [
        "--input",
        bundlePath,
        "--public-key",
        toBase64url(publicKey),
        "--against-log",
        "--fortress",
        fortress,
      ],
      out: hostOut,
      err: new Capture(),
      env: {},
    });
    expect(hostCode).toBe(1);
    expect(hostOut.text()).toContain("Verdict: FAIL");
    expect(hostOut.text()).toContain("log_head_behind_checkpoint");
  });
});
