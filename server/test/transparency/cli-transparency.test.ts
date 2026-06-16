/**
 * End-to-end CLI drill: provision a fortress with a local castle-pinned key,
 * emit checkpoints, export a bundle, verify it offline with the pinned key,
 * and prove the failure paths (wrong key, truncated log, unsigned refusal).
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  EXIT_PARTIAL,
  runTransparencyCommand,
  runVerifyTransparencyCommand,
} from "../../src/cli/transparency.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";

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

const PASSPHRASE = "transparency-cli-passphrase";

describe("sanctuary transparency / verify-transparency CLI", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress(): Promise<{
    fortress: string;
    publicKey: Uint8Array;
    binaryPath: string;
  }> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-transparency-cli-"));
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
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
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

  it("emit -> export -> verify round-trip passes under the pinned key", async () => {
    const { fortress, publicKey, binaryPath } = await makeFortress();

    // Emit two checkpoints.
    for (let i = 0; i < 2; i++) {
      const out = new Capture();
      const err = new Capture();
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
        out,
        err,
        env: {},
      });
      expect(err.text()).toBe("");
      expect(code).toBe(0);
      expect(out.text()).toContain(`Enforcement checkpoint ${i + 1} emitted`);
    }

    // Export the bundle.
    const bundlePath = join(fortress, "bundle.json");
    const exportOut = new Capture();
    const exportErr = new Capture();
    const exportCode = await runTransparencyCommand({
      argv: ["export", "--fortress", fortress, "--output", bundlePath],
      out: exportOut,
      err: exportErr,
      env: {},
    });
    expect(exportCode).toBe(0);
    expect(exportErr.text()).toContain("Exported 2 checkpoint(s)");
    expect(exportErr.text()).toContain("operator action");

    // Verify offline with the pinned key (raw 32-byte key file).
    const keyPath = join(fortress, "verify-key.bin");
    await writeFile(keyPath, publicKey);
    const verifyOut = new Capture();
    const verifyCode = await runVerifyTransparencyCommand({
      argv: ["--input", bundlePath, "--public-key-file", keyPath],
      out: verifyOut,
      err: new Capture(),
      env: {},
    });
    expect(verifyCode).toBe(0);
    expect(verifyOut.text()).toContain("Verdict: PASS");
    expect(verifyOut.text()).toContain("counters 1..2");
    expect(verifyOut.text()).toContain("Signature basis: pinned key");
    // Honesty: limits are always stated.
    expect(verifyOut.text()).toContain("Not checked by this run:");
    expect(verifyOut.text()).toContain("self-reported");

    // Host mode on the intact log also passes and recomputes the root.
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
        "--passphrase",
        PASSPHRASE,
      ],
      out: hostOut,
      err: new Capture(),
      env: {},
    });
    expect(hostCode).toBe(0);
    expect(hostOut.text()).toContain("Verdict: PASS");
    expect(hostOut.text()).toContain("recomputed and MATCHED");
    expect(hostOut.text()).toContain("recounted and MATCHED");
  });

  it("--allow-partial on a genesis-less suffix returns Verdict: PARTIAL and exit 10 (never PASS/0)", async () => {
    const { fortress, publicKey, binaryPath } = await makeFortress();

    // Emit three checkpoints (counters 1..3).
    for (let i = 0; i < 3; i++) {
      await runTransparencyCommand({
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
    }

    // Export then drop the genesis checkpoint to make a suffix (counters 2..3).
    const bundlePath = join(fortress, "bundle.json");
    await runTransparencyCommand({
      argv: ["export", "--fortress", fortress, "--output", bundlePath],
      out: new Capture(),
      err: new Capture(),
      env: {},
    });
    const bundle = JSON.parse(await readFile(bundlePath, "utf8")) as {
      checkpoints: Array<{ counter: number }>;
    };
    bundle.checkpoints = bundle.checkpoints.filter((c) => c.counter !== 1);
    const suffixPath = join(fortress, "suffix.json");
    await writeFile(suffixPath, JSON.stringify(bundle));

    // Without --allow-partial: FAIL / exit 1 (withheld prefix).
    const strictOut = new Capture();
    const strictCode = await runVerifyTransparencyCommand({
      argv: ["--input", suffixPath, "--public-key", toBase64url(publicKey)],
      out: strictOut,
      err: new Capture(),
      env: {},
    });
    expect(strictCode).toBe(1);
    expect(strictOut.text()).toContain("Verdict: FAIL");
    expect(strictOut.text()).toContain("counter_prefix_missing");

    // With --allow-partial: distinct PARTIAL verdict + dedicated exit code 10,
    // never PASS / 0 (automation must not read incomplete evidence as complete).
    const partialOut = new Capture();
    const partialCode = await runVerifyTransparencyCommand({
      argv: [
        "--input",
        suffixPath,
        "--public-key",
        toBase64url(publicKey),
        "--allow-partial",
      ],
      out: partialOut,
      err: new Capture(),
      env: {},
    });
    expect(partialCode).toBe(EXIT_PARTIAL);
    expect(partialCode).toBe(10);
    expect(partialCode).not.toBe(0);
    expect(partialOut.text()).toContain("Verdict: PARTIAL");
    expect(partialOut.text()).not.toContain("Verdict: PASS");
    expect(partialOut.text()).toContain("suffix fragment");
  });

  it("FAILS verification under the wrong key (exit 1, honest finding)", async () => {
    const { fortress, binaryPath } = await makeFortress();
    await runTransparencyCommand({
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
    const bundlePath = join(fortress, "bundle.json");
    await runTransparencyCommand({
      argv: ["export", "--fortress", fortress, "--output", bundlePath],
      out: new Capture(),
      err: new Capture(),
      env: {},
    });
    const out = new Capture();
    const code = await runVerifyTransparencyCommand({
      argv: [
        "--input",
        bundlePath,
        "--public-key",
        toBase64url(ed25519.getPublicKey(randomBytes(32))),
      ],
      out,
      err: new Capture(),
      env: {},
    });
    expect(code).toBe(1);
    expect(out.text()).toContain("Verdict: FAIL");
    expect(out.text()).toContain("signature_invalid");
  });

  it("host mode DETECTS a truncated audit log (exit 1)", async () => {
    const { fortress, publicKey, binaryPath } = await makeFortress();
    await runTransparencyCommand({
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
    const bundlePath = join(fortress, "bundle.json");
    await runTransparencyCommand({
      argv: ["export", "--fortress", fortress, "--output", bundlePath],
      out: new Capture(),
      err: new Capture(),
      env: {},
    });
    // Truncate the tail of the live log. The emission itself appended a
    // "transparency_checkpoint_emitted" entry after the covered window, so
    // remove the last two entries to pull the head BEHIND the signed head.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const keys = (await storage.list("_audit", "entry-")).map((m) => m.key);
    await storage.delete("_audit", keys.at(-1)!);
    await storage.delete("_audit", keys.at(-2)!);

    const out = new Capture();
    const code = await runVerifyTransparencyCommand({
      argv: [
        "--input",
        bundlePath,
        "--public-key",
        toBase64url(publicKey),
        "--against-log",
        "--fortress",
        fortress,
      ],
      out,
      err: new Capture(),
      env: {},
    });
    expect(code).toBe(1);
    expect(out.text()).toContain("Verdict: FAIL");
    expect(out.text()).toContain("log_head_behind_checkpoint");
  });

  it("checkpoint REFUSES without any signer (no unsigned emission path)", async () => {
    const { fortress, binaryPath } = await makeFortress();
    // Remove the local key and provide no helper shim: emission must refuse.
    await rm(join(fortress, "castle-pinned-privkey.enc"), { force: true });
    const err = new Capture();
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
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("refusing to emit unsigned");
    // Nothing persisted.
    const storage = new FilesystemStorage(join(fortress, "state"));
    expect(await storage.list("_transparency_checkpoints")).toHaveLength(0);
  });

  it("export REFUSES on an empty checkpoint store", async () => {
    const { fortress } = await makeFortress();
    const err = new Capture();
    const code = await runTransparencyCommand({
      argv: ["export", "--fortress", fortress],
      out: new Capture(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("No enforcement checkpoints exist");
  });

  it("rejects unknown options with a usage error", async () => {
    const err = new Capture();
    const code = await runTransparencyCommand({
      argv: ["checkpoint", "--frobnicate"],
      out: new Capture(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("unknown option");
  });
});
