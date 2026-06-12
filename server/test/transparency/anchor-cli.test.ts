/**
 * CLI surface of transparency anchoring (PR-2):
 *
 *   - enable REQUIRES explicit consent (--yes when non-interactive);
 *     refusal changes nothing and transmits nothing
 *   - default OFF: `transparency checkpoint` with anchoring never enabled
 *     emits cleanly with no anchor activity
 *   - `anchor now` against an unreachable log fails LOUDLY (nonzero exit,
 *     failure receipt, honest status), never silently
 *
 * The only socket touched is a loopback connect to a closed port (instant
 * ECONNREFUSED); no test reaches a real network.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { runTransparencyCommand } from "../../src/cli/transparency.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { deriveMasterKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
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

const PASSPHRASE = "transparency-anchor-cli-passphrase";

describe("sanctuary transparency anchor CLI", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFortress(): Promise<{ fortress: string; binaryPath: string }> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-anchor-cli-"));
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
      join(rulesDir, "allow-github.json"),
      JSON.stringify({ rule_id: "allow-github" })
    );
    const binaryPath = join(fortress, "fake-binary.js");
    await writeFile(binaryPath, "exit(0)");
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-anchor-cli",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return { fortress, binaryPath };
  }

  function run(argv: string[]): {
    code: Promise<number>;
    out: Capture;
    err: Capture;
  } {
    const out = new Capture();
    const err = new Capture();
    const code = runTransparencyCommand({ argv, out, err, env: {} });
    return { code, out, err };
  }

  it("enable without --yes (non-interactive) refuses: consent is never assumed", async () => {
    const { fortress } = await makeFortress();
    const attempt = run([
      "anchor",
      "enable",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await attempt.code).toBe(2);
    expect(attempt.err.text()).toContain("explicit consent");
    // Nothing was changed: status still reports the default-off state.
    const status = run([
      "anchor",
      "status",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await status.code).toBe(0);
    expect(status.out.text()).toContain("off (never enabled; default)");
  });

  it("enable --yes prints the consent statement, records it, and status reflects it", async () => {
    const { fortress } = await makeFortress();
    const enable = run([
      "anchor",
      "enable",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--rekor-url",
      "http://127.0.0.1:1",
      "--yes",
    ]);
    expect(await enable.code).toBe(0);
    expect(enable.out.text()).toContain("salted SHA-256 hash");
    expect(enable.out.text()).toContain("Anchoring ENABLED");

    const status = run([
      "anchor",
      "status",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--json",
    ]);
    expect(await status.code).toBe(0);
    const parsed = JSON.parse(status.out.text()) as {
      anchoring: string;
      rekor_url: string;
    };
    expect(parsed.anchoring).toBe("enabled");
    expect(parsed.rekor_url).toBe("http://127.0.0.1:1");
  });

  it("default OFF: checkpoint emission with anchoring never enabled has no anchor activity", async () => {
    const { fortress, binaryPath } = await makeFortress();
    const emit = run([
      "checkpoint",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--local-sign",
      "--binary",
      binaryPath,
    ]);
    expect(await emit.code).toBe(0);
    expect(emit.err.text()).toBe("");
    expect(emit.out.text()).not.toContain("[anchor]");
    expect(emit.out.text()).toContain("Enforcement checkpoint 1 emitted");
  });

  it("anchor now without enablement refuses with guidance", async () => {
    const { fortress } = await makeFortress();
    const now = run([
      "anchor",
      "now",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await now.code).toBe(1);
    expect(now.err.text()).toContain("off by default");
  });

  it("emission with anchoring enabled and the log unreachable is LOUD and nonzero but the checkpoint stands", async () => {
    const { fortress, binaryPath } = await makeFortress();
    const enable = run([
      "anchor",
      "enable",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--rekor-url",
      "http://127.0.0.1:1",
      "--yes",
    ]);
    expect(await enable.code).toBe(0);

    const emit = run([
      "checkpoint",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
      "--local-sign",
      "--binary",
      binaryPath,
    ]);
    expect(await emit.code).toBe(1);
    expect(emit.err.text()).toContain("ANCHORING FAILED");
    expect(emit.out.text()).toContain("Enforcement checkpoint 1 emitted");

    // Honest coverage: status reports the failure and the retry path.
    const status = run([
      "anchor",
      "status",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await status.code).toBe(0);
    expect(status.out.text()).toContain("1 failed");
    expect(status.out.text()).toContain("anchor now");

    // The catch-up verb is loud too while the log stays unreachable.
    const now = run([
      "anchor",
      "now",
      "--fortress",
      fortress,
      "--passphrase",
      PASSPHRASE,
    ]);
    expect(await now.code).toBe(1);
    expect(now.err.text()).toContain("FAILED");
    expect(now.err.text()).toContain("coverage is incomplete");
  });
});
