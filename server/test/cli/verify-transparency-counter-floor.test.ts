/**
 * CLI surface for anti-rollback Stage 2: `verify-transparency
 * --check-counter-floor`. The HOST-side external Rekor counter-floor
 * cross-check. Runs the real fortress + real anchoring pipeline against the
 * synthetic Rekor fixture (no network), then asserts:
 *
 *   - a fortress whose floor matches the highest anchored counter →
 *     CONSISTENT, exit 0, no freeze;
 *   - a fortress whose on-disk floor is rolled back below the highest
 *     externally-anchored counter → SUSPECTED-ROLLBACK, FAIL, the freeze is
 *     in effect (enforceCustodyFloor would refuse), and a
 *     custody_rollback_suspected audit entry was written;
 *   - a fortress that never enabled transparency → NOT-APPLICABLE, exit 0,
 *     never frozen;
 *   - the flag requires a host master key (fails closed without it).
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
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { hmacSha256 } from "../../src/core/hashing.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { canonicalJson } from "../../src/audit/chain.js";
import { TRANSPARENCY_FLOOR_META_KEY } from "../../src/transparency/emitter.js";
import { isRollbackFrozen } from "../../src/core/anti-rollback.js";
import type { FetchLike } from "../../src/transparency/rekor-client.js";
import { FakeRekorLog } from "../transparency/fake-rekor-log.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(c: unknown, _e: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.chunks.push(String(c));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

const PASSPHRASE = "stage2-counter-floor-cli-passphrase";
const REKOR_URL = "https://rekor.fixture.test";

describe("verify-transparency --check-counter-floor (anti-rollback Stage 2)", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) await rm(dir, { recursive: true, force: true });
  });

  function run(
    argv: string[],
    extras: { fetchFn?: FetchLike } = {}
  ): { code: Promise<number>; out: Capture; err: Capture } {
    const out = new Capture();
    const err = new Capture();
    const code = runTransparencyCommand({ argv, out, err, env: {}, ...extras });
    return { code, out, err };
  }

  async function makeFortress(): Promise<{ fortress: string; binaryPath: string }> {
    const fortress = await mkdtemp(join(tmpdir(), "sanctuary-stage2-cli-"));
    tempDirs.push(fortress);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(PASSPHRASE);
    await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(derived.params)));
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), publicKey);
    await writeFile(
      join(fortress, "castle-pinned-privkey.enc"),
      JSON.stringify(encrypt(privateKey, derived.key))
    );
    const rulesDir = join(fortress, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(join(rulesDir, "allow-github.json"), JSON.stringify({ rule_id: "allow-github" }));
    const binaryPath = join(fortress, "fake-binary.js");
    await writeFile(binaryPath, "exit(0)");
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: "fortress-stage2-cli",
      result: "success",
      details: { rule_id: "deny-default" },
    });
    await auditLog.flush();
    derived.key.fill(0);
    return { fortress, binaryPath };
  }

  async function appendAudit(fortress: string, operation: string, ruleId: string): Promise<void> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(
      PASSPHRASE,
      JSON.parse(Buffer.from((await storage.read("_meta", "key-params"))!).toString("utf8"))
    );
    const auditLog = new AuditLog(storage, derived.key, { checkpointInterval: 0 });
    await auditLog.appendCritical({
      layer: "l1",
      operation,
      identity_id: "fortress-stage2-cli",
      result: "success",
      details: { rule_id: ruleId },
    });
    await auditLog.flush();
    derived.key.fill(0);
  }

  /** Enable anchoring, emit + anchor n checkpoints against the fixture log. */
  async function anchored(n: number): Promise<{ fortress: string; log: FakeRekorLog }> {
    const { fortress, binaryPath } = await makeFortress();
    const log = new FakeRekorLog();
    log.appendNoise("pre-existing");
    expect(
      await run([
        "anchor", "enable", "--fortress", fortress, "--passphrase", PASSPHRASE,
        "--rekor-url", REKOR_URL, "--yes",
      ]).code
    ).toBe(0);
    for (let i = 0; i < n; i++) {
      if (i > 0) await appendAudit(fortress, "egress_allowed", `rule-${i}`);
      const emit = run(
        ["checkpoint", "--fortress", fortress, "--passphrase", PASSPHRASE, "--local-sign", "--binary", binaryPath],
        { fetchFn: log.fetchLike() }
      );
      expect(await emit.code).toBe(0);
      log.appendNoise(`foreign-${i}`);
    }
    return { fortress, log };
  }

  async function masterKeyOf(fortress: string): Promise<Uint8Array> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const derived = await deriveMasterKey(
      PASSPHRASE,
      JSON.parse(Buffer.from((await storage.read("_meta", "key-params"))!).toString("utf8"))
    );
    return derived.key;
  }

  /** Roll the MAC'd on-disk transparency floor back to a lower counter. */
  async function rollFloorBack(fortress: string, counter: number): Promise<void> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const master = await masterKeyOf(fortress);
    const macKey = derivePurposeKey(master, "transparency-counter-floor");
    const data = { highest_counter: counter };
    const mac = hmacSha256(
      macKey,
      stringToBytes("sanctuary.transparency-counter-floor.v1\n" + canonicalJson(data))
    );
    macKey.fill(0);
    const envelope = {
      ["__sanctuary_transparency_counter_floor_v1"]: true,
      data,
      mac: toBase64url(mac),
    };
    await storage.write(
      "_meta",
      TRANSPARENCY_FLOOR_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
    master.fill(0);
  }

  it("CONSISTENT (exit 0, no freeze) when the floor matches the highest anchored counter", async () => {
    const { fortress } = await anchored(2);
    // verify-transparency needs a real --input; export a bundle and use it.
    const bundlePath = join(fortress, "bundle.json");
    expect(await run(["export", "--fortress", fortress, "--output", bundlePath]).code).toBe(0);
    const v = run([
      "verify", "--input", bundlePath,
      "--public-key-file", join(fortress, "castle-pinned-pubkey.bin"),
      "--fortress", fortress, "--passphrase", PASSPHRASE,
      "--check-counter-floor",
    ]);
    const code = await v.code;
    const text = v.out.text();
    expect(text).toContain("Anti-rollback Stage 2 (Rekor counter-floor): CONSISTENT");
    expect(text).toContain("on-disk transparency floor: 2");
    expect(text).toContain("highest locally-recorded anchored checkpoint: 2");
    expect(code).toBe(0);
    const master = await masterKeyOf(fortress);
    expect((await isRollbackFrozen(new FilesystemStorage(join(fortress, "state")), master)).frozen).toBe(false);
    master.fill(0);
  });

  it("SUSPECTED-ROLLBACK (FAIL) + freeze + audit finding when the floor is rolled back below the anchors", async () => {
    const { fortress } = await anchored(3);
    const bundlePath = join(fortress, "bundle.json");
    expect(await run(["export", "--fortress", fortress, "--output", bundlePath]).code).toBe(0);
    await rollFloorBack(fortress, 1);
    const v = run([
      "verify", "--input", bundlePath,
      "--public-key-file", join(fortress, "castle-pinned-pubkey.bin"),
      "--fortress", fortress, "--passphrase", PASSPHRASE,
      "--check-counter-floor",
    ]);
    const code = await v.code;
    const text = v.out.text();
    expect(text).toContain("Anti-rollback Stage 2 (Rekor counter-floor): SUSPECTED-ROLLBACK");
    expect(text).toContain("on-disk transparency floor: 1");
    expect(text).toContain("highest locally-recorded anchored checkpoint: 3");
    expect(text).toContain("Verdict: FAIL");
    expect(code).toBe(1);

    // The freeze is in effect via the same Stage-1 marker.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const master = await masterKeyOf(fortress);
    expect((await isRollbackFrozen(storage, master)).frozen).toBe(true);

    // A custody_rollback_suspected audit entry was written, tagged stage 2.
    const auditLog = new AuditLog(storage, master, { checkpointInterval: 0 });
    const { entries } = await auditLog.query({ limit: 1000 });
    const finding = entries.find(
      (e) => e.operation === "custody_rollback_suspected" && e.details?.stage === 2
    );
    expect(finding).toBeDefined();
    master.fill(0);
  });

  it("NOT-APPLICABLE (exit 0, never frozen) when transparency was never enabled", async () => {
    const { fortress } = await makeFortress();
    // No anchoring enable, but we still need a checkpoint bundle for --input.
    const bundlePath = join(fortress, "bundle.json");
    // Emit one checkpoint (no anchoring) so export has something.
    const v0 = run([
      "checkpoint", "--fortress", fortress, "--passphrase", PASSPHRASE, "--local-sign",
      "--binary", join(fortress, "fake-binary.js"),
    ]);
    expect(await v0.code).toBe(0);
    expect(await run(["export", "--fortress", fortress, "--output", bundlePath]).code).toBe(0);
    const v = run([
      "verify", "--input", bundlePath,
      "--public-key-file", join(fortress, "castle-pinned-pubkey.bin"),
      "--fortress", fortress, "--passphrase", PASSPHRASE,
      "--check-counter-floor",
    ]);
    const code = await v.code;
    expect(v.out.text()).toContain(
      "Anti-rollback Stage 2 (Rekor counter-floor): NOT APPLICABLE"
    );
    expect(code).toBe(0);
    const master = await masterKeyOf(fortress);
    expect((await isRollbackFrozen(new FilesystemStorage(join(fortress, "state")), master)).frozen).toBe(false);
    master.fill(0);
  });

  it("fails closed (exit 1) when --check-counter-floor is run without a host master key", async () => {
    const { fortress } = await anchored(1);
    const bundlePath = join(fortress, "bundle.json");
    expect(await run(["export", "--fortress", fortress, "--output", bundlePath]).code).toBe(0);
    // No passphrase, no recovery key in env → cannot resolve the master key.
    const v = run(["verify", "--input", bundlePath, "--fortress", fortress, "--check-counter-floor"]);
    const code = await v.code;
    expect(code).toBe(1);
    expect(v.err.text()).toContain("--check-counter-floor runs on the fortress host");
  });
});
