import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { runProvisionPin, runStatus } from "../../src/cli/castle-wall.js";

class CaptureStream extends Writable {
  value = "";
  override _write(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    this.value += chunk.toString();
    callback();
  }
}

function fingerprint(pub: Uint8Array): string {
  return createHash("sha256").update(pub).digest("hex").slice(0, 16);
}

async function mkFortress(): Promise<string> {
  return mkdtemp(join(tmpdir(), "sanctuary-castle-wall-"));
}

describe("sanctuary castle-wall CLI", () => {
  it("provision-pin creates keypair files", async () => {
    const fortress = await mkFortress();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runProvisionPin({
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortress,
        SANCTUARY_PASSPHRASE: "test-passphrase",
      },
    });

    expect(code).toBe(0);
    expect(err.value).toBe("");

    const pubPath = join(fortress, "castle-pinned-pubkey.bin");
    const privPath = join(fortress, "castle-pinned-privkey.enc");
    const pub = await readFile(pubPath);
    const priv = await readFile(privPath, "utf8");
    const pubStat = await stat(pubPath);

    expect(pub.length).toBe(32);
    expect(priv).toContain("\"alg\":\"aes-256-gcm\"");
    expect((pubStat.mode & 0o777)).toBe(0o600);
    expect(out.value.trim()).toBe(fingerprint(pub));
  });

  it("provision-pin is idempotent", async () => {
    const fortress = await mkFortress();
    const pubPath = join(fortress, "castle-pinned-pubkey.bin");
    const existing = Buffer.from(new Uint8Array(32).fill(7));
    await writeFile(pubPath, existing, { mode: 0o600 });

    const out = new CaptureStream();
    const err = new CaptureStream();
    const code = await runProvisionPin({
      out,
      err,
      env: {
        SANCTUARY_STORAGE_PATH: fortress,
        SANCTUARY_PASSPHRASE: "test-passphrase",
      },
    });

    const after = await readFile(pubPath);
    expect(code).toBe(0);
    expect(err.value).toBe("");
    expect(Buffer.compare(after, existing)).toBe(0);
    expect(out.value).toContain(fingerprint(existing));
    expect(out.value).toContain("Pinned key already provisioned");
  });

  it("status with pinned key", async () => {
    const fortress = await mkFortress();
    const pub = Buffer.from(new Uint8Array(32).fill(3));
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), pub, {
      mode: 0o600,
    });
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortress },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.value).toContain(`Pinned key fingerprint: ${fingerprint(pub)}`);
  });

  it("status without pinned key", async () => {
    const fortress = await mkFortress();
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortress },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.value).toContain(
      "No pinned key provisioned. Run: sanctuary castle-wall provision-pin"
    );
  });

  it("status on non-macOS", async () => {
    const fortress = await mkFortress();
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortress },
      platform: "linux",
    });

    expect(code).toBe(0);
    expect(out.value).toContain("Castle Wall sysext: not applicable (non-macOS)");
  });

  it("status with sysext running", async () => {
    const fortress = await mkFortress();
    const pub = Buffer.from(new Uint8Array(32).fill(9));
    await writeFile(join(fortress, "castle-pinned-pubkey.bin"), pub, {
      mode: 0o600,
    });
    const out = new CaptureStream();
    const code = await runStatus({
      out,
      env: { SANCTUARY_STORAGE_PATH: fortress },
      platform: "darwin",
      execSyncFn: () =>
        "com.sanctuary.castle-wall [activated enabled] (state: enabled)",
    });

    expect(code).toBe(0);
    expect(out.value).toContain("Castle Wall sysext: [activated enabled]");
  });
});
