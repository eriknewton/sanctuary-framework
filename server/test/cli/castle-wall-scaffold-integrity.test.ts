import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { CrossProcessLockError } from "../../src/storage/cross-process-lock.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { CASTLE_PINNED_PUBKEY, runDaemon } from "../../src/cli/castle-wall.js";

vi.mock("../../src/core/master-custody.js", async (importOriginal) => {
  const custody = await importOriginal<typeof import("../../src/core/master-custody.js")>();
  return { ...custody, establishMaster: vi.fn() };
});

describe("castle-wall custody structure refusal message", () => {
  let fortress: string | undefined;
  let previousRoot: string | undefined;

  afterEach(async () => {
    vi.mocked(establishMaster).mockReset();
    if (previousRoot === undefined) delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
    else process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
    if (fortress !== undefined) await rm(fortress, { recursive: true, force: true });
  });

  it("names the custody structure and operator check without a provisioning hint", async () => {
    previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
    fortress = await mkdtemp(join(tmpdir(), "cw-si-"));
    process.env.SANCTUARY_CUSTODY_LOCK_ROOT = join(fortress, "locks");
    const publicKey = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    await writeFile(join(fortress, CASTLE_PINNED_PUBKEY), publicKey);
    vi.mocked(establishMaster).mockRejectedValue(new CrossProcessLockError(
      "custody lock structure refused. Check the custody lock directory owner and contents.",
      "scaffold-integrity",
    ));
    let diagnostic = "";
    const err = new Writable({ write(chunk, _encoding, done) { diagnostic += String(chunk); done(); } });
    const out = new Writable({ write(_chunk, _encoding, done) { done(); } });
    const start = vi.fn();
    const code = await runDaemon([], {
      platform: "linux",
      env: {
        SANCTUARY_STORAGE_PATH: fortress,
        SANCTUARY_PASSPHRASE: "test-custody-message-passphrase",
        SANCTUARY_CASTLE_LOCAL_SIGN: "1",
        SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED: "1",
      },
      out, err, fullDaemonStart: start,
    });
    expect(code).toBe(1);
    expect(establishMaster).toHaveBeenCalledWith(expect.objectContaining({ barrierDegradeMode: "inert" }));
    expect(start).not.toHaveBeenCalled();
    expect(diagnostic).toContain("custody lock structure is malformed or substituted");
    expect(diagnostic).toContain("daemon refused to start without its rotation barrier");
    expect(diagnostic).toContain("Check the custody lock directory owner and contents.");
    expect(diagnostic).not.toContain("nothing provisioned");
    expect(diagnostic).not.toContain("credential does not unlock");
  });
});
