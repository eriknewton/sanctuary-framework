import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";

import { runSdwOwnerCommand } from "../../src/cli/sdw-owner.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { readSdwOwnerPin } from "../../src/sdw/memory-isolation.js";

const PASSPHRASE = "ic16-cli-passphrase";
const dirs: string[] = [];

function capture(): { stream: Writable; text: () => string } {
  let value = "";
  return {
    stream: new Writable({
      write(chunk, _encoding, callback) {
        value += String(chunk);
        callback();
      },
    }),
    text: () => value,
  };
}

async function fortress(): Promise<{ root: string; masterKey: Uint8Array }> {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-sdw-owner-cli-"));
  dirs.push(root);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(root, "state"));
  const established = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    storagePathHint: root,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return { root, masterKey: established.masterKey };
}

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe("sanctuary sdw-owner", () => {
  it("claims and transfers only after exact typed confirmation", async () => {
    const f = await fortress();
    const out = capture();
    const err = capture();
    expect(
      await runSdwOwnerCommand({
        argv: ["claim", "--agent-id", "claude_code:ic16", "--fortress", f.root],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        stdin: Readable.from("claude_code:ic16\nCLAIM\n"),
        out: out.stream,
        err: err.stream,
      }),
    ).toBe(0);
    let pin = await readSdwOwnerPin(
      new FilesystemStorage(join(f.root, "state")),
      f.masterKey,
    );
    expect(pin.status).toBe("valid");
    if (pin.status === "valid") expect(pin.data.agent_id).toBe("claude_code:ic16");

    expect(
      await runSdwOwnerCommand({
        argv: [
          "transfer",
          "--from-agent-id",
          "claude_code:ic16",
          "--to-agent-id",
          "codex:ic16",
          "--fortress",
          f.root,
        ],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        stdin: Readable.from("codex:ic16\nTRANSFER\n"),
        out: out.stream,
        err: err.stream,
      }),
    ).toBe(0);
    pin = await readSdwOwnerPin(
      new FilesystemStorage(join(f.root, "state")),
      f.masterKey,
    );
    expect(pin.status).toBe("valid");
    if (pin.status === "valid") expect(pin.data.agent_id).toBe("codex:ic16");
  });

  it("does not mutate on a mistyped confirmation or while a runtime may be live", async () => {
    const f = await fortress();
    const out = capture();
    const err = capture();
    expect(
      await runSdwOwnerCommand({
        argv: ["claim", "--agent-id", "claude_code:ic16", "--fortress", f.root],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        stdin: Readable.from("wrong\nCLAIM\n"),
        out: out.stream,
        err: err.stream,
      }),
    ).toBe(1);
    expect(
      await readSdwOwnerPin(
        new FilesystemStorage(join(f.root, "state")),
        f.masterKey,
      ),
    ).toEqual({ status: "absent" });

    await writeFile(join(f.root, "runtime.json"), "{}", { mode: 0o600 });
    expect(
      await runSdwOwnerCommand({
        argv: ["claim", "--agent-id", "claude_code:ic16", "--fortress", f.root],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        stdin: Readable.from("claude_code:ic16\nCLAIM\n"),
        out: out.stream,
        err: err.stream,
      }),
    ).toBe(1);
    expect(err.text()).toContain("runtime.json");
  });
});
