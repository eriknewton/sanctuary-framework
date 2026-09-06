/**
 * Round-2 (nuke wipe worker deadline): the identity-bound wipe worker runs in a
 * separate process under the held custody lock. Before this fix its `await` had
 * no deadline, so a wedged secure-overwrite or hung filesystem would pin the
 * custody lock forever. The worker now runs under a bounded deadline: on expiry
 * it is SIGKILLed (whole process group, so no orphan keeps deleting files) and
 * the reset fails closed with a re-run remedy.
 *
 * A tiny deadline reliably trips before the subprocess can finish (Node startup
 * alone exceeds it), proving the bound fires and the reset refuses rather than
 * hanging. The default (10 min) path is exercised by the other nuke tests.
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runResetPassphraseCommand } from "../../src/cli/reset-passphrase.js";

function sink(): { stream: Writable; text: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      chunks.push(String(chunk));
      cb();
    },
  });
  return { stream, text: () => chunks.join("") };
}

function stdinLines(lines: string[]): NodeJS.ReadableStream & { isTTY?: boolean } {
  const s = Readable.from([Buffer.from(lines.map((l) => l + "\n").join(""))]) as
    Readable & { isTTY?: boolean };
  s.isTTY = false;
  return s;
}

// Darwin keychain fake: every lookup/delete reports absence, never touching a
// real keychain.
const absentExec = async (): Promise<{ stdout: string; stderr: string; code: number }> => ({
  stdout: "",
  stderr: "not found",
  code: 44,
});

describe.skipIf(process.platform === "win32")("nuke wipe worker deadline (round-2)", () => {
  let tempDir: string;
  let storage: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "nuke-deadline-"));
    storage = join(tempDir, "fortress-alpha");
    mkdirSync(join(storage, "state"), { recursive: true });
    writeFileSync(join(storage, "principal-policy.yaml"), "policy: stub\n");
    writeFileSync(join(storage, "state", "ns-a.enc"), Buffer.from([1, 2, 3, 4]));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  it("fails the reset CLOSED with a re-run remedy when the wipe worker exceeds its deadline", async () => {
    const out = sink();
    const err = sink();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: out.stream,
      err: err.stream,
      stdin: stdinLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec: absentExec,
      // 1ms: the worker subprocess cannot start and finish within this, so the
      // deadline fires and SIGKILLs it before it completes the wipe.
      wipeDeadlineMs: 1,
    });

    expect(code).not.toBe(0);
    expect(err.text()).toMatch(/deadline/i);
    expect(err.text()).toMatch(/re-run/i);
    expect(out.text()).not.toContain("Reset complete.");
  });
});
