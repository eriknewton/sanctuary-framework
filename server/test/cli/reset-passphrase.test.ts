/**
 * `sanctuary reset-passphrase` CLI tests.
 *
 * Covers the three-mode survey, the per-mode degradation messages, the
 * three-confirmation nuke flow with all abort paths, and the
 * refuse-if-unlocked guard. Tests inject a temp `storagePath` and a buffered
 * stdin so no real fortress, real Keychain, or real `runtime.json` is
 * touched. The macOS Keychain `security` command is replaced with an exec
 * stub so the test passes on Linux CI as well as on Macs.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  existsSync,
  readFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";
import { runResetPassphraseCommand } from "../../src/cli/reset-passphrase.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function stdinFromLines(
  lines: string[]
): NodeJS.ReadableStream & { isTTY?: boolean } {
  // Trailing newline so the readline interface fires `line` for the last
  // entry. Without the terminal newline, readline waits for more input.
  const payload = lines.join("\n") + "\n";
  const stream = Readable.from([Buffer.from(payload)]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  stream.isTTY = false;
  return stream;
}

interface ExecCall {
  cmd: string;
  args: string[];
}

function makeExec(): {
  exec: (
    cmd: string,
    args: string[]
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  calls: ExecCall[];
} {
  const calls: ExecCall[] = [];
  return {
    calls,
    exec: async (cmd, args) => {
      calls.push({ cmd, args });
      // Simulate Keychain delete success.
      return { stdout: "", stderr: "", code: 0 };
    },
  };
}

describe("sanctuary reset-passphrase CLI", () => {
  let tempDir: string;
  let storage: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "sanctuary-reset-pp-"));
    storage = join(tempDir, "fortress-alpha");
    mkdirSync(storage, { recursive: true });
    // Seed a few synthetic state files so the inventory has something to
    // print and the wipe has something to remove.
    writeFileSync(join(storage, "principal-policy.yaml"), "policy: stub\n");
    writeFileSync(join(storage, "passphrase.enc"), Buffer.from([0, 1, 2, 3]));
    mkdirSync(join(storage, "state"), { recursive: true });
    writeFileSync(
      join(storage, "state", "ns-a.enc"),
      Buffer.from([4, 5, 6, 7, 8])
    );
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort.
    }
  });

  it("--help prints usage", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--help"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("Usage: sanctuary reset-passphrase");
    expect(out.text).toContain("shares");
    expect(out.text).toContain("guardian");
    expect(out.text).toContain("nuke");
  });

  it("--mode shares prints the not-yet-configured degradation", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "shares"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(2);
    expect(err.text).toContain("not yet configured on this fortress");
  });

  it("--mode guardian prints the v1.1 ships-with-federation degradation", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "guardian"],
      out,
      err,
      stdin: stdinFromLines([]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(2);
    expect(err.text).toContain("guardian path ships with federation v0.1 full mesh");
  });

  it("--mode nuke with all three confirmations destroys storage and writes a reset marker", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec, calls } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec,
    });
    expect(code).toBe(0);
    // Pre-existing state files are gone.
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(false);
    expect(existsSync(join(storage, "passphrase.enc"))).toBe(false);
    expect(existsSync(join(storage, "state"))).toBe(false);
    // Reset marker written, contains a JSON line with recovery_mode=nuke.
    const marker = readFileSync(join(storage, ".reset-history.log"), "utf8");
    const parsed = JSON.parse(marker.trim().split("\n")[0] ?? "{}");
    expect(parsed.recovery_mode).toBe("nuke");
    expect(parsed.fortress_name).toBe("fortress-alpha");
    expect(parsed.storage_path).toBe(storage);
    expect(parsed.keychain_cleared).toBe(true);
    // Keychain delete call was made on darwin.
    expect(calls.some((c) => c.cmd === "security" && c.args[0] === "delete-generic-password")).toBe(true);
    // Success summary printed.
    expect(out.text).toContain("Reset complete.");
  });

  it("--mode nuke with wrong fortress name aborts and leaves storage intact", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["wrong-name"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(1);
    expect(err.text.toLowerCase()).toContain("fortress name did not match");
    // Storage is untouched.
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
    expect(existsSync(join(storage, "passphrase.enc"))).toBe(true);
    expect(existsSync(join(storage, ".reset-history.log"))).toBe(false);
  });

  it("--mode nuke with wrong DESTROY word aborts after passing fortress-name check", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-alpha", "destroy"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(1);
    expect(err.text.toLowerCase()).toContain("confirmation word did not match");
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
  });

  it("--mode nuke with no on the final confirmation aborts", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "n"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(1);
    expect(err.text.toLowerCase()).toContain("final confirmation declined");
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
  });

  it("refuses to run while runtime.json indicates a live process", async () => {
    writeFileSync(
      join(storage, "runtime.json"),
      JSON.stringify({
        version: "1.0.0",
        pid: 99999,
        started_at: new Date().toISOString(),
        dashboard_host: "127.0.0.1",
        dashboard_port: 3501,
        mode: "wrap",
      })
    );
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("Refusing to reset");
    expect(err.text).toContain("Close the dashboard and stop all wrapped agents");
    // Storage is untouched.
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
    expect(existsSync(join(storage, "runtime.json"))).toBe(true);
  });

  it("interactive menu surfaces availability and routes choice 3 to nuke", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: [],
      out,
      err,
      stdin: stdinFromLines(["3", "fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("1) shares");
    expect(out.text).toContain("(unavailable)");
    expect(out.text).toContain("2) guardian");
    expect(out.text).toContain("3) nuke");
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(false);
  });

  it("interactive menu with q aborts cleanly", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: [],
      out,
      err,
      stdin: stdinFromLines(["q"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(1);
    expect(err.text).toContain("Aborted: no recovery mode selected.");
  });

  it("rejects unknown --mode value", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    await expect(
      runResetPassphraseCommand({
        argv: ["--mode", "bogus"],
        out,
        err,
        stdin: stdinFromLines([]),
        storagePath: storage,
        home: tempDir,
        platformOverride: "linux",
        exec,
      })
    ).rejects.toThrow(/--mode must be one of/);
  });

  it("preserves an existing reset-history.log across iterative resets", async () => {
    writeFileSync(
      join(storage, ".reset-history.log"),
      JSON.stringify({ prior: "marker" }) + "\n"
    );
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(0);
    const log = readFileSync(join(storage, ".reset-history.log"), "utf8");
    const lines = log.trim().split("\n");
    expect(lines.length).toBeGreaterThanOrEqual(2);
    expect(JSON.parse(lines[0] ?? "{}").prior).toBe("marker");
    expect(JSON.parse(lines[lines.length - 1] ?? "{}").recovery_mode).toBe("nuke");
  });
});
