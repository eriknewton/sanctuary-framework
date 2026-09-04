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
  linkSync,
  renameSync,
  symlinkSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable, PassThrough } from "node:stream";
import { runResetPassphraseCommand } from "../../src/cli/reset-passphrase.js";
import {
  fallbackFilePath,
  persistUserProvidedPassphrase,
  readStoredPassphrase,
} from "../../src/wrap/passphrase.js";
import { allFortressKeychainCredentialServices } from "../../src/wrap/credential-registry.js";
import {
  probeKeychainRecoveryKey,
  readKeychainCustodyKeyStatus,
} from "../../src/wrap/keychain-custody.js";

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

class HookWritable extends StringWritable {
  constructor(private readonly hook: (chunk: string) => void) {
    super();
  }

  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    this.chunks.push(text);
    this.hook(text);
    cb();
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

function makeStatefulDarwinExec(initialServices: readonly string[]): {
  exec: (
    cmd: string,
    args: string[],
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  store: Map<string, string>;
} {
  const encoded = Buffer.alloc(32, 0x53).toString("base64url");
  const store = new Map(initialServices.map((service) => [service, encoded]));
  return {
    store,
    exec: async (cmd, args) => {
      if (cmd !== "security") {
        return { stdout: "", stderr: "unhandled command", code: 1 };
      }
      const serviceIndex = args.indexOf("-s");
      const service = serviceIndex >= 0 ? args[serviceIndex + 1] ?? "" : "";
      if (args[0] === "delete-generic-password") {
        return store.delete(service)
          ? { stdout: "", stderr: "", code: 0 }
          : { stdout: "", stderr: "could not be found", code: 44 };
      }
      if (args[0] === "find-generic-password") {
        const value = store.get(service);
        return value === undefined
          ? { stdout: "", stderr: "could not be found", code: 44 }
          : { stdout: `${value}\n`, stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "unhandled operation", code: 1 };
    },
  };
}

function makeStatefulLinuxExec(initialServices: readonly string[]): {
  exec: (
    cmd: string,
    args: string[],
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  store: Map<string, string>;
} {
  const encoded = Buffer.alloc(32, 0x54).toString("base64url");
  const store = new Map(initialServices.map((service) => [service, encoded]));
  return {
    store,
    exec: async (cmd, args) => {
      if (cmd !== "secret-tool") {
        return { stdout: "", stderr: "unhandled command", code: 1 };
      }
      const serviceIndex = args.indexOf("service");
      const service = serviceIndex >= 0 ? args[serviceIndex + 1] ?? "" : "";
      if (args[0] === "clear") {
        return store.delete(service)
          ? { stdout: "", stderr: "", code: 0 }
          : { stdout: "", stderr: "", code: 1 };
      }
      if (args[0] === "lookup") {
        const value = store.get(service);
        return value === undefined
          ? { stdout: "", stderr: "", code: 1 }
          : { stdout: `${value}\n`, stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "unhandled operation", code: 1 };
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
    expect(existsSync(join(storage, "state", "ns-a.enc"))).toBe(false);
    // The live kernel-lock inode remains as the exact inert scaffold. Removing
    // its namespace while held would let a concurrent writer acquire a new
    // inode and escape mutual exclusion.
    expect(
      existsSync(join(storage, "state", "_meta", "custody-master.lock")),
    ).toBe(true);
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

  it("destructive reset clears the complete read identity registry, including canonical 12-hex", async () => {
    const realParent = join(tempDir, "real-parent");
    const aliasParent = join(tempDir, "alias-parent");
    const real = join(realParent, "fortress");
    const alias = join(aliasParent, "fortress");
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, "payload"), "state");
    symlinkSync(realParent, aliasParent);
    const expected = allFortressKeychainCredentialServices(alias, tempDir);
    expect(expected.length).toBeGreaterThan(4);
    expect(expected.some((service) => service.startsWith("sanctuary-custody"))).toBe(true);
    expect(expected.some((service) => service.startsWith("sanctuary-recovery"))).toBe(true);

    const out = new StringWritable();
    const err = new StringWritable();
    const { exec, calls } = makeExec();
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out,
      err,
      stdin: stdinFromLines(["fortress", "DESTROY", "y"]),
      storagePath: alias,
      home: tempDir,
      platformOverride: "darwin",
      exec,
    })).toBe(0);
    const deleted = calls
      .filter((call) => call.cmd === "security" && call.args[0] === "delete-generic-password")
      .map((call) => call.args[call.args.indexOf("-s") + 1]);
    expect(new Set(deleted)).toEqual(new Set(expected));
  });

  it("clears every Darwin credential family before wiping and all post-nuke reads are absent", async () => {
    const services = allFortressKeychainCredentialServices(storage, tempDir);
    const keychain = makeStatefulDarwinExec(services);
    expect(keychain.store.size).toBe(services.length);
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec: keychain.exec,
    })).toBe(0);
    expect(keychain.store.size).toBe(0);
    expect(await readStoredPassphrase({
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec: keychain.exec,
      readOnly: true,
    })).toBeNull();
    expect(await readKeychainCustodyKeyStatus(storage, {
      platformOverride: "darwin",
      exec: keychain.exec,
    })).toMatchObject({ status: "not-found" });
    expect(await probeKeychainRecoveryKey(storage, {
      platformOverride: "darwin",
      exec: keychain.exec,
    })).toMatchObject({ status: "not-found" });
  });

  it("refuses a symlink fortress root before accepting destructive confirmation", async () => {
    const real = join(tempDir, "real-fortress");
    const alias = join(tempDir, "alias-fortress");
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, "payload"), "state");
    symlinkSync(real, alias);
    const err = new StringWritable();
    const { exec, calls } = makeExec();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: stdinFromLines(["alias-fortress", "DESTROY", "y"]),
      storagePath: alias,
      home: tempDir,
      platformOverride: "darwin",
      exec,
    })).toBe(1);
    expect(err.text).toContain("non-symlink directory");
    expect(readFileSync(join(real, "payload"), "utf8")).toBe("state");
    expect(calls).toEqual([]);
  });

  it("refuses when the confirmed fortress directory is replaced before the final answer", async () => {
    const displaced = join(tempDir, "confirmed-fortress");
    const input = new PassThrough() as PassThrough & { isTTY?: boolean };
    input.isTTY = false;
    input.write("fortress-alpha\nDESTROY\n");
    let swapped = false;
    const err = new HookWritable((chunk) => {
      if (!swapped && chunk.includes("Final confirmation")) {
        swapped = true;
        renameSync(storage, displaced);
        mkdirSync(storage, { recursive: true });
        writeFileSync(join(storage, "replacement-payload"), "must survive");
        input.end("y\n");
      }
    });
    const { exec, calls } = makeExec();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: input,
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec,
    })).toBe(1);
    expect(swapped).toBe(true);
    expect(err.text).toContain("changed while confirmation was pending");
    expect(readFileSync(join(displaced, "principal-policy.yaml"), "utf8")).toBe(
      "policy: stub\n",
    );
    expect(readFileSync(join(storage, "replacement-payload"), "utf8")).toBe(
      "must survive",
    );
    expect(calls).toEqual([]);
  });

  it("never wipes a replacement root swapped in after the final identity check", async () => {
    const displaced = join(tempDir, "confirmed-root-held-by-lock");
    const replacementPayload = "replacement must survive";
    let swapped = false;
    const err = new StringWritable();
    const { exec } = makeExec();

    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec,
      beforeIdentityBoundWipe: async () => {
        swapped = true;
        renameSync(storage, displaced);
        mkdirSync(storage, { recursive: true });
        writeFileSync(join(storage, "replacement-payload"), replacementPayload);
      },
    });

    expect(swapped).toBe(true);
    expect(code).toBe(1);
    expect(err.text).toContain("FilesystemStorage root changed while the custody lock was held");
    expect(readFileSync(join(storage, "replacement-payload"), "utf8")).toBe(
      replacementPayload,
    );
    expect(readFileSync(join(displaced, "principal-policy.yaml"), "utf8")).toBe(
      "policy: stub\n",
    );
    expect(existsSync(join(displaced, "state", "ns-a.enc"))).toBe(true);
    expect(existsSync(join(storage, ".reset-history.log"))).toBe(false);
  });

  it("refuses a hard-linked custody lock scaffold before destructive cleanup", async () => {
    const outside = join(tempDir, "outside-lock-inode");
    const lockDir = join(storage, "state", "_meta");
    const lockPath = join(lockDir, "custody-master.lock");
    mkdirSync(lockDir, { recursive: true });
    chmodSync(lockDir, 0o700);
    writeFileSync(outside, "");
    linkSync(outside, lockPath);
    const err = new StringWritable();
    const { exec, calls } = makeExec();

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "darwin",
      exec,
    })).toBe(1);
    expect(err.text).toContain("single-link");
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
    expect(calls).toEqual([]);
  });

  it("Linux nuke clears every Secret Service identity and removes encrypted fallback", async () => {
    const expected = allFortressKeychainCredentialServices(storage, tempDir);
    const keychain = makeStatefulLinuxExec(expected);
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: keychain.exec,
    })).toBe(0);
    expect(keychain.store.size).toBe(0);
    expect(existsSync(join(storage, "passphrase.enc"))).toBe(false);
    expect(await readStoredPassphrase({
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: keychain.exec,
      readOnly: true,
    })).toBeNull();
    expect(await readKeychainCustodyKeyStatus(storage, {
      platformOverride: "linux",
      exec: keychain.exec,
    })).toMatchObject({ status: "not-found" });
    expect(await probeKeychainRecoveryKey(storage, {
      platformOverride: "linux",
      exec: keychain.exec,
    })).toMatchObject({ status: "not-found" });
  });

  it("aborts without deleting fortress data or fallback when keyring cleanup is indeterminate", async () => {
    const err = new StringWritable();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err,
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: async () => ({
        stdout: "",
        stderr: "Cannot autolaunch D-Bus without X11 DISPLAY",
        code: 1,
      }),
    });
    expect(code).toBe(1);
    expect(err.text).toContain("locked or unreachable");
    expect(err.text).toContain("fallback were preserved");
    expect(existsSync(join(storage, "principal-policy.yaml"))).toBe(true);
    expect(existsSync(fallbackFilePath(tempDir, storage))).toBe(true);
    expect(existsSync(join(storage, ".reset-history.log"))).toBe(false);
  });

  it("explicitly removes encrypted fallback custody so it cannot be reused later", async () => {
    const passphrase = "fallback-that-must-not-survive-nuke";
    const keyringStoreFailure = async () => ({
      stdout: "",
      stderr: "no Secret Service",
      code: 1,
    });
    const persisted = await persistUserProvidedPassphrase(passphrase, {
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: keyringStoreFailure,
    });
    expect(persisted.source).toBe("fallback-file");
    expect(existsSync(fallbackFilePath(tempDir, storage))).toBe(true);

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "nuke"],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: stdinFromLines(["fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: async () => ({ stdout: "", stderr: "", code: 0 }),
    })).toBe(0);
    expect(existsSync(fallbackFilePath(tempDir, storage))).toBe(false);
    expect(await readStoredPassphrase({
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec: async () => ({ stdout: "", stderr: "", code: 1 }),
      readOnly: true,
    })).toBeNull();
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

  it("interactive menu puts recovery first and routes choice 4 to nuke", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const { exec } = makeExec();
    const code = await runResetPassphraseCommand({
      argv: [],
      out,
      err,
      stdin: stdinFromLines(["4", "fortress-alpha", "DESTROY", "y"]),
      storagePath: storage,
      home: tempDir,
      platformOverride: "linux",
      exec,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("1) recovery-key");
    expect(out.text).toContain("2) shares");
    expect(out.text).toContain("(unavailable)");
    expect(out.text).toContain("3) guardian");
    expect(out.text).toContain("4) nuke");
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
      JSON.stringify({ prior: "marker" }) + "\n",
      { mode: 0o600 }
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
