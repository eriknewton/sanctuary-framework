/**
 * `sanctuary reset-passphrase --mode recovery-key` — the recovery-key rekey.
 *
 * Verifies the enroll-then-verify-then-remove ordering: a fresh passphrase is
 * enrolled as a new custody wrap AND the exact-fortress stored credential, both
 * are verified, and only then are the old passphrase wraps removed — with the
 * master, the data, and the recovery wrap preserved. A wrong key mutates
 * nothing; a failed verification leaves at least one valid factor (crash-safe);
 * a non-TTY session without the test override is refused.
 *
 * The macOS Keychain is replaced with an in-memory `security` stub so nothing
 * touches the operator's real keyring, and the test passes on Linux CI too.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtemp,
  rm,
  mkdir,
  readFile,
  lstat,
  symlink,
  writeFile,
  readdir,
} from "node:fs/promises";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";

import { runResetPassphraseCommand } from "../../src/cli/reset-passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  establishMaster,
  readCustodyEnvelope,
  unwrapMaster,
} from "../../src/core/master-custody.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import { capturePassphraseCredentialIdentity } from "../../src/wrap/passphrase.js";

const OLD_PASSPHRASE = "reset-rk-OLD-correct-horse-not-a-real-secret";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function nonTtyStdin(isTTY = false): NodeJS.ReadableStream & { isTTY?: boolean } {
  const s = Readable.from([Buffer.from("")]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  s.isTTY = isTTY;
  return s;
}

type Exec = (
  cmd: string,
  args: string[],
  input?: string,
) => Promise<{ stdout: string; stderr: string; code: number | null }>;

/** In-memory macOS `security` stub. `readbackOverride` forces a verify miss. */
function fakeKeychain(readbackOverride?: string): { exec: Exec; store: Map<string, string> } {
  const store = new Map<string, string>();
  const exec: Exec = async (cmd, args, input) => {
    if (cmd !== "security") return { stdout: "", stderr: "unhandled", code: 1 };
    if (args[0] === "-i" && input) {
      const svc = /-s "([^"]*)"/.exec(input)?.[1];
      const val = /-w "([^"]*)"/.exec(input)?.[1];
      if (svc !== undefined && val !== undefined) {
        store.set(svc, val);
        return { stdout: "", stderr: "", code: 0 };
      }
      return { stdout: "", stderr: "bad batch", code: 1 };
    }
    if (args[0] === "find-generic-password") {
      const i = args.indexOf("-s");
      const svc = i >= 0 ? args[i + 1]! : "";
      if (readbackOverride !== undefined) {
        return { stdout: readbackOverride + "\n", stderr: "", code: 0 };
      }
      if (store.has(svc)) return { stdout: store.get(svc)! + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "could not be found", code: 44 };
    }
    if (args[0] === "delete-generic-password") {
      const i = args.indexOf("-s");
      const svc = i >= 0 ? args[i + 1]! : "";
      const had = store.delete(svc);
      return { stdout: "", stderr: "", code: had ? 0 : 44 };
    }
    return { stdout: "", stderr: "unhandled", code: 1 };
  };
  return { exec, store };
}

interface Seeded {
  storagePath: string;
  home: string;
  recoveryKey: string;
  cleanup: () => Promise<void>;
}

async function seed(mintRecoveryKey = true): Promise<Seeded> {
  const home = await mkdtemp(join(tmpdir(), "reset-rk-"));
  const storagePath = join(home, ".sanctuary");
  const statePath = join(storagePath, "state");
  await mkdir(statePath, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(statePath);
  const custody = await establishMaster({
    storage,
    passphrase: OLD_PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey },
    storagePathHint: storagePath,
  });
  custody.masterKey.fill(0);
  return {
    storagePath,
    home,
    recoveryKey: custody.mintedRecoveryKey ?? "",
    cleanup: () => rm(home, { recursive: true, force: true }),
  };
}

function stdinFromLines(lines: string[]): NodeJS.ReadableStream & { isTTY?: boolean } {
  const s = Readable.from([
    Buffer.from(lines.join("\n") + "\n"),
  ]) as unknown as NodeJS.ReadableStream & { isTTY?: boolean };
  s.isTTY = false;
  return s;
}

async function envelopeOf(storagePath: string) {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  return readCustodyEnvelope(storage);
}
async function rawEnvelope(storagePath: string): Promise<Uint8Array | null> {
  const storage = new FilesystemStorage(join(storagePath, "state"));
  return storage.read("_meta", "custody-envelope");
}
async function unlockableBy(
  storagePath: string,
  cred: { passphrase: string } | { recoveryKey: Uint8Array },
): Promise<boolean> {
  const env = await envelopeOf(storagePath);
  if (!env) return false;
  try {
    const m = await unwrapMaster(env, cred);
    m.fill(0);
    return true;
  } catch {
    return false;
  }
}

describe("reset-passphrase --mode recovery-key", () => {
  let f: Seeded;
  beforeEach(async () => {
    f = await seed();
  });
  afterEach(async () => {
    await f.cleanup();
  });

  it("rekeys: enrolls+verifies a new passphrase, then removes the old one, preserving the recovery wrap", async () => {
    const before = await envelopeOf(f.storagePath);
    const out = new StringWritable();
    const err = new StringWritable();
    const kc = fakeKeychain();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out,
      err,
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(0);

    // The stored credential now opens the fortress; the OLD passphrase does not.
    const stored = [...kc.store.values()][0];
    expect(stored).toBeDefined();
    expect(await unlockableBy(f.storagePath, { passphrase: stored! })).toBe(true);
    expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(false);
    // The recovery key is unchanged and still works.
    expect(
      await unlockableBy(f.storagePath, { recoveryKey: fromBase64url(f.recoveryKey) }),
    ).toBe(true);

    // Exactly one passphrase wrap (the new one) and the recovery wrap survive.
    const env = await envelopeOf(f.storagePath);
    expect({
      v: env!.v,
      install_mode: env!.install_mode,
      created_at: env!.created_at,
      epoch: env!.epoch,
      epoch_id: env!.epoch_id,
    }).toEqual({
      v: before!.v,
      install_mode: before!.install_mode,
      created_at: before!.created_at,
      epoch: before!.epoch,
      epoch_id: before!.epoch_id,
    });
    expect(env!.wraps.filter((w) => w.type === "passphrase")).toHaveLength(1);
    expect(env!.wraps.some((w) => w.type === "recovery-key")).toBe(true);

    // Auditable without secrets: the marker records the event, not the key.
    const marker = await readFile(join(f.storagePath, ".reset-history.log"), "utf8");
    const record = JSON.parse(marker.trim()) as Record<string, unknown>;
    expect(record.schema).toBe("sanctuary.reset-marker.v1");
    expect(record.authoritative).toBe(false);
    expect(record.recovery_mode).toBe("recovery-key");
    expect((await lstat(join(f.storagePath, ".reset-history.log"))).mode & 0o777).toBe(0o600);
    expect(marker).not.toContain(stored!);
    expect(marker).not.toContain(f.recoveryKey);
  });

  it("quarantines a symlink reset history without following its target or wedging custody", async () => {
    const target = join(f.home, "outside-marker-target");
    await writeFile(target, "unchanged\n", { mode: 0o600 });
    await symlink(target, join(f.storagePath, ".reset-history.log"));
    const kc = fakeKeychain();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(0);
    expect(await readFile(target, "utf8")).toBe("unchanged\n");
    expect((await lstat(join(f.storagePath, ".reset-history.log"))).isFile()).toBe(true);
    const quarantine = (await readdir(f.storagePath)).find((name) =>
      name.startsWith(".reset-history.log.quarantine."),
    );
    expect(quarantine).toBeDefined();
    expect((await lstat(join(f.storagePath, quarantine!))).isSymbolicLink()).toBe(true);
    expect(await new FilesystemStorage(join(f.storagePath, "state")).read(
      "_meta",
      "custody-rekey-journal",
    )).toBeNull();
  });

  it("quarantines incomplete history, records a fresh frame, and leaves no journal", async () => {
    const markerPath = join(f.storagePath, ".reset-history.log");
    await writeFile(markerPath, '{"incomplete":true', { mode: 0o600, flag: "wx" });
    const kc = fakeKeychain();
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    const quarantine = (await readdir(f.storagePath)).find((name) =>
      name.startsWith(".reset-history.log.quarantine."),
    );
    expect(quarantine).toBeDefined();
    expect(await readFile(join(f.storagePath, quarantine!), "utf8")).toBe(
      '{"incomplete":true',
    );
    expect(JSON.parse((await readFile(markerPath, "utf8")).trim()).authoritative).toBe(false);
    expect(await new FilesystemStorage(join(f.storagePath, "state")).read(
      "_meta",
      "custody-rekey-journal",
    )).toBeNull();
  });

  it("rotates oversize history and commits a bounded fresh frame", async () => {
    const markerPath = join(f.storagePath, ".reset-history.log");
    await writeFile(markerPath, Buffer.alloc(1024 * 1024 + 1, 0x78), {
      mode: 0o600,
      flag: "wx",
    });
    const kc = fakeKeychain();
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    const quarantine = (await readdir(f.storagePath)).find((name) =>
      name.startsWith(".reset-history.log.quarantine."),
    );
    expect(quarantine).toBeDefined();
    expect((await lstat(join(f.storagePath, quarantine!))).size).toBe(1024 * 1024 + 1);
    expect((await lstat(markerPath)).size).toBeLessThan(1024 * 1024);
    expect(await new FilesystemStorage(join(f.storagePath, "state")).read(
      "_meta",
      "custody-rekey-journal",
    )).toBeNull();
  });

  it("wrong recovery key mutates nothing", async () => {
    const before = await rawEnvelope(f.storagePath);
    const kc = fakeKeychain();
    const wrongKey = toBase64url(new Uint8Array(32)); // valid shape, wrong key
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: wrongKey,
    });
    expect(code).toBe(1);
    // Envelope byte-identical, keychain untouched, old passphrase still works.
    const after = await rawEnvelope(f.storagePath);
    expect(Buffer.from(after!).equals(Buffer.from(before!))).toBe(true);
    expect(kc.store.size).toBe(0);
    expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(true);
  });

  it("binds rekey writes to the acquired root inode and refuses a post-acquire replacement", async () => {
    const before = await rawEnvelope(f.storagePath);
    const displaced = `${f.storagePath}.displaced`;
    const marker = "replacement-must-remain-untouched";
    const kc = fakeKeychain();
    const err = new StringWritable();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err,
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
      __testAfterKernelHolderAcquired: () => {
        renameSync(f.storagePath, displaced);
        mkdirSync(f.storagePath, { recursive: true, mode: 0o700 });
        writeFileSync(join(f.storagePath, "replacement-marker"), marker, {
          mode: 0o600,
          flag: "wx",
        });
      },
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/root (?:identity )?changed/);
    expect(await readFile(join(f.storagePath, "replacement-marker"), "utf8")).toBe(marker);
    expect(await rawEnvelope(f.storagePath)).toBeNull();
    const displacedEnvelope = await rawEnvelope(displaced);
    expect(Buffer.from(displacedEnvelope!).equals(Buffer.from(before!))).toBe(true);
    expect(kc.store.size).toBe(0);
  });

  it("binds credential persistence across an awaited keychain write and resumes on the displaced inode", async () => {
    const displaced = `${f.storagePath}.await-displaced`;
    const marker = join(f.storagePath, "replacement-marker");
    const kc = fakeKeychain();
    let swapped = false;
    const exec: Exec = async (cmd, args, input) => {
      const result = await kc.exec(cmd, args, input);
      if (!swapped && cmd === "security" && args[0] === "-i") {
        swapped = true;
        renameSync(f.storagePath, displaced);
        mkdirSync(f.storagePath, { recursive: true, mode: 0o700 });
        writeFileSync(marker, "replacement", { mode: 0o600 });
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
      return result;
    };
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(1);
    expect(await readFile(marker, "utf8")).toBe("replacement");
    await expect(lstat(join(f.storagePath, "passphrase.enc")))
      .rejects.toMatchObject({ code: "ENOENT" });

    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", displaced],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(0);
    expect(await unlockableBy(displaced, {
      recoveryKey: fromBase64url(f.recoveryKey),
    })).toBe(true);
  });

  it("crash-safe: a failed verification leaves the old passphrase AND the recovery key working", async () => {
    // Force the stored-credential readback to mismatch so finalization refuses.
    const kc = fakeKeychain("this-is-not-the-freshly-stored-passphrase");
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(1);
    // Old passphrase wraps were NOT removed, and the recovery key still works.
    expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(true);
    expect(
      await unlockableBy(f.storagePath, { recoveryKey: fromBase64url(f.recoveryKey) }),
    ).toBe(true);
    await expect(lstat(join(f.storagePath, "passphrase.enc")))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect([...kc.store.values()]).toEqual([
      "this-is-not-the-freshly-stored-passphrase",
    ]);
  });

  it("does not create a stale fallback when updating a prior keyring credential fails", async () => {
    const kc = fakeKeychain();
    const identity = capturePassphraseCredentialIdentity(
      f.storagePath,
      f.home,
    );
    kc.store.set(identity.keychainService, OLD_PASSPHRASE);
    const exec: Exec = async (cmd, args, input) => {
      if (cmd === "security" && args[0] === "-i") {
        return { stdout: "", stderr: "injected keychain write failure", code: 1 };
      }
      return kc.exec(cmd, args, input);
    };
    expect(await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err: new StringWritable(),
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec,
      recoveryKeyOverride: f.recoveryKey,
    })).toBe(1);
    expect(kc.store.get(identity.keychainService)).toBe(OLD_PASSPHRASE);
    await expect(lstat(join(f.storagePath, "passphrase.enc")))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(true);
  });

  it("refuses a non-interactive session (no override) without mutating", async () => {
    const before = await rawEnvelope(f.storagePath);
    const kc = fakeKeychain();
    const err = new StringWritable();
    const code = await runResetPassphraseCommand({
      argv: ["--mode", "recovery-key", "--fortress", f.storagePath],
      out: new StringWritable(),
      err,
      stdin: nonTtyStdin(false),
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      // no recoveryKeyOverride → the real TTY guard fires
    });
    expect(code).toBe(2);
    expect(err.text).toContain("interactive terminal");
    const after = await rawEnvelope(f.storagePath);
    expect(Buffer.from(after!).equals(Buffer.from(before!))).toBe(true);
    expect(kc.store.size).toBe(0);
  });
});

describe("reset-passphrase interactive menu exposes the recovery-key route (F2)", () => {
  let f: Seeded;
  afterEach(async () => {
    await f.cleanup();
  });

  it("does not claim unauthenticated recovery-wrap availability and routes recovery-first choice 1 to the authenticated rekey", async () => {
    f = await seed(true);
    const out = new StringWritable();
    const err = new StringWritable();
    const kc = fakeKeychain();
    const code = await runResetPassphraseCommand({
      argv: [], // no --mode → interactive menu
      out,
      err,
      stdin: stdinFromLines(["1"]), // pick recovery-key
      storagePath: f.storagePath,
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      // the menu selected recovery-key; the override stands in for the hidden
      // prompt so the non-TTY test can still exercise the rekey.
      recoveryKeyOverride: f.recoveryKey,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("1) recovery-key");
    expect(out.text).toContain("availability is not claimed");
    expect(out.text).not.toContain("this fortress carries a human-held recovery-key wrap");
    // The rekey actually ran: the stored credential now opens the fortress.
    const stored = [...kc.store.values()][0];
    expect(await unlockableBy(f.storagePath, { passphrase: stored! })).toBe(true);
    expect(await unlockableBy(f.storagePath, { passphrase: OLD_PASSPHRASE })).toBe(false);
  });

  it("uses the same custody-neutral recovery label when no recovery wrap exists", async () => {
    f = await seed(false); // no recovery factor
    const out = new StringWritable();
    const err = new StringWritable();
    const kc = fakeKeychain();
    // Pick nuke (3) so the menu renders but nothing hangs; assert only the label.
    const code = await runResetPassphraseCommand({
      argv: [],
      out,
      err,
      stdin: stdinFromLines(["q"]), // abort after rendering the menu
      storagePath: f.storagePath,
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
    });
    expect(code).toBe(1); // aborted
    expect(out.text).toContain("1) recovery-key");
    expect(out.text).toContain("human-held key required");
    expect(out.text).toContain("availability is not claimed");
  });

  it("selecting recovery-key from the menu in a non-TTY session (no override) refuses", async () => {
    f = await seed(true);
    const before = await rawEnvelope(f.storagePath);
    const out = new StringWritable();
    const err = new StringWritable();
    const kc = fakeKeychain();
    const code = await runResetPassphraseCommand({
      argv: [],
      out,
      err,
      stdin: stdinFromLines(["1"]),
      storagePath: f.storagePath,
      home: f.home,
      platformOverride: "darwin",
      exec: kc.exec,
      // no recoveryKeyOverride → the real TTY guard fires after menu selection
    });
    expect(code).toBe(2);
    expect(err.text).toContain("interactive terminal");
    const after = await rawEnvelope(f.storagePath);
    expect(Buffer.from(after!).equals(Buffer.from(before!))).toBe(true);
    expect(kc.store.size).toBe(0);
  });
});
