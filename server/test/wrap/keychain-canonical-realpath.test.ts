/**
 * Finding 5: the fortress keyring identity is symlink-resolved (realpath), so a
 * fortress reached through a symlink alias and through its real path share ONE
 * credential instead of orphaning custody across the two lexical paths. The
 * legacy lexical/12-hex credential is read for compatibility and promoted onto
 * the canonical service — authenticated, conflict-refusing, and with a readback
 * before any legacy factor is deleted.
 *
 * An injected in-memory `security` stub keyed by service name lets these tests
 * observe exactly which identity each read/write/delete touches, without a real
 * keyring and on Linux CI as well as macOS.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtemp,
  rm,
  mkdir,
  symlink,
  realpath,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gcm } from "@noble/ciphers/aes.js";
import { toBase64url } from "../../src/core/encoding.js";

import {
  canonicalKeychainServiceFor,
  canonicalLegacyKeychainServiceFor,
  capturePassphraseCredentialIdentity,
  fortressKeychainReadServices,
  keychainServiceFor,
  legacyKeychainServiceFor,
  readStoredPassphrase,
  persistUserProvidedPassphrase,
  type ExecResult,
} from "../../src/wrap/passphrase.js";
import {
  canonicalCustodyServiceFor,
  canonicalRecoveryKeyServiceFor,
  custodyServiceFor,
  fortressCustodyCredentialServices,
  probeKeychainCustodyKey,
  probeKeychainRecoveryKey,
  recoveryKeyServiceFor,
} from "../../src/wrap/keychain-custody.js";

/** In-memory `security` stub keyed by `account:service`. */
function makeExec(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
  stored: Map<string, string>;
} {
  const stored = new Map<string, string>();
  const unescape = (s: string) => s.replace(/\\(.)/g, "$1");
  const exec = async (cmd: string, args: string[], input?: string): Promise<ExecResult> => {
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      const wm = input?.match(/-w "((?:[^"\\]|\\.)*)"/);
      const am = input?.match(/-a "((?:[^"\\]|\\.)*)"/);
      const sm = input?.match(/-s "((?:[^"\\]|\\.)*)"/);
      if (!wm || !sm) return { stdout: "", stderr: "missing", code: 1 };
      stored.set(`${am ? unescape(am[1]!) : ""}:${unescape(sm[1]!)}`, unescape(wm[1]!));
      return { stdout: "", stderr: "", code: 0 };
    }
    const a = args.indexOf("-a");
    const s = args.indexOf("-s");
    const key = `${a >= 0 ? args[a + 1] : ""}:${s >= 0 ? args[s + 1] : ""}`;
    if (args[0] === "find-generic-password") {
      const v = stored.get(key);
      return v !== undefined
        ? { stdout: v + "\n", stderr: "", code: 0 }
        : { stdout: "", stderr: "not found", code: 44 };
    }
    if (args[0] === "delete-generic-password") {
      return stored.delete(key)
        ? { stdout: "", stderr: "", code: 0 }
        : { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec, stored };
}

describe("canonical realpath keyring identity (F5)", () => {
  let parent: string;
  let realDir: string;
  let aliasDir: string;
  const home = "/home/test";

  beforeEach(async () => {
    parent = await mkdtemp(join(tmpdir(), "f5-canonical-"));
    realDir = join(parent, "real-fortress");
    aliasDir = join(parent, "alias-fortress");
    await mkdir(realDir, { recursive: true });
    await symlink(realDir, aliasDir);
  });
  afterEach(async () => {
    await rm(parent, { recursive: true, force: true });
  });

  it("an alias and the real path map to ONE canonical service; the lexical names differ", () => {
    expect(canonicalKeychainServiceFor(aliasDir, home)).toBe(
      canonicalKeychainServiceFor(realDir, home),
    );
    // The pre-realpath lexical derivation splits them (the orphaning bug).
    expect(keychainServiceFor(aliasDir, home)).not.toBe(keychainServiceFor(realDir, home));
  });

  it("canonicalizes custody and recovery services while retaining lexical compatibility identities", () => {
    expect(canonicalCustodyServiceFor(aliasDir, home)).toBe(
      canonicalCustodyServiceFor(realDir, home),
    );
    expect(canonicalRecoveryKeyServiceFor(aliasDir, home)).toBe(
      canonicalRecoveryKeyServiceFor(realDir, home),
    );
    expect(custodyServiceFor(aliasDir, home)).not.toBe(custodyServiceFor(realDir, home));
    expect(recoveryKeyServiceFor(aliasDir, home)).not.toBe(
      recoveryKeyServiceFor(realDir, home),
    );
    const services = fortressCustodyCredentialServices(aliasDir, home);
    expect(services).toContain(canonicalCustodyServiceFor(aliasDir, home));
    expect(services).toContain(custodyServiceFor(aliasDir, home));
    expect(services).toContain(canonicalRecoveryKeyServiceFor(aliasDir, home));
    expect(services).toContain(recoveryKeyServiceFor(aliasDir, home));
  });

  it("presence-only custody probes scrub the decoded key before returning", async () => {
    const { exec, stored } = makeExec();
    const service = canonicalCustodyServiceFor(aliasDir, home);
    stored.set(`sanctuary:${service}`, Buffer.alloc(32, 0x73).toString("base64url"));
    let observed: Uint8Array | undefined;
    const result = await probeKeychainCustodyKey(aliasDir, {
      home,
      platformOverride: "darwin",
      exec,
      __testObserveSecretBuffer: (label, buffer) => {
        if (label === "custody-probe-key") observed = buffer;
      },
    });
    expect(result.status).toBe("found");
    expect(result.key).toBeUndefined();
    expect(observed).toBeDefined();
    expect([...(observed ?? [])]).toEqual(new Array(32).fill(0));
  });

  it.each([
    ["custody", probeKeychainCustodyKey, canonicalCustodyServiceFor],
    ["recovery", probeKeychainRecoveryKey, canonicalRecoveryKeyServiceFor],
  ] as const)("scrubs the %s presence-probe buffer when an observer throws", async (
    _kind,
    probe,
    serviceFor,
  ) => {
    const { exec, stored } = makeExec();
    stored.set(
      `sanctuary:${serviceFor(aliasDir, home)}`,
      Buffer.alloc(32, 0x74).toString("base64url"),
    );
    let observed: Uint8Array | undefined;
    await expect(probe(aliasDir, {
      home,
      platformOverride: "darwin",
      exec,
      __testObserveSecretBuffer: (_label, buffer) => {
        observed = buffer;
        throw new Error("observer failure");
      },
    })).rejects.toThrow("observer failure");
    expect(observed).toBeDefined();
    expect([...(observed ?? [])]).toEqual(new Array(32).fill(0));
  });

  it("canonicalizes the deepest existing ancestor for a fresh nonexistent suffix", () => {
    const viaAlias = join(aliasDir, "fresh", "nested", ".sanctuary");
    const viaReal = join(realDir, "fresh", "nested", ".sanctuary");
    expect(canonicalKeychainServiceFor(viaAlias, home)).toBe(
      canonicalKeychainServiceFor(viaReal, home),
    );
    expect(keychainServiceFor(viaAlias, home)).not.toBe(
      keychainServiceFor(viaReal, home),
    );
  });

  it("maps fresh /tmp and /private/tmp paths to one identity on macOS", async () => {
    const realTmp = await realpath("/tmp");
    if (process.platform === "darwin") expect(realTmp).toBe("/private/tmp");
    const leaf = `sanctuary-fresh-${process.pid}-${Date.now()}`;
    expect(canonicalKeychainServiceFor(join("/tmp", leaf), home)).toBe(
      canonicalKeychainServiceFor(join(realTmp, leaf), home),
    );
  });

  it("binds V3 fallback ciphertext to the same realpath identity through an alias", async () => {
    const { exec } = makeExec();
    await persistUserProvidedPassphrase("alias-fallback-pass", {
      home,
      storagePath: aliasDir,
      platformOverride: "win32",
      exec,
    });
    const raw = JSON.parse(
      await readFile(join(realDir, "passphrase.enc"), "utf8"),
    ) as { v: number; aad: string };
    expect(raw).toMatchObject({ v: 3, aad: "canonical-storage-path" });

    const opened = await readStoredPassphrase({
      home,
      storagePath: realDir,
      platformOverride: "win32",
      exec,
    });
    expect(opened?.value).toBe("alias-fallback-pass");
  });

  it("reads a real-path V2 lexical-AAD fallback through an alias and promotes only after authentication", async () => {
    const { exec } = makeExec();
    const fallback = join(realDir, "passphrase.enc");
    const key = new Uint8Array(32).fill(0x5a);
    const nonce = new Uint8Array(12).fill(0x24);
    // Exact shipped V2 contract: dirname(the actual fallback path), not the
    // caller's current storage-path spelling or a newly canonicalized guess.
    const ciphertext = gcm(
      key,
      nonce,
      Buffer.from(
        `sanctuary-passphrase:${resolve(dirname(join(aliasDir, "passphrase.enc")))}`,
        "utf8",
      ),
    ).encrypt(Buffer.from("legacy-fallback-pass", "utf8"));
    await writeFile(fallback, JSON.stringify({
      v: 2,
      alg: "aes-256-gcm",
      aad: "storage-path",
      nonce: toBase64url(nonce),
      ct: toBase64url(ciphertext),
    }), { mode: 0o600 });

    const opened = await readStoredPassphrase({
      home,
      storagePath: aliasDir,
      platformOverride: "win32",
      exec,
      deriveMachineKey: () => key.slice(),
    });
    expect(opened?.value).toBe("legacy-fallback-pass");
    const promoted = JSON.parse(await readFile(fallback, "utf8")) as {
      v: number;
      aad: string;
    };
    expect(promoted).toMatchObject({ v: 3, aad: "canonical-storage-path" });
  });

  it("does not promote a V2 fallback when neither bounded AAD candidate authenticates", async () => {
    const { exec } = makeExec();
    const fallback = join(realDir, "passphrase.enc");
    const key = new Uint8Array(32).fill(0x5a);
    const nonce = new Uint8Array(12).fill(0x25);
    const ciphertext = gcm(key, nonce, Buffer.from("unrelated-aad", "utf8"))
      .encrypt(Buffer.from("must-not-promote", "utf8"));
    const original = Buffer.from(JSON.stringify({
      v: 2,
      alg: "aes-256-gcm",
      aad: "storage-path",
      nonce: toBase64url(nonce),
      ct: toBase64url(ciphertext),
    }), "utf8");
    await writeFile(fallback, original, { mode: 0o600 });

    await expect(readStoredPassphrase({
      home,
      storagePath: aliasDir,
      platformOverride: "win32",
      exec,
      deriveMachineKey: () => key.slice(),
    })).rejects.toThrow();
    expect(Buffer.from(await readFile(fallback)).equals(original)).toBe(true);
  });

  it("propagates indeterminate realpath failures instead of falling back lexically", async () => {
    const loop = join(parent, "realpath-loop");
    await symlink("realpath-loop", loop);
    expect(() => canonicalKeychainServiceFor(join(loop, "fortress"), home)).toThrow();
  });

  it("tolerates a failed optional inode read candidate but keeps canonical capture strict", async () => {
    const wrongLeaf = join(parent, "fortress-is-a-file");
    await writeFile(wrongLeaf, "not a directory", { mode: 0o600 });
    expect(() => fortressKeychainReadServices(wrongLeaf, home)).not.toThrow();
    expect(() => capturePassphraseCredentialIdentity(
      wrongLeaf,
      home,
    )).toThrow(/identity|directory/i);
  });

  it("a fully-canonical path (already its own realpath) keeps canonical === lexical (existing bytes unchanged)", async () => {
    // A path with NO symlink on ANY component: its realpath equals itself, so
    // the realpath-based canonical name is byte-identical to the lexical one.
    const canonicalPath = await realpath(realDir);
    expect(canonicalKeychainServiceFor(canonicalPath, home)).toBe(
      keychainServiceFor(canonicalPath, home),
    );
  });

  it("reads a credential stored under the legacy lexical name (compat read)", async () => {
    const { exec, stored } = makeExec();
    // Seed the credential ONLY under the lexical name of the alias path.
    stored.set(`sanctuary:${keychainServiceFor(aliasDir, home)}`, "alias-legacy-pass");
    // The canonical name has nothing yet.
    expect(stored.has(`sanctuary:${canonicalKeychainServiceFor(aliasDir, home)}`)).toBe(false);

    const result = await readStoredPassphrase({
      home,
      storagePath: aliasDir,
      platformOverride: "darwin",
      exec,
    });
    expect(result?.value).toBe("alias-legacy-pass");
  });

  it("reads the canonical realpath 12-hex legacy credential through an alias", async () => {
    // S8: the writable "promote legacy -> canonical" authority was removed as an
    // inert capability, so this test now pins only the READ-through-alias
    // behavior (the read chain never promotes/deletes).
    const { exec, stored } = makeExec();
    const canonicalLegacy = canonicalLegacyKeychainServiceFor(aliasDir, home);
    const aliasLegacy = legacyKeychainServiceFor(aliasDir, home);
    expect(canonicalLegacy).not.toBe(aliasLegacy);
    stored.set(`sanctuary:${canonicalLegacy}`, "realpath-legacy-pass");

    const opened = await readStoredPassphrase({
      home,
      storagePath: aliasDir,
      platformOverride: "darwin",
      exec,
    });
    expect(opened?.value).toBe("realpath-legacy-pass");
    // The read is non-destructive: the legacy entry is untouched (never promoted).
    expect(stored.get(`sanctuary:${canonicalLegacy}`)).toBe("realpath-legacy-pass");
  });

  it("persist writes canonical but never deletes an unauthenticated legacy credential", async () => {
    const { exec, stored } = makeExec();
    const lexical = keychainServiceFor(aliasDir, home);
    const canonical = canonicalKeychainServiceFor(aliasDir, home);
    expect(lexical).not.toBe(canonical); // symlink path: they diverge
    stored.set(`sanctuary:${lexical}`, "old-alias-pass");

    await persistUserProvidedPassphrase("fresh-pass", {
      home,
      storagePath: aliasDir,
      platformOverride: "darwin",
      exec,
    });
    // Persistence alone has not authenticated either value against the
    // fortress. Cleanup is exclusively the verified promotion path below.
    expect(stored.get(`sanctuary:${canonical}`)).toBe("fresh-pass");
    expect(stored.get(`sanctuary:${lexical}`)).toBe("old-alias-pass");
  });

  it("a concurrent canonical overwrite still cannot authorize legacy deletion", async () => {
    const { exec: baseExec, stored } = makeExec();
    const lexical = keychainServiceFor(aliasDir, home);
    const canonical = canonicalKeychainServiceFor(aliasDir, home);
    stored.set(`sanctuary:${lexical}`, "still-valid-legacy-pass");

    let signalFirstWrite!: () => void;
    const firstWrite = new Promise<void>((resolve) => {
      signalFirstWrite = resolve;
    });
    let releaseFirstWrite!: () => void;
    const firstWriteMayReturn = new Promise<void>((resolve) => {
      releaseFirstWrite = resolve;
    });
    let intercepted = false;
    const exec = async (
      cmd: string,
      args: string[],
      input?: string,
    ): Promise<ExecResult> => {
      const result = await baseExec(cmd, args, input);
      if (!intercepted && args[0] === "-i" && result.code === 0) {
        intercepted = true;
        signalFirstWrite();
        await firstWriteMayReturn;
      }
      return result;
    };

    const persist = persistUserProvidedPassphrase("first-writer-pass", {
      home,
      storagePath: aliasDir,
      platformOverride: "darwin",
      exec,
    });
    const concurrentOverwrite = (async () => {
      await firstWrite;
      stored.set(`sanctuary:${canonical}`, "second-writer-pass");
      releaseFirstWrite();
    })();

    await expect(persist).resolves.toMatchObject({ source: "keychain" });
    await concurrentOverwrite;
    expect(stored.get(`sanctuary:${canonical}`)).toBe("second-writer-pass");
    expect(stored.get(`sanctuary:${lexical}`)).toBe("still-valid-legacy-pass");
  });
});
