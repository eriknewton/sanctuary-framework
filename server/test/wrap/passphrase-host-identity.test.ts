/**
 * The machine-local passphrase fallback file across a change in the host's
 * resolved hostname.
 *
 * Capability under test: a fortress whose only stored credential is the
 * encrypted fallback file keeps opening hands-free after the host answers to a
 * different spelling of its own name, and the file is re-wrapped under the
 * stable host identity on the first writable read. A caller that declared
 * itself read-only reads the same value and leaves the bytes untouched. A file
 * that belongs to a different host is still refused, whether that host has a
 * different name or the same name and a different machine identity. A host with
 * no stable identity still writes under the current label, a file written while
 * the stable-identity probe was failing is still reached, and a repair that
 * cannot be written defers rather than denying custody, reporting the file's
 * observed state rather than assuming one.
 *
 * Register id: defect.fallback-passphrase-key-derived-from-volatile-hostname
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import {
  fallbackFilePath,
  getOrCreatePassphrase,
  persistUserProvidedPassphrase,
  PassphraseUnreadableError,
  readStoredPassphrase,
  type ExecResult,
} from "../../src/wrap/passphrase.js";
import type { MachineIdentity } from "../../src/wrap/host-identity.js";

/**
 * The two spellings one Mac gave for itself on either side of a reboot, with
 * the machine, the file, and the operator all untouched in between.
 */
const FORMER_HOSTNAME = "sanctuary-drill-host.localdomain";
const CURRENT_HOSTNAME = "sanctuary-drill-host.local";
/** A canonical 8-4-4-4-12 platform UUID standing in for this host's stable id. */
const STABLE_HOST_ID = "4F1D3C2B-9A87-4655-B3E1-0C7D2A96F5E4";
/**
 * A DIFFERENT machine's stable identity. Used with the SAME hostname, which is
 * the only way to show that the binding is to the host rather than to its name:
 * two machines can genuinely answer to one name (a reused DHCP name, a restored
 * clone), and the file must not open across them.
 */
const OTHER_STABLE_HOST_ID = "0B6E71A4-5C32-4D89-9F10-8E4A7B23C6D5";
/** A name from which none of the migration candidates can reach the two above. */
const UNRELATED_HOSTNAME = "some-other-machine.example.net";
/** 32 = the AES-256-GCM key width the fallback file is encrypted under. */
const MACHINE_KEY_BYTES = 32;

/** This host, after the rename, with a stable identity available. */
const RENAMED_HOST: MachineIdentity = {
  stableHostId: STABLE_HOST_ID,
  hostname: CURRENT_HOSTNAME,
};

/**
 * A Linux host with no usable Secret Service: lookups report a clean miss (so
 * the read chain proceeds to the fallback file rather than failing closed) and
 * stores fail (so a persisted value lands in the fallback file). This is the
 * shipped no-OS-keyring path the fallback file exists for.
 */
const noKeyring = async (
  _cmd: string,
  args: string[],
): Promise<ExecResult> =>
  args[0] === "lookup"
    ? { stdout: "", stderr: "", code: 1 }
    : { stdout: "", stderr: "no secret service", code: 1 };

/**
 * The same "no usable keyring" host, answering for EITHER backend, so a test
 * can run one call under a simulated platform and the next under the real one
 * without either touching an operator credential store. On macOS `security`
 * reports a clean miss with exit 44; any other non-zero exit is classified as
 * an unreachable keychain, which is a different state and would test something
 * else.
 */
const noKeyringEitherBackend = async (
  cmd: string,
  args: string[],
): Promise<ExecResult> =>
  cmd === "security"
    ? {
        stdout: "",
        stderr: "The specified item could not be found in the keychain.",
        code: 44,
      }
    : noKeyring(cmd, args);

/**
 * Mirror of the SUPERSEDED machine-key derivation. Must match
 * `deriveLegacyHostnameMachineKey` in `server/src/wrap/passphrase.ts`
 * (`<host>:<uid>:<username>:<home>`, HKDF-SHA256, info
 * "sanctuary-passphrase-v1", 32 bytes).
 *
 * FAILURE MODE if it drifts: the planted file stops being the artifact these
 * tests are about, the migration ladder never has to do anything, and the whole
 * file passes while proving nothing. The pin comment on the source side names
 * this file for the same reason.
 */
function supersededHostnameKey(host: string, home: string): Uint8Array {
  const info = userInfo();
  return hkdf(
    sha256,
    Buffer.from(`${host}:${info.uid}:${info.username}:${home}`, "utf-8"),
    undefined,
    "sanctuary-passphrase-v1",
    MACHINE_KEY_BYTES,
  );
}

/**
 * Mirror of the CURRENT machine-key derivation. Must match `deriveMachineKey`
 * in `server/src/wrap/passphrase.ts` (`<host fact>:<uid>:<username>:<home>`,
 * HKDF-SHA256, info "sanctuary-passphrase-v2-host-identity", 32 bytes), where
 * the host fact is the stable host id when there is one and the resolved
 * hostname when there is not.
 *
 * FAILURE MODE if it drifts: the label-discrimination test below stops
 * comparing the two labels and starts comparing two wrong keys, which fails the
 * same way whether or not the production code is correct.
 */
function currentLabelKey(hostFact: string, home: string): Uint8Array {
  const info = userInfo();
  return hkdf(
    sha256,
    Buffer.from(`${hostFact}:${info.uid}:${info.username}:${home}`, "utf-8"),
    undefined,
    "sanctuary-passphrase-v2-host-identity",
    MACHINE_KEY_BYTES,
  );
}

describe("passphrase fallback file across a change of hostname", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-passphrase-hostid-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  const fallback = (): string => fallbackFilePath(home, home);

  /**
   * Write the file exactly as the shipped code wrote it on this host BEFORE the
   * rename: current envelope, key derived from the former hostname.
   */
  async function plantFileFromBeforeTheRename(value: string): Promise<Buffer> {
    await persistUserProvidedPassphrase(value, {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      deriveMachineKey: (h) => supersededHostnameKey(FORMER_HOSTNAME, h),
    });
    return readFile(fallback());
  }

  it("opens a file written under the former hostname and re-wraps it under the stable host identity", async () => {
    const planted = await plantFileFromBeforeTheRename("fortress-value-across-a-reboot");

    const resolved = await getOrCreatePassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
    });
    expect(resolved.source).toBe("fallback-file");
    expect(resolved.value).toBe("fortress-value-across-a-reboot");

    // The repair actually ran: the at-rest bytes are not the planted ones.
    const migrated = await readFile(fallback());
    expect(migrated.equals(planted)).toBe(false);

    // And the repaired file now opens under the current key alone. A second
    // read leaving it byte-identical is the proof: had it still needed the
    // ladder, this read would have repaired it again.
    const second = await getOrCreatePassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
    });
    expect(second.value).toBe("fortress-value-across-a-reboot");
    expect((await readFile(fallback())).equals(migrated)).toBe(true);
  });

  it("lets a read-only caller open a file from before the rename without touching its bytes", async () => {
    const planted = await plantFileFromBeforeTheRename("read-only-caller-value");

    const read = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      readOnly: true,
      machineIdentityOverride: RENAMED_HOST,
    });
    expect(read?.source).toBe("fallback-file");
    expect(read?.value).toBe("read-only-caller-value");
    expect((await readFile(fallback())).equals(planted)).toBe(true);
  });

  it("derives the same machine key when only the resolved hostname changes", async () => {
    await persistUserProvidedPassphrase("stable-identity-value", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: {
        stableHostId: STABLE_HOST_ID,
        hostname: FORMER_HOSTNAME,
      },
    });
    const written = await readFile(fallback());

    const read = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: {
        stableHostId: STABLE_HOST_ID,
        hostname: UNRELATED_HOSTNAME,
      },
    });
    expect(read?.value).toBe("stable-identity-value");
    // Unchanged bytes are what makes this a test of the DERIVATION rather than
    // of the ladder: a ladder hit would have reported the file stale and
    // repaired it. The hostname is not in the material at all.
    expect((await readFile(fallback())).equals(written)).toBe(true);
  });

  it("still round-trips on a host that exposes no stable identity", async () => {
    const hostWithoutStableId: MachineIdentity = {
      stableHostId: null,
      hostname: FORMER_HOSTNAME,
    };
    await persistUserProvidedPassphrase("no-stable-identity-value", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: hostWithoutStableId,
    });

    const read = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: hostWithoutStableId,
    });
    expect(read?.source).toBe("fallback-file");
    expect(read?.value).toBe("no-stable-identity-value");
  });

  it("writes under the current label on a host with no stable identity, so the superseded label cannot open the file", async () => {
    const hostWithoutStableId: MachineIdentity = {
      stableHostId: null,
      hostname: FORMER_HOSTNAME,
    };
    await persistUserProvidedPassphrase("label-discrimination-value", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: hostWithoutStableId,
    });

    // The registry rows say the superseded label never encrypts. If a host with
    // no stable identity wrote under it, that claim would be false and this
    // read would succeed. An injected derivation carries the WHOLE authority,
    // so the built-in migration ladder is not run underneath it and this is a
    // clean single-key test of exactly one label.
    await expect(
      readStoredPassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec: noKeyring,
        deriveMachineKey: (h) => supersededHostnameKey(FORMER_HOSTNAME, h),
      }),
    ).rejects.toThrow(PassphraseUnreadableError);

    // The same host fact under the CURRENT label does open it: the hostname is
    // still the material on such a host, only the label moved.
    const read = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      deriveMachineKey: (h) => currentLabelKey(FORMER_HOSTNAME, h),
    });
    expect(read?.value).toBe("label-discrimination-value");
  });

  it("refuses a file written under a different stable host identity even when the hostname matches", async () => {
    await persistUserProvidedPassphrase("host-a-value", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
    });
    const planted = await readFile(fallback());

    // Same hostname, different machine. Every hostname migration candidate is
    // available to this read and none of them helps, because the material the
    // file was sealed under is the stable identity, not the name. This is the
    // machine binding the new derivation claims.
    await expect(
      readStoredPassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec: noKeyring,
        machineIdentityOverride: {
          stableHostId: OTHER_STABLE_HOST_ID,
          hostname: CURRENT_HOSTNAME,
        },
      }),
    ).rejects.toThrow(PassphraseUnreadableError);
    expect((await readFile(fallback())).equals(planted)).toBe(true);
  });

  it("round-trips a file written under a simulated keyring platform and read under the real one", async () => {
    // `platformOverride` selects which OS-keyring backend to exercise. It says
    // NOTHING about which machine this is, and the shipped callers do not agree
    // about it: the wrap CLI's persistence in these suites forces "linux" to
    // stay off a developer host's real keychain, while the dashboard reads the
    // same file with no override at all. If the machine-key derivation consults
    // the override, those two disagree and a fallback file becomes
    // undecryptable on a machine where nothing changed.
    await persistUserProvidedPassphrase("platform-override-value", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyringEitherBackend,
    });

    const read = await readStoredPassphrase({
      home,
      storagePath: home,
      exec: noKeyringEitherBackend,
    });
    expect(read?.source).toBe("fallback-file");
    expect(read?.value).toBe("platform-override-value");
  });

  it("returns the stored value and leaves the file untouched when the in-place repair cannot be written", async () => {
    const planted = await plantFileFromBeforeTheRename("repair-deferred-value");

    // Storage that reads what is on disk and refuses every write: the shape of
    // a read-only mount or a full disk. The read has already authenticated the
    // value, so a failed modernization must not become a custody denial.
    const readOnlyStorage = {
      read: async (): Promise<Uint8Array> =>
        new Uint8Array(await readFile(fallback())),
      write: async (): Promise<void> => {
        throw new Error("EROFS: read-only file system");
      },
      delete: async (): Promise<boolean> => false,
    };
    const warnings: string[] = [];
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: unknown): boolean => {
        warnings.push(String(chunk));
        return true;
      });
    try {
      const resolved = await getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec: noKeyring,
        machineIdentityOverride: RENAMED_HOST,
        fallbackCapability: readOnlyStorage,
      });
      expect(resolved.source).toBe("fallback-file");
      expect(resolved.value).toBe("repair-deferred-value");
    } finally {
      stderr.mockRestore();
    }

    // The old ciphertext is still exactly as it was, so the next writable read
    // can still open it through the ladder and repair it then.
    expect((await readFile(fallback())).equals(planted)).toBe(true);

    // The deferred repair is surfaced, and the surfaced line carries no secret.
    const surfaced = warnings.join("");
    expect(surfaced).toContain(fallback());
    expect(surfaced).not.toContain("repair-deferred-value");
  });

  it("opens a file written while the stable-identity probe was failing, and re-wraps it under the stable key", async () => {
    // The window this closes: one run's probe does not answer, so the file is
    // written under the CURRENT label with the hostname as the host fact. On
    // the next run the probe succeeds and the primary key is the
    // stable-identity one. Without a rung for the current label over the
    // hostname candidates, nothing would ever reach this file again.
    await persistUserProvidedPassphrase("probe-failed-on-the-write-run", {
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: {
        stableHostId: null,
        hostname: FORMER_HOSTNAME,
      },
    });
    const planted = await readFile(fallback());

    const resolved = await getOrCreatePassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
    });
    expect(resolved.source).toBe("fallback-file");
    expect(resolved.value).toBe("probe-failed-on-the-write-run");

    // Reported stale and repaired: the bytes moved, and the repaired file now
    // opens under the primary key alone (a second read leaves it identical).
    const migrated = await readFile(fallback());
    expect(migrated.equals(planted)).toBe(false);
    const second = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
    });
    expect(second?.value).toBe("probe-failed-on-the-write-run");
    expect((await readFile(fallback())).equals(migrated)).toBe(true);
  });

  it("reports the observed state when the repair writes its bytes and THEN fails", async () => {
    const planted = await plantFileFromBeforeTheRename("repair-landed-then-threw");

    // Storage that commits the new ciphertext and then rejects: the shipped
    // writer renames the new file into place BEFORE the directory fsync, so a
    // raised error is not evidence that the old bytes survived. Claiming the
    // file is unchanged here would be a claim, not an observation.
    const writeThenFailStorage = {
      read: async (): Promise<Uint8Array> =>
        new Uint8Array(await readFile(fallback())),
      write: async (data: Uint8Array): Promise<void> => {
        await writeFile(fallback(), data, { mode: 0o600 });
        throw new Error("EIO: the bytes landed and the fsync failed");
      },
      delete: async (): Promise<boolean> => false,
    };
    const warnings: string[] = [];
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: unknown): boolean => {
        warnings.push(String(chunk));
        return true;
      });
    try {
      const resolved = await getOrCreatePassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec: noKeyring,
        machineIdentityOverride: RENAMED_HOST,
        fallbackCapability: writeThenFailStorage,
      });
      expect(resolved.value).toBe("repair-landed-then-threw");
    } finally {
      stderr.mockRestore();
    }

    // The file really was rewritten, and the warning says so rather than
    // promising it was unchanged.
    expect((await readFile(fallback())).equals(planted)).toBe(false);
    const surfaced = warnings.join("");
    expect(surfaced).toContain(fallback());
    expect(surfaced).toContain("now opens under the current key");
    expect(surfaced).toContain("the rewrite landed");
    expect(surfaced).not.toContain("unchanged");
    expect(surfaced).not.toContain("repair-landed-then-threw");

    // And the rewritten file is readable afterwards, under the primary key
    // alone: the failed write did not cost custody.
    const after = await readStoredPassphrase({
      home,
      storagePath: home,
      platformOverride: "linux",
      exec: noKeyring,
      machineIdentityOverride: RENAMED_HOST,
      readOnly: true,
    });
    expect(after?.value).toBe("repair-landed-then-threw");
  });

  it("still refuses a file that belongs to a different host", async () => {
    const planted = await plantFileFromBeforeTheRename("value-from-another-machine");

    // The migration candidates are derived only from THIS host's own name, so a
    // file carried over from an unrelated machine gains nothing from them.
    await expect(
      readStoredPassphrase({
        home,
        storagePath: home,
        platformOverride: "linux",
        exec: noKeyring,
        machineIdentityOverride: {
          stableHostId: STABLE_HOST_ID,
          hostname: UNRELATED_HOSTNAME,
        },
      }),
    ).rejects.toThrow(PassphraseUnreadableError);
    expect((await readFile(fallback())).equals(planted)).toBe(true);
  });
});
