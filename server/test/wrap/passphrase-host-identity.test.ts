/**
 * The machine-local passphrase fallback file across a change in the host's
 * resolved hostname.
 *
 * Capability under test: a fortress whose only stored credential is the
 * encrypted fallback file keeps opening hands-free after the host answers to a
 * different spelling of its own name, and the file is re-wrapped under the
 * stable host identity on the first writable read. A caller that declared
 * itself read-only reads the same value and leaves the bytes untouched. A file
 * that belongs to a different host is still refused.
 *
 * Register id: defect.fallback-passphrase-key-derived-from-volatile-hostname
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
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

  it("keeps the hostname derivation on a host that exposes no stable identity", async () => {
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
