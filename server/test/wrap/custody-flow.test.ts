/**
 * Wrap custody-flow tests (sovereign-custody build, 2026-06-12).
 *
 * establishWrapCustody is the `sanctuary wrap` face of the unified scheme:
 * fresh fortresses get one master wrapped under passphrase + minted
 * recovery key; legacy fortresses migrate in place and THEN get the
 * recovery wrap the legacy scheme never had — the incident cure.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";

import {
  establishWrapCustody,
  establishSupervisedWrapCustody,
  SupervisedCustodyError,
} from "../../src/wrap/custody-flow.js";
import {
  establishMaster,
  readCustodyEnvelope,
  CustodyRotationInProgressError,
  ROTATION_JOURNAL_KEY,
} from "../../src/core/master-custody.js";
import {
  verifyRecoveryKeyReentry,
  RecoveryKeyReentryMismatchError,
  RECOVERY_KEY_FILENAME,
} from "../../src/wrap/recovery-key-disclosure.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  deriveMasterKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";

function extractRecoveryKey(fileContent: string): string {
  const line = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!line) throw new Error("no recovery key found in disclosure file");
  return line;
}

describe("establishWrapCustody", () => {
  let fortress: string;

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "sanctuary-wrap-custody-"));
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  it("fresh fortress (non-interactive): headless envelope, minted recovery key unlocks the master, audited", async () => {
    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
    });
    expect(result.origin).toBe("first-run");
    expect(result.mintedRecoveryKey).toBe(true);
    expect(result.envelope.install_mode).toBe("headless");

    // The disclosed recovery key is a wrap of the one true master.
    const fileContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );
    const recoveryKey = extractRecoveryKey(fileContent);
    const storage = new FilesystemStorage(join(fortress, "state"));
    const unlocked = await establishMaster({ storage, recoveryKey });
    expect(toBase64url(unlocked.masterKey)).toBe(
      toBase64url(result.masterKey)
    );

    // Audited as a distinct headless install, never a silent relaxation.
    const auditLog = new AuditLog(storage, result.masterKey);
    const { entries } = await auditLog.query({ layer: "l2", limit: 50 });
    const ops = entries.map((e) => e.operation);
    expect(ops).toContain("custody_envelope_created");
    expect(ops).toContain("custody_headless_install");
    expect(ops).toContain("custody_wrap_added");
  });

  it("legacy passphrase fortress: migrates in place and mints a recovery key that unlocks the LEGACY master (incident cure)", async () => {
    // Seed a legacy fortress: key-params + one identity under the Argon2id
    // master, exactly the drill fortress shape before the incident.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const { key: legacyMaster, params } = await deriveMasterKey("legacy-pass");
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
    const idKey = derivePurposeKey(legacyMaster, "identity-encryption");
    await storage.write(
      "_identities",
      "seed",
      stringToBytes(
        JSON.stringify(encrypt(stringToBytes('{"identity_id":"seed"}'), idKey))
      )
    );

    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "legacy-pass",
      interactive: false,
    });
    expect(result.origin).toBe("migrated-passphrase");
    expect(toBase64url(result.masterKey)).toBe(toBase64url(legacyMaster));
    expect(result.mintedRecoveryKey).toBe(true);

    // THE incident regression: the printed recovery key reconstructs the
    // master that actually encrypts this fortress's data.
    const fileContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );
    const recoveryKey = extractRecoveryKey(fileContent);
    const unlocked = await establishMaster({ storage, recoveryKey });
    expect(toBase64url(unlocked.masterKey)).toBe(toBase64url(legacyMaster));
  });

  it("re-running wrap custody is idempotent: no re-mint, recovery-key.txt unchanged", async () => {
    await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
    });
    const firstContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );

    const second = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
    });
    expect(second.origin).toBe("envelope");
    expect(second.mintedRecoveryKey).toBe(false);

    const secondContent = await readFile(
      join(fortress, RECOVERY_KEY_FILENAME),
      "utf-8"
    );
    expect(secondContent).toBe(firstContent);

    const envelope = await readCustodyEnvelope(
      new FilesystemStorage(join(fortress, "state"))
    );
    expect(
      envelope!.wraps.filter((w) => w.type === "recovery-key")
    ).toHaveLength(1);
  });

  it("a wrong passphrase against an envelope fortress fails closed (no parallel master)", async () => {
    await establishWrapCustody({
      storagePath: fortress,
      passphrase: "right-pass",
      interactive: false,
    });
    await expect(
      establishWrapCustody({
        storagePath: fortress,
        passphrase: "wrong-pass",
        interactive: false,
      })
    ).rejects.toThrow(/does not unlock/);
  });
});

describe("establishSupervisedWrapCustody (Phase S1 live mile)", () => {
  let fortress: string;

  beforeEach(async () => {
    fortress = await mkdtemp(join(tmpdir(), "sanctuary-superd-custody-"));
  });

  afterEach(async () => {
    await rm(fortress, { recursive: true, force: true });
  });

  /** Establish an envelope fortress the way the dashboard would have, returning the master. */
  async function seedEnvelopeFortress(): Promise<Uint8Array> {
    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "operator-passphrase",
      interactive: false,
    });
    // Return a COPY: establishSupervisedWrapCustody adopts the buffer it is
    // handed as the fortress master, mirroring the over-fd handoff.
    return Uint8Array.from(result.masterKey);
  }

  it("adopts the supervisor's master when it verifies against the on-disk envelope (origin=envelope)", async () => {
    const master = await seedEnvelopeFortress();
    const result = await establishSupervisedWrapCustody({
      storagePath: fortress,
      master,
    });
    expect(result.origin).toBe("envelope");
    expect(result.mintedRecoveryKey).toBe(false);
    // The returned masterKey IS the supplied buffer (threaded forward so
    // runWrap zeroes exactly one buffer on teardown).
    expect(result.masterKey).toBe(master);
    // No new credential / recovery key disclosed.
    expect(result.envelope).not.toBeNull();

    // The supervised unlock is audited (visible in the same log the dashboard reads).
    const storage = new FilesystemStorage(join(fortress, "state"));
    const auditLog = new AuditLog(storage, master);
    const { entries } = await auditLog.query({ layer: "l2", limit: 50 });
    expect(entries.map((e) => e.operation)).toContain(
      "custody_supervised_unlock"
    );
  });

  it("FAILS CLOSED when the supervisor master does not unlock this fortress (wrong key)", async () => {
    await seedEnvelopeFortress();
    // A random 32-byte key that is NOT this fortress's master.
    const wrongMaster = new Uint8Array(32).fill(7);
    await expect(
      establishSupervisedWrapCustody({ storagePath: fortress, master: wrongMaster })
    ).rejects.toBeInstanceOf(SupervisedCustodyError);
    await expect(
      establishSupervisedWrapCustody({ storagePath: fortress, master: new Uint8Array(32).fill(7) })
    ).rejects.toThrow(/does not unlock this fortress/);
  });

  it("FAILS CLOSED when there is no custody envelope (fresh/legacy fortress)", async () => {
    // No envelope established — a supervised launch must refuse rather than
    // mint custody over (possibly existing) data from an ambient master.
    const master = new Uint8Array(32).fill(3);
    await expect(
      establishSupervisedWrapCustody({ storagePath: fortress, master })
    ).rejects.toBeInstanceOf(SupervisedCustodyError);
    await expect(
      establishSupervisedWrapCustody({ storagePath: fortress, master: new Uint8Array(32).fill(3) })
    ).rejects.toThrow(/requires an established custody envelope/);
  });

  it("FAILS CLOSED when a master rotation is in flight (refuses to launch under a split master)", async () => {
    const master = await seedEnvelopeFortress();
    // Journal a rotation: while present, the master may be split old/new.
    const storage = new FilesystemStorage(join(fortress, "state"));
    await storage.write("_meta", ROTATION_JOURNAL_KEY, stringToBytes("{}"));
    await expect(
      establishSupervisedWrapCustody({ storagePath: fortress, master })
    ).rejects.toBeInstanceOf(CustodyRotationInProgressError);
  });
});

describe("verifyRecoveryKeyReentry", () => {
  function io(lines: string[]): { input: Readable; output: Writable } {
    return {
      input: Readable.from(lines.map((l) => l + "\n")),
      output: new Writable({
        write(_chunk, _enc, cb) {
          cb();
        },
      }),
    };
  }

  it("accepts a matching re-entry", async () => {
    await expect(
      verifyRecoveryKeyReentry({
        check: async (entered) => entered === "the-right-key",
        io: io(["the-right-key"]),
      })
    ).resolves.toBeUndefined();
  });

  it("throws after the attempts run out", async () => {
    await expect(
      verifyRecoveryKeyReentry({
        check: async () => false,
        io: io(["wrong-1", "wrong-2", "wrong-3"]),
      })
    ).rejects.toThrow(RecoveryKeyReentryMismatchError);
  });
});
