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

import { establishWrapCustody } from "../../src/wrap/custody-flow.js";
import {
  establishMaster,
  readCustodyEnvelope,
  CUSTODY_ENVELOPE_KEY,
} from "../../src/core/master-custody.js";
import { generateRandomKey } from "../../src/core/random.js";
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
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../../src/core/encoding.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

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

  it("pre-mac legacy envelope: in-place re-stamp emits a custody_legacy_migrated audit entry (no silent custody transition)", async () => {
    // Seed a pre-mac v:1 envelope (no top-level mac, wrap has no id) whose
    // single passphrase wrap was bound with the id-less legacy AEAD AAD, plus
    // a matching identity so the migration evidence check CONFIRMS.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const master = generateRandomKey();
    const { key: wrapKey, params } = await deriveMasterKey("pre-mac-pass");
    const legacyAad = stringToBytes("sanctuary-custody-v1:passphrase");
    const payload = encrypt(master, wrapKey, legacyAad);
    wrapKey.fill(0);
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(
        JSON.stringify({
          v: 1,
          install_mode: "legacy-migrated",
          wraps: [
            {
              type: "passphrase",
              payload,
              kdf: params,
              verified: true,
              created_at: new Date().toISOString(),
            },
          ],
          created_at: new Date().toISOString(),
          // NO mac, NO wrap.id (the pre-mac shape).
        })
      )
    );
    const idKey = derivePurposeKey(master, "identity-encryption");
    await storage.write(
      "_identities",
      "seed",
      stringToBytes(
        JSON.stringify(encrypt(stringToBytes('{"identity_id":"seed"}'), idKey))
      )
    );

    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "pre-mac-pass",
      interactive: false,
    });
    // The re-stamp keeps origin "envelope"; the migration signal is the flag.
    expect(result.origin).toBe("envelope");
    expect(toBase64url(result.masterKey)).toBe(toBase64url(master));

    // The custody state transition (full re-wrap + fresh MAC + new sentinel)
    // MUST be audited; before the fix this path emitted nothing.
    const auditLog = new AuditLog(storage, result.masterKey);
    const { entries } = await auditLog.query({ layer: "l2", limit: 50 });
    expect(entries.map((e) => e.operation)).toContain("custody_legacy_migrated");
  });

  it("recovery-unlock-enroll over a pre-mac recovery-only envelope: the in-place re-stamp is audited as custody_legacy_migrated, not masked as a plain wrap-add", async () => {
    // Seed a pre-mac v:1 envelope whose ONLY wrap is recovery-key (no
    // passphrase wrap, no top-level mac, no wrap.id) bound with the id-less
    // legacy recovery AAD, plus a matching identity so migration evidence
    // CONFIRMS. Running `wrap` with a passphrase fails to unlock (no passphrase
    // wrap) and falls into the recovery-unlock-enroll path; establishMaster
    // there re-stamps the pre-mac envelope in place (migratedInPlace === true)
    // AND the passphrase is enrolled. The transition must be labeled as the
    // security-relevant legacy migration, not the co-occurring wrap-add.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const master = generateRandomKey();
    const recoveryKeyStr = toBase64url(generateRandomKey());
    const recoveryKeyBytes = fromBase64url(recoveryKeyStr);
    const recoveryWrapKey = hkdf(
      sha256,
      recoveryKeyBytes,
      stringToBytes("sanctuary-custody-v1"),
      stringToBytes("recovery-key-wrap"),
      32
    );
    const legacyAad = stringToBytes("sanctuary-custody-v1:recovery-key");
    const payload = encrypt(master, recoveryWrapKey, legacyAad);
    recoveryWrapKey.fill(0);
    await storage.write(
      "_meta",
      CUSTODY_ENVELOPE_KEY,
      stringToBytes(
        JSON.stringify({
          v: 1,
          install_mode: "legacy-migrated",
          wraps: [
            {
              type: "recovery-key",
              payload,
              verified: true,
              created_at: new Date().toISOString(),
            },
          ],
          created_at: new Date().toISOString(),
          // NO mac, NO wrap.id (the pre-mac shape).
        })
      )
    );
    const idKey = derivePurposeKey(master, "identity-encryption");
    await storage.write(
      "_identities",
      "seed",
      stringToBytes(
        JSON.stringify(encrypt(stringToBytes('{"identity_id":"seed"}'), idKey))
      )
    );

    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "new-pass",
      interactive: true,
      io: {
        input: Readable.from([recoveryKeyStr + "\n"]),
        output: new Writable({
          write(_chunk, _enc, cb) {
            cb();
          },
        }),
      },
    });
    expect(result.origin).toBe("recovery-unlock-enroll");
    expect(toBase64url(result.masterKey)).toBe(toBase64url(master));

    const auditLog = new AuditLog(storage, result.masterKey);
    const { entries } = await auditLog.query({ layer: "l2", limit: 50 });
    const ops = entries.map((e) => e.operation);
    // The re-stamp must surface as a legacy migration, never be masked.
    expect(ops).toContain("custody_legacy_migrated");
    expect(ops).not.toContain("custody_wrap_added");
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
