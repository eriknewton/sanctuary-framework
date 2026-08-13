/**
 * Wrap custody-flow tests (sovereign-custody build, 2026-06-12).
 *
 * establishWrapCustody is the `sanctuary wrap` face of the unified scheme:
 * fresh fortresses get one master wrapped under passphrase + minted
 * recovery key; legacy fortresses migrate in place and THEN get the
 * recovery wrap the legacy scheme never had — the incident cure.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable, Writable } from "node:stream";

import { agentGuidedRecoveryOutputPath, establishWrapCustody } from "../../src/wrap/custody-flow.js";
import {
  establishMaster,
  readCustodyEnvelope,
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

  it("agent-guided first run stages recovery outside the fortress without transcript disclosure", async () => {
    const output: string[] = [];
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    try {
      const result = await establishWrapCustody({
        storagePath: fortress,
        passphrase: "agent-guided-passphrase",
        interactive: false,
        agentGuided: true,
        io: {
          input: Readable.from([]),
          output: new Writable({
            write(chunk, _encoding, callback) {
              output.push(String(chunk));
              callback();
            },
          }),
        },
      });

      const fileContent = await readFile(recoveryPath, "utf8");
      const recoveryKey = extractRecoveryKey(fileContent);
      expect(output.join("")).toContain(recoveryPath);
      expect(output.join("")).not.toContain(recoveryKey);
      await expect(readFile(join(fortress, RECOVERY_KEY_FILENAME), "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });

      const storage = new FilesystemStorage(join(fortress, "state"));
      const unlocked = await establishMaster({ storage, recoveryKey });
      expect(toBase64url(unlocked.masterKey)).toBe(toBase64url(result.masterKey));
    } finally {
      await rm(recoveryPath, { force: true });
    }
  });

  it("does not persist an orphaned recovery wrap when the staging path loses the race", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    try {
      await expect(
        establishWrapCustody({
          storagePath: fortress,
          passphrase: "agent-guided-race-passphrase",
          interactive: false,
          agentGuided: true,
          beforeAgentRecoveryFileCreate: async () => {
            await writeFile(recoveryPath, "planted after preflight", { mode: 0o600 });
          },
        }),
      ).rejects.toThrow(/existing .*recovery-out file/i);

      const envelope = await readCustodyEnvelope(
        new FilesystemStorage(join(fortress, "state")),
      );
      expect(envelope?.wraps.some((wrap) => wrap.type === "recovery-key")).toBe(false);
      expect(await readFile(recoveryPath, "utf8")).toBe("planted after preflight");
    } finally {
      await rm(recoveryPath, { force: true });
    }
  });

  it("resumes an authenticated staged recovery key after a crash before envelope commit", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    try {
      await expect(
        establishWrapCustody({
          storagePath: fortress,
          passphrase: "agent-guided-resume-passphrase",
          interactive: false,
          agentGuided: true,
          afterAgentRecoveryFileCreate: () => {
            throw new Error("simulated crash after recovery staging");
          },
        }),
      ).rejects.toThrow("simulated crash after recovery staging");

      const stagedBeforeRetry = await readFile(recoveryPath, "utf8");
      const recoveryKey = extractRecoveryKey(stagedBeforeRetry);
      expect(stagedBeforeRetry).toContain("Recovery staging receipt:");
      const envelopeBeforeRetry = await readCustodyEnvelope(
        new FilesystemStorage(join(fortress, "state")),
      );
      expect(envelopeBeforeRetry?.wraps.some((wrap) => wrap.type === "recovery-key")).toBe(false);

      const resumed = await establishWrapCustody({
        storagePath: fortress,
        passphrase: "agent-guided-resume-passphrase",
        interactive: false,
        agentGuided: true,
      });

      expect(resumed.mintedRecoveryKey).toBe(true);
      expect(await readFile(recoveryPath, "utf8")).toBe(stagedBeforeRetry);
      const unlocked = await establishMaster({
        storage: new FilesystemStorage(join(fortress, "state")),
        recoveryKey,
      });
      expect(toBase64url(unlocked.masterKey)).toBe(toBase64url(resumed.masterKey));
    } finally {
      await rm(recoveryPath, { force: true });
    }
  });

  it("refuses a planted recovery file that lacks a valid staging receipt", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    try {
      await mkdir(dirname(recoveryPath), { recursive: true, mode: 0o700 });
      await writeFile(
        recoveryPath,
        "Recovery key:\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nRecovery staging receipt:\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n",
        { mode: 0o600 },
      );
      await expect(
        establishWrapCustody({
          storagePath: fortress,
          passphrase: "agent-guided-planted-passphrase",
          interactive: false,
          agentGuided: true,
        }),
      ).rejects.toThrow(/not an authenticated interrupted handoff/i);
      const envelope = await readCustodyEnvelope(
        new FilesystemStorage(join(fortress, "state")),
      );
      expect(envelope?.wraps.some((wrap) => wrap.type === "recovery-key")).toBe(false);
    } finally {
      await rm(recoveryPath, { force: true });
    }
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
