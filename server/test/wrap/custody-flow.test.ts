/**
 * Wrap custody-flow tests (sovereign-custody build, 2026-06-12).
 *
 * establishWrapCustody is the `sanctuary wrap` face of the unified scheme:
 * fresh fortresses get one master wrapped under passphrase + minted
 * recovery key; legacy fortresses migrate in place and THEN get the
 * recovery wrap the legacy scheme never had — the incident cure.
 *
 * Since 2026-09-04: ordinary noninteractive protect/wrap also stages recovery
 * outside the fortress (agentGuided || !interactive), so recovery bytes never
 * appear in a headless agent transcript. Tests use a parent temp dir so staged
 * files (dirname(fortress)/Sanctuary Recovery/…) are cleaned up recursively.
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
  // parent wraps both fortress and the staged-recovery sibling dir
  // (dirname(fortress)/Sanctuary Recovery/…) so rm(parent, recursive)
  // cleans all test artifacts without touching unrelated paths.
  let parent: string;
  let fortress: string;

  beforeEach(async () => {
    parent = await mkdtemp(join(tmpdir(), "sanctuary-wrap-custody-"));
    fortress = join(parent, "fortress");
  });

  afterEach(async () => {
    await rm(parent, { recursive: true, force: true });
  });

  it("fresh fortress (non-interactive): headless envelope, staged to external path, key verifies against committed envelope, audited", async () => {
    const output: string[] = [];
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);

    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
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
    expect(result.origin).toBe("first-run");
    expect(result.mintedRecoveryKey).toBe(true);
    expect(result.envelope!.install_mode).toBe("headless");

    // Staged to external path, NOT inside the fortress.
    const fileContent = await readFile(recoveryPath, "utf-8");
    const recoveryKey = extractRecoveryKey(fileContent);

    // Recovery bytes must not appear in any headless transcript output.
    expect(output.join("")).not.toContain(recoveryKey);

    // No recovery key file inside the fortress itself.
    await expect(
      readFile(join(fortress, RECOVERY_KEY_FILENAME), "utf-8"),
    ).rejects.toMatchObject({ code: "ENOENT" });

    // Key verifies against the committed envelope.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const unlocked = await establishMaster({ storage, recoveryKey });
    expect(toBase64url(unlocked.masterKey)).toBe(toBase64url(result.masterKey));

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
  });

  it("does not persist an orphaned recovery wrap when the staging path loses the race", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
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
  });

  it("resumes an authenticated staged recovery key after a crash before envelope commit", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
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
  });

  it("refuses a planted recovery file that lacks a valid staging receipt", async () => {
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
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
  });

  it("legacy passphrase fortress: migrates in place, stages recovery outside fortress, key unlocks the LEGACY master (incident cure)", async () => {
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

    // Staged outside the fortress, not at RECOVERY_KEY_FILENAME inside.
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    const fileContent = await readFile(recoveryPath, "utf-8");
    const recoveryKey = extractRecoveryKey(fileContent);

    // THE incident regression: the recovery key reconstructs the master that
    // actually encrypts this fortress's data.
    const unlocked = await establishMaster({ storage, recoveryKey });
    expect(toBase64url(unlocked.masterKey)).toBe(toBase64url(legacyMaster));
  });

  it("re-running wrap custody is idempotent: no re-mint, staged file unchanged", async () => {
    await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
    });
    const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
    const firstContent = await readFile(recoveryPath, "utf-8");

    const second = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "wrap-passphrase",
      interactive: false,
    });
    expect(second.origin).toBe("envelope");
    expect(second.mintedRecoveryKey).toBe(false);

    const secondContent = await readFile(recoveryPath, "utf-8");
    expect(secondContent).toBe(firstContent);

    const envelope = await readCustodyEnvelope(
      new FilesystemStorage(join(fortress, "state"))
    );
    expect(
      envelope!.wraps.filter((w) => w.type === "recovery-key")
    ).toHaveLength(1);
  });

  it("does not invoke explicit-passphrase persistence when custody authentication fails", async () => {
    await establishWrapCustody({
      storagePath: fortress,
      passphrase: "current-passphrase",
      interactive: false,
    });
    let persistCalls = 0;

    await expect(
      establishWrapCustody({
        storagePath: fortress,
        passphrase: "wrong-replacement",
        interactive: false,
        persistAuthenticatedPassphrase: async () => {
          persistCalls += 1;
          return { location: "test-keyring", source: "keychain" };
        },
      }),
    ).rejects.toThrow(/unlock|credential|passphrase/i);

    expect(persistCalls).toBe(0);
    const unlocked = await establishMaster({
      storage: new FilesystemStorage(join(fortress, "state")),
      passphrase: "current-passphrase",
    });
    expect(unlocked.envelope).not.toBeNull();
  });

  it("persists an explicit passphrase only after the committed envelope reads back", async () => {
    let observedCommittedEnvelope = false;
    const result = await establishWrapCustody({
      storagePath: fortress,
      passphrase: "authenticated-passphrase",
      interactive: false,
      persistAuthenticatedPassphrase: async () => {
        const storage = new FilesystemStorage(join(fortress, "state"));
        const envelope = await readCustodyEnvelope(storage);
        const unlocked = await establishMaster({
          storage,
          passphrase: "authenticated-passphrase",
        });
        observedCommittedEnvelope = envelope !== null && unlocked.envelope !== null;
        return { location: "test-keyring", source: "keychain" };
      },
    });

    expect(observedCommittedEnvelope).toBe(true);
    expect(result.persistedPassphrase).toEqual({
      location: "test-keyring",
      source: "keychain",
    });
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
