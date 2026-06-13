/**
 * Master-rotation tests (F7, custody/crypto lane).
 *
 * The property under test: rotation mints a fresh master, re-encrypts
 * EVERYTHING under it (state envelopes re-signed, identities, purpose
 * stores, MAC'd records, castle pin), re-wraps custody (passphrase +
 * verified NEW recovery key), retires the old master — and a crash at ANY
 * point either leaves a fully old-keyed fortress (pre-journal) or a
 * journaled fortress that refuses to boot and resumes FORWARD to a fully
 * new-keyed one. No window exists where data sits under one master and
 * wraps only under the other.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import {
  establishMaster,
  readCustodyEnvelope,
  countVerifiedWraps,
  envelopeEpochOf,
  readEnvelopeEpoch,
  CustodyUnlockError,
  CustodyRotationInProgressError,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
  STAGED_CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import {
  readEpochWitness,
  observeWitnessEpoch,
  evaluateRollback,
  EPOCH_WITNESS_META_KEY,
} from "../../src/core/anti-rollback.js";
import {
  readCustodyEpochCount,
  probeAuditHeadAnchor,
  deriveAuditEpochKeys,
  AUDIT_EPOCH_KEYS_KEY,
} from "../../src/l2-operational/audit-log.js";
import {
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import {
  rotateMaster,
  resumeRotation,
  RotationPreflightError,
  RotationResumeError,
  type RotateMasterOptions,
} from "../../src/core/master-rotation.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import {
  deriveNamespaceKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import {
  toBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";
import type { StoredIdentity } from "../../src/core/identity.js";

const PASSPHRASE = "rotation-test-passphrase";
const KID = "agent-rotate-1";
const FORTRESS_ID = "fortress-rotation-test";

interface Fortress {
  storage: MemoryStorage;
  master: Uint8Array;
  identity: StoredIdentity;
  oldRecoveryKey: string;
}

async function buildFortress(): Promise<Fortress> {
  const storage = new MemoryStorage();
  const est = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "interactive", mintRecoveryKey: true },
  });
  const master = est.masterKey;

  // A resident identity (outer record AND inner private key under the
  // identity-encryption purpose key — both must rotate).
  const seed = generateRandomKey();
  const publicKey = ed25519.getPublicKey(seed);
  const idKey = derivePurposeKey(master, "identity-encryption");
  const identity: StoredIdentity = {
    identity_id: KID,
    label: "rotation test agent",
    public_key: toBase64url(publicKey),
    did: "did:key:test",
    created_at: new Date().toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encrypt(seed, idKey),
    rotation_history: [],
  };
  await storage.write(
    "_identities",
    KID,
    stringToBytes(
      JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), idKey))
    )
  );

  // Signed state entries in two user namespaces (ciphertext-bound writer
  // signatures: the rotation must re-sign).
  const stateStore = new StateStore(storage, master);
  await stateStore.write(
    "notes",
    "k1",
    "hello sovereign world",
    KID,
    identity.encrypted_private_key,
    idKey
  );
  await stateStore.write(
    "notes",
    "k2",
    "second entry",
    KID,
    identity.encrypted_private_key,
    idKey
  );
  await stateStore.write(
    "plans",
    "p1",
    JSON.stringify({ goal: "rotate safely" }),
    KID,
    identity.encrypted_private_key,
    idKey
  );

  // Audit chain (entries stay byte-identical across rotation; epoch-scoped
  // decryption must keep them readable).
  const audit = new AuditLog(storage, master);
  for (let i = 0; i < 3; i++) {
    await audit.appendCritical({
      layer: "l1",
      operation: `fixture_op_${i}`,
      identity_id: KID,
      result: "success",
    });
  }
  await audit.flush();

  // A purpose-keyed store without AAD (reputation)…
  await storage.write(
    "_reputation",
    "att-1",
    stringToBytes(
      JSON.stringify(
        encrypt(
          stringToBytes(JSON.stringify({ attestation: "fixture" })),
          derivePurposeKey(master, "l4-reputation")
        )
      )
    )
  );
  // …and one WITH a per-record AAD (sentinel findings: aad = finding id).
  await storage.write(
    "_sentinel_findings",
    "finding-1",
    stringToBytes(
      JSON.stringify(
        encrypt(
          stringToBytes(JSON.stringify({ severity: "low" })),
          derivePurposeKey(master, "l2-sentinel-finding-v1"),
          stringToBytes("finding-1")
        )
      )
    )
  );

  return {
    storage,
    master,
    identity,
    oldRecoveryKey: est.mintedRecoveryKey!,
  };
}

function rotateOpts(
  fortress: Fortress,
  overrides?: Partial<RotateMasterOptions>
): RotateMasterOptions {
  return {
    storage: fortress.storage,
    fortressId: FORTRESS_ID,
    passphrase: PASSPHRASE,
    approve: async () => true,
    // Capture rules: the disclosed key is re-entered and proven by
    // unwrapping the staged master with it.
    captureRecoveryKey: async (recoveryKey, verify) => verify(recoveryKey),
    ...overrides,
  };
}

/** Full post-rotation verification battery. */
async function verifyRotated(
  fortress: Fortress,
  opts?: { newRecoveryKey?: string }
): Promise<void> {
  const { storage } = fortress;

  // Custody: passphrase unlocks a DIFFERENT master; journal + staged gone.
  expect(await storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
  expect(await storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)).toBeNull();
  expect(await storage.read("_meta", STAGED_CUSTODY_SENTINEL_KEY)).toBeNull();
  expect(await storage.read("_meta", "key-params")).toBeNull();
  expect(await storage.read("_meta", "recovery-key-hash")).toBeNull();

  const est = await establishMaster({ storage, passphrase: PASSPHRASE });
  const newMaster = est.masterKey;
  expect(toBase64url(newMaster)).not.toBe(toBase64url(fortress.master));

  // Two-factor floor preserved (passphrase + re-entry-verified recovery key).
  expect(countVerifiedWraps(est.envelope!)).toBeGreaterThanOrEqual(2);
  expect(est.envelope!.install_mode).toBe("interactive");

  // The OLD recovery key is retired.
  await expect(
    establishMaster({ storage, recoveryKey: fortress.oldRecoveryKey })
  ).rejects.toThrow(CustodyUnlockError);
  // The NEW recovery key unlocks the SAME new master.
  if (opts?.newRecoveryKey) {
    const viaRecovery = await establishMaster({
      storage,
      recoveryKey: opts.newRecoveryKey,
    });
    expect(toBase64url(viaRecovery.masterKey)).toBe(toBase64url(newMaster));
  }

  // State: decrypts, verifies signatures, survives with intact plaintext.
  const stateStore = new StateStore(storage, newMaster);
  const read1 = await stateStore.read("notes", "k1");
  expect(read1?.value).toBe("hello sovereign world");
  expect(read1?.signature_verified).toBe(true);
  const read3 = await stateStore.read("plans", "p1");
  expect(JSON.parse(read3!.value).goal).toBe("rotate safely");

  // Nothing decrypts under the OLD master anymore (user state).
  const oldNsKey = deriveNamespaceKey(fortress.master, "notes");
  const rawEntry = await storage.read("notes", "k1");
  const entry = JSON.parse(bytesToString(rawEntry!)) as {
    payload: EncryptedPayload;
  };
  expect(() => decrypt(entry.payload, oldNsKey)).toThrow();

  // Audit: the FULL chain (pre- and post-rotation entries) loads cleanly in
  // strict mode under the new master — verifiable ACROSS the boundary.
  const audit = new AuditLog(storage, newMaster);
  const result = await audit.query({ limit: 100 });
  expect(result.integrity_findings).toEqual([]);
  const operations = result.entries.map((e) => e.operation);
  expect(operations).toContain("fixture_op_0");
  expect(operations).toContain("fixture_op_2");
  expect(operations).toContain("custody_rotation_started");
  expect(operations).toContain("custody_master_rotated");
  // The rotation audit entry records envelope/wrap ids, never key material.
  const rotated = result.entries.find(
    (e) => e.operation === "custody_master_rotated"
  )!;
  expect(rotated.details?.rotation_id).toBeTruthy();
  expect(Array.isArray(rotated.details?.old_wrap_ids)).toBe(true);
  expect(JSON.stringify(rotated.details)).not.toContain(
    toBase64url(fortress.master)
  );
  expect(JSON.stringify(rotated.details)).not.toContain(toBase64url(newMaster));

  // Purpose stores re-keyed (with and without AAD).
  const rep = JSON.parse(
    bytesToString((await storage.read("_reputation", "att-1"))!)
  ) as EncryptedPayload;
  expect(() =>
    decrypt(rep, derivePurposeKey(fortress.master, "l4-reputation"))
  ).toThrow();
  const repPlain = decrypt(rep, derivePurposeKey(newMaster, "l4-reputation"));
  expect(JSON.parse(bytesToString(repPlain)).attestation).toBe("fixture");

  const finding = JSON.parse(
    bytesToString((await storage.read("_sentinel_findings", "finding-1"))!)
  ) as EncryptedPayload;
  const findingPlain = decrypt(
    finding,
    derivePurposeKey(newMaster, "l2-sentinel-finding-v1"),
    stringToBytes("finding-1")
  );
  expect(JSON.parse(bytesToString(findingPlain)).severity).toBe("low");

  // Identities: outer + inner re-keyed; private key seed unchanged.
  const idKeyNew = derivePurposeKey(newMaster, "identity-encryption");
  const idRaw = JSON.parse(
    bytesToString((await storage.read("_identities", KID))!)
  ) as EncryptedPayload;
  const identity = JSON.parse(
    bytesToString(decrypt(idRaw, idKeyNew))
  ) as StoredIdentity;
  const seed = decrypt(identity.encrypted_private_key, idKeyNew);
  expect(toBase64url(ed25519.getPublicKey(seed))).toBe(identity.public_key);
}

describe("master rotation — happy path", () => {
  it("rotates the master end to end: new wraps, re-encrypted data, retired old master, audit chain verifiable across the boundary", async () => {
    const fortress = await buildFortress();
    let disclosedKey = "";
    const result = await rotateMaster(
      rotateOpts(fortress, {
        captureRecoveryKey: async (rk, verify) => {
          disclosedKey = rk;
          return verify(rk);
        },
      })
    );
    expect(result.converted_entries).toBeGreaterThan(0);
    expect(result.old_wrap_ids.length).toBeGreaterThan(0);
    await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
  });

  it("re-encrypts the castle pin file in place", async () => {
    const fortress = await buildFortress();
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-rotate-pin-"));
    try {
      const seed = generateRandomKey();
      await writeFile(
        join(dir, "castle-pinned-privkey.enc"),
        JSON.stringify(encrypt(seed, fortress.master))
      );
      await rotateMaster(rotateOpts(fortress, { fortressPath: dir }));
      const est = await establishMaster({
        storage: fortress.storage,
        passphrase: PASSPHRASE,
      });
      const pin = JSON.parse(
        await readFile(join(dir, "castle-pinned-privkey.enc"), "utf-8")
      ) as EncryptedPayload;
      expect(() => decrypt(pin, fortress.master)).toThrow();
      expect(toBase64url(decrypt(pin, est.masterKey))).toBe(toBase64url(seed));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("a second rotation keeps BOTH prior audit epochs readable", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    // Append an entry in epoch 1, then rotate again.
    const est1 = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const audit1 = new AuditLog(fortress.storage, est1.masterKey);
    await audit1.appendCritical({
      layer: "l1",
      operation: "epoch1_op",
      identity_id: KID,
      result: "success",
    });
    await audit1.flush();

    await rotateMaster(rotateOpts(fortress));
    const est2 = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const audit2 = new AuditLog(fortress.storage, est2.masterKey);
    const result = await audit2.query({ limit: 100 });
    expect(result.integrity_findings).toEqual([]);
    const ops = result.entries.map((e) => e.operation);
    expect(ops).toContain("fixture_op_0"); // epoch 0
    expect(ops).toContain("epoch1_op"); // epoch 1
    expect(ops.filter((o) => o === "custody_master_rotated")).toHaveLength(2);
  });
});

describe("master rotation — Tier-1 gate and capture rules", () => {
  it("refuses without operator approval, mutating nothing", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(rotateOpts(fortress, { approve: async () => false }))
    ).rejects.toThrow(RotationPreflightError);
    // Fortress untouched: old credentials still unlock; no rotation artifacts.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
  });

  it("refuses when recovery-key capture is not completed, removing the staged envelope", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, { captureRecoveryKey: async () => false })
      )
    ).rejects.toThrow(RotationPreflightError);
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
    expect(await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY)).toBeNull();
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("re-entry verification is real: a wrong key does not verify the wrap", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          captureRecoveryKey: async (_rk, verify) => {
            // Operator "saved" the wrong string; the unwrap proof fails and
            // capture reports failure → rotation refuses.
            return verify(toBase64url(generateRandomKey()));
          },
        })
      )
    ).rejects.toThrow(RotationPreflightError);
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("refuses with the wrong passphrase before touching anything", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(rotateOpts(fortress, { passphrase: "wrong-passphrase" }))
    ).rejects.toThrow(CustodyUnlockError);
  });
});

describe("master rotation — fail-closed coverage", () => {
  it("aborts (nothing mutated) when an unsupported namespace holds data", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_privacy_placeholder_vault",
      "scope__record__x",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts on an unknown _meta key", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_meta",
      "mystery-record",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });

  it("rotates compound-AAD records (anomaly classifier: key state.<a>.<b>, AAD a|b — codex r2)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_anomaly_classifier_state",
      "state.chi8.agent-rotate-1",
      stringToBytes(
        JSON.stringify(
          encrypt(
            stringToBytes(JSON.stringify({ weights: [1, 2, 3] })),
            derivePurposeKey(fortress.master, "l2-anomaly-classifier-state-v1"),
            stringToBytes("chi8|agent-rotate-1")
          )
        )
      )
    );
    await rotateMaster(rotateOpts(fortress));
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const raw = JSON.parse(
      bytesToString(
        (await fortress.storage.read(
          "_anomaly_classifier_state",
          "state.chi8.agent-rotate-1"
        ))!
      )
    ) as EncryptedPayload;
    const plain = decrypt(
      raw,
      derivePurposeKey(est.masterKey, "l2-anomaly-classifier-state-v1"),
      stringToBytes("chi8|agent-rotate-1")
    );
    expect(JSON.parse(bytesToString(plain)).weights).toEqual([1, 2, 3]);
  });

  it("aborts BY NAME on unified-inbox operator-prefs records (hash-keyed AAD — codex r2)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_unified_inbox",
      "operator-prefs.v1.abcdef0123456789",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      /operator-prefs/
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts on an unknown _audit_checkpoints key (codex r1 HIGH: no silent skip in an internal namespace)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.write(
      "_audit_checkpoints",
      "mystery-anchor",
      stringToBytes("{}")
    );
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
  });

  it("aborts BEFORE staging when the audit chain is tampered (codex r1 MEDIUM: no disclosure over a broken chain)", async () => {
    const fortress = await buildFortress();
    // Tamper one persisted audit entry's bytes.
    const entries = await fortress.storage.list("_audit");
    const target = entries[0]!;
    const raw = await fortress.storage.read("_audit", target.key);
    const record = JSON.parse(bytesToString(raw!)) as { entry_hash: string };
    record.entry_hash = record.entry_hash.replace(/^./, (c) =>
      c === "a" ? "b" : "a"
    );
    await fortress.storage.write(
      "_audit",
      target.key,
      stringToBytes(JSON.stringify(record))
    );

    let captureCalled = false;
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          captureRecoveryKey: async (rk, verify) => {
            captureCalled = true;
            return verify(rk);
          },
        })
      )
    ).rejects.toThrow(RotationPreflightError);
    // The recovery key was never disclosed and nothing was staged.
    expect(captureCalled).toBe(false);
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).toBeNull();
  });

  it("aborts when a state entry's writer identity is not resident (no laundering, no orphaning)", async () => {
    const fortress = await buildFortress();
    await fortress.storage.delete("_identities", KID);
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });
});

describe("master rotation — crash safety (journaled two-phase, forward resume)", () => {
  const POST_JOURNAL_FAILPOINTS = [
    "journal-converting-written",
    `converted:_identities/${KID}`,
    "converted:notes/k1",
    "audit-epoch-written",
    "journal-finalizing-written",
    "envelope-promoted",
    "rotation-audited",
  ];

  for (const point of POST_JOURNAL_FAILPOINTS) {
    it(`crash at "${point}": boot refuses, resume completes, fortress fully rotated`, async () => {
      const fortress = await buildFortress();
      let disclosedKey = "";
      await expect(
        rotateMaster(
          rotateOpts(fortress, {
            captureRecoveryKey: async (rk, verify) => {
              disclosedKey = rk;
              return verify(rk);
            },
            failpoint: (p) => {
              if (p === point) throw new Error(`simulated crash at ${p}`);
            },
          })
        )
      ).rejects.toThrow(/simulated crash/);

      // The lockout-killer property: with the journal present, NO normal
      // establishment path may serve a half-keyed fortress.
      await expect(
        establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
      ).rejects.toThrow(CustodyRotationInProgressError);

      // Forward resume with just the passphrase.
      const result = await resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      });
      expect(result.rotation_id).toBeTruthy();
      await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
    });
  }

  it("crash BEFORE the journal (staged envelope written): fortress boots under the old master; a fresh rotation cleans the orphan and succeeds", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "staged-envelope-written") {
              throw new Error("simulated crash at staging");
            }
          },
        })
      )
    ).rejects.toThrow(/simulated crash/);

    // No journal → normal boot works and yields the OLD master; the staged
    // orphan is present but inert.
    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(est.masterKey)).toBe(toBase64url(fortress.master));
    expect(
      await fortress.storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY)
    ).not.toBeNull();

    // A fresh rotation cleans the orphan and completes.
    let disclosedKey = "";
    await rotateMaster(
      rotateOpts(fortress, {
        captureRecoveryKey: async (rk, verify) => {
          disclosedKey = rk;
          return verify(rk);
        },
      })
    );
    await verifyRotated(fortress, { newRecoveryKey: disclosedKey });
  });

  it("resume is idempotent: a crash DURING resume resumes again cleanly", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash 1");
          },
        })
      )
    ).rejects.toThrow(/crash 1/);

    // First resume crashes later, mid-finalize.
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
        failpoint: (p) => {
          if (p === "envelope-promoted") throw new Error("crash 2");
        },
      })
    ).rejects.toThrow(/crash 2/);

    await expect(
      establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
    ).rejects.toThrow(CustodyRotationInProgressError);

    await resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
    });
    await verifyRotated(fortress);
  });

  it("resume fails closed on a wrong passphrase", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: "not-the-passphrase",
      })
    ).rejects.toThrow(CustodyUnlockError);
    // Still journaled; still refuses to boot; still resumable with the truth.
    await expect(
      establishMaster({ storage: fortress.storage, passphrase: PASSPHRASE })
    ).rejects.toThrow(CustodyRotationInProgressError);
    await resumeRotation({
      storage: fortress.storage,
      fortressId: FORTRESS_ID,
      passphrase: PASSPHRASE,
    });
    await verifyRotated(fortress);
  });

  it("resume fails closed on a tampered journal", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);

    const raw = await fortress.storage.read("_meta", ROTATION_JOURNAL_KEY);
    const journal = JSON.parse(bytesToString(raw!)) as {
      data: { phase: string };
      mac: string;
    };
    journal.data.phase = "finalizing"; // attacker tries to skip conversion
    await fortress.storage.write(
      "_meta",
      ROTATION_JOURNAL_KEY,
      stringToBytes(JSON.stringify(journal))
    );

    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      })
    ).rejects.toThrow(RotationResumeError);
  });

  it("a second rotation refuses while a journal exists", async () => {
    const fortress = await buildFortress();
    await expect(
      rotateMaster(
        rotateOpts(fortress, {
          failpoint: (p) => {
            if (p === "converted:notes/k1") throw new Error("crash");
          },
        })
      )
    ).rejects.toThrow(/crash/);
    await expect(rotateMaster(rotateOpts(fortress))).rejects.toThrow(
      RotationPreflightError
    );
  });

  it("resume with no journal refuses", async () => {
    const fortress = await buildFortress();
    await expect(
      resumeRotation({
        storage: fortress.storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
      })
    ).rejects.toThrow(RotationResumeError);
  });
});

describe("master rotation — custody floor on the rotated fortress", () => {
  it("the rotated envelope holds >= 2 verified distinct factors", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    const envelope = await readCustodyEnvelope(fortress.storage);
    expect(countVerifiedWraps(envelope!)).toBeGreaterThanOrEqual(2);
    const types = envelope!.wraps.map((w) => w.type).sort();
    expect(types).toContain("passphrase");
    expect(types).toContain("recovery-key");
  });

  it("re-creates the keychain wrap when the custody key is supplied", async () => {
    const fortress = await buildFortress();
    const custodyKey = generateRandomKey();
    await rotateMaster(rotateOpts(fortress, { keychainKey: custodyKey }));
    const envelope = await readCustodyEnvelope(fortress.storage);
    expect(envelope!.wraps.some((w) => w.type === "keychain")).toBe(true);
    // And it unwraps the SAME new master.
    const viaKeychain = await establishMaster({
      storage: fortress.storage,
      keychainKey: custodyKey,
    });
    const viaPassphrase = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    expect(toBase64url(viaKeychain.masterKey)).toBe(
      toBase64url(viaPassphrase.masterKey)
    );
  });
});

describe("master rotation — anti-rollback epoch advance (Stage 1)", () => {
  it("a fresh fortress is epoch 0 with no witness yet", async () => {
    const fortress = await buildFortress();
    expect(await readEnvelopeEpoch(fortress.storage)).toBe(0);
    const witness = await readEpochWitness(fortress.storage, fortress.master);
    expect(witness.status).toBe("absent");
  });

  it("a single rotation advances the on-disk epoch and witness to 1", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));

    const newEnvelope = await readCustodyEnvelope(fortress.storage);
    expect(envelopeEpochOf(newEnvelope)).toBe(1);

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const witness = await readEpochWitness(fortress.storage, est.masterKey);
    expect(witness.status).toBe("valid");
    if (witness.status === "valid") {
      expect(witness.data.epoch).toBe(1);
      expect(witness.data.epoch_id).toBe(newEnvelope!.epoch_id);
    }
  });

  it("two rotations advance the epoch to 2 and the rotation count agrees", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));
    await rotateMaster(rotateOpts(fortress));

    expect(await readEnvelopeEpoch(fortress.storage)).toBe(2);

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    const epochKeys = deriveAuditEpochKeys(est.masterKey);
    const count = await readCustodyEpochCount(fortress.storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    expect(count.status).toBe("present");
    if (count.status === "present") expect(count.count).toBe(2);
  });

  it("a legitimate rotation does NOT trip the boot detector (the #501 interaction)", async () => {
    const fortress = await buildFortress();
    await rotateMaster(rotateOpts(fortress));

    const est = await establishMaster({
      storage: fortress.storage,
      passphrase: PASSPHRASE,
    });
    // Re-run the exact boot cross-check the server runs: observe the witnesses,
    // compare against the on-disk envelope epoch. The rotation advanced BOTH the
    // envelope epoch and the witness in lockstep, so the verdict is OK.
    const epochKeys = deriveAuditEpochKeys(est.masterKey);
    const epochRecord = await readCustodyEpochCount(fortress.storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    const rotationEpochCount =
      epochRecord.status === "present" ? epochRecord.count : 0;
    const observation = await observeWitnessEpoch({
      storage: fortress.storage,
      master: est.masterKey,
      rotationEpochCount,
      rotationEpochTampered: epochRecord.status === "tampered",
    });
    const envelopeEpoch = await readEnvelopeEpoch(fortress.storage);
    const verdict = evaluateRollback({ envelopeEpoch, observation });
    expect(verdict.kind).toBe("ok");
  });

  it("DETECTS a custody-only splice that resurrects the retired credential even with both epoch witnesses deleted (codex r1 HIGH)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;

    // Capture the PRE-rotation custody artifacts (old master). These are what an
    // attacker with disk write would restore to swap the old (leaked) master
    // back in after the operator rotated it away.
    const oldEnvelope = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
    const oldSentinel = await storage.read("_meta", CUSTODY_SENTINEL_KEY);
    expect(oldEnvelope).not.toBeNull();

    // Operator rotates (the remedy for the leak): new master, epoch advances,
    // the audit head anchor is restamped under the NEW master.
    await rotateMaster(rotateOpts(fortress));
    const newMaster = (
      await establishMaster({ storage, passphrase: PASSPHRASE })
    ).masterKey;

    // ── The attack: restore ONLY the old custody files (swap the master back),
    // and DELETE both epoch witnesses (the cheapest move to avoid the obvious
    // epoch mismatch). State + audit stay current.
    await storage.write("_meta", CUSTODY_ENVELOPE_KEY, oldEnvelope!);
    if (oldSentinel) await storage.write("_meta", CUSTODY_SENTINEL_KEY, oldSentinel);
    await storage.delete("_meta", EPOCH_WITNESS_META_KEY);
    await storage.delete("_audit_checkpoints", AUDIT_EPOCH_KEYS_KEY);

    // Boot now establishes the OLD (retired) master from the restored envelope.
    const spliced = await establishMaster({ storage, passphrase: PASSPHRASE });
    expect(toBase64url(spliced.masterKey)).toBe(toBase64url(fortress.master));
    expect(toBase64url(spliced.masterKey)).not.toBe(toBase64url(newMaster));

    // The boot cross-check, run under the spliced-in OLD master: the epoch
    // record + witness are gone (deleted), so a naive epoch comparison reads
    // epoch 0 / floor 0 = OK. But the audit head anchor — restamped under the
    // NEW master during rotation — does NOT authenticate under the old master,
    // exposing the splice.
    const headProbe = await probeAuditHeadAnchor(storage, spliced.masterKey);
    expect(headProbe.status).toBe("tampered");

    const epochKeys = deriveAuditEpochKeys(spliced.masterKey);
    const epochRecord = await readCustodyEpochCount(storage, {
      epochMacKey: epochKeys.epochMacKey,
    });
    epochKeys.epochWrapKey.fill(0);
    epochKeys.epochMacKey.fill(0);
    const observation = await observeWitnessEpoch({
      storage,
      master: spliced.masterKey,
      rotationEpochCount: epochRecord.status === "present" ? epochRecord.count : 0,
      rotationEpochTampered: epochRecord.status === "tampered",
      headAnchor: { status: headProbe.status },
    });
    expect(observation.suspect).toBe(true);

    const verdict = evaluateRollback({
      envelopeEpoch: await readEnvelopeEpoch(storage),
      observation,
    });
    expect(verdict.kind).toBe("rollback-suspected");
  });

  it("head-anchor probe treats a DELETED head anchor as tampered when it was once established (codex r2)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;
    // buildFortress writes an audit chain → a head anchor + established marker.
    const probeBefore = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probeBefore.status).toBe("valid");

    // Attacker deletes the head anchor to dodge the splice check, but the
    // plaintext `audit-head-anchor-established-v1` marker remains → tampered.
    await storage.delete("_audit_checkpoints", "__head_anchor");
    const probeAfter = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probeAfter.status).toBe("tampered");
  });

  it("head-anchor probe stays tampered even after deleting the established MARKER, while audit entries survive (codex r3 HIGH)", async () => {
    const fortress = await buildFortress();
    const { storage } = fortress;
    // Attacker deletes BOTH the head anchor and its plaintext established marker
    // to erase the detector's memory — but the audit chain itself survives (the
    // splice attacker keeps the current audit). The audit entries are the second
    // independent "was established" signal, so the probe stays tampered.
    await storage.delete("_audit_checkpoints", "__head_anchor");
    await storage.delete("_meta", "audit-head-anchor-established-v1");
    expect((await storage.list("_audit")).length).toBeGreaterThan(0);
    const probe = await probeAuditHeadAnchor(storage, fortress.master);
    expect(probe.status).toBe("tampered");
  });

  it("head-anchor probe is absent (neutral) on a genuinely never-audited fortress", async () => {
    const storage = new MemoryStorage();
    const est = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
    });
    // No audit chain written → no head anchor, no established marker.
    const probe = await probeAuditHeadAnchor(storage, est.masterKey);
    expect(probe.status).toBe("absent");
  });
});
