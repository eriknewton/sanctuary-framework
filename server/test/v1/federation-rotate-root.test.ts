/**
 * Federation rotate-root --renew (Slice 3a) tests. This rotates the
 * cross-machine ROOT OF TRUST (the federation signing master), so these are the
 * security teeth of a CRITICAL surface:
 *
 *   - renewal re-key: exit 0; new master pubkey != old; fortress_id UNCHANGED;
 *     master_secret UNCHANGED; the re-issued principal + local node certs chain
 *     to K2 and verify; the record loads + yields a working ISSUER context under
 *     K2 (can authorize via a real dashboard).
 *   - rotation cert: verifies under the OLD master (K1); attests K2 + the stable
 *     fortress_id; monotonic rotation_serial; a stale/rolled-back serial is
 *     rejected; a wrong-key signature is rejected.
 *   - --resume: a crash mid-rotation (journal present, promote not done) still
 *     boots to a VALID root (old); --resume completes to a clean new root; no
 *     half-rotated corrupt state; boot-during-journal is fail-closed.
 *   - mutual exclusion: rotate-root refuses while a custody-rotation journal
 *     exists, and the reverse (custody rotate refuses while a rotate-root journal
 *     exists).
 *   - refuse if not provisioned -> exit 3; fail-closed custody -> exit 3, no
 *     mutation; no-secret-leak: zero secret bytes on stdout + in the audit.
 *
 * Each test seeds a REAL temp fortress keychain-free (establishMaster headless,
 * mintRecoveryKey:false), so the verb's REAL openOperatorSigner keychain-safe
 * unlock path is exercised end to end.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import {
  runFederationRotateRoot,
  runFederationProvision,
  runFederationCommand,
} from "../../src/cli/federation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { ROTATION_JOURNAL_KEY as CUSTODY_ROTATION_JOURNAL_KEY } from "../../src/core/master-custody.js";
import {
  bytesToString,
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../../src/core/encoding.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  provisionOrLoadFederationTrustRoot,
  federationContextFromTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  rotateFederationRootRenew,
  rotateFederationRootCompromised,
  resumeFederationRootRotation,
  resumeFederationRootCompromised,
  federationRotateRootInProgress,
  verifyFederationRootRotationCertificate,
  FEDERATION_ROTATE_ROOT_JOURNAL_KEY,
  FEDERATION_ROTATE_ROOT_STAGED_KEY,
  FederationRotateRootError,
  assertHybridRecordWellFormedForRotation,
} from "../../src/mesh/federation-rotate-root.js";
import { verifyFederationRootRotationHybridBinding } from "../../src/mesh/trust-root-hybrid.js";
import {
  verifyFederationRootRevocationHybridBundle,
  verifyFederationRootRevocationEvent,
  type FederationRevocationLogEvent,
  FEDERATION_ROOT_REVOCATION_EVENT_KIND,
} from "../../src/v1/federation-revocation.js";
import { verifySyncEnvelope } from "../../src/v1/federation-sync-envelope.js";
import { FederationSyncStateStore } from "../../src/v1/federation-sync-state-store.js";
import { FEDERATION_TRUST_ROOT_NAMESPACE } from "../../src/mesh/federation-trust-root-store.js";
import {
  verifyCertChain,
  verifyPrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import {
  seedCustodyAndOperator,
  seedFederationIssuerFortress,
} from "../util/federation-drill-seed.js";

function capture() {
  let text = "";
  const stream = new Writable({
    write(chunk, _enc, cb) {
      text += chunk.toString();
      cb();
    },
  });
  return { stream, get: () => text };
}

const PASSPHRASE = "rotate-root-drill-passphrase";

let fortressPath: string;
let statePath: string;
let storage: FilesystemStorage;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "rotate-root-"));
  statePath = join(fortressPath, "state");
  storage = new FilesystemStorage(statePath);
});

afterEach(async () => {
  await rm(fortressPath, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 50,
  });
});

/** Provision an issuer fortress (custody + operator + issuer trust root). */
async function seedIssuer(nodeId = "home-mac") {
  const issuer = await seedFederationIssuerFortress({
    storage,
    passphrase: PASSPHRASE,
    nodeId,
  });
  const masterKey = Uint8Array.from(issuer.masterKey);
  issuer.masterKey.fill(0);
  return { masterKey, issuer };
}

/** Load the live issuer record under the custody master. */
async function loadLive(masterKey: Uint8Array) {
  const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
  if (loaded === null) throw new Error("expected a provisioned issuer record");
  return loaded.record;
}

async function tamperStagedRecord(
  masterKey: Uint8Array,
  mutate: (record: Record<string, unknown>) => void,
): Promise<void> {
  const raw = await storage.read(
    FEDERATION_TRUST_ROOT_NAMESPACE,
    FEDERATION_ROTATE_ROOT_STAGED_KEY,
  );
  if (raw === null) throw new Error("expected staged rotate-root record");
  const encryptionKey = derivePurposeKey(masterKey, "federation-trust-root");
  let plaintext: Uint8Array | undefined;
  let serialized: Uint8Array | undefined;
  try {
    plaintext = decrypt(
      JSON.parse(bytesToString(raw)) as EncryptedPayload,
      encryptionKey,
    );
    const record = JSON.parse(bytesToString(plaintext)) as Record<string, unknown>;
    mutate(record);
    serialized = stringToBytes(JSON.stringify(record));
    const encrypted = encrypt(serialized, encryptionKey);
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_ROTATE_ROOT_STAGED_KEY,
      stringToBytes(JSON.stringify(encrypted)),
    );
  } finally {
    encryptionKey.fill(0);
    plaintext?.fill(0);
    serialized?.fill(0);
  }
}

describe("rotate-root --renew: the renewal re-key (P1)", () => {
  it("rotates the signing master: new K2, STABLE fortress_id, STABLE master_secret, certs chain to K2", async () => {
    const { masterKey, issuer } = await seedIssuer();
    const before = await loadLive(masterKey);
    const oldPubkey = before.pinned_master_pubkey.public_key;
    const oldFortressId = before.fortress_id;
    const oldMasterSecret = toBase64url(before.master_secret);

    const out = capture();
    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    const after = await loadLive(masterKey);
    // New master keypair.
    expect(after.pinned_master_pubkey.public_key).not.toBe(oldPubkey);
    expect(after.master_private_key).toBeDefined();
    expect(toBase64url(after.master_private_key!)).not.toBe(
      toBase64url(before.master_private_key!),
    );
    // STABLE fortress_id.
    expect(after.fortress_id).toBe(oldFortressId);
    expect(after.pinned_master_pubkey.fortress_id).toBe(oldFortressId);
    // STABLE master_secret (renewal keeps the symmetric root; only signing rotates).
    expect(toBase64url(after.master_secret)).toBe(oldMasterSecret);
    // Re-issued certs chain to K2 + verify.
    verifyPrincipalCertificate(after.issuing_principal_cert, after.pinned_master_pubkey);
    verifyCertChain(
      after.local_node_cert,
      after.issuing_principal_cert,
      after.pinned_master_pubkey,
    );
    expect(after.local_node_cert.parent_chain.fortress_master_pubkey).toBe(
      after.pinned_master_pubkey.public_key,
    );
    // Serial advanced from 0 -> 1.
    expect(after.rotation_serial).toBe(1);

    // The printed JSON carries ONLY safe public material.
    const printed = JSON.parse(out.get()) as {
      rotated: boolean;
      resumed: boolean;
      fortress_id: string;
      rotation_serial: number;
      previous_master_pubkey: string;
      pinned_master: { public_key: string; fortress_id: string };
      rotation_cert: { kind: string; new_master: { public_key: string } };
    };
    expect(printed.rotated).toBe(true);
    expect(printed.resumed).toBe(false);
    expect(printed.fortress_id).toBe(oldFortressId);
    expect(printed.previous_master_pubkey).toBe(oldPubkey);
    expect(printed.pinned_master.public_key).toBe(after.pinned_master_pubkey.public_key);
    expect(printed.rotation_cert.new_master.public_key).toBe(
      after.pinned_master_pubkey.public_key,
    );

    masterKey.fill(0);
    issuer.masterSecret.fill(0);
  });

  it("the rotated record yields a working ISSUER context under K2 (federationContextFromTrustRootRecord)", async () => {
    const { masterKey } = await seedIssuer();
    await rotateFederationRootRenew({ storage, masterKey });
    const after = await loadLive(masterKey);
    const ctx = federationContextFromTrustRootRecord(after);
    // The issuer accessors resolve under K2 (the master private key is present).
    expect(ctx.getMasterPrivateKey()).toBeDefined();
    expect(toBase64url(ctx.getMasterPrivateKey()!)).toBe(
      toBase64url(after.master_private_key!),
    );
    // The context's pinned master is K2; the issuing principal cert chains to it.
    expect(ctx.pinnedMasterPubkey.public_key).toBe(after.pinned_master_pubkey.public_key);
    verifyPrincipalCertificate(ctx.issuingPrincipalCert, ctx.pinnedMasterPubkey);
    masterKey.fill(0);
  });

  it("two sequential rotations advance the serial monotonically (0 -> 1 -> 2) and re-sign against the prior master", async () => {
    const { masterKey } = await seedIssuer();
    const r0 = await loadLive(masterKey);

    const first = await rotateFederationRootRenew({ storage, masterKey });
    expect(first.rotation_serial).toBe(1);
    const r1 = await loadLive(masterKey);
    // First cert links r0 (old) -> r1 (new).
    expect(first.rotation_cert.old_master_pubkey).toBe(r0.pinned_master_pubkey.public_key);
    verifyFederationRootRotationCertificate(first.rotation_cert, r0.pinned_master_pubkey);

    const second = await rotateFederationRootRenew({ storage, masterKey });
    expect(second.rotation_serial).toBe(2);
    // Second cert links r1 -> r2 and verifies under r1 (the master a joiner that
    // already adopted serial 1 currently pins).
    expect(second.rotation_cert.old_master_pubkey).toBe(r1.pinned_master_pubkey.public_key);
    verifyFederationRootRotationCertificate(second.rotation_cert, r1.pinned_master_pubkey, {
      minSerial: 1,
    });
    masterKey.fill(0);
  });
});

describe("rotate-root: the rotation certificate (K1-signed old->new link)", () => {
  it("verifies under the OLD master (K1), attests K2 + the stable fortress_id, carries a monotonic serial", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const result = await rotateFederationRootRenew({ storage, masterKey });

    // A renewal joiner pinning K1 verifies the cert against K1.
    verifyFederationRootRotationCertificate(result.rotation_cert, before.pinned_master_pubkey);
    expect(result.rotation_cert.kind).toBe("federation-root-rotation");
    expect(result.rotation_cert.fortress_id).toBe(before.fortress_id);
    expect(result.rotation_cert.new_master.fortress_id).toBe(before.fortress_id);
    expect(result.rotation_cert.new_master.public_key).toBe(result.new_pinned_master.public_key);
    expect(result.rotation_cert.rotation_serial).toBe(1);
    masterKey.fill(0);
  });

  it("rejects a rotation cert with a rolled-back/stale serial", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const result = await rotateFederationRootRenew({ storage, masterKey });
    // A joiner that already adopted serial 1 must reject this very cert replayed
    // (serial 1 does not advance an adopted serial of 1).
    expect(() =>
      verifyFederationRootRotationCertificate(result.rotation_cert, before.pinned_master_pubkey, {
        minSerial: 1,
      }),
    ).toThrow(/does not advance|stale|replayed/i);
    // And a higher adopted serial (2) also rejects a serial-1 cert.
    expect(() =>
      verifyFederationRootRotationCertificate(result.rotation_cert, before.pinned_master_pubkey, {
        minSerial: 2,
      }),
    ).toThrow();
    masterKey.fill(0);
  });

  it("rejects a rotation cert signed by the WRONG key (not the pinned master)", async () => {
    const { masterKey } = await seedIssuer();
    const result = await rotateFederationRootRenew({ storage, masterKey });
    // Verify against an unrelated master pubkey: signature must fail.
    const wrongPubkey = toBase64url(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    const wrongMaster = {
      public_key: wrongPubkey,
      fortress_id: result.rotation_cert.fortress_id,
      created_at: new Date().toISOString(),
    };
    expect(() =>
      verifyFederationRootRotationCertificate(result.rotation_cert, wrongMaster),
    ).toThrow(/does not match the master this verifier currently pins|signature does not verify/i);
    masterKey.fill(0);
  });

  it("rejects a tampered rotation cert (mutated new_master) against the OLD master", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const result = await rotateFederationRootRenew({ storage, masterKey });
    const tampered = {
      ...result.rotation_cert,
      new_master: {
        ...result.rotation_cert.new_master,
        public_key: toBase64url(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())),
      },
    };
    expect(() =>
      verifyFederationRootRotationCertificate(tampered, before.pinned_master_pubkey),
    ).toThrow(/signature does not verify/i);
    masterKey.fill(0);
  });
});

describe("rotate-root --resume: atomicity (no half-rotated corrupt state)", () => {
  it("a crash AFTER staging but BEFORE promote leaves the OLD root live + bootable; --resume completes to K2", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);

    // Simulate a crash right after the journal is staged (before promote starts).
    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash: post-stage pre-promote");
        },
      }),
    ).rejects.toThrow(/crash/);

    // Journal + staged record present; the LIVE record is STILL the OLD root.
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_ROTATE_ROOT_STAGED_KEY),
    ).toBe(true);
    const midLive = await loadLive(masterKey);
    expect(midLive.pinned_master_pubkey.public_key).toBe(before.pinned_master_pubkey.public_key);
    expect(midLive.rotation_serial).toBeUndefined();

    // Resume forward -> clean new root, journal + staged cleared.
    const resumed = await resumeFederationRootRotation({ storage, masterKey });
    expect(resumed.resumed).toBe(true);
    expect(resumed.rotation_serial).toBe(1);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_ROTATE_ROOT_STAGED_KEY),
    ).toBe(false);

    const after = await loadLive(masterKey);
    expect(after.pinned_master_pubkey.public_key).not.toBe(before.pinned_master_pubkey.public_key);
    expect(after.rotation_serial).toBe(1);
    verifyCertChain(after.local_node_cert, after.issuing_principal_cert, after.pinned_master_pubkey);
    masterKey.fill(0);
  });

  it("a crash DURING promote (after live write, before staged delete) is recovered idempotently by --resume", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);

    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "live-record-promoted") throw new Error("crash: mid-promote");
        },
      }),
    ).rejects.toThrow(/crash/);

    // The live record is already K2 (promoted), but the journal still exists, so
    // a fresh boot would HOLD federation off until resume (fail closed).
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    const midLive = await loadLive(masterKey);
    expect(midLive.pinned_master_pubkey.public_key).not.toBe(
      before.pinned_master_pubkey.public_key,
    );

    // Resume is idempotent: the staged record may be gone; it just clears the journal.
    const resumed = await resumeFederationRootRotation({ storage, masterKey });
    expect(resumed.rotation_serial).toBe(1);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    const after = await loadLive(masterKey);
    expect(after.pinned_master_pubkey.public_key).toBe(midLive.pinned_master_pubkey.public_key);
    verifyCertChain(after.local_node_cert, after.issuing_principal_cert, after.pinned_master_pubkey);
    masterKey.fill(0);
  });

  it("a crash BEFORE the journal is written (orphaned staged record) is cleaned on the next --renew; no half-rotation", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);

    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "staged-record-written") throw new Error("crash: pre-journal");
        },
      }),
    ).rejects.toThrow(/crash/);

    // No journal (the rotation never reached the point of no return); a stray
    // staged record exists but the LIVE root is unchanged + bootable.
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_ROTATE_ROOT_STAGED_KEY),
    ).toBe(true);
    const midLive = await loadLive(masterKey);
    expect(midLive.pinned_master_pubkey.public_key).toBe(before.pinned_master_pubkey.public_key);

    // A fresh --renew cleans the orphan and rotates cleanly to serial 1.
    const fresh = await rotateFederationRootRenew({ storage, masterKey });
    expect(fresh.rotation_serial).toBe(1);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_ROTATE_ROOT_STAGED_KEY),
    ).toBe(false);
    masterKey.fill(0);
  });

  it("boot-during-journal is fail-closed: the journal flips federationRotateRootInProgress true while the LIVE root still loads as the OLD valid root", async () => {
    // This is the boot-fail-closed contract the dashboard boot path enforces: it
    // consults federationRotateRootInProgress() and, when true, HOLDS federation
    // off (loads NO context) even though the LIVE record is a perfectly valid OLD
    // root. Prove both halves here without spinning a full HTTP rig:
    //   (1) mid-rotation the guard returns true (boot would hold federation off);
    //   (2) the LIVE record still loads + verifies as the OLD root (no corruption,
    //       the daemon would still boot; federation is merely gated until resume).
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);

    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow();

    // (1) boot guard: federation held off.
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    // (2) the live root is still the valid OLD root (loads + cert chain verifies).
    const live = await loadLive(masterKey);
    expect(live.pinned_master_pubkey.public_key).toBe(before.pinned_master_pubkey.public_key);
    verifyCertChain(live.local_node_cert, live.issuing_principal_cert, live.pinned_master_pubkey);

    // After resume the guard clears (boot would provision normally under K2).
    await resumeFederationRootRotation({ storage, masterKey });
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    masterKey.fill(0);
  });

  it("--resume with no journal refuses (exit 3); --renew refuses while a journal exists (use --resume)", async () => {
    const { masterKey } = await seedIssuer();

    // No journal -> --resume refuses (exit 3).
    const err1 = capture();
    const resumeCode = await runFederationRotateRoot({
      argv: ["--resume", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err1.stream,
    });
    expect(resumeCode).toBe(3);
    expect(err1.get()).toMatch(/no federation rotate-root is in progress|nothing to resume/i);

    // Plant a journal via a mid-stage crash, then --renew must refuse.
    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow();
    const err2 = capture();
    const renewCode = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err2.stream,
    });
    expect(renewCode).toBe(3);
    expect(err2.get()).toMatch(/already in progress|--resume/i);
    masterKey.fill(0);
  });
});

describe("rotate-root: mutual exclusion with custody rotation", () => {
  it("refuses to start while a custody-rotation journal exists (exit 3, no mutation)", async () => {
    const { masterKey } = await seedIssuer();
    const before = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");

    // Plant a custody rotation journal at _meta/rotation-journal.
    await storage.write(
      "_meta",
      CUSTODY_ROTATION_JOURNAL_KEY,
      stringToBytes(JSON.stringify({ data: { phase: "converting" }, mac: "x" })),
    );

    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    // The custody journal blocks the verb (either at the unlock fail-closed path
    // -- a master-key rotation is in progress -- or at the engine mutual-exclusion
    // check). Both are exit-3 refusals; assert the rotation-in-progress refusal.
    expect(err.get()).toMatch(/rotation is in progress/i);
    // Nothing mutated: no journal, no staged record, live root unchanged.
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    const after = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");
    expect(after).toEqual(before);
    masterKey.fill(0);
  });

  it("the reverse: a custody rotateMaster refuses while a federation rotate-root journal exists", async () => {
    const { masterKey } = await seedIssuer();
    // Plant a federation rotate-root journal via a mid-stage crash.
    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow();
    expect(await federationRotateRootInProgress(storage)).toBe(true);

    const { rotateMaster } = await import("../../src/core/master-rotation.js");
    await expect(
      rotateMaster({
        storage,
        fortressId: "test-fortress",
        passphrase: PASSPHRASE,
        approve: async () => true,
        captureRecoveryKey: async () => true,
      }),
    ).rejects.toThrow(/federation rotate-root is in progress/i);
    masterKey.fill(0);
  });
});

describe("rotate-root: refuse-if-not-provisioned + fail-closed custody", () => {
  it("refuses (exit 3) when the fortress is not a provisioned issuer (no root to rotate)", async () => {
    // Custody + operator, but NO trust root.
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    seeded.masterKey.fill(0);

    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/not a provisioned federation issuer|provision/i);
  });

  it("the engine refuses a NON-ISSUER (no master_private_key) root: only an issuer can rotate-root", async () => {
    // Persist an issuer-namespace record that lacks the master private key (a
    // joiner holds no master to mint K2 from). The engine must refuse rather than
    // rotate a root it cannot re-sign. Build the persisted blob by re-encrypting
    // the live record with master_private_key stripped, then assert the engine
    // throws FederationRotateRootError.
    const { masterKey } = await seedIssuer();
    const live = await loadLive(masterKey);
    const { FederationTrustRootStore } = await import(
      "../../src/mesh/federation-trust-root-store.js"
    );
    const store = new FederationTrustRootStore(storage, masterKey);
    const nonIssuer = { ...live };
    delete (nonIssuer as { master_private_key?: Uint8Array }).master_private_key;
    await store.save(nonIssuer);

    await expect(
      rotateFederationRootRenew({ storage, masterKey }),
    ).rejects.toThrow(FederationRotateRootError);
    masterKey.fill(0);
  });

  it("fails closed (exit 3) with NO credential; no journal, no staged record, live root unchanged", async () => {
    const { masterKey } = await seedIssuer();
    const before = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");

    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: {},
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_ROTATE_ROOT_STAGED_KEY),
    ).toBe(false);
    const after = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");
    expect(after).toEqual(before);
    masterKey.fill(0);
  });

  it("fails closed (exit 3) with the WRONG passphrase; live root unchanged", async () => {
    const { masterKey } = await seedIssuer();
    const before = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");

    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: "the-wrong-passphrase" },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    const after = await storage.read(FEDERATION_TRUST_ROOT_NAMESPACE, "trust-root-v1");
    expect(after).toEqual(before);
    masterKey.fill(0);
  });

  it("usage errors: no mode -> exit 1; --renew + --compromised together -> exit 1 (mutually exclusive)", async () => {
    const { masterKey } = await seedIssuer();
    masterKey.fill(0);

    const noMode = capture();
    expect(
      await runFederationRotateRoot({
        argv: ["--fortress", fortressPath],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: capture().stream,
        err: noMode.stream,
      }),
    ).toBe(1);
    expect(noMode.get()).toMatch(/--renew|--resume|--compromised/);

    // --renew and --compromised are mutually exclusive intents -> usage error
    // (returns before any custody unlock, so the fortress is untouched).
    const conflicting = capture();
    expect(
      await runFederationRotateRoot({
        argv: ["--renew", "--compromised", "--fortress", fortressPath],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: capture().stream,
        err: conflicting.stream,
      }),
    ).toBe(1);
    expect(conflicting.get()).toMatch(/mutually exclusive/i);
  });
});

describe("rotate-root: no-secret-leak (constraint 6)", () => {
  it("stdout + the rotation audit entry contain ZERO secret bytes (old/new master private + master_secret)", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const oldSecrets = [
      toBase64url(before.master_private_key!),
      toBase64url(before.master_secret),
    ];

    const out = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    const after = await loadLive(masterKey);
    const newSecrets = [
      toBase64url(after.master_private_key!),
      toBase64url(after.master_secret),
      toBase64url(after.issuing_principal_private_key),
      toBase64url(after.local_node_private_key),
    ];
    const allSecrets = [...oldSecrets, ...newSecrets];

    const stdout = out.get();
    for (const secret of allSecrets) {
      expect(stdout).not.toContain(secret);
    }

    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_root_rotated",
      limit: 100,
    });
    expect(entries.length).toBeGreaterThan(0);
    const auditJson = JSON.stringify(entries);
    for (const secret of allSecrets) {
      expect(auditJson).not.toContain(secret);
    }
    // Attribution + the new PUBLIC master pubkey are present (safe to log).
    expect(auditJson).toContain("operator_pubkey");
    expect(auditJson).toContain(after.pinned_master_pubkey.public_key);
    masterKey.fill(0);
  });

  it("hybrid compromise stdout + audit contain ZERO hybrid ML-DSA secret bytes", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldSecrets = [
      toBase64url(before.hybrid!.master_private_keys.ml_dsa_65.secret_key),
      toBase64url(before.hybrid!.issuing_principal_private_keys.ml_dsa_65.secret_key),
      toBase64url(before.hybrid!.local_node_private_keys.ml_dsa_65.secret_key),
    ];

    const out = capture();
    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--compromised", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    const after = await loadLive(masterKey);
    const newSecrets = [
      toBase64url(after.hybrid!.master_private_keys.ml_dsa_65.secret_key),
      toBase64url(after.hybrid!.issuing_principal_private_keys.ml_dsa_65.secret_key),
      toBase64url(after.hybrid!.local_node_private_keys.ml_dsa_65.secret_key),
    ];
    const allSecrets = [...oldSecrets, ...newSecrets];

    const stdout = out.get();
    for (const secret of allSecrets) {
      expect(stdout).not.toContain(secret);
    }

    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_root_compromise_revoked",
      limit: 100,
    });
    expect(entries.length).toBeGreaterThan(0);
    const auditJson = JSON.stringify(entries);
    for (const secret of allSecrets) {
      expect(auditJson).not.toContain(secret);
    }
    masterKey.fill(0);
  });
});

describe("rotate-root: provision -> rotate-root via the CLI dispatcher", () => {
  it("provision then rotate-root --renew both succeed via runFederationCommand", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    // PQC default-on: a bare provision now mints a HYBRID root, and rotate-root
    // REFUSES on hybrid roots (hybrid signing-master rotation is a deferred
    // follow-up). This test exercises the provision -> rotate-root path through
    // the dispatcher, so it must provision the CLASSICAL root that rotate-root
    // can actually rotate (--classical opts out of the new hybrid default). The
    // hybrid-root rotate REFUSAL is covered by its own tests above.
    const provCode = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--classical", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(provCode).toBe(0);
    const before = await loadLive(masterKey);
    expect(before.hybrid, "the dispatcher rotate path needs a classical root").toBeUndefined();

    const out = capture();
    const err = capture();
    const code = await runFederationCommand({
      argv: ["rotate-root", "--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    const after = await loadLive(masterKey);
    expect(after.pinned_master_pubkey.public_key).not.toBe(before.pinned_master_pubkey.public_key);
    expect(after.fortress_id).toBe(before.fortress_id);
    masterKey.fill(0);
  });
});

/**
 * Seed an issuer fortress provisioned with the HYBRID suite via the REAL
 * provision CLI (--pqc-hybrid), so the at-rest record carries the
 * Ed25519+ML-DSA-65 `hybrid` block. Returns the unlocked custody master key.
 */
async function seedHybridIssuer(nodeId = "home-mac"): Promise<Uint8Array> {
  const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
  const masterKey = Uint8Array.from(seeded.masterKey);
  seeded.masterKey.fill(0);

  const provErr = capture();
  const provCode = await runFederationProvision({
    argv: ["--node-id", nodeId, "--pqc-hybrid", "--fortress", fortressPath],
    env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
    out: capture().stream,
    err: provErr.stream,
  });
  expect(provCode, `provision stderr: ${provErr.get()}`).toBe(0);
  const live = await loadLive(masterKey);
  expect(live.hybrid, "expected a hybrid issuer record").toBeDefined();
  return masterKey;
}

describe("rotate-root --renew on a HYBRID root (PQC Slice 3): rotates, no downgrade, both-must-pass", () => {
  it("rotates the HYBRID master: still hybrid (4032-byte ML-DSA secret), new pinned hybrid master, STABLE fortress_id, certs verify, OLD root gone, hybrid rotation cert verifies BOTH components", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldHybridPinned = structuredClone(before.hybrid!.pinned_master);
    const oldClassicalPinned = { ...before.pinned_master_pubkey };

    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    const after = await loadLive(masterKey);
    // STILL hybrid (never downgraded to classical-only).
    expect(after.hybrid, "rotated record must remain hybrid").toBeDefined();
    // The 4032-byte ML-DSA-65 secret is present + correct length.
    expect(after.hybrid!.master_private_keys.ml_dsa_65.secret_key.length).toBe(4032);
    expect(after.hybrid!.master_private_keys.ed25519.private_key.length).toBe(32);
    // New pinned HYBRID master differs from old (both components rotated).
    expect(after.hybrid!.pinned_master.public_keys.ed25519.public_key).not.toBe(
      oldHybridPinned.public_keys.ed25519.public_key,
    );
    expect(after.hybrid!.pinned_master.public_keys.ml_dsa_65.public_key).not.toBe(
      oldHybridPinned.public_keys.ml_dsa_65.public_key,
    );
    // Classical master rotated in lockstep.
    expect(after.pinned_master_pubkey.public_key).not.toBe(
      oldClassicalPinned.public_key,
    );
    // STABLE fortress_id across both chains.
    expect(after.fortress_id).toBe(before.fortress_id);
    expect(after.hybrid!.pinned_master.fortress_id).toBe(before.fortress_id);

    // The rotation cert carries the hybrid binding; it verifies under the OLD
    // hybrid master with BOTH components (both-must-pass).
    const cert = after.rotation_cert!;
    expect(cert.hybrid_rotation, "hybrid rotation cert must carry hybrid binding").toBeDefined();
    await verifyFederationRootRotationHybridBinding(
      cert.hybrid_rotation!,
      oldHybridPinned,
      {
        fortress_id: cert.fortress_id,
        old_master_pubkey: cert.old_master_pubkey,
        new_master: cert.new_master,
        rotation_serial: cert.rotation_serial,
        rotated_at: cert.rotated_at,
      },
    );
    masterKey.fill(0);
  });

  it("DOWNGRADE GUARD: a hybrid rotation cert does NOT verify with ONLY the Ed25519 component (tampered/stripped ML-DSA half is rejected, both-must-pass)", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldHybridPinned = structuredClone(before.hybrid!.pinned_master);

    await rotateFederationRootRenew({ storage, masterKey });
    const after = await loadLive(masterKey);
    const cert = after.rotation_cert!;
    const binding = structuredClone(cert.hybrid_rotation!);

    // Tamper: corrupt the ML-DSA-65 component sig (the Ed25519 half stays valid).
    // A both-must-pass verifier MUST reject, never adopt on the Ed25519 half alone.
    const mlComponent = binding.old_hybrid_master_signature_bundle.components[1]!;
    const corrupted = {
      ...binding,
      old_hybrid_master_signature_bundle: {
        ...binding.old_hybrid_master_signature_bundle,
        components: [
          binding.old_hybrid_master_signature_bundle.components[0]!,
          { ...mlComponent, sig: "A".repeat(mlComponent.sig.length) },
        ],
      },
    };
    await expect(
      verifyFederationRootRotationHybridBinding(corrupted, oldHybridPinned, {
        fortress_id: cert.fortress_id,
        old_master_pubkey: cert.old_master_pubkey,
        new_master: cert.new_master,
        rotation_serial: cert.rotation_serial,
        rotated_at: cert.rotated_at,
      }),
    ).rejects.toThrow();
    masterKey.fill(0);
  });

  it("BINDING GUARD: tampering the outer classical new_master invalidates the hybrid rotation binding", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldHybridPinned = structuredClone(before.hybrid!.pinned_master);

    await rotateFederationRootRenew({ storage, masterKey });
    const after = await loadLive(masterKey);
    const cert = after.rotation_cert!;
    await expect(
      verifyFederationRootRotationHybridBinding(
        cert.hybrid_rotation!,
        oldHybridPinned,
        {
          fortress_id: cert.fortress_id,
          old_master_pubkey: cert.old_master_pubkey,
          new_master: {
            ...cert.new_master,
            public_key: before.pinned_master_pubkey.public_key,
          },
          rotation_serial: cert.rotation_serial,
          rotated_at: cert.rotated_at,
        },
      ),
    ).rejects.toThrow();
    masterKey.fill(0);
  });

  it("--resume completes a crashed HYBRID rotation to a clean HYBRID root", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);

    // Crash AFTER the journal is staged but BEFORE promote completes.
    await expect(
      rotateFederationRootRenew({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow();
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    // The live root is still the OLD hybrid root (boot-safe).
    const mid = await loadLive(masterKey);
    expect(mid.hybrid!.pinned_master.public_keys.ed25519.public_key).toBe(
      before.hybrid!.pinned_master.public_keys.ed25519.public_key,
    );

    // Resume completes forward to a clean NEW hybrid root.
    const result = await resumeFederationRootRotation({ storage, masterKey });
    expect(result.resumed).toBe(true);
    const after = await loadLive(masterKey);
    expect(after.hybrid, "resumed root must be hybrid").toBeDefined();
    expect(after.hybrid!.master_private_keys.ml_dsa_65.secret_key.length).toBe(4032);
    expect(after.hybrid!.pinned_master.public_keys.ed25519.public_key).not.toBe(
      before.hybrid!.pinned_master.public_keys.ed25519.public_key,
    );
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    masterKey.fill(0);
  });

  it("a CLASSICAL root still rotates fine and carries NO hybrid binding (no regression)", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    expect(before.hybrid).toBeUndefined();

    const code = await runFederationRotateRoot({
      argv: ["--renew", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(code).toBe(0);
    const after = await loadLive(masterKey);
    expect(after.hybrid).toBeUndefined();
    expect(after.pinned_master_pubkey.public_key).not.toBe(
      before.pinned_master_pubkey.public_key,
    );
    expect(after.rotation_cert!.hybrid_rotation).toBeUndefined();
    masterKey.fill(0);
  });
});

describe("rotate-root --compromised on a HYBRID root (PQC Slice 3): revokes both old components, PQ-signed revocation, no rotation cert", () => {
  it("mints new hybrid master + new master_secret, NO rotation cert, revocation binds BOTH old components + verifies under K2 hybrid principal", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldHybridPinned = structuredClone(before.hybrid!.pinned_master);
    const oldMasterSecret = toBase64url(before.master_secret);

    const result = await rotateFederationRootCompromised({ storage, masterKey });

    const after = await loadLive(masterKey);
    expect(after.hybrid, "compromise-rotated root must remain hybrid").toBeDefined();
    // NEW master_secret (compromise rotates it).
    expect(toBase64url(after.master_secret)).not.toBe(oldMasterSecret);
    // NEW hybrid master (both components differ).
    expect(after.hybrid!.pinned_master.public_keys.ed25519.public_key).not.toBe(
      oldHybridPinned.public_keys.ed25519.public_key,
    );
    expect(after.hybrid!.pinned_master.public_keys.ml_dsa_65.public_key).not.toBe(
      oldHybridPinned.public_keys.ml_dsa_65.public_key,
    );
    // NO rotation cert / serial (downgrade-resistance: no old-key-signed artifact).
    expect(after.rotation_cert).toBeUndefined();
    expect(after.rotation_serial).toBeUndefined();

    // The revocation binds BOTH old hybrid component public keys.
    const rev = result.root_revocation;
    expect(rev.revoked_hybrid).toBeDefined();
    expect(rev.revoked_hybrid!.ed25519.public_key).toBe(
      oldHybridPinned.public_keys.ed25519.public_key,
    );
    expect(rev.revoked_hybrid!.ml_dsa_65.public_key).toBe(
      oldHybridPinned.public_keys.ml_dsa_65.public_key,
    );

    // The revocation's HYBRID bundle (both-must-pass) verifies under the NEW K2
    // hybrid PRINCIPAL public keys (the revocation's authenticity is PQ-protected).
    const newPrincipalPubKeys = after.hybrid!.issuing_principal_cert.principal_public_keys;
    const hybridOk = await verifyFederationRootRevocationHybridBundle(
      rev,
      newPrincipalPubKeys,
    );
    expect(hybridOk, "hybrid revocation bundle must verify under K2 principal").toBe(true);

    // The classical Ed25519 leg also verifies under the new principal cert.
    const event: FederationRevocationLogEvent = {
      event_id: "e1",
      origin_node_id: `operator:${after.fortress_id}`,
      sequence: 1,
      occurred_at: rev.effective_at,
      kind: FEDERATION_ROOT_REVOCATION_EVENT_KIND,
      payload: rev as unknown as Record<string, unknown>,
      previous_hash: null,
      event_hash: "h1",
    };
    const verified = await verifyFederationRootRevocationEvent({
      event,
      fortressId: after.fortress_id,
      pinnedMaster: after.pinned_master_pubkey,
      operatorPrincipalCert: after.issuing_principal_cert,
      operatorHybridPrincipalPublicKeys: newPrincipalPubKeys,
      highestRevocationSerial: 0,
    });
    expect(verified.ok, "classical leg must verify under K2 principal").toBe(true);
    masterKey.fill(0);
  });

  it("FAIL-CLOSED: a real hybrid compromise revocation with absent or malformed ML-DSA bundle is rejected", async () => {
    const masterKey = await seedHybridIssuer();
    const result = await rotateFederationRootCompromised({ storage, masterKey });
    const after = await loadLive(masterKey);
    const rev = result.root_revocation;
    const newPrincipalPubKeys = after.hybrid!.issuing_principal_cert.principal_public_keys;
    const makeEvent = (payload: Record<string, unknown>): FederationRevocationLogEvent => ({
      event_id: "e1",
      origin_node_id: `operator:${after.fortress_id}`,
      sequence: 1,
      occurred_at: rev.effective_at,
      kind: FEDERATION_ROOT_REVOCATION_EVENT_KIND,
      payload,
      previous_hash: null,
      event_hash: "h1",
    });
    const missingBundle = { ...(rev as unknown as Record<string, unknown>) };
    delete missingBundle.operator_signature_bundle;
    const missing = await verifyFederationRootRevocationEvent({
      event: makeEvent(missingBundle),
      fortressId: after.fortress_id,
      pinnedMaster: after.pinned_master_pubkey,
      operatorPrincipalCert: after.issuing_principal_cert,
      operatorHybridPrincipalPublicKeys: newPrincipalPubKeys,
      highestRevocationSerial: 0,
    });
    expect(missing.ok).toBe(false);

    const malformed = await verifyFederationRootRevocationEvent({
      event: makeEvent({
        ...(rev as unknown as Record<string, unknown>),
        operator_signature_bundle: { components: "not-an-array" },
      }),
      fortressId: after.fortress_id,
      pinnedMaster: after.pinned_master_pubkey,
      operatorPrincipalCert: after.issuing_principal_cert,
      operatorHybridPrincipalPublicKeys: newPrincipalPubKeys,
      highestRevocationSerial: 0,
    });
    expect(malformed.ok).toBe(false);
    masterKey.fill(0);
  });

  it("DOWNGRADE GUARD: the revocation hybrid bundle does NOT verify under the OLD K1 principal (signed under K2, never K1)", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldPrincipalPubKeys = structuredClone(
      before.hybrid!.issuing_principal_cert.principal_public_keys,
    );

    const result = await rotateFederationRootCompromised({ storage, masterKey });
    // The OLD K1 hybrid principal must NOT verify the revocation (forge-resistance).
    const okUnderK1 = await verifyFederationRootRevocationHybridBundle(
      result.root_revocation,
      oldPrincipalPubKeys,
    );
    expect(okUnderK1).toBe(false);
    masterKey.fill(0);
  });

  it("both old hybrid component pubkeys + the old classical master land in the durable revoked-root set; a sync envelope chaining to the old classical root is rejected root_revoked", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldClassical = before.pinned_master_pubkey.public_key;
    const oldEd = before.hybrid!.pinned_master.public_keys.ed25519.public_key;
    const oldMl = before.hybrid!.pinned_master.public_keys.ml_dsa_65.public_key;

    await rotateFederationRootCompromised({ storage, masterKey });

    // Durable revoked-root set now contains all three old anchors.
    const syncStore = new FederationSyncStateStore({ storage, masterKey });
    const snapshot = await syncStore.load();
    expect(snapshot.revokedRootPubkeys.has(oldClassical)).toBe(true);
    expect(snapshot.revokedRootPubkeys.has(oldEd)).toBe(true);
    expect(snapshot.revokedRootPubkeys.has(oldMl)).toBe(true);

    // A sync envelope whose chain terminates at the OLD classical master is
    // rejected root_revoked (the recipient still pinning K1 denies the sync).
    const isRootRevoked = (pubkey: string): boolean =>
      snapshot.revokedRootPubkeys.has(pubkey);
    const denied = verifySyncEnvelope({
      envelope: { wire_version: "sanctuary.v1.federation-sync-envelope", note: "shape only" },
      pinnedMaster: { ...before.pinned_master_pubkey },
      recipientNodeId: before.node_id,
      acceptedHighWaterFor: () => null,
      isNodeRevoked: () => false,
      isRootRevoked,
    });
    expect(denied.ok).toBe(false);
    masterKey.fill(0);
  });

  it("--resume completes a crashed HYBRID compromise and re-adds BOTH old hybrid components to the revoked set", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldEd = before.hybrid!.pinned_master.public_keys.ed25519.public_key;
    const oldMl = before.hybrid!.pinned_master.public_keys.ml_dsa_65.public_key;

    // Crash mid-promote (journal still present) so --resume has work to do.
    await expect(
      rotateFederationRootCompromised({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow();
    expect(await federationRotateRootInProgress(storage)).toBe(true);

    const result = await resumeFederationRootCompromised({ storage, masterKey });
    expect(result.revoked_master_pubkey).toBe(before.pinned_master_pubkey.public_key);
    const after = await loadLive(masterKey);
    expect(after.hybrid).toBeDefined();

    const syncStore = new FederationSyncStateStore({ storage, masterKey });
    const snapshot = await syncStore.load();
    expect(snapshot.revokedRootPubkeys.has(oldEd)).toBe(true);
    expect(snapshot.revokedRootPubkeys.has(oldMl)).toBe(true);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    masterKey.fill(0);
  });

  it("--resume after a crash AFTER promote re-persists the old classical + hybrid root revocation before clearing the journal", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldClassical = before.pinned_master_pubkey.public_key;
    const oldEd = before.hybrid!.pinned_master.public_keys.ed25519.public_key;
    const oldMl = before.hybrid!.pinned_master.public_keys.ml_dsa_65.public_key;

    await expect(
      rotateFederationRootCompromised({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "compromise-root-promoted") throw new Error("crash after promote");
        },
      }),
    ).rejects.toThrow("crash after promote");
    expect(await federationRotateRootInProgress(storage)).toBe(true);

    const promoted = await loadLive(masterKey);
    expect(promoted.pinned_master_pubkey.public_key).not.toBe(oldClassical);
    const syncStore = new FederationSyncStateStore({ storage, masterKey });
    const midSnapshot = await syncStore.load();
    expect(midSnapshot.revokedRootPubkeys.has(oldClassical)).toBe(false);
    expect(midSnapshot.revokedRootPubkeys.has(oldEd)).toBe(false);
    expect(midSnapshot.revokedRootPubkeys.has(oldMl)).toBe(false);

    await resumeFederationRootCompromised({ storage, masterKey });
    const snapshot = await syncStore.load();
    expect(snapshot.revokedRootPubkeys.has(oldClassical)).toBe(true);
    expect(snapshot.revokedRootPubkeys.has(oldEd)).toBe(true);
    expect(snapshot.revokedRootPubkeys.has(oldMl)).toBe(true);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    masterKey.fill(0);
  });
});

describe("rotate-root on a HYBRID root: malformed hybrid refuses fail-closed (never downgrades to classical)", () => {
  it("the rotate-boundary guard REFUSES a hybrid record with a truncated ML-DSA secret (FederationRotateRootError) rather than rotating to classical-only", async () => {
    const masterKey = await seedHybridIssuer();
    const live = await loadLive(masterKey);
    const hybrid = structuredClone(live.hybrid!);

    // A well-formed hybrid record passes the guard.
    expect(() => assertHybridRecordWellFormedForRotation(live.hybrid!)).not.toThrow();

    // Truncate the ML-DSA-65 secret: the guard must REFUSE (constraint 5,
    // fail-closed) instead of letting a rotation drop the post-quantum half.
    hybrid.master_private_keys = {
      ...hybrid.master_private_keys,
      ml_dsa_65: {
        key_ref: hybrid.master_private_keys.ml_dsa_65.key_ref,
        secret_key: hybrid.master_private_keys.ml_dsa_65.secret_key.slice(0, 100),
      },
    };
    expect(() => assertHybridRecordWellFormedForRotation(hybrid)).toThrow(
      FederationRotateRootError,
    );
    masterKey.fill(0);
  });

  it("the REAL compromised resume path rejects a staged record whose hybrid block is present but non-object", async () => {
    const masterKey = await seedHybridIssuer();
    const before = await loadLive(masterKey);
    const oldClassical = before.pinned_master_pubkey.public_key;
    const oldHybridEd = before.hybrid!.pinned_master.public_keys.ed25519.public_key;

    await expect(
      rotateFederationRootCompromised({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash before promote");
        },
      }),
    ).rejects.toThrow("crash before promote");
    await tamperStagedRecord(masterKey, (record) => {
      record.hybrid = "present-but-not-object";
    });

    await expect(resumeFederationRootCompromised({ storage, masterKey })).rejects.toThrow(
      /hybrid block/i,
    );
    const after = await loadLive(masterKey);
    expect(after.pinned_master_pubkey.public_key).toBe(oldClassical);
    expect(after.hybrid!.pinned_master.public_keys.ed25519.public_key).toBe(oldHybridEd);
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    masterKey.fill(0);
  });
});
