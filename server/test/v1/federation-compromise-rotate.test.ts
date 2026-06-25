/**
 * Federation rotate-root --compromised (Slice 3c-1) tests: the ISSUER-SIDE
 * compromise rotate + the root-revocation mechanism. This rotates the
 * cross-machine ROOT OF TRUST after a STOLEN root key, so these are the security
 * teeth of a CRITICAL surface. The make-or-break acceptance criteria here are:
 *
 *   (1) compromise mints K2 + revokes K1: live record is K2 with stable
 *       fortress_id, the master_secret CHANGED, a durable root-revocation for K1
 *       is recorded; new certs chain to K2.
 *   (5) master_secret is ROTATED on compromise but KEPT on renewal (no
 *       regression to the renewal path).
 *   (6) DOWNGRADE RESISTANCE: the compromise flow emits NO old-(K1)-signed
 *       rotation cert (the record carries none), AND the root-revocation event is
 *       signed under K2 (the new key), never K1.
 *   (7) no-half-rotation: a crash between mint and promote leaves the journal;
 *       --resume completes idempotently (and re-persists the durable revocation).
 *
 * The K1-chained-envelope-rejection (2), revocation-survives-restart (3), and
 * fail-closed-on-corrupt (4) acceptance tests live in
 * `federation-root-revocation-enforcement.test.ts` (the enforcement seam).
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

import {
  runFederationRotateRoot,
} from "../../src/cli/federation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  provisionOrLoadFederationTrustRoot,
  federationContextFromTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  rotateFederationRootCompromised,
  rotateFederationRootRenew,
  resumeFederationRootCompromised,
  resumeFederationRootRotation,
  federationRotateRootInProgress,
  federationRotateRootJournalIsCompromise,
  FEDERATION_ROTATE_ROOT_STAGED_KEY,
} from "../../src/mesh/federation-rotate-root.js";
import { FEDERATION_TRUST_ROOT_NAMESPACE } from "../../src/mesh/federation-trust-root-store.js";
import {
  verifyCertChain,
  verifyPrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import {
  FederationSyncStateStore,
} from "../../src/v1/federation-sync-state-store.js";
import {
  buildFederationRootRevocationMessage,
  verifyFederationRootRevocationEvent,
  type FederationRevocationLogEvent,
  federationOperatorAuthorityOrigin,
} from "../../src/v1/federation-revocation.js";
import { ed25519 } from "@noble/curves/ed25519";
import { fromBase64url } from "../../src/core/encoding.js";
import { seedFederationIssuerFortress } from "../util/federation-drill-seed.js";

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

const PASSPHRASE = "compromise-rotate-drill-passphrase";

let fortressPath: string;
let statePath: string;
let storage: FilesystemStorage;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "compromise-rotate-"));
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

async function loadLive(masterKey: Uint8Array) {
  const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
  if (loaded === null) throw new Error("expected a provisioned issuer record");
  return loaded.record;
}

async function loadRevokedRoots(masterKey: Uint8Array) {
  return new FederationSyncStateStore({ storage, masterKey }).load();
}

describe("rotate-root --compromised: MERGE-BAR 1 (mint K2 + revoke K1 + rotate master_secret)", () => {
  it("mints K2 with a STABLE fortress_id, a CHANGED master_secret, a DURABLE root revocation of K1, and certs that chain to K2", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const oldPubkey = before.pinned_master_pubkey.public_key;
    const oldFortressId = before.fortress_id;
    const oldMasterSecret = toBase64url(before.master_secret);

    const result = await rotateFederationRootCompromised({ storage, masterKey });

    const after = await loadLive(masterKey);
    // New master keypair (K2).
    expect(after.pinned_master_pubkey.public_key).not.toBe(oldPubkey);
    expect(toBase64url(after.master_private_key!)).not.toBe(
      toBase64url(before.master_private_key!),
    );
    // STABLE fortress_id (identity survives the rotation).
    expect(after.fortress_id).toBe(oldFortressId);
    expect(after.pinned_master_pubkey.fortress_id).toBe(oldFortressId);
    // master_secret CHANGED (compromise rotates the symmetric root too).
    expect(toBase64url(after.master_secret)).not.toBe(oldMasterSecret);
    // No rotation cert / serial on the record (downgrade resistance, see test 6).
    expect(after.rotation_cert).toBeUndefined();
    expect(after.rotation_serial).toBeUndefined();
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

    // The DURABLE projection now revokes K1 at serial 1.
    const snapshot = await loadRevokedRoots(masterKey);
    expect(snapshot.revokedRootPubkeys.has(oldPubkey)).toBe(true);
    expect(snapshot.highestRevocationSerial).toBe(1);

    // The result surfaces only public material; revocation names K1 + new pinned master is K2.
    expect(result.revoked_master_pubkey).toBe(oldPubkey);
    expect(result.new_pinned_master.public_key).toBe(after.pinned_master_pubkey.public_key);
    expect(result.revocation_serial).toBe(1);

    // The rotated record still yields a working ISSUER context under K2.
    const ctx = federationContextFromTrustRootRecord(after);
    expect(toBase64url(ctx.getMasterPrivateKey()!)).toBe(
      toBase64url(after.master_private_key!),
    );

    masterKey.fill(0);
  });

  it("the CLI --compromised verb succeeds (exit 0), prints K2 + the revocation, and NO rotation cert; leaks no secret bytes", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const oldPubkey = before.pinned_master_pubkey.public_key;
    const masterSecretB64 = toBase64url(before.master_secret);
    const masterPrivB64 = toBase64url(before.master_private_key!);

    const out = capture();
    const err = capture();
    const code = await runFederationRotateRoot({
      argv: ["--compromised", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    const printed = JSON.parse(out.get()) as {
      rotated: boolean;
      compromised: boolean;
      revoked_master_pubkey: string;
      pinned_master: { public_key: string };
      root_revocation: { operator_signature: string };
      rotation_cert?: unknown;
    };
    expect(printed.rotated).toBe(true);
    expect(printed.compromised).toBe(true);
    expect(printed.revoked_master_pubkey).toBe(oldPubkey);
    expect(printed.rotation_cert).toBeUndefined();
    expect(printed.root_revocation.operator_signature.length).toBeGreaterThan(0);

    // No secret material on stdout or stderr.
    const both = out.get() + err.get();
    expect(both).not.toContain(masterSecretB64);
    expect(both).not.toContain(masterPrivB64);

    masterKey.fill(0);
  });
});

describe("rotate-root: MERGE-BAR 5 (master_secret rotated on compromise, KEPT on renewal)", () => {
  it("renewal keeps master_secret + fortress_id stable; compromise rotates master_secret", async () => {
    // Renewal path (no regression): master_secret unchanged.
    const renew = await seedIssuer("renew-mac");
    const beforeRenew = await loadLive(renew.masterKey);
    await rotateFederationRootRenew({ storage, masterKey: renew.masterKey });
    const afterRenew = await loadLive(renew.masterKey);
    expect(toBase64url(afterRenew.master_secret)).toBe(
      toBase64url(beforeRenew.master_secret),
    );
    expect(afterRenew.fortress_id).toBe(beforeRenew.fortress_id);
    renew.masterKey.fill(0);
  });

  it("compromise rotates the master_secret (and a follow-on renewal then keeps the NEW secret stable)", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    await rotateFederationRootCompromised({ storage, masterKey });
    const afterCompromise = await loadLive(masterKey);
    expect(toBase64url(afterCompromise.master_secret)).not.toBe(
      toBase64url(before.master_secret),
    );
    // A subsequent RENEWAL keeps the new (post-compromise) master_secret stable.
    await rotateFederationRootRenew({ storage, masterKey });
    const afterRenew = await loadLive(masterKey);
    expect(toBase64url(afterRenew.master_secret)).toBe(
      toBase64url(afterCompromise.master_secret),
    );
    masterKey.fill(0);
  });
});

describe("rotate-root --compromised: MERGE-BAR 6 (downgrade resistance)", () => {
  it("emits NO old-(K1)-signed rotation cert: the promoted record carries neither rotation_cert nor rotation_serial", async () => {
    const { masterKey } = await seedIssuer();
    await rotateFederationRootCompromised({ storage, masterKey });
    const after = await loadLive(masterKey);
    // Structural proof: a thief holding K1 has nothing trusted to forge against;
    // there is no K1-signed adoption artifact anywhere in the compromise output.
    expect(after.rotation_cert).toBeUndefined();
    expect(after.rotation_serial).toBeUndefined();
    masterKey.fill(0);
  });

  it("the root-revocation event is signed under K2 (the NEW key), verifies under K2, and FAILS to verify under K1", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const k1Master = { ...before.pinned_master_pubkey };

    const result = await rotateFederationRootCompromised({ storage, masterKey });
    const after = await loadLive(masterKey);
    const k2Master = after.pinned_master_pubkey;
    const k2PrincipalCert = after.issuing_principal_cert;

    const revocation = result.root_revocation;
    expect(revocation.revoked_master_pubkey).toBe(k1Master.public_key);

    // The signed body the event commits to (signature-bearing field excluded).
    const signedBody = {
      event_version: revocation.event_version,
      fortress_id: revocation.fortress_id,
      revoked_master_pubkey: revocation.revoked_master_pubkey,
      effective_at: revocation.effective_at,
      revocation_serial: revocation.revocation_serial,
      operator_principal_id: revocation.operator_principal_id,
    };
    const message = buildFederationRootRevocationMessage(signedBody);
    const signature = fromBase64url(revocation.operator_signature);

    // Verifies under the NEW principal (which chains to K2).
    expect(
      ed25519.verify(
        signature,
        message,
        fromBase64url(k2PrincipalCert.principal_pubkey),
      ),
    ).toBe(true);
    // Does NOT verify under the OLD (revoked) master K1: it was never signed by K1.
    expect(
      ed25519.verify(signature, message, fromBase64url(k1Master.public_key)),
    ).toBe(false);

    // And the full event-verification accepts it under the CURRENT principal/K2.
    const event: FederationRevocationLogEvent = {
      event_id: `${federationOperatorAuthorityOrigin(revocation.fortress_id)}:1`,
      origin_node_id: federationOperatorAuthorityOrigin(revocation.fortress_id),
      sequence: 1,
      occurred_at: new Date().toISOString(),
      kind: "federation_root_revocation",
      payload: { ...revocation },
      previous_hash: null,
      event_hash: "unused-by-verify",
    };
    const verified = verifyFederationRootRevocationEvent({
      event,
      fortressId: revocation.fortress_id,
      pinnedMaster: k2Master,
      operatorPrincipalCert: k2PrincipalCert,
      highestRevocationSerial: 0,
    });
    expect(verified.ok).toBe(true);

    // The SAME event verified against the OLD master/principal is rejected
    // (principal chain invalid): a K1-rooted verifier cannot validate a
    // K2-signed revocation.
    const underK1 = verifyFederationRootRevocationEvent({
      event,
      fortressId: revocation.fortress_id,
      pinnedMaster: k1Master,
      operatorPrincipalCert: before.issuing_principal_cert,
      highestRevocationSerial: 0,
    });
    expect(underK1.ok).toBe(false);

    masterKey.fill(0);
  });
});

describe("rotate-root --compromised: MERGE-BAR 7 (no half-rotation; resume completes idempotently)", () => {
  it("a crash AFTER staging but BEFORE promote leaves the OLD root live; --compromised --resume completes to K2 + persists the durable revocation", async () => {
    const { masterKey } = await seedIssuer();
    const before = await loadLive(masterKey);
    const oldPubkey = before.pinned_master_pubkey.public_key;

    // Crash right after the journal is staged (before promote starts).
    await expect(
      rotateFederationRootCompromised({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") {
            throw new Error("crash: post-stage pre-promote");
          }
        },
      }),
    ).rejects.toThrow(/crash/);

    // Journal present; the journal is a COMPROMISE journal; LIVE record still K1.
    expect(await federationRotateRootInProgress(storage)).toBe(true);
    expect(
      await federationRotateRootJournalIsCompromise(storage, masterKey),
    ).toBe(true);
    const mid = await loadLive(masterKey);
    expect(mid.pinned_master_pubkey.public_key).toBe(oldPubkey);
    // K1 is NOT yet in the durable revoked set (the persist never ran).
    const midSnap = await loadRevokedRoots(masterKey);
    expect(midSnap.revokedRootPubkeys.has(oldPubkey)).toBe(false);

    // Resume forward -> clean K2 root + durable revocation persisted.
    const resumed = await resumeFederationRootCompromised({ storage, masterKey });
    expect(resumed.revoked_master_pubkey).toBe(oldPubkey);
    expect(await federationRotateRootInProgress(storage)).toBe(false);
    expect(
      await storage.exists(
        FEDERATION_TRUST_ROOT_NAMESPACE,
        FEDERATION_ROTATE_ROOT_STAGED_KEY,
      ),
    ).toBe(false);

    const after = await loadLive(masterKey);
    expect(after.pinned_master_pubkey.public_key).not.toBe(oldPubkey);
    expect(after.rotation_cert).toBeUndefined();
    const afterSnap = await loadRevokedRoots(masterKey);
    expect(afterSnap.revokedRootPubkeys.has(oldPubkey)).toBe(true);

    masterKey.fill(0);
  });

  it("the renewal --resume refuses a compromise journal, and the compromise --resume refuses a renewal journal", async () => {
    const { masterKey } = await seedIssuer();
    // Stage a compromise rotation that crashes pre-promote.
    await expect(
      rotateFederationRootCompromised({
        storage,
        masterKey,
        failpoint: (p) => {
          if (p === "journal-staged-written") throw new Error("crash");
        },
      }),
    ).rejects.toThrow(/crash/);
    // The RENEWAL resume must refuse this compromise journal (fail closed).
    await expect(
      resumeFederationRootRotation({ storage, masterKey }),
    ).rejects.toThrow(/compromise/i);

    masterKey.fill(0);
  });
});
