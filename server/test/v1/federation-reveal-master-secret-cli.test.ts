/**
 * Federation reveal-master-secret CLI verb tests --
 * `sanctuary federation reveal-master-secret`.
 *
 * This verb DISCLOSES the fortress issuer master secret (the 32-byte symmetric
 * HKDF source a joining machine feeds to `federation join --master-secret`), so
 * the tests are the security teeth of a custody-core surface:
 *
 *   (a) succeeds (exit 0) and emits the correct base64url for a provisioned
 *       issuer with custody unlocked + the confirm flag;
 *   (b) FAILS CLOSED (exit 3) with NO custody credential, keychain-safe, nothing
 *       revealed;
 *   (c) FAILS (exit 1) without the confirm flag, BEFORE custody is even unlocked,
 *       nothing revealed;
 *   (d) ROUND-TRIP: the revealed secret is byte-identical to the SAME value the
 *       join path consumes (deriveNodeTransportKey({ fortress_master_secret }))
 *       -- i.e. a join assembled with the revealed secret matches a join
 *       assembled with the in-record secret;
 *   (e) emits a Tier-1 disclosure audit event under the operator's PUBLIC key;
 *   plus fail-closed-when-not-provisioned and refuse-over-corrupt-record.
 *
 * Each test seeds a REAL temp fortress keychain-free (the drill seed:
 * `establishMaster` headless, no recovery-key disk fallback), so the verb's REAL
 * `openOperatorSigner` keychain-safe unlock path is exercised end to end. No gate
 * is relaxed and no signer is faked on the happy path.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  runFederationRevealMasterSecret,
  assembleJoinRequest,
  runFederationCommand,
} from "../../src/cli/federation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog, AuditPersistenceError } from "../../src/operational/audit-log.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import {
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FEDERATION_TRUST_ROOT_KEY,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  seedCustodyAndOperator,
  seedFederationIssuerFortress,
} from "../util/federation-drill-seed.js";
import type { BootstrapToken } from "../../src/mesh/lifecycle/types.js";

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

const PASSPHRASE = "reveal-drill-passphrase";

let fortressPath: string;
let statePath: string;
let storage: FilesystemStorage;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "reveal-"));
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

describe("federation reveal-master-secret -- happy path (a)", () => {
  it("reveals the issuer master secret (exit 0) as base64url with --yes + custody", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const expected = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    // The revealed secret is EXACTLY the in-record master secret, base64url, 32B.
    const revealed = out.get().trim();
    expect(revealed).toBe(expected);
    expect(fromBase64url(revealed).length).toBe(32);
  });

  it("the -y alias and the dispatcher path both work", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const expected = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationCommand({
      argv: ["reveal-master-secret", "-y", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    expect(out.get().trim()).toBe(expected);
  });

  it("accepts the long-form --i-understand-this-reveals-the-master-secret confirm flag", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const expected = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--i-understand-this-reveals-the-master-secret", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    expect(out.get().trim()).toBe(expected);
  });
});

describe("federation reveal-master-secret -- confirm gate (c)", () => {
  it("REFUSES (exit 1) without a confirm flag, BEFORE unlocking custody, nothing revealed", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const secretB64 = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      // No --yes; a correct passphrase IS supplied -- the refusal must come from
      // the missing confirm flag, not custody.
      argv: ["--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--yes/);
    expect(err.get()).toMatch(/master secret/);
    // Nothing was printed to stdout.
    expect(out.get()).toBe("");
    // And the secret bytes never appeared anywhere we wrote.
    expect(out.get()).not.toContain(secretB64);
    expect(err.get()).not.toContain(secretB64);
  });
});

describe("federation reveal-master-secret -- fail-closed custody (b)", () => {
  it("fails closed (exit 3) with NO credential, keychain-safe, nothing revealed", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const secretB64 = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      // Confirmed, but NO custody credential at all.
      argv: ["--yes", "--fortress", fortressPath],
      env: {},
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
    expect(out.get()).toBe("");
    expect(out.get()).not.toContain(secretB64);
  });

  it("fails closed (exit 3) with the WRONG passphrase, nothing revealed", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const secretB64 = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: "the-wrong-passphrase" },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(out.get()).toBe("");
    expect(out.get()).not.toContain(secretB64);
  });

  it("fails closed (exit 3) when custody exists but there is NO default operator identity", async () => {
    // Custody only -- no operator identity, no trust root.
    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    masterKey.fill(0);

    const err = capture();
    const out = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/operator identity/);
    expect(out.get()).toBe("");
  });
});

describe("federation reveal-master-secret -- not provisioned / corrupt (fail closed)", () => {
  it("fails closed (exit 3) when there is no federation trust root, nothing revealed", async () => {
    // Custody + a default operator identity, but NO trust root minted.
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    seeded.masterKey.fill(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/no federation trust root|provision/);
    expect(out.get()).toBe("");
  });

  it("refuses over a CORRUPT trust-root record (exit 3), nothing revealed", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    seeded.masterKey.fill(0);
    // Garbage ciphertext at the issuer key: a record that EXISTS but cannot decrypt.
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify({
          v: 1,
          alg: "aes-256-gcm",
          iv: "not-valid",
          ct: "not-valid",
          ts: new Date().toISOString(),
        }),
      ),
    );

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/could not load|trust root/);
    expect(out.get()).toBe("");
  });
});

describe("federation reveal-master-secret -- round-trip with join (d)", () => {
  it("the revealed secret feeds join byte-identically to the in-record secret", async () => {
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    // The in-record master secret (what the seed exposes out of band) is the
    // authoritative comparison value -- the SAME bytes a real join consumes.
    const inRecordSecret = Uint8Array.from(issuer.masterSecret);
    issuer.masterKey.fill(0);

    const out = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    // Decode the revealed base64url EXACTLY the way `join` parses --master-secret.
    const revealedSecret = fromBase64url(out.get().trim());
    expect(revealedSecret.length).toBe(32);
    expect(Buffer.from(revealedSecret).equals(Buffer.from(inRecordSecret))).toBe(true);

    // Stronger end-to-end check: assemble a join with the REVEALED secret and a
    // join with the IN-RECORD secret. Both must produce the same HKDF salt proof,
    // proving the revealed value is what the transport-key derivation consumes.
    const bootstrapToken = {
      intended_node_id: "joiner-linux",
      intended_node_mode: "local",
      signature: "stub-signature-not-verified-here",
      nonce: "n",
      issued_at: 0,
    } as unknown as BootstrapToken;

    const joinFromRevealed = assembleJoinRequest({
      bootstrapToken,
      fortressMasterSecret: revealedSecret,
    });
    const joinFromRecord = assembleJoinRequest({
      bootstrapToken,
      fortressMasterSecret: inRecordSecret,
    });
    try {
      expect(joinFromRevealed.joinRequest.hkdf_salt_proof).toBe(
        joinFromRecord.joinRequest.hkdf_salt_proof,
      );
    } finally {
      joinFromRevealed.nodePrivateKey.fill(0);
      joinFromRecord.nodePrivateKey.fill(0);
      revealedSecret.fill(0);
      inRecordSecret.fill(0);
    }
  });
});

describe("federation reveal-master-secret -- audit (e)", () => {
  it("records a Tier-1 disclosure audit event under the operator's PUBLIC key", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const operatorPubkeyB64 = toBase64url(seeded.operator.publicKey);
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    // Provision an issuer so the reveal succeeds and emits a success audit event.
    const { runFederationProvision } = await import("../../src/cli/federation.js");
    const provCode = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(provCode).toBe(0);

    const out = capture();
    const revealCode = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
    });
    expect(revealCode).toBe(0);
    const revealed = out.get().trim();

    // A disclosure event exists, marked success, attributed to the operator's
    // PUBLIC key -- and it does NOT contain the revealed secret value.
    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_master_secret_reveal",
      limit: 100,
    });
    expect(entries.length).toBeGreaterThan(0);
    const success = entries.find((e) => e.result === "success");
    expect(success).toBeDefined();
    const auditJson = JSON.stringify(entries);
    expect(auditJson).toContain("operator_pubkey");
    expect(auditJson).toContain(operatorPubkeyB64);
    // The disclosed secret must NOT be written into the audit log.
    expect(auditJson).not.toContain(revealed);
    masterKey.fill(0);
  });

  it("records a FAILURE disclosure event when not provisioned", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(code).toBe(3);

    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_master_secret_reveal",
      limit: 100,
    });
    const failure = entries.find((e) => e.result === "failure");
    expect(failure).toBeDefined();
    expect(JSON.stringify(failure)).toContain("not_provisioned");
    masterKey.fill(0);
  });
});

describe("federation reveal-master-secret -- audit-before-disclose fail-closed (Fix 1)", () => {
  it("aborts (exit 3) and writes NOTHING to stdout when the durable success audit cannot persist", async () => {
    // A fully provisioned issuer: custody + operator + trust root all present, so
    // the verb reaches the success path and would otherwise reveal the secret.
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    const secretB64 = toBase64url(issuer.masterSecret);
    issuer.masterKey.fill(0);

    // Inject an AuditLog whose DURABLE appendCritical() rejects, simulating a
    // disk-full / permission / torn-write persistence failure on the disclosure
    // event. Everything else stays a real AuditLog.
    class FailingCriticalAuditLog extends AuditLog {
      override async appendCritical(): Promise<void> {
        throw new AuditPersistenceError(
          "simulated durable-append failure",
          "disk_full",
        );
      }
    }

    const out = capture();
    const err = capture();
    const code = await runFederationRevealMasterSecret({
      argv: ["--yes", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
      makeAuditLog: (storageArg, masterKey) =>
        new FailingCriticalAuditLog(storageArg, masterKey),
    });

    // Fail-closed: exit 3, and the master secret NEVER reached stdout.
    expect(code, `stderr: ${err.get()}`).toBe(3);
    expect(out.get()).toBe("");
    expect(out.get()).not.toContain(secretB64);
    // The operator is told WHY (the disclosure audit could not be persisted).
    expect(err.get()).toMatch(/durably record|disclosure audit|refusing/);
  });
});
