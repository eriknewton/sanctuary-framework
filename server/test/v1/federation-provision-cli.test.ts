/**
 * Federation issuer-provision CLI verb tests -- `sanctuary federation provision`
 * (alias `init-issuer`). This verb MINTS the cross-machine root of trust, so the
 * tests are the security teeth of a CRITICAL surface:
 *
 *   (a) mint on a clean already-init'd fortress -> exit 0, the issuer record
 *       exists, the pinned_master is printed, and the post-state byte-equals what
 *       `seedFederationIssuerFortress` produces (a real dashboard boots the
 *       persisted record as provisioned + an operator identity loaded);
 *   (b) REFUSE-IF-ISSUER-RECORD-EXISTS -> exit 3, the on-disk record UNCHANGED;
 *   (c) REFUSE-IF-JOINER-RECORD-EXISTS (split-brain) -> exit 3;
 *   (d) REFUSE-IF-CORRUPT-RECORD -> exit 3, byte-unchanged (refuse without
 *       decrypt-and-overwrite);
 *   (e) fail-closed custody: no passphrase / wrong passphrase / no operator
 *       identity -> exit 3, NO record written;
 *   (f) no-secret-leak: stdout + the mint audit entry contain ZERO secret bytes;
 *   (g) end-to-end: after provision, `federation enable` + `authorize` succeed
 *       against a REAL booted dashboard (the admin-session rig).
 *
 * Each test seeds a REAL temp fortress keychain-free (the drill seed:
 * `establishMaster` headless, no recovery-key disk fallback), so the verb's REAL
 * `openOperatorSigner` keychain-safe unlock path is exercised end to end.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { runFederationProvision } from "../../src/cli/federation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { AuditLog } from "../../src/operational/audit-log.js";
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
  provisionOrLoadFederationTrustRoot,
  verifyHybridFederationChain,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import {
  seedCustodyAndOperator,
  seedFederationIssuerFortress,
} from "../util/federation-drill-seed.js";
import { startRig, type TestRig } from "./rig.js";

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

const PASSPHRASE = "provision-drill-passphrase";

let fortressPath: string;
let statePath: string;
let storage: FilesystemStorage;

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "provision-"));
  statePath = join(fortressPath, "state");
  storage = new FilesystemStorage(statePath);
});

afterEach(async () => {
  // maxRetries/retryDelay: the e2e rig writes to fortress storage; on Linux a
  // late storage flush into state/_meta can race the recursive remove and
  // surface ENOTEMPTY. Retrying drains the transient race (Node's documented
  // remedy for EBUSY/ENOTEMPTY on rm).
  await rm(fortressPath, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 50,
  });
});

/** Seed custody + a DEFAULT operator identity (NO trust root) -- the precondition. */
async function seedInitializedFortress(): Promise<void> {
  const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
  seeded.masterKey.fill(0);
}

describe("federation provision -- mint the issuer trust root (P1, post-state parity)", () => {
  it("mints on a clean already-init'd fortress (exit 0), persists ciphertext, prints pinned_master", async () => {
    await seedInitializedFortress();
    const out = capture();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    // The issuer record now exists as AES-GCM ciphertext.
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(true);
    const raw = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    expect(bytesToString(raw!)).toContain('"alg":"aes-256-gcm"');

    // The printed JSON carries ONLY safe public material + the pinned master.
    const printed = JSON.parse(out.get()) as {
      provisioned: boolean;
      fortress_id: string;
      node_id: string;
      pinned_master: { public_key: string; fortress_id: string; created_at: string };
    };
    expect(printed.provisioned).toBe(true);
    expect(printed.node_id).toBe("home-mac");
    expect(printed.pinned_master.fortress_id).toBe(printed.fortress_id);
    expect(printed.pinned_master.public_key.length).toBeGreaterThan(0);
    expect(printed.pinned_master.created_at.length).toBeGreaterThan(0);
  });

  it("P2 post-state parity: the minted record boots a real dashboard provisioned + enables OPERATOR_SIGNED", async () => {
    // Seed custody + the SEEDED operator identity, then PROVISION via the verb.
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    // LOAD the persisted record (mint:false) -- exactly the production boot path
    // (`dashboard-standalone.ts`, mint:false). This is the post-state the marquee
    // boot->enable->authorize chain depends on.
    const loaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
    });
    expect(loaded?.source).toBe("persisted");
    expect(loaded?.record.node_id).toBe("home-mac");
    masterKey.fill(0);

    // Boot a REAL dashboard whose operator identity is the SEEDED operator key,
    // with the loaded issuer context. status -> provisioned + enable succeeds via
    // an operator-signed call by the SAME operator identity that minted.
    const { openOperatorSigner } = await import(
      "../../src/cli/federation-operator-signing.js"
    );
    const { openV1Session } = await import("../../src/cli/v1-session.js");
    const { runFederationEnableDisable } = await import("../../src/cli/federation.js");

    const rig: TestRig = await startRig({ operatorPublicKey: seeded.operator.publicKey });
    rig.dashboard.setFederationContext(loaded!.context);
    try {
      // Read status with a session token opened by the seeded operator.
      const signer = await openOperatorSigner({ passphrase: PASSPHRASE, fortressPath });
      let token: string;
      try {
        const session = await openV1Session(
          { dashboardUrl: rig.baseUrl },
          { buildAttestation: (pk) => signer.signAttestation(pk, Date.now()) },
        );
        token = session.token;
      } finally {
        signer.masterKey.fill(0);
      }

      const statusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(statusRes.status).toBe(200);
      const status = (await statusRes.json()) as Record<string, unknown>;
      expect(status).toEqual(
        expect.objectContaining({
          provisioned: true,
          enabled: false,
          fortress_id: loaded!.record.pinned_master_pubkey.fortress_id,
          node_id: "home-mac",
        }),
      );

      // enable via the REAL verb (opens its own /v1 session, signs with the
      // seeded operator identity the verb resolved from the provisioned fortress).
      const enErr = capture();
      const enableCode = await runFederationEnableDisable({
        enable: true,
        argv: ["--fortress-url", rig.baseUrl, "--fortress", fortressPath],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: capture().stream,
        err: enErr.stream,
      });
      expect(enableCode, `stderr: ${enErr.get()}`).toBe(0);
    } finally {
      await rig.stop();
    }
  });

  it("alias init-issuer mints identically (exit 0)", async () => {
    await seedInitializedFortress();
    const { runFederationCommand } = await import("../../src/cli/federation.js");
    const out = capture();
    const err = capture();
    const code = await runFederationCommand({
      argv: ["init-issuer", "--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(true);
  });
});

describe("federation provision -- refuse-if-exists (the orphan footgun)", () => {
  it("N1 refuses if an ISSUER record already exists (exit 3), record BYTE-UNCHANGED", async () => {
    // A full issuer fortress already (seed mints the issuer root).
    const issuer = await seedFederationIssuerFortress({
      storage,
      passphrase: PASSPHRASE,
      nodeId: "home-mac",
    });
    issuer.masterKey.fill(0);
    const before = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );

    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac-2", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/already has a federation trust root|orphan/);
    expect(err.get()).toMatch(/rotate-root/);

    const after = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    expect(after).toEqual(before);
  });

  it("idempotent-safe: a second provision run refuses, never a second root", async () => {
    await seedInitializedFortress();
    const first = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(first).toBe(0);
    const minted = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );

    const err = capture();
    const second = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(second).toBe(3);
    expect(err.get()).toMatch(/already has a federation trust root/);
    const after = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    expect(after).toEqual(minted);
  });

  it("N2 refuses if a JOINER record exists (split-brain, exit 3)", async () => {
    // Seed custody + operator, then plant a joiner record (an issuer mint reused
    // as the joiner-namespace blob is enough for the raw existence probe; the
    // verb refuses WITHOUT decrypting, so any bytes there block).
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    seeded.masterKey.fill(0);
    await storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      stringToBytes(JSON.stringify({ planted: "joiner-record" })),
    );

    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/JOINER|split-brain/);
    // No issuer record was minted.
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("N3 refuses over a CORRUPT issuer record (exit 3), byte-unchanged (no decrypt-and-overwrite)", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    seeded.masterKey.fill(0);
    // Garbage ciphertext at the issuer key: a record that EXISTS but cannot decrypt.
    const garbage = stringToBytes(
      JSON.stringify({
        v: 1,
        alg: "aes-256-gcm",
        iv: "not-valid",
        ct: "not-valid",
        ts: new Date().toISOString(),
      }),
    );
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      garbage,
    );
    const before = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );

    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/already has a federation trust root|orphan/);
    const after = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    expect(after).toEqual(before);
  });
});

describe("federation provision -- fail-closed custody (no unsigned mint, no keychain modal)", () => {
  it("N7 exits 1 when --node-id is missing", async () => {
    await seedInitializedFortress();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--node-id/);
  });

  it("N4 fails closed (exit 3) with NO credential, keychain-safe, no record written", async () => {
    await seedInitializedFortress();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: {},
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("N5 fails closed (exit 3) with the WRONG passphrase, no record written", async () => {
    await seedInitializedFortress();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: "the-wrong-passphrase" },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("N6 fails closed (exit 3) when custody exists but there is NO default operator identity", async () => {
    // Custody only -- no operator identity (skip seedCustodyAndOperator's identity).
    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    masterKey.fill(0);

    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/operator identity/);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });
});

describe("federation provision -- no-secret-leak (constraint 6)", () => {
  it("N8 stdout + the mint audit entry contain ZERO secret bytes", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    const out = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    // Load the persisted record under the custody master to learn the secrets
    // that MUST NOT have leaked.
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(loaded).not.toBeNull();
    const record = loaded!.record;
    const secrets = [
      toBase64url(record.master_secret),
      toBase64url(record.master_private_key!),
      toBase64url(record.issuing_principal_private_key),
      toBase64url(record.local_node_private_key),
    ];

    // stdout: zero occurrences of any secret.
    const stdout = out.get();
    for (const secret of secrets) {
      expect(stdout).not.toContain(secret);
    }

    // The mint audit entry (read back via a fresh AuditLog over the same fortress
    // under the custody master): zero occurrences of any secret in the decrypted
    // event detail JSON.
    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_trust_root_mint",
      limit: 100,
    });
    expect(entries.length).toBeGreaterThan(0);
    const auditJson = JSON.stringify(entries);
    for (const secret of secrets) {
      expect(auditJson).not.toContain(secret);
    }
    // The attribution detail is present (the operator PUBLIC key -- safe to log).
    expect(auditJson).toContain("operator_pubkey");
    expect(auditJson).toContain(toBase64url(seeded.operator.publicKey));
    masterKey.fill(0);
  });
});

describe("federation provision -- PQC default-on (hybrid is the default; --classical opts out)", () => {
  it("merge-bar 1 (default flip): a bare provision (no crypto flag) is HYBRID and prints the version-requirement note", async () => {
    await seedInitializedFortress();
    const out = capture();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    // PQC default-on: NO flag -> HYBRID issuance; output declares the hybrid suite
    // and the hybrid pinned master is printed alongside the classical one.
    const printed = JSON.parse(out.get()) as {
      issuance_suite: string;
      pinned_master: { public_key: string };
      hybrid_pinned_master?: {
        signature_suite: string;
        public_keys: {
          ed25519: { public_key: string };
          ml_dsa_65: { public_key: string };
        };
      };
    };
    expect(printed.issuance_suite).toBe("ed25519+ml-dsa-v1");
    expect(printed.pinned_master.public_key.length).toBeGreaterThan(0);
    expect(printed.hybrid_pinned_master).toBeDefined();
    expect(printed.hybrid_pinned_master!.signature_suite).toBe("ed25519+ml-dsa-v1");
    expect(
      printed.hybrid_pinned_master!.public_keys.ml_dsa_65.public_key.length,
    ).toBeGreaterThan(0);

    // The default note states the scope honestly (no overclaim) AND the
    // version-requirement trade plainly; it is on stderr, not in the stdout JSON.
    expect(err.get()).toMatch(/DEFAULT hybrid/);
    expect(err.get()).toMatch(/does NOT make audit/);
    expect(err.get()).toMatch(/hybrid-capable Sanctuary version/);
    // Disclosure-at-decision-point: the default note warns the hybrid root is not
    // yet rotatable / compromise-revocable in place (so the operator learns it
    // BEFORE they are stuck), and names --classical as the in-place-rotation path.
    expect(err.get()).toMatch(/cannot yet be rotated or compromise-revoked/);

    // The persisted record is hybrid (carries the hybrid block + 4032-byte secret).
    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(loaded!.record.hybrid).toBeDefined();
    expect(
      loaded!.record.hybrid!.master_private_keys.ml_dsa_65.secret_key.length,
    ).toBe(4032);
    masterKey.fill(0);
  });

  it("merge-bar 2 (opt-out): --classical mints a CLASSICAL root and prints the back-compat note", async () => {
    await seedInitializedFortress();
    const out = capture();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath, "--classical"],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    // --classical -> classical issuance; output declares the classical suite and
    // NO hybrid pinned master is printed (the unchanged old-default behavior).
    const printed = JSON.parse(out.get()) as {
      issuance_suite: string;
      hybrid_pinned_master?: unknown;
    };
    expect(printed.issuance_suite).toBe("ed25519-v1");
    expect(printed.hybrid_pinned_master).toBeUndefined();

    // The inverse note: classical opt-out, no post-quantum protection, max back-compat.
    expect(err.get()).toMatch(/OPT-OUT classical/);
    expect(err.get()).toMatch(/NO post-quantum protection/);

    // The persisted record is classical (no hybrid fields).
    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(loaded!.record.hybrid).toBeUndefined();
    masterKey.fill(0);
  });

  it("merge-bar 2 (opt-out): --crypto-suite ed25519-v1 mints a CLASSICAL root (alias of --classical)", async () => {
    await seedInitializedFortress();
    const out = capture();
    const err = capture();
    const code = await runFederationProvision({
      argv: [
        "--node-id",
        "home-mac",
        "--fortress",
        fortressPath,
        "--crypto-suite",
        "ed25519-v1",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    const printed = JSON.parse(out.get()) as {
      issuance_suite: string;
      hybrid_pinned_master?: unknown;
    };
    expect(printed.issuance_suite).toBe("ed25519-v1");
    expect(printed.hybrid_pinned_master).toBeUndefined();
    expect(err.get()).toMatch(/OPT-OUT classical/);
  });

  it("merge-bar 4 (default chain verifies): the default hybrid root verifies both-must-pass AND its Ed25519 component verifies", async () => {
    await seedInitializedFortress();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    const hybrid = loaded!.record.hybrid!;
    expect(hybrid).toBeDefined();
    // both-must-pass over the persisted hybrid chain.
    await expect(verifyHybridFederationChain(hybrid)).resolves.toBeUndefined();
    // The Ed25519 component of the hybrid pinned master is a real 32-byte key, so
    // the hybrid root still carries a verifiable Ed25519 chain for current peers.
    expect(
      fromBase64url(hybrid.pinned_master.public_keys.ed25519.public_key).length,
    ).toBe(32);
    masterKey.fill(0);
  });

  it("rejects --classical AND --pqc-hybrid together (exit 1, nothing minted)", async () => {
    await seedInitializedFortress();
    const err = capture();
    const code = await runFederationProvision({
      argv: [
        "--node-id",
        "home-mac",
        "--fortress",
        fortressPath,
        "--classical",
        "--pqc-hybrid",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/mutually/);
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("--pqc-hybrid still provisions hybrid (now a no-op-but-accepted alias of the default)", async () => {
    await seedInitializedFortress();
    const out = capture();
    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath, "--pqc-hybrid"],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);

    const printed = JSON.parse(out.get()) as {
      issuance_suite: string;
      pinned_master: { public_key: string };
      hybrid_pinned_master?: {
        signature_suite: string;
        public_keys: {
          ed25519: { public_key: string };
          ml_dsa_65: { public_key: string };
        };
      };
    };
    expect(printed.issuance_suite).toBe("ed25519+ml-dsa-v1");
    expect(printed.pinned_master.public_key.length).toBeGreaterThan(0);
    expect(printed.hybrid_pinned_master).toBeDefined();
    expect(printed.hybrid_pinned_master!.signature_suite).toBe("ed25519+ml-dsa-v1");
    expect(
      printed.hybrid_pinned_master!.public_keys.ml_dsa_65.public_key.length,
    ).toBeGreaterThan(0);

    // Same DEFAULT note (no overclaim) as the bare-provision path.
    expect(err.get()).toMatch(/DEFAULT hybrid/);
    expect(err.get()).toMatch(/does NOT make audit/);

    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(loaded!.record.hybrid).toBeDefined();
    expect(
      loaded!.record.hybrid!.master_private_keys.ml_dsa_65.secret_key.length,
    ).toBe(4032);
    masterKey.fill(0);
  });

  it("merge-bar 4 (CLI no-leak): a hybrid provision leaks NO ML-DSA secret to stdout or the audit entry", async () => {
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);

    const out = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath, "--pqc-hybrid"],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
    });
    expect(code).toBe(0);

    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    const hybrid = loaded!.record.hybrid!;
    const secrets = [
      toBase64url(hybrid.master_private_keys.ml_dsa_65.secret_key),
      toBase64url(hybrid.master_private_keys.ed25519.private_key),
      toBase64url(hybrid.issuing_principal_private_keys.ml_dsa_65.secret_key),
      toBase64url(hybrid.local_node_private_keys.ml_dsa_65.secret_key),
    ];
    const stdout = out.get();
    for (const secret of secrets) expect(stdout).not.toContain(secret);

    const auditLog = new AuditLog(storage, masterKey);
    const { entries } = await auditLog.query({
      operation_type: "federation_trust_root_mint",
      limit: 100,
    });
    const auditJson = JSON.stringify(entries);
    for (const secret of secrets) expect(auditJson).not.toContain(secret);
    // The suite is recorded for attribution (PUBLIC metadata, no secret).
    expect(auditJson).toContain("ed25519+ml-dsa-v1");
    masterKey.fill(0);
  });

  it("rejects an unknown --crypto-suite (exit 1)", async () => {
    await seedInitializedFortress();
    const err = capture();
    const code = await runFederationProvision({
      argv: [
        "--node-id",
        "home-mac",
        "--fortress",
        fortressPath,
        "--crypto-suite",
        "rsa-9999",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--crypto-suite/);
    // Nothing was minted.
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });
});

describe("federation provision -- defensive race (record appears between probe and mint)", () => {
  it("refuses (exit 3) if a record raced in: source:persisted is treated as a refusal", async () => {
    // Drive the verb with an injected signer whose storage already has a valid
    // issuer record but whose `exists` lies (returns false) so the existence
    // probe passes and the mint primitive's load-first guard is what catches it.
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    const masterKey = Uint8Array.from(seeded.masterKey);
    seeded.masterKey.fill(0);
    // Pre-mint a real issuer record so the primitive loads it (source:persisted).
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "raced-in",
    });

    const operatorPublicKey = ed25519.getPublicKey(randomBytes(32));
    // Storage that LIES on `exists` (always false) but delegates every real op to
    // the underlying fortress storage. This forces the existence probe to pass so
    // the mint primitive's own load-first guard (source:"persisted") is the layer
    // that catches the raced-in record -- proving the verb treats that as a refusal.
    const lyingStorage = {
      exists: async () => false,
      read: storage.read.bind(storage),
      write: storage.write.bind(storage),
      delete: storage.delete.bind(storage),
      list: storage.list.bind(storage),
      totalSize: storage.totalSize.bind(storage),
    };
    const lyingSigner = (async () => ({
      operatorPublicKey,
      storage: lyingStorage,
      masterKey: Uint8Array.from(masterKey),
      signPayload: () => "",
      signAttestation: () => ({
        type: "operator_ed25519" as const,
        operator_pubkey: "",
        issued_at: 0,
        signature: "",
      }),
    })) as never;

    const err = capture();
    const code = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
      openSigner: lyingSigner,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/already has a federation trust root|refusing to mint a second/);
    masterKey.fill(0);
  });
});

describe("federation provision -- end-to-end (g): provision then enable + authorize", () => {
  let rig: TestRig;
  let operatorPublicKey: Uint8Array;

  beforeEach(async () => {
    // A fresh fortress with custody + a default operator identity (NO trust root).
    const seeded = await seedCustodyAndOperator({ storage, passphrase: PASSPHRASE });
    operatorPublicKey = Uint8Array.from(seeded.operator.publicKey);
    seeded.masterKey.fill(0);
  });

  afterEach(async () => {
    if (rig) await rig.stop();
  });

  it("provision -> enable -> authorize all succeed against a REAL dashboard", async () => {
    // 1) PROVISION via the verb (mints the issuer root in the real fortress).
    const provCode = await runFederationProvision({
      argv: ["--node-id", "home-mac", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(provCode).toBe(0);

    // 2) Load the minted issuer context (production boot path) into a REAL
    // dashboard that resolves the SAME seeded operator identity.
    const loaded = await loadProvisionedIssuerContext();
    const { runFederationEnableDisable, runFederationAuthorize } = await import(
      "../../src/cli/federation.js"
    );
    rig = await startRig({ operatorPublicKey });
    rig.dashboard.setFederationContext(loaded.context);

    // 3) enable
    const enErr = capture();
    const enableCode = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", rig.baseUrl, "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: enErr.stream,
    });
    expect(enableCode, `stderr: ${enErr.get()}`).toBe(0);

    // 4) authorize -> a bootstrap token for a joining node
    const auOut = capture();
    const auErr = capture();
    const authorizeCode = await runFederationAuthorize({
      argv: [
        "--fortress-url",
        rig.baseUrl,
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
        "--node-mode",
        "local",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: auOut.stream,
      err: auErr.stream,
    });
    expect(authorizeCode, `stderr: ${auErr.get()}`).toBe(0);
    const printed = JSON.parse(auOut.get()) as {
      bootstrap_token: { intended_node_id: string };
    };
    expect(printed.bootstrap_token.intended_node_id).toBe("joiner-linux");
  });

  /** Load the provisioned issuer context from the real fortress (mint:false). */
  async function loadProvisionedIssuerContext() {
    const { masterKey } = await establishMaster({
      storage,
      passphrase: PASSPHRASE,
      firstRun: { installMode: "headless", mintRecoveryKey: false },
    });
    try {
      const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
      if (loaded === null) throw new Error("expected a provisioned issuer record");
      return loaded;
    } finally {
      masterKey.fill(0);
    }
  }
});
