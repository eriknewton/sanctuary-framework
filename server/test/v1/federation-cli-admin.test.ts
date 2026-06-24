/**
 * Federation Slice 3b -- operator-signed admin CLI verb tests.
 *
 * Covers `sanctuary federation enable / disable / authorize` and
 * `join --persist`. The verbs are thin clients of the existing
 * `/v1/federation/*` endpoints: each opens the local fortress headless
 * (keychain-safe, no modal), resolves the DEFAULT operator identity, and
 * produces the inline OPERATOR_SIGNED signature the server independently
 * verifies. These tests assert:
 *   (a) the verbs FAIL CLOSED without an unlocked operator identity;
 *   (b) the signature the verb produces is the one the server's
 *       `verifyOperatorSignature` accepts (operator-signed, no bypass);
 *   (c) `--persist` uses an OUT-OF-BAND pinned master and refuses a cert that
 *       does not chain to it.
 *
 * Each verb opens a REAL temp fortress seeded keychain-free by the drill seed,
 * so these tests also exercise the no-modal headless unlock path end to end.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  runFederationAuthorize,
  runFederationEnableDisable,
  runFederationJoin,
} from "../../src/cli/federation.js";
import { verifyOperatorSignature } from "../../src/v1/operator-signed.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { mintFederationTrustRootRecord } from "../../src/mesh/federation-trust-root-store.js";
import {
  seedFederationIssuerFortress,
  type SeededIssuerFortress,
} from "../util/federation-drill-seed.js";
import { makeIssuerCompleteResponder } from "./federation-real-join.js";
import { toBase64url } from "../../src/core/encoding.js";
import { JoinCeremony } from "../../src/v1/federation.js";
import { issuerContextWithApprover } from "./federation-real-join.js";

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

let fortressPath: string;
let issuer: SeededIssuerFortress;
const PASSPHRASE = "slice3b-drill-passphrase";

beforeEach(async () => {
  fortressPath = await mkdtemp(join(tmpdir(), "slice3b-"));
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  issuer = await seedFederationIssuerFortress({
    storage,
    passphrase: PASSPHRASE,
    nodeId: "home-mac",
  });
  issuer.masterKey.fill(0);
});

afterEach(async () => {
  await rm(fortressPath, { recursive: true, force: true });
});

describe("federation enable/disable -- operator-signed, fail-closed", () => {
  it("fails closed (exit 3) when no operator credential is supplied (keychain-safe)", async () => {
    const err = capture();
    const code = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", "http://127.0.0.1:9", "--fortress", fortressPath],
      env: {},
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new Error("request should not be reached without an operator identity");
      },
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
  });

  it("produces an operator signature the server's verifyOperatorSignature accepts", async () => {
    let captured: { action: string; body: Record<string, unknown> } | null = null;
    const out = capture();
    const code = await runFederationEnableDisable({
      enable: true,
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--idempotency-key",
        "idem-1",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
      request: async (path, init) => {
        captured = {
          action: path,
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        };
        return { enabled: true };
      },
    });
    expect(code).toBe(0);
    expect(captured).not.toBeNull();
    const { action, body } = captured!;
    expect(action).toBe("/v1/federation/enable");
    expect(typeof body.operator_signature).toBe("string");

    // Reconstruct the SERVER-side signed payload (server includes
    // idempotency_key only when it is a string; never the signature itself).
    const signedPayload: Record<string, unknown> = { idempotency_key: body.idempotency_key };
    const ok = verifyOperatorSignature({
      action,
      payload: signedPayload,
      signature: body.operator_signature as string,
      operatorPublicKey: issuer.operator.publicKey,
    });
    expect(ok).toBe(true);
  });

  it("surfaces a 503 from the server as fail-closed not-provisioned (exit 3)", async () => {
    const { DashboardRequestError } = await import("../../src/cli/dashboard-request.js");
    const err = capture();
    const code = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", "http://127.0.0.1:9", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new DashboardRequestError("unavailable", "server", 503);
      },
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/not provisioned/);
  });
});

describe("federation authorize -- operator-signed bootstrap token", () => {
  it("fails closed (exit 3) without an operator credential", async () => {
    const err = capture();
    const code = await runFederationAuthorize({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
      ],
      env: {},
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new Error("request should not be reached without an operator identity");
      },
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
  });

  it("exits 1 when --node-id is missing", async () => {
    const err = capture();
    const code = await runFederationAuthorize({
      argv: ["--fortress-url", "http://127.0.0.1:9", "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--node-id/);
  });

  it("signs authorize/init with the operator key and prints the bootstrap token", async () => {
    let captured: { action: string; body: Record<string, unknown> } | null = null;
    const out = capture();
    const code = await runFederationAuthorize({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
        "--node-mode",
        "local",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
      request: async (path, init) => {
        captured = {
          action: path,
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        };
        return { bootstrap_token: { intended_node_id: "joiner-linux", nonce: "n" } };
      },
    });
    expect(code).toBe(0);
    const { action, body } = captured!;
    expect(action).toBe("/v1/federation/authorize/init");
    const ok = verifyOperatorSignature({
      action,
      payload: {
        intended_node_id: body.intended_node_id,
        intended_node_mode: body.intended_node_mode,
      },
      signature: body.operator_signature as string,
      operatorPublicKey: issuer.operator.publicKey,
    });
    expect(ok).toBe(true);
    const printed = JSON.parse(out.get()) as { bootstrap_token: { intended_node_id: string } };
    expect(printed.bootstrap_token.intended_node_id).toBe("joiner-linux");
  });

  it("accepts the `authorize init` two-word form", async () => {
    const code = await runFederationAuthorize({
      argv: [
        "init",
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
      request: async () => ({ bootstrap_token: { intended_node_id: "joiner-linux" } }),
    });
    expect(code).toBe(0);
  });
});

describe("federation join --persist -- out-of-band pinned master", () => {
  it("exits 1 when --persist is set without --pinned-master", async () => {
    const err = capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--bootstrap-token",
        "{}",
        "--master-secret",
        "AA",
        "--persist",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--pinned-master/);
  });

  it("exits 1 when --persist is set without a custody credential", async () => {
    const pinnedMaster = JSON.stringify(issuer.pinnedMaster);
    const err = capture();
    const code = await runFederationJoin({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--bootstrap-token",
        "{}",
        "--master-secret",
        "AA",
        "--persist",
        "--pinned-master",
        pinnedMaster,
      ],
      env: {},
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/unlocked operator identity|SANCTUARY_PASSPHRASE/);
  });

  it("persists a joiner trust root from a REAL join and refuses a non-chaining cert", async () => {
    // The issuer responder runs the REAL JoinCeremony against the JoinRequest the
    // VERB submits, so the issued cert binds to the verb's freshly-generated node
    // keypair (the cert pubkey matches the node key the verb persists). The CLI
    // persists against the OUT-OF-BAND pinned master and must REFUSE a cert that
    // does not chain to it.
    const respond = makeIssuerCompleteResponder(issuer);
    const masterSecretB64 = toBase64url(issuer.masterSecret);
    // A real bootstrap token minted by the issuer (operator authorizing the join).
    const bootstrapToken = new JoinCeremony(issuerContextWithApprover(issuer)).authorizeInit({
      intendedNodeId: "joiner-linux",
      intendedNodeMode: "local",
    });

    // Seed an isolated JOINER fortress (custody + default operator identity).
    const joinerPath = await mkdtemp(join(tmpdir(), "slice3b-joiner-"));
    try {
      const joinerStorage = new FilesystemStorage(join(joinerPath, "state"));
      const { seedCustodyAndOperator } = await import("../util/federation-drill-seed.js");
      const seeded = await seedCustodyAndOperator({
        storage: joinerStorage,
        passphrase: PASSPHRASE,
      });
      seeded.masterKey.fill(0);

      // CORRECT pinned master -> persist succeeds (exit 0, persisted: true).
      const out = capture();
      const okCode = await runFederationJoin({
        argv: [
          "--fortress-url",
          "http://127.0.0.1:9",
          "--bootstrap-token",
          JSON.stringify(bootstrapToken),
          "--master-secret",
          masterSecretB64,
          "--persist",
          "--pinned-master",
          JSON.stringify(issuer.pinnedMaster),
          "--fortress",
          joinerPath,
        ],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: out.stream,
        err: capture().stream,
        request: respond as never,
      });
      expect(okCode).toBe(0);
      const printed = JSON.parse(out.get()) as { joined: boolean; persisted: boolean };
      expect(printed.joined).toBe(true);
      expect(printed.persisted).toBe(true);

      // WRONG pinned master (a different fortress) -> refuse to persist (exit 3).
      const foreign = mintFederationTrustRootRecord({ nodeId: "foreign" });
      const err2 = capture();
      const refuseCode = await runFederationJoin({
        argv: [
          "--fortress-url",
          "http://127.0.0.1:9",
          "--bootstrap-token",
          JSON.stringify(bootstrapToken),
          "--master-secret",
          masterSecretB64,
          "--persist",
          "--pinned-master",
          JSON.stringify(foreign.pinned_master_pubkey),
          "--fortress",
          joinerPath,
        ],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: capture().stream,
        err: err2.stream,
        request: respond as never,
      });
      expect(refuseCode).toBe(3);
      expect(err2.get()).toMatch(/refused to persist/);
    } finally {
      await rm(joinerPath, { recursive: true, force: true });
    }
  });
});
