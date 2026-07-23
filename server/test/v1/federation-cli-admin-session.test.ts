/**
 * Federation admin CLI verbs — /v1 session-gap regression (drill-surfaced).
 *
 * A live hardware drill (2026-06-23) caught `sanctuary federation enable |
 * disable | authorize` returning 401 Unauthorized against a REAL booted
 * dashboard: the verbs sent an EMPTY auth token, relying on loopback auto-auth.
 * But `/v1/*` endpoints are SESSION-TOKEN only — loopback auto-auth at the
 * bearer-header level covers the legacy `/api/*` convenience routes, NOT `/v1`.
 * The in-process admin unit tests masked this because they inject a `request`
 * stub that never enforces the session gate.
 *
 * This test boots a REAL DashboardApprovalChannel over a real loopback socket
 * (the live `/v1` session gate + OPERATOR_SIGNED federation perimeter) and runs
 * the actual verb with NO `--auth-token`. The verb must open its OWN /v1 session
 * (via the existing ceremony client, signing the session attestation with the
 * same already-unlocked operator identity) and use that session token.
 *
 *   - FAILS on the OLD code (empty token → 401 → exit 3).
 *   - PASSES on the FIX  (verb opens a /v1 session → 200 → exit 0).
 *
 * Keychain-free: the operator fortress is seeded by the drill seed
 * (`establishMaster` headless, no recovery-key disk fallback, no macOS modal),
 * and the daemon resolves the SAME seeded operator key, so both the session
 * attestation and the federation operator signature verify against one key.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  runFederationAuthorize,
  runFederationEnableDisable,
  runFederationRevoke,
} from "../../src/cli/federation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  seedFederationIssuerFortress,
  type SeededIssuerFortress,
} from "../util/federation-drill-seed.js";
import { startRig, type TestRig } from "./rig.js";
import { makeFederationMaterials, type FedMaterials } from "./fed-materials.js";

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

const PASSPHRASE = "admin-session-drill-passphrase";

let fortressPath: string;
let issuer: SeededIssuerFortress;
let rig: TestRig;
let materials: FedMaterials;

beforeEach(async () => {
  // Seed a REAL operator fortress keychain-free (the verb opens this to sign).
  fortressPath = await mkdtemp(join(tmpdir(), "admin-session-"));
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  issuer = await seedFederationIssuerFortress({
    storage,
    passphrase: PASSPHRASE,
    nodeId: "home-mac",
  });
  issuer.masterKey.fill(0);

  // Boot a REAL dashboard whose operator identity is the SEEDED operator key,
  // with federation provisioned (so enable/authorize can reach a 200).
  rig = await startRig({ operatorPublicKey: issuer.operator.publicKey });
  materials = makeFederationMaterials();
  rig.dashboard.setFederationContext(materials.context);
});

afterEach(async () => {
  await rig.stop();
  // maxRetries/retryDelay: recursive teardown races the OS releasing child
  // handles under parallel CI, throwing ENOTEMPTY. Bounded retries are the
  // repo's established mitigation (see audit-log-concurrent-write.test.ts).
  await rm(fortressPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
});

describe("federation admin verbs open their own /v1 session (drill 401 gap)", () => {
  it("enable succeeds against a REAL dashboard with NO --auth-token", async () => {
    const out = capture();
    const err = capture();
    const code = await runFederationEnableDisable({
      enable: true,
      // No --auth-token: the verb must open its own /v1 session.
      argv: ["--fortress-url", rig.baseUrl, "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
      // Real openV1Session + real dashboardRequest against the live socket.
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    expect(JSON.parse(out.get())).toEqual({ enabled: true });

    // The federation enable was actually honored on the real daemon.
    const statusRes = await fetch(`${rig.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${await openSessionToken()}` },
    });
    expect(((await statusRes.json()) as { enabled: boolean }).enabled).toBe(true);
  });

  it("authorize mints a bootstrap token against a REAL dashboard with NO --auth-token", async () => {
    // Enable first (authorize/init requires federation enabled).
    const enableCode = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", rig.baseUrl, "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(enableCode).toBe(0);

    const out = capture();
    const err = capture();
    const code = await runFederationAuthorize({
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
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    const printed = JSON.parse(out.get()) as {
      bootstrap_token: { intended_node_id: string };
    };
    expect(printed.bootstrap_token.intended_node_id).toBe("joiner-linux");
  });

  it("revoke emits an eviction event against a REAL dashboard with NO --auth-token", async () => {
    const enableCode = await runFederationEnableDisable({
      enable: true,
      argv: ["--fortress-url", rig.baseUrl, "--fortress", fortressPath],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: capture().stream,
      err: capture().stream,
    });
    expect(enableCode).toBe(0);

    const out = capture();
    const err = capture();
    const code = await runFederationRevoke({
      argv: [
        "--fortress-url",
        rig.baseUrl,
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
        "--reason",
        "operator_removed",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: err.stream,
    });
    expect(code, `stderr: ${err.get()}`).toBe(0);
    const printed = JSON.parse(out.get()) as {
      revoked: boolean;
      node_id: string;
      event_id: string;
      eviction_serial: number;
    };
    expect(printed).toEqual({
      revoked: true,
      node_id: "joiner-linux",
      event_id: expect.any(String),
      eviction_serial: 1,
    });
    expect(materials.context.isNodeRevoked("joiner-linux")).toBe(true);
  });
});

/** Open a durable operator session token (for the assertion-side status read). */
async function openSessionToken(): Promise<string> {
  const { openV1Session } = await import("../../src/cli/v1-session.js");
  const { openOperatorSigner } = await import(
    "../../src/cli/federation-operator-signing.js"
  );
  const signer = await openOperatorSigner({
    passphrase: PASSPHRASE,
    fortressPath,
  });
  try {
    const session = await openV1Session(
      { dashboardUrl: rig.baseUrl },
      { buildAttestation: (pk) => signer.signAttestation(pk, Date.now()) },
    );
    return session.token;
  } finally {
    signer.masterKey.fill(0);
  }
}
