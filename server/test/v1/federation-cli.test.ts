/**
 * Federation PR-A3 — `sanctuary federation join` CLI tests.
 *
 * Covers the pure JoinRequest assembly (the HKDF proof it produces verifies
 * end-to-end through the JoinCeremony) and the command's exit-code contract:
 * usage errors, a successful submission, and the denied / unreachable paths.
 */

import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";

import { assembleJoinRequest, runFederationJoin } from "../../src/cli/federation.js";
import { JoinCeremony } from "../../src/v1/federation.js";
import { DashboardRequestError } from "../../src/cli/dashboard-request.js";
import { toBase64url } from "../../src/core/encoding.js";
import { makeFederationMaterials } from "./fed-materials.js";

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

describe("assembleJoinRequest", () => {
  it("produces a JoinRequest whose proof the ceremony accepts", async () => {
    const materials = makeFederationMaterials();
    const token = new JoinCeremony(materials.context).authorizeInit({
      intendedNodeId: "cli-node-1",
      intendedNodeMode: "local",
    });
    const assembled = assembleJoinRequest({
      bootstrapToken: token,
      fortressMasterSecret: materials.masterSecret,
    });
    expect(assembled.joinRequest.node_pubkey).toBe(toBase64url(assembled.nodePublicKey));
    expect(assembled.joinRequest.node_mode).toBe("local");

    const outcome = await new JoinCeremony(materials.context).authorizeComplete(assembled.joinRequest);
    expect(outcome.approved).toBe(true);
  });
});

describe("runFederationJoin exit codes", () => {
  const materials = makeFederationMaterials();
  const token = new JoinCeremony(materials.context).authorizeInit({
    intendedNodeId: "cli-node-2",
    intendedNodeMode: "local",
  });
  const tokenJson = JSON.stringify(token);
  const secretB64 = toBase64url(materials.masterSecret);

  const baseArgs = (extra: string[] = []) => [
    "--fortress-url",
    "http://127.0.0.1:9",
    "--bootstrap-token",
    tokenJson,
    "--master-secret",
    secretB64,
    ...extra,
  ];

  it("exits 1 when required flags are missing", async () => {
    const err = capture();
    const code = await runFederationJoin({ argv: [], env: {}, out: capture().stream, err: err.stream });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/--fortress-url/);
  });

  it("exits 1 when the bootstrap token is not valid JSON", async () => {
    const err = capture();
    const code = await runFederationJoin({
      argv: ["--fortress-url", "http://x", "--bootstrap-token", "{bad", "--master-secret", secretB64],
      env: {},
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(1);
    expect(err.get()).toMatch(/not valid JSON/);
  });

  it("exits 0 and prints the certificate on a successful submission", async () => {
    const out = capture();
    const code = await runFederationJoin({
      argv: baseArgs(),
      env: {},
      out: out.stream,
      err: capture().stream,
      request: async () => ({
        certificate: { node_id: "cli-node-2" },
        issuing_principal_cert: { principal_id: "p" },
      }),
    });
    expect(code).toBe(0);
    const printed = JSON.parse(out.get()) as { joined: boolean; node_id: string };
    expect(printed.joined).toBe(true);
    expect(printed.node_id).toBe("cli-node-2");
  });

  it("exits 3 when the fortress denies the join (auth error)", async () => {
    const err = capture();
    const code = await runFederationJoin({
      argv: baseArgs(),
      env: {},
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new DashboardRequestError("denied", "auth");
      },
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/denied/i);
  });

  it("exits 2 when the fortress is unreachable (network error)", async () => {
    const err = capture();
    const code = await runFederationJoin({
      argv: baseArgs(),
      env: {},
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new DashboardRequestError("down", "network");
      },
    });
    expect(code).toBe(2);
    expect(err.get()).toMatch(/unreachable/i);
  });
});
