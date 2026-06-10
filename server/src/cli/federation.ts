/**
 * `sanctuary federation join` (Federation PR-A3).
 *
 * Runs on the JOINING node. Wraps the existing mesh lifecycle primitives —
 * it generates the node keypair, derives the master-bound HKDF salt proof,
 * and assembles a JoinRequest from an operator-issued bootstrap token, then
 * submits it to the fortress's `/v1/federation/authorize/complete` endpoint
 * and reports the issued NodeIdentityCertificate.
 *
 * The bootstrap token comes from the operator (who minted it via
 * `/v1/federation/authorize/init`). The fortress master secret is delivered
 * out of band when a node joins a local-mode fortress (SANCTUARY mesh design
 * §3.1) — here it is supplied explicitly via env/flag, which IS that
 * out-of-band channel. The node private key is generated transiently and
 * never leaves this process; only the public key rides in the JoinRequest.
 */

import type { Writable } from "node:stream";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { generateNodeKeypair } from "../mesh/lifecycle/join-approver.js";
import { computeJoinHkdfSaltProof } from "../mesh/lifecycle/bootstrap-token.js";
import { deriveNodeTransportKey } from "../mesh/trust-root.js";
import type { BootstrapToken, JoinRequest } from "../mesh/lifecycle/types.js";
import {
  dashboardRequest,
  DashboardRequestError,
  type DashboardRequestContext,
} from "./dashboard-request.js";

export interface AssembledJoin {
  joinRequest: JoinRequest;
  /** Transient node Ed25519 private key — caller MUST zero after use. */
  nodePrivateKey: Uint8Array;
  nodePublicKey: Uint8Array;
}

/**
 * Assemble a JoinRequest for a bootstrap token. Pure (no I/O): generates the
 * node keypair, derives the node transport key from the out-of-band fortress
 * master secret, and computes the HKDF salt proof that defeats a stolen token
 * held without the master-derived key. The node_id / node_mode come from the
 * token, so the proof is bound to exactly what the operator authorized.
 */
export function assembleJoinRequest(params: {
  bootstrapToken: BootstrapToken;
  fortressMasterSecret: Uint8Array;
}): AssembledJoin {
  const { bootstrapToken, fortressMasterSecret } = params;
  const { publicKey, privateKey } = generateNodeKeypair();

  const transportKey = deriveNodeTransportKey({
    fortress_master_secret: fortressMasterSecret,
    node_id: bootstrapToken.intended_node_id,
    node_mode: bootstrapToken.intended_node_mode,
  });
  const proof = computeJoinHkdfSaltProof({
    intended_node_id: bootstrapToken.intended_node_id,
    node_mode: bootstrapToken.intended_node_mode,
    node_transport_key: transportKey,
  });

  const joinRequest: JoinRequest = {
    bootstrap_token: bootstrapToken,
    node_pubkey: toBase64url(publicKey),
    node_mode: bootstrapToken.intended_node_mode,
    hkdf_salt_proof: proof,
  };
  return { joinRequest, nodePrivateKey: privateKey, nodePublicKey: publicKey };
}

interface JoinFlags {
  fortressUrl?: string;
  bootstrapTokenJson?: string;
  masterSecretB64?: string;
}

function parseJoinFlags(argv: string[], env: NodeJS.ProcessEnv): JoinFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    fortressUrl: flag("--fortress-url") ?? env.SANCTUARY_FORTRESS_URL,
    bootstrapTokenJson: flag("--bootstrap-token"),
    masterSecretB64: flag("--master-secret") ?? env.SANCTUARY_FORTRESS_MASTER_SECRET,
  };
}

/**
 * `sanctuary federation join`. Submits a JoinRequest to a fortress and prints
 * the issued certificate. Returns a catalog CLI exit code:
 *   0 success · 1 usage/input error · 3 join denied · 2 daemon unreachable.
 */
export async function runFederationJoin(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const request = args.request ?? dashboardRequest;
  const flags = parseJoinFlags(args.argv, env);

  if (!flags.fortressUrl) {
    err.write("sanctuary federation join: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n");
    return 1;
  }
  if (!flags.bootstrapTokenJson) {
    err.write("sanctuary federation join: --bootstrap-token <json> is required\n");
    return 1;
  }
  if (!flags.masterSecretB64) {
    err.write(
      "sanctuary federation join: the fortress master secret is required " +
        "(--master-secret or SANCTUARY_FORTRESS_MASTER_SECRET, base64url)\n",
    );
    return 1;
  }

  let bootstrapToken: BootstrapToken;
  try {
    bootstrapToken = JSON.parse(flags.bootstrapTokenJson) as BootstrapToken;
  } catch {
    err.write("sanctuary federation join: --bootstrap-token is not valid JSON\n");
    return 1;
  }
  if (
    typeof bootstrapToken.intended_node_id !== "string" ||
    typeof bootstrapToken.intended_node_mode !== "string" ||
    typeof bootstrapToken.signature !== "string"
  ) {
    err.write("sanctuary federation join: --bootstrap-token is missing required fields\n");
    return 1;
  }

  let masterSecret: Uint8Array;
  try {
    masterSecret = fromBase64url(flags.masterSecretB64);
  } catch {
    err.write("sanctuary federation join: --master-secret is not valid base64url\n");
    return 1;
  }
  if (masterSecret.length !== 32) {
    err.write("sanctuary federation join: master secret must be 32 bytes\n");
    return 1;
  }

  const assembled = assembleJoinRequest({ bootstrapToken, fortressMasterSecret: masterSecret });
  try {
    const ctx: DashboardRequestContext = { dashboardUrl: flags.fortressUrl, authToken: "" };
    const response = (await request(
      "/v1/federation/authorize/complete",
      { method: "POST", body: JSON.stringify(assembled.joinRequest) },
      ctx,
    )) as { certificate?: unknown; issuing_principal_cert?: unknown };

    if (typeof response.certificate !== "object" || response.certificate === null) {
      err.write("sanctuary federation join: fortress returned no certificate\n");
      return 3;
    }
    out.write(
      `${JSON.stringify(
        {
          joined: true,
          node_id: bootstrapToken.intended_node_id,
          node_pubkey: toBase64url(assembled.nodePublicKey),
          certificate: response.certificate,
          issuing_principal_cert: response.issuing_principal_cert ?? null,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (cause) {
    if (cause instanceof DashboardRequestError) {
      if (cause.kind === "auth") {
        err.write(
          "sanctuary federation join: join denied — the fortress rejected this request " +
            "(bad/expired bootstrap token, wrong master secret, or operator denial)\n",
        );
        return 3;
      }
      err.write(`sanctuary federation join: fortress unreachable at ${flags.fortressUrl}\n`);
      return 2;
    }
    err.write(`sanctuary federation join: unexpected error: ${String(cause)}\n`);
    return 1;
  } finally {
    // Constraint 6: the node private key never persists past this call.
    assembled.nodePrivateKey.fill(0);
    masterSecret.fill(0);
  }
}

const FEDERATION_HELP = `sanctuary federation — cross-machine federation (Wave 1, PR-A3)

Usage:
  sanctuary federation join --fortress-url <url> --bootstrap-token <json> [--master-secret <b64url>]

  join     Submit a JoinRequest to a fortress and install the issued node
           certificate. The bootstrap token is minted by the operator on the
           fortress (POST /v1/federation/authorize/init). The fortress master
           secret is delivered out of band (env SANCTUARY_FORTRESS_MASTER_SECRET).

Federation enable/disable/status and join authorization are operator actions
driven from the dashboard / host app over the session-gated /v1/federation API.
`;

export async function runFederationCommand(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
}): Promise<number> {
  const out = args.out ?? process.stdout;
  const sub = args.argv[0];
  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    out.write(FEDERATION_HELP);
    return 0;
  }
  if (sub === "join") {
    return runFederationJoin({ ...args, argv: args.argv.slice(1) });
  }
  (args.err ?? process.stderr).write(
    `sanctuary federation: unknown subcommand "${sub}"\n\n${FEDERATION_HELP}`,
  );
  return 1;
}
