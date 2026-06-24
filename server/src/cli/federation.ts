/**
 * `sanctuary federation join` (Federation PR-A3).
 *
 * Runs on the JOINING node. Wraps the existing mesh lifecycle primitives --
 * it generates the node keypair, derives the master-bound HKDF salt proof,
 * and assembles a JoinRequest from an operator-issued bootstrap token, then
 * submits it to the fortress's `/v1/federation/authorize/complete` endpoint
 * and reports the issued NodeIdentityCertificate.
 *
 * The bootstrap token comes from the operator (who minted it via
 * `/v1/federation/authorize/init`). The fortress master secret is delivered
 * out of band when a node joins a local-mode fortress (SANCTUARY mesh design
 * §3.1) -- here it is supplied explicitly via env/flag, which IS that
 * out-of-band channel. The node private key is generated transiently and
 * never leaves this process; only the public key rides in the JoinRequest.
 */

import type { Writable } from "node:stream";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { generateNodeKeypair } from "../mesh/lifecycle/join-approver.js";
import { computeJoinHkdfSaltProof } from "../mesh/lifecycle/bootstrap-token.js";
import { deriveNodeTransportKey } from "../mesh/trust-root.js";
import {
  computeOperatorCloudJoinProof,
  computeBundleDigest,
  computeManifestDigest,
  computeScopedSecretCiphertextDigest,
  openScopedSecret,
  type OperatorCloudProvisionBundle,
} from "../mesh/operator-cloud-provision.js";
import type { BootstrapToken, JoinRequest } from "../mesh/lifecycle/types.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../mesh/types.js";
import type { NodeMode } from "../mesh/constants.js";
import {
  persistFederationJoinerTrustRoot,
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
} from "../mesh/federation-joiner-trust-root-store.js";
import {
  provisionOrLoadFederationTrustRoot,
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FEDERATION_TRUST_ROOT_KEY,
  type FederationTrustRootAuditEvent,
} from "../mesh/federation-trust-root-store.js";
import { AuditLog } from "../operational/audit-log.js";
import { CustodyUnlockError } from "../core/master-custody.js";
import {
  dashboardRequest,
  DashboardRequestError,
  type DashboardRequestContext,
} from "./dashboard-request.js";
import {
  openOperatorSigner,
  OperatorSigningError,
  type OperatorSigner,
} from "./federation-operator-signing.js";
import { openV1Session } from "./v1-session.js";

export interface AssembledJoin {
  joinRequest: JoinRequest;
  /** Transient node Ed25519 private key -- caller MUST zero after use. */
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

/**
 * Operator Cloud Slice 2: assemble a JoinRequest from a SCOPED PROVISION BUNDLE
 * instead of the raw fortress master secret. The cloud node:
 *   - opens the scoped-secret section with the one-time delivery key,
 *   - takes the node-scoped proof key (NOT the master secret) it carries,
 *   - generates its OWN node keypair locally,
 *   - computes the operator-cloud join proof bound to {bootstrap nonce, this
 *     node's public key, bundle digest} under the node-scoped proof key.
 *
 * A substituted bundle (different manifest/ciphertext/delivery target) yields a
 * different bundle digest, so the proof no longer matches the approved claim and
 * the join is denied. The node_join_proof_key is zeroed after the proof.
 */
export function assembleOperatorCloudJoinRequest(params: {
  bundle: OperatorCloudProvisionBundle;
  deliveryKey: Uint8Array;
  deliveryTarget: string;
}): AssembledJoin {
  const { bundle, deliveryKey, deliveryTarget } = params;
  const manifest = bundle.manifest;
  const scoped = openScopedSecret(bundle, deliveryKey);
  const nodeJoinProofKey = fromBase64url(scoped.node_join_proof_key);
  const { publicKey, privateKey } = generateNodeKeypair();

  const manifestDigest = computeManifestDigest(manifest);
  const scopedCtDigest = computeScopedSecretCiphertextDigest(bundle.scoped_secret);
  // Recompute the SAME canonical bundle digest the home node recorded in the
  // claim (manifest + scoped ciphertext + delivery target; no pubkey). The proof
  // then binds that digest plus this node's pubkey plus the bootstrap nonce.
  const bundleDigest = computeBundleDigest({
    manifestDigest,
    scopedSecretCiphertextDigest: scopedCtDigest,
    deliveryTarget,
  });

  const proof = computeOperatorCloudJoinProof({
    nodeJoinProofKey,
    fortressId: manifest.fortress_id,
    nodeId: manifest.node_id,
    bootstrapNonce: manifest.bootstrap_token.nonce,
    nodePubkeyB64: toBase64url(publicKey),
    bundleDigest,
  });
  nodeJoinProofKey.fill(0);

  const joinRequest: JoinRequest = {
    bootstrap_token: manifest.bootstrap_token,
    node_pubkey: toBase64url(publicKey),
    node_mode: "operator_cloud",
    hkdf_salt_proof: proof,
  };
  return { joinRequest, nodePrivateKey: privateKey, nodePublicKey: publicKey };
}

interface JoinFlags {
  fortressUrl?: string;
  bootstrapTokenJson?: string;
  masterSecretB64?: string;
  /** Operator Cloud Slice 2: path to / inline JSON of the scoped provision bundle. */
  provisionBundleJson?: string;
  /** Operator Cloud Slice 2: one-time delivery key (base64url) for the bundle's scoped secret. */
  deliveryKeyB64?: string;
  /** Operator Cloud Slice 2: delivery target string bound into the bundle digest. */
  deliveryTarget?: string;
  /** Slice 3b: persist the issued joiner trust root after a successful join (default OFF). */
  persist: boolean;
  /** Slice 3b: out-of-band pinned master JSON (FortressMasterPublicKey) for --persist. */
  pinnedMasterJson?: string;
  /** Slice 3b: custody passphrase for --persist (opens the local fortress to write the joiner store). */
  passphrase?: string;
  /** Slice 3b: custody recovery key for --persist (alternative to passphrase). */
  recoveryKey?: string;
  /** Slice 3b: fortress path override for --persist. */
  fortressPath?: string;
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
    provisionBundleJson: flag("--provision-bundle"),
    deliveryKeyB64: flag("--delivery-key") ?? env.SANCTUARY_OC_DELIVERY_KEY,
    deliveryTarget: flag("--delivery-target"),
    persist: argv.includes("--persist"),
    pinnedMasterJson: flag("--pinned-master"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
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
  /**
   * Slice 3b seam: opens the local fortress + writes the joiner trust root for
   * `--persist`. Defaults to the real custody-unlocking implementation; tests
   * inject a stub to assert the persist contract (out-of-band pinned master,
   * cert-chain refusal) without unlocking a real fortress.
   */
  persistJoinerTrustRoot?: typeof persistJoinerTrustRootFromJoin;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const request = args.request ?? dashboardRequest;
  const persistJoiner = args.persistJoinerTrustRoot ?? persistJoinerTrustRootFromJoin;
  const flags = parseJoinFlags(args.argv, env);

  if (!flags.fortressUrl) {
    err.write("sanctuary federation join: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n");
    return 1;
  }

  // Slice 3b: --persist requires an OUT-OF-BAND pinned master (never inferred
  // from the server response, constraint 4) and a custody credential to open
  // the local fortress. Validate up front so a missing prerequisite fails the
  // verb cleanly BEFORE a join ceremony runs (do not join, then discover we
  // cannot persist).
  let pinnedMaster: FortressMasterPublicKey | null = null;
  if (flags.persist) {
    if (!flags.pinnedMasterJson) {
      err.write(
        "sanctuary federation join: --persist requires --pinned-master <json> " +
          "(the out-of-band fortress-master public key this joiner trusts; " +
          "the server response is never the trust source)\n",
      );
      return 1;
    }
    pinnedMaster = parsePinnedMaster(flags.pinnedMasterJson);
    if (pinnedMaster === null) {
      err.write(
        "sanctuary federation join: --pinned-master is not a valid FortressMasterPublicKey " +
          "(needs public_key, fortress_id, created_at)\n",
      );
      return 1;
    }
    if (!flags.passphrase && !flags.recoveryKey) {
      err.write(
        "sanctuary federation join: --persist needs an unlocked operator identity " +
          "(set SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY)\n",
      );
      return 1;
    }
  }

  // Operator Cloud Slice 2: a scoped provision bundle REPLACES the raw fortress
  // master secret for operator-cloud nodes. The cloud node never receives the
  // master secret; it joins with the bundle's node-scoped proof key.
  const useBundle = flags.provisionBundleJson !== undefined;
  if (useBundle && flags.masterSecretB64) {
    err.write(
      "sanctuary federation join: --provision-bundle and --master-secret are mutually exclusive; " +
        "operator-cloud nodes never receive the fortress master secret\n",
    );
    return 1;
  }

  let assembled: AssembledJoin;
  let bootstrapToken: BootstrapToken;
  let masterSecret: Uint8Array | null = null;

  if (useBundle) {
    if (!flags.deliveryKeyB64) {
      err.write(
        "sanctuary federation join: --delivery-key (or SANCTUARY_OC_DELIVERY_KEY, base64url) " +
          "is required with --provision-bundle\n",
      );
      return 1;
    }
    if (!flags.deliveryTarget) {
      err.write("sanctuary federation join: --delivery-target is required with --provision-bundle\n");
      return 1;
    }
    let bundle: OperatorCloudProvisionBundle;
    try {
      bundle = JSON.parse(flags.provisionBundleJson as string) as OperatorCloudProvisionBundle;
    } catch {
      err.write("sanctuary federation join: --provision-bundle is not valid JSON\n");
      return 1;
    }
    if (
      typeof bundle.manifest !== "object" ||
      bundle.manifest === null ||
      typeof bundle.scoped_secret !== "object" ||
      bundle.scoped_secret === null
    ) {
      err.write("sanctuary federation join: --provision-bundle is malformed\n");
      return 1;
    }
    let deliveryKey: Uint8Array;
    try {
      deliveryKey = fromBase64url(flags.deliveryKeyB64);
    } catch {
      err.write("sanctuary federation join: --delivery-key is not valid base64url\n");
      return 1;
    }
    if (deliveryKey.length !== 32) {
      err.write("sanctuary federation join: delivery key must be 32 bytes\n");
      return 1;
    }
    bootstrapToken = bundle.manifest.bootstrap_token;
    try {
      assembled = assembleOperatorCloudJoinRequest({
        bundle,
        deliveryKey,
        deliveryTarget: flags.deliveryTarget,
      });
    } catch {
      err.write("sanctuary federation join: failed to open the provision bundle (bad delivery key?)\n");
      return 1;
    } finally {
      deliveryKey.fill(0);
    }
  } else {
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
    if (bootstrapToken.intended_node_mode === "operator_cloud") {
      err.write(
        "sanctuary federation join: operator-cloud nodes must join with --provision-bundle, " +
          "not the raw fortress master secret\n",
      );
      return 1;
    }
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
    assembled = assembleJoinRequest({ bootstrapToken, fortressMasterSecret: masterSecret });
  }

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

    let persisted = false;
    if (flags.persist) {
      // pinnedMaster + custody credential were validated up front. Persist the
      // joiner trust root BEFORE printing and BEFORE the finally zeroes the node
      // key. The store re-runs the full cert-chain verification against the
      // OUT-OF-BAND pinned master and refuses a cert that does not chain to it
      // (constraint 4), so a server response that does not match the pinned
      // anchor fails the verb non-zero rather than persisting bad trust.
      if (
        typeof response.issuing_principal_cert !== "object" ||
        response.issuing_principal_cert === null
      ) {
        err.write(
          "sanctuary federation join: --persist requires the issuing principal cert " +
            "in the join response; the fortress returned none\n",
        );
        return 3;
      }
      try {
        await persistJoiner({
          pinnedMaster: pinnedMaster as FortressMasterPublicKey,
          issuingPrincipalCert:
            response.issuing_principal_cert as PrincipalCertificate,
          localNodeCert: response.certificate as NodeIdentityCertificate,
          localNodePrivateKey: assembled.nodePrivateKey,
          ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
          ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
          ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
        });
        persisted = true;
      } catch (persistErr) {
        const reason =
          persistErr instanceof OperatorSigningError
            ? persistErr.message
            : "the issued certificate does not chain to --pinned-master, or the " +
              "local fortress could not be opened";
        err.write(
          `sanctuary federation join: joined, but refused to persist the joiner ` +
            `trust root: ${reason}\n`,
        );
        return 3;
      }
    }

    out.write(
      `${JSON.stringify(
        {
          joined: true,
          persisted,
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
          "sanctuary federation join: join denied -- the fortress rejected this request " +
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
    masterSecret?.fill(0);
  }
}

/** Parse + structurally validate an out-of-band FortressMasterPublicKey JSON. */
function parsePinnedMaster(json: string): FortressMasterPublicKey | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const candidate = parsed as Record<string, unknown>;
  if (
    typeof candidate.public_key !== "string" ||
    candidate.public_key.length === 0 ||
    typeof candidate.fortress_id !== "string" ||
    candidate.fortress_id.length === 0 ||
    typeof candidate.created_at !== "string" ||
    candidate.created_at.length === 0
  ) {
    return null;
  }
  return {
    public_key: candidate.public_key,
    fortress_id: candidate.fortress_id,
    created_at: candidate.created_at,
  };
}

/**
 * Real `--persist` implementation: open the local fortress headless
 * (keychain-safe, no modal) and write the joiner trust root, encrypted under
 * the joiner's own custody master. The pinned master is the OUT-OF-BAND trust
 * anchor; `persistFederationJoinerTrustRoot` re-runs the full cert-chain
 * verification and refuses a cert that does not chain to it (constraint 4).
 * The node private key is zeroed by the caller's `finally`; the master key is
 * zeroed here after the write.
 */
export async function persistJoinerTrustRootFromJoin(opts: {
  pinnedMaster: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  localNodeCert: NodeIdentityCertificate;
  localNodePrivateKey: Uint8Array;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}): Promise<void> {
  // Reuse the same keychain-safe custody-unlock path the admin verbs use; it
  // fails closed (OperatorSigningError) when only a keychain credential exists
  // in a headless session. We need only the master key + storage from it.
  const signer = await openOperatorSigner({
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    ...(opts.fortressPath !== undefined ? { fortressPath: opts.fortressPath } : {}),
  });
  try {
    await persistFederationJoinerTrustRoot({
      storage: signer.storage,
      masterKey: signer.masterKey,
      pinnedMasterPubkey: opts.pinnedMaster,
      issuingPrincipalCert: opts.issuingPrincipalCert,
      localNodeCert: opts.localNodeCert,
      localNodePrivateKey: opts.localNodePrivateKey,
    });
  } finally {
    signer.masterKey.fill(0);
  }
}

interface AdminFlags {
  fortressUrl?: string;
  authToken?: string;
  idempotencyKey?: string;
  nodeId?: string;
  nodeMode: NodeMode;
  nodeModeValid: boolean;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseAdminFlags(argv: string[], env: NodeJS.ProcessEnv): AdminFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const rawMode = flag("--node-mode") ?? "local";
  const nodeModeValid = (["local", "operator_cloud", "sovereign_tee"] as const).includes(
    rawMode as NodeMode,
  );
  return {
    fortressUrl: flag("--fortress-url") ?? env.SANCTUARY_FORTRESS_URL,
    authToken: flag("--auth-token") ?? env.SANCTUARY_DASHBOARD_AUTH_TOKEN,
    idempotencyKey: flag("--idempotency-key"),
    nodeId: flag("--node-id"),
    nodeMode: rawMode as NodeMode,
    nodeModeValid,
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
  };
}

/**
 * Build the dashboard-request context for an admin verb's HTTP call, carrying
 * the resolved /v1 session token (or an explicit `--auth-token` override).
 */
function adminRequestContext(flags: AdminFlags, sessionToken: string): DashboardRequestContext {
  return {
    ...(flags.fortressUrl !== undefined ? { dashboardUrl: flags.fortressUrl } : {}),
    authToken: sessionToken,
  };
}

/**
 * Resolve the /v1 bearer token an admin verb attaches to its
 * session-gated `/v1/federation/*` call.
 *
 * The `/v1` surface is session-token only: it does NOT honor loopback auto-auth
 * at the bearer-header level the way the legacy `/api/*` convenience routes do
 * (a live drill caught the admin verbs 401ing against a real booted dashboard
 * because they sent an empty token). So unless the operator supplies an explicit
 * `--auth-token`, the verb OPENS its own /v1 session via the existing ceremony
 * client, signing the session attestation with the SAME already-unlocked
 * operator identity (no second prompt). Fails closed: a session that cannot be
 * opened maps to a non-zero exit, never an unauthenticated request.
 */
async function resolveAdminSessionToken(
  verb: string,
  flags: AdminFlags,
  signer: OperatorSigner,
  err: Writable,
  openSession: typeof openV1Session,
): Promise<string | number> {
  // Explicit override: the operator handed us a token; use it verbatim.
  if (flags.authToken !== undefined) return flags.authToken;
  try {
    const session = await openSession(
      flags.fortressUrl !== undefined ? { dashboardUrl: flags.fortressUrl } : undefined,
      {
        buildAttestation: (clientPubkey) =>
          signer.signAttestation(clientPubkey, Date.now()),
      },
    );
    return session.token;
  } catch (cause) {
    if (cause instanceof DashboardRequestError) {
      if (cause.kind === "auth") {
        err.write(
          `sanctuary federation ${verb}: could not open a /v1 session ` +
            `(operator attestation rejected)\n`,
        );
        return 3;
      }
      err.write(
        `sanctuary federation ${verb}: fortress unreachable at ${flags.fortressUrl}\n`,
      );
      return 2;
    }
    err.write(`sanctuary federation ${verb}: unexpected error opening a /v1 session: ${String(cause)}\n`);
    return 1;
  }
}

/**
 * Open the operator signer (keychain-safe) for an admin verb, mapping the
 * fail-closed `OperatorSigningError` to a clear message + non-zero exit. The
 * caller MUST zero `signer.masterKey` after use.
 */
async function openAdminSigner(
  verb: string,
  flags: AdminFlags,
  err: Writable,
): Promise<OperatorSigner | number> {
  try {
    return await openOperatorSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    if (cause instanceof OperatorSigningError) {
      err.write(`sanctuary federation ${verb}: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation ${verb}: unexpected error: ${String(cause)}\n`);
    return 1;
  }
}

/** Map a DashboardRequestError to the catalog exit code + a clear message. */
function mapAdminRequestError(
  verb: string,
  cause: unknown,
  fortressUrl: string,
  err: Writable,
): number {
  if (cause instanceof DashboardRequestError) {
    if (cause.kind === "auth") {
      err.write(`sanctuary federation ${verb}: operator authorization rejected\n`);
      return 3;
    }
    if (cause.kind === "server") {
      err.write(
        `sanctuary federation ${verb}: federation is not provisioned on this fortress\n`,
      );
      return 3;
    }
    if (cause.kind === "not-implemented") {
      err.write(
        `sanctuary federation ${verb}: this endpoint is not available on the fortress\n`,
      );
      return 3;
    }
    err.write(`sanctuary federation ${verb}: fortress unreachable at ${fortressUrl}\n`);
    return 2;
  }
  err.write(`sanctuary federation ${verb}: unexpected error: ${String(cause)}\n`);
  return 1;
}

/**
 * `sanctuary federation enable` / `disable`. Operator-signed Tier-1 admin verbs
 * that drive the existing `/v1/federation/enable` (resp. `/disable`) endpoint.
 * Thin client: produces the inline operator signature the server independently
 * verifies; introduces no second trust-decision path. Fails closed when no
 * operator identity can be unlocked.
 */
export async function runFederationEnableDisable(args: {
  enable: boolean;
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
  /** Test seam: the /v1 session-open ceremony (defaults to the real client). */
  openSession?: typeof openV1Session;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const request = args.request ?? dashboardRequest;
  const openSession = args.openSession ?? openV1Session;
  const verb = args.enable ? "enable" : "disable";
  const action = args.enable ? "/v1/federation/enable" : "/v1/federation/disable";
  const flags = parseAdminFlags(args.argv, env);

  if (!flags.fortressUrl) {
    err.write(
      `sanctuary federation ${verb}: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n`,
    );
    return 1;
  }

  const signer = await openAdminSigner(verb, flags, err);
  if (typeof signer === "number") return signer;
  try {
    const sessionToken = await resolveAdminSessionToken(verb, flags, signer, err, openSession);
    if (typeof sessionToken === "number") return sessionToken;
    // The signed payload MUST match the server's reconstruction exactly: the
    // server includes idempotency_key only when it is a string.
    const signedPayload: Record<string, unknown> = {};
    if (flags.idempotencyKey !== undefined) {
      signedPayload.idempotency_key = flags.idempotencyKey;
    }
    const operatorSignature = signer.signPayload(action, signedPayload);
    const body = { ...signedPayload, operator_signature: operatorSignature };

    const response = (await request(
      action,
      { method: "POST", body: JSON.stringify(body) },
      adminRequestContext(flags, sessionToken),
    )) as { enabled?: unknown };
    out.write(`${JSON.stringify({ enabled: response.enabled === true }, null, 2)}\n`);
    return 0;
  } catch (cause) {
    return mapAdminRequestError(verb, cause, flags.fortressUrl, err);
  } finally {
    signer.masterKey.fill(0);
  }
}

/**
 * `sanctuary federation authorize [init]`. Operator-signed Tier-1 verb that
 * mints a bootstrap token for a node the operator is authorizing to join, via
 * `/v1/federation/authorize/init`. Prints the bootstrap token JSON (the
 * intended output) ready to hand to the joiner's `federation join`.
 */
export async function runFederationAuthorize(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
  /** Test seam: the /v1 session-open ceremony (defaults to the real client). */
  openSession?: typeof openV1Session;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const request = args.request ?? dashboardRequest;
  const openSession = args.openSession ?? openV1Session;
  const action = "/v1/federation/authorize/init";
  // Accept both `authorize` and `authorize init`; strip a leading `init`.
  const argv = args.argv[0] === "init" ? args.argv.slice(1) : args.argv;
  const flags = parseAdminFlags(argv, env);

  if (!flags.fortressUrl) {
    err.write(
      "sanctuary federation authorize: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n",
    );
    return 1;
  }
  if (!flags.nodeId) {
    err.write("sanctuary federation authorize: --node-id <id> is required\n");
    return 1;
  }
  if (!flags.nodeModeValid) {
    err.write(
      "sanctuary federation authorize: --node-mode must be local, operator_cloud, or sovereign_tee\n",
    );
    return 1;
  }

  const signer = await openAdminSigner("authorize", flags, err);
  if (typeof signer === "number") return signer;
  try {
    const sessionToken = await resolveAdminSessionToken("authorize", flags, signer, err, openSession);
    if (typeof sessionToken === "number") return sessionToken;
    const signedPayload: Record<string, unknown> = {
      intended_node_id: flags.nodeId,
      intended_node_mode: flags.nodeMode,
    };
    const operatorSignature = signer.signPayload(action, signedPayload);
    const body = { ...signedPayload, operator_signature: operatorSignature };

    const response = (await request(
      action,
      { method: "POST", body: JSON.stringify(body) },
      adminRequestContext(flags, sessionToken),
    )) as { bootstrap_token?: unknown };
    if (typeof response.bootstrap_token !== "object" || response.bootstrap_token === null) {
      err.write("sanctuary federation authorize: fortress returned no bootstrap token\n");
      return 3;
    }
    // The bootstrap token is the intended output of authorize (NOT a secret to
    // suppress): hand it to the joiner's `federation join --bootstrap-token`.
    out.write(`${JSON.stringify({ bootstrap_token: response.bootstrap_token }, null, 2)}\n`);
    return 0;
  } catch (cause) {
    return mapAdminRequestError("authorize", cause, flags.fortressUrl, err);
  } finally {
    signer.masterKey.fill(0);
  }
}

interface ProvisionFlags {
  nodeId?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseProvisionFlags(
  argv: string[],
  env: NodeJS.ProcessEnv,
): ProvisionFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    nodeId: flag("--node-id"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
  };
}

/**
 * `sanctuary federation provision` (alias `init-issuer`). MINTS the federation
 * issuer trust root for THIS fortress: a fresh fortress master + a
 * `_federation/trust-root-v1` record, encrypted under the local custody master.
 * This is the highest-stakes Tier-1 local write in the system -- it creates the
 * cross-machine root of trust every joining node will pin out of band.
 *
 * SECURITY CONTRACT (the whole point of this verb):
 *   - REFUSE-IF-EXISTS, HARD. Before minting, it raw-probes BOTH the issuer
 *     record (`_federation/trust-root-v1`) AND the joiner record
 *     (`_federation/joiner-trust-root-v1`) via `storage.exists` -- WITHOUT
 *     decrypting. If EITHER exists (or is present-but-corrupt), it refuses with
 *     exit 3. Minting over an existing root would create a NEW fortress master +
 *     fortress_id and silently orphan every node already joined to this mesh.
 *     There is NO --force and NO rotation in this slice.
 *   - Operator-gated by custody unlock (NOT a /v1 session, NOT a theater
 *     signature). It reuses `openOperatorSigner` (passphrase / recovery-key
 *     only, keychain-safe, fail-closed): no credential / wrong passphrase / no
 *     default operator identity all -> exit 3, never an unsigned mint, never a
 *     keychain modal. Possession of the unlock credential IS the authorization;
 *     the resolved operator pubkey is recorded in the mint audit for attribution.
 *   - REQUIRES an already-init'd fortress with a default operator identity (the
 *     non-bootstrap unlock path); it never auto-creates custody or identity.
 *   - On success prints ONLY safe public material:
 *     `{ provisioned, fortress_id, node_id, pinned_master }`. The pinned_master
 *     is the `FortressMasterPublicKey` -- PUBLIC, and the out-of-band trust
 *     anchor a joiner needs for `--pinned-master`. NEVER prints/logs the master
 *     secret, master private key, principal private key, or recovery key.
 *
 * Exit codes:
 *   0 minted + persisted · 1 usage (missing --node-id) · 3 refused (already
 *   provisioned / corrupt record / fail-closed custody / persist failure).
 *   No exit 2 -- this verb makes no HTTP call.
 */
export async function runFederationProvision(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  /**
   * Test seam: opens the local fortress headless (keychain-safe), resolving the
   * default operator identity. Defaults to the real `openOperatorSigner`. Tests
   * seed a real temp fortress and let this default run end to end; the seam
   * exists for parity with the other verbs.
   */
  openSigner?: typeof openOperatorSigner;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const openSigner = args.openSigner ?? openOperatorSigner;
  const flags = parseProvisionFlags(args.argv, env);

  if (!flags.nodeId) {
    err.write("sanctuary federation provision: --node-id <id> is required\n");
    return 1;
  }

  // Operator gate: open the local fortress keychain-safe. Fails closed
  // (OperatorSigningError -> exit 3) on no credential, wrong passphrase, or no
  // default operator identity -- never a keychain modal, never an unsigned mint.
  let signer: OperatorSigner;
  try {
    signer = await openSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    // Fail-closed custody: a missing/wrong credential, no default operator
    // identity, or any custody-unlock failure (e.g. wrong passphrase ->
    // CustodyUnlockError) maps to a refusal (exit 3), never an unsigned mint and
    // never a keychain modal. Only a genuinely unexpected error is exit 1.
    if (
      cause instanceof OperatorSigningError ||
      cause instanceof CustodyUnlockError
    ) {
      err.write(`sanctuary federation provision: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation provision: unexpected error: ${String(cause)}\n`);
    return 1;
  }

  // The mint must be attributable to the resolving operator. Open the SAME
  // AuditLog the standalone boot uses (storage + custody master), and record
  // the resolved operator pubkey (PUBLIC, safe to log). An audit-write failure
  // must NEVER mask the verb's fail-closed behavior, so audit appends are
  // best-effort (mirrors dashboard-standalone's federation audit callback).
  const operatorPubkeyB64 = toBase64url(signer.operatorPublicKey);
  const auditLog = new AuditLog(signer.storage, signer.masterKey);
  const audit = async (event: FederationTrustRootAuditEvent): Promise<void> => {
    try {
      await auditLog.append(
        "l2",
        event.operation,
        "federation",
        { ...event.details, operator_pubkey: operatorPubkeyB64 },
        event.result,
      );
    } catch {
      // Federation stays fail-closed; never let an audit-write failure block or
      // mask the mint's refusal / success behavior.
    }
  };

  try {
    // REFUSE-IF-EXISTS (the most important safety property). Raw existence probe
    // on BOTH record kinds, WITHOUT decrypting -- so a present-but-corrupt record
    // is refused too (corrupt == do-not-overwrite, NOT == absent). The mint
    // primitive's load-first behavior is NOT relied on here: we must distinguish
    // "refused because one exists" from "minted a fresh one", and we must refuse
    // over a broken record the primitive would treat as absent.
    const issuerExists = await signer.storage.exists(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    if (issuerExists) {
      await audit({
        operation: "federation_trust_root_mint",
        result: "failure",
        details: { reason: "refused_issuer_record_exists" },
      });
      err.write(
        "sanctuary federation provision: this fortress already has a federation " +
          "trust root (_federation/trust-root-v1). Minting a new one would create " +
          "a NEW fortress master and orphan every node that already joined this " +
          "mesh. Refusing. To inspect the existing root, boot the dashboard " +
          "(federation status shows fortress_id + node_id). Rotating the root is a " +
          "separate, not-yet-built operation (`sanctuary federation rotate-root`, " +
          "future slice).\n",
      );
      return 3;
    }
    const joinerExists = await signer.storage.exists(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    if (joinerExists) {
      await audit({
        operation: "federation_trust_root_mint",
        result: "failure",
        details: { reason: "refused_joiner_record_exists" },
      });
      err.write(
        "sanctuary federation provision: this fortress is a federation JOINER " +
          "(_federation/joiner-trust-root-v1 exists); it cannot also be an issuer. " +
          "Minting an issuer root here would create an issuer-on-joiner split-brain. " +
          "Refusing.\n",
      );
      return 3;
    }

    // Mint + persist. The primitive loads-first (defense in depth against a
    // record that raced in between the probe and here): if it returns
    // source:"persisted" we REFUSE (never report a fresh mint), and if it
    // returns null (a record appeared and failed to load) we REFUSE (never
    // re-mint over it).
    let provisioned;
    try {
      provisioned = await provisionOrLoadFederationTrustRoot({
        storage: signer.storage,
        masterKey: signer.masterKey,
        mint: true,
        nodeId: flags.nodeId,
        nodeMode: "local",
        principalId: "principal-root",
        audit,
      });
    } catch (cause) {
      err.write(
        `sanctuary federation provision: failed to mint the federation trust root: ${String(cause)}\n`,
      );
      return 3;
    }

    if (provisioned === null) {
      err.write(
        "sanctuary federation provision: refused -- a federation trust root " +
          "appeared on disk during minting and could not be loaded. Refusing to " +
          "overwrite it.\n",
      );
      return 3;
    }
    if (provisioned.source !== "minted") {
      err.write(
        "sanctuary federation provision: this fortress already has a federation " +
          "trust root; refusing to mint a second one (it would orphan the mesh).\n",
      );
      return 3;
    }

    // Print ONLY safe public material. The pinned_master is the
    // FortressMasterPublicKey (public_key, fortress_id, created_at -- all PUBLIC),
    // the out-of-band trust anchor a joiner pins via `--pinned-master`. NEVER
    // print the master secret / private keys (they stay owned by the primitive).
    out.write(
      `${JSON.stringify(
        {
          provisioned: true,
          fortress_id: provisioned.record.pinned_master_pubkey.fortress_id,
          node_id: provisioned.record.node_id,
          pinned_master: { ...provisioned.record.pinned_master_pubkey },
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } finally {
    // Keep the audit durable before this short-lived CLI exits, on EVERY path
    // (success mint, refuse-with-failure-audit, throw). The audit encryption key
    // was derived in the AuditLog ctor, so flush does not depend on masterKey and
    // is safe to run here. A non-durable audit append must NEVER turn the verb's
    // mint/refuse outcome into a different exit code, so flush failures are
    // swallowed (the trust-root persistence is the source of truth, not the log).
    try {
      await auditLog.flush();
    } catch {
      // Federation stays fail-closed; audit durability is best-effort here.
    }
    // Constraint 6: the custody master never persists past this call (every path:
    // success, refuse, throw).
    signer.masterKey.fill(0);
  }
}

const FEDERATION_HELP = `sanctuary federation -- cross-machine federation (Wave 1)

Provision (issuer) verb -- custody-unlocked, runs LOCALLY on the home fortress:
  sanctuary federation provision --node-id <id> \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]
  (alias: sanctuary federation init-issuer ...)

  provision   MINT this fortress's federation issuer trust root: a fresh fortress
              master + the local _federation/trust-root-v1 record. This is the
              cross-machine ROOT OF TRUST every joining node pins out of band.
              Custody-gated (needs an unlocked default operator identity:
              SANCTUARY_PASSPHRASE / --passphrase / SANCTUARY_RECOVERY_KEY; never
              prompts the keychain). REFUSES if this fortress already has a
              federation root (issuer OR joiner record): minting a second one
              would orphan the whole mesh. There is no --force and no rotation
              yet. Prints the pinned_master (the PUBLIC trust anchor) to hand to
              joiners for their --pinned-master.

Operator (issuer) verbs -- operator-signed, run on the home fortress:
  sanctuary federation enable  --fortress-url <url> [--idempotency-key <s>]
  sanctuary federation disable --fortress-url <url> [--idempotency-key <s>]
  sanctuary federation authorize [init] --fortress-url <url> --node-id <id> \\
    [--node-mode local|operator_cloud|sovereign_tee]

  enable / disable   Turn federation on/off for this fortress. Operator-signed
                     Tier-1: needs an unlocked default operator identity
                     (SANCTUARY_PASSPHRASE / --passphrase / SANCTUARY_RECOVERY_KEY).
                     Enable fails closed if the fortress is not provisioned.

  authorize [init]   Mint a bootstrap token for a node you are authorizing to
                     join (POST /v1/federation/authorize/init). Prints the
                     bootstrap token JSON to hand to the joiner's
                     'federation join --bootstrap-token'. Operator-signed Tier-1.

Joiner verb -- runs on the joining node:
  Local / sovereign_tee node:
  sanctuary federation join --fortress-url <url> --bootstrap-token <json> [--master-secret <b64url>]

  Operator-cloud node (Slice 2 scoped custody):
  sanctuary federation join --fortress-url <url> --provision-bundle <json> \\
    --delivery-key <b64url> --delivery-target <target>

  Persist the joiner trust root (boots this node provisioned next start):
  sanctuary federation join ... --persist --pinned-master <FortressMasterPublicKey json>

  join     Submit a JoinRequest to a fortress and install the issued node
           certificate. The bootstrap token is minted by the operator on the
           fortress (POST /v1/federation/authorize/init).

           Local-mode nodes derive the join proof from the fortress master
           secret, delivered out of band (env SANCTUARY_FORTRESS_MASTER_SECRET).

           Operator-cloud nodes NEVER receive the fortress master secret. They
           join with a scoped provision bundle delivered after VM boot over an
           operator-approved channel. The bundle carries only this node's scoped
           proof key and assigned grants; the master secret stays home.

           --persist (default OFF) writes the issued joiner trust root to the
           local fortress so this node boots provisioned. It requires the
           OUT-OF-BAND --pinned-master (the fortress-master public key you trust;
           the server response is never the trust source) and refuses to persist
           a certificate that does not chain to it. It opens the local fortress,
           so an operator credential is required (SANCTUARY_PASSPHRASE /
           --passphrase / SANCTUARY_RECOVERY_KEY).
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
  if (sub === "provision" || sub === "init-issuer") {
    return runFederationProvision({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "join") {
    return runFederationJoin({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "enable" || sub === "disable") {
    return runFederationEnableDisable({
      ...args,
      enable: sub === "enable",
      argv: args.argv.slice(1),
    });
  }
  if (sub === "authorize") {
    return runFederationAuthorize({ ...args, argv: args.argv.slice(1) });
  }
  (args.err ?? process.stderr).write(
    `sanctuary federation: unknown subcommand "${sub}"\n\n${FEDERATION_HELP}`,
  );
  return 1;
}
