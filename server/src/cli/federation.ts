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

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Writable } from "node:stream";
import { ed25519 } from "@noble/curves/ed25519";
import { loadConfig } from "../config.js";
import { toBase64url, fromBase64url } from "../core/encoding.js";
import { generateIdentityId } from "../core/identity.js";
import {
  REVOCATION_LIST_SIGN_ACTION,
  canonicalizeRevocationListIds,
  effectiveRevocationVersionFloor,
  persistPushedRevocationListSerialized,
  readDowngradeLog,
  type RevocationListPayload,
} from "../entitlement/index.js";
import { readFileCustody } from "../storage/custody-fs.js";
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
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../mesh/types.js";
import type { NodeMode } from "../mesh/constants.js";
import {
  adoptFederationJoinerPlannedRoot,
  persistFederationJoinerTrustRoot,
  FederationJoinerTrustRootStoreError,
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
  type FederationJoinerPlannedRootAdoptResult,
  type FederationJoinerPlannedRootAdoptReissueRequest,
  type FederationJoinerPlannedRootAdoptReissueResult,
} from "../mesh/federation-joiner-trust-root-store.js";
import {
  provisionOrLoadFederationTrustRoot,
  FederationTrustRootStore,
  FederationTrustRootStoreError,
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FEDERATION_TRUST_ROOT_KEY,
  FEDERATION_ISSUANCE_SUITE_CLASSICAL,
  FEDERATION_ISSUANCE_SUITE_HYBRID,
  type FederationTrustRootAuditEvent,
} from "../mesh/federation-trust-root-store.js";
import {
  rotateFederationRootRenew,
  rotateFederationRootCompromised,
  resumeFederationRootRotation,
  resumeFederationRootCompromised,
  federationRotateRootInProgress,
  federationRotateRootJournalIsCompromise,
  FederationRotateRootError,
  FederationRotateRootResumeError,
  type FederationRotateRootAuditEvent,
} from "../mesh/federation-rotate-root.js";
import { AuditLog } from "../operational/audit-log.js";
import { parsePolicy } from "../principal-policy/loader.js";
import {
  CustodyUnlockError,
  CustodyRotationInProgressError,
} from "../core/master-custody.js";
import {
  buildFederationReissueNodeCertProofMessage,
  federationEventHash,
  type FederationEvent,
} from "../v1/federation.js";
import {
  FEDERATION_SYNC_WIRE_VERSION,
  federationOperatorAuthorityOrigin,
} from "../v1/federation-revocation.js";
import {
  FEDERATION_POLICY_BUNDLE_EVENT_KIND,
  FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM,
  signFederationPolicyBundlePayload,
} from "../v1/federation-policy-bundle.js";
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
          persistErr instanceof OperatorSigningError ||
          persistErr instanceof FederationJoinerTrustRootStoreError
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

// ═══════════════════════════════════════════════════════════════════════
// `sanctuary federation adopt --renew` (planned-rotation joiner auto-adopt)
// ═══════════════════════════════════════════════════════════════════════

const FEDERATION_REISSUE_NODE_CERT_PATH =
  "/v1/federation/rotate/reissue-node-cert";

interface AdoptFlags {
  renew: boolean;
  fortressUrl?: string;
  rotationCertArg?: string;
  pinnedMasterArg?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseAdoptFlags(argv: string[], env: NodeJS.ProcessEnv): AdoptFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    renew: argv.includes("--renew"),
    fortressUrl: flag("--fortress-url") ?? env.SANCTUARY_FORTRESS_URL,
    rotationCertArg: flag("--rotation-cert"),
    pinnedMasterArg: flag("--pinned-master"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
  };
}

/**
 * `sanctuary federation adopt --renew`. Joiner-side driver for a PLANNED
 * rotate-root: verify the K1-signed rotation cert under the locally pinned K1,
 * run the reissue proof-of-possession round against the EXISTING reissue
 * endpoint (no new route), re-verify the returned chain to the K2 learned from
 * that cert (never the server response), and atomically re-pin K2. Prints only
 * PUBLIC material. Catalog exit codes: 0 adopted, 1 usage, 2 fortress
 * unreachable, 3 refused / held-old-trust.
 */
export async function runFederationAdopt(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
  /**
   * Seam: unlock the local fortress + run the planned-adopt core. Defaults to
   * the real custody-unlocking implementation; tests inject a stub to assert the
   * verb's flag parsing, exit-code mapping, and printing without a real fortress.
   */
  performPlannedAdopt?: typeof performPlannedAdoptFromCli;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const request = args.request ?? dashboardRequest;
  const perform = args.performPlannedAdopt ?? performPlannedAdoptFromCli;
  const flags = parseAdoptFlags(args.argv, env);

  if (!flags.renew) {
    err.write(
      "sanctuary federation adopt: --renew is required (this verb adopts a " +
        "PLANNED rotation only; a COMPROMISE rotation is re-joined by hand with " +
        "'sanctuary federation rejoin')\n",
    );
    return 1;
  }
  if (!flags.fortressUrl) {
    err.write(
      "sanctuary federation adopt: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n",
    );
    return 1;
  }
  if (!flags.rotationCertArg) {
    err.write(
      "sanctuary federation adopt: --rotation-cert <json | @file> is required " +
        "(the K1-signed rotation certificate, received out of band)\n",
    );
    return 1;
  }
  const rotationCertJson = await readInlineOrFile(flags.rotationCertArg);
  if (rotationCertJson === null) {
    err.write(
      "sanctuary federation adopt: could not read --rotation-cert (bad @file path?)\n",
    );
    return 1;
  }
  const rotationCert = parseRotationCert(rotationCertJson);
  if (rotationCert === null) {
    err.write(
      "sanctuary federation adopt: --rotation-cert is not a valid federation " +
        "root-rotation certificate\n",
    );
    return 1;
  }
  // A-FULL: the operator's OUT-OF-BAND expected new root is REQUIRED. Verifying
  // the K1-signed cert is not enough trust when K1 may be compromised; the
  // adopted anchor must match a root the operator confirms by hand.
  if (!flags.pinnedMasterArg) {
    err.write(
      "sanctuary federation adopt: --pinned-master <K2 json | @file> is required " +
        "(the OUT-OF-BAND expected NEW fortress-master public key; a K1-signed " +
        "rotation cert alone is not a sufficient trust anchor when K1 may be " +
        "compromised)\n",
    );
    return 1;
  }
  const pinnedMasterJson = await readInlineOrFile(flags.pinnedMasterArg);
  if (pinnedMasterJson === null) {
    err.write(
      "sanctuary federation adopt: could not read --pinned-master (bad @file path?)\n",
    );
    return 1;
  }
  const expectedPinnedMaster = parsePinnedMaster(pinnedMasterJson);
  if (expectedPinnedMaster === null) {
    err.write(
      "sanctuary federation adopt: --pinned-master is not a valid " +
        "FortressMasterPublicKey (needs public_key, fortress_id, created_at)\n",
    );
    return 1;
  }
  if (!flags.passphrase && !flags.recoveryKey) {
    err.write(
      "sanctuary federation adopt: needs an unlocked operator identity to read " +
        "and re-pin the local joiner store (SANCTUARY_PASSPHRASE, --passphrase, " +
        "or SANCTUARY_RECOVERY_KEY)\n",
    );
    return 1;
  }

  let result: FederationJoinerPlannedRootAdoptResult;
  try {
    result = await perform({
      rotationCert,
      expectedPinnedMaster,
      fortressUrl: flags.fortressUrl,
      request,
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    if (cause instanceof OperatorSigningError) {
      err.write(`sanctuary federation adopt: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation adopt: unexpected error: ${String(cause)}\n`);
    return 1;
  }

  if (result.adopted) {
    out.write(
      `${JSON.stringify(
        {
          adopted: true,
          // Observation-shaped: assert only what was verified, never
          // "the fortress is secure now".
          result:
            "re-pinned the new federation root; the reissued node cert chains " +
            "to it under this fortress at the adopted rotation serial",
          fortress_id: result.record.fortress_id,
          node_id: result.record.node_id,
          previous_pinned_master: result.previousPinnedMaster,
          pinned_master: result.pinnedMaster,
          rotation_serial: result.rotationSerial,
          node_cert: result.record.local_node_cert,
          issuing_principal_cert: result.record.issuing_principal_cert,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  }

  err.write(
    `sanctuary federation adopt: held the old trust anchor (nothing adopted): ` +
      `${plannedAdoptHeldReason(result.reason)}` +
      `${result.detail ? ` (${result.detail})` : ""}\n`,
  );
  return result.reason === "reissue_unreachable" ? 2 : 3;
}

function plannedAdoptHeldReason(reason: string): string {
  switch (reason) {
    case "joiner_trust_root_missing":
      return "this machine has no persisted joiner trust root to re-pin";
    case "joiner_trust_root_unavailable":
      return "the local joiner store could not be opened or decoded";
    case "hybrid_rotation_unsupported":
      return "the rotation cert is HYBRID (post-quantum); classical-only adopt " +
        "refuses it rather than silently drop the post-quantum half";
    case "rotation_signer_revoked":
      return "the rotation cert is signed by a root this machine has locally " +
        "revoked (a compromised old root can never re-anchor trust)";
    case "rotation_cert_invalid":
      return "the rotation cert did not verify under the currently pinned root " +
        "(wrong signer, bad signature, or a stale/replayed serial)";
    case "adopted_root_mismatch_operator_pin":
      return "the new root the rotation cert attests does not match the " +
        "operator-supplied --pinned-master; a K1-signed cert alone is not a " +
        "sufficient anchor when K1 may be compromised";
    case "reissue_denied":
      return "the fortress refused to reissue this node's cert (revoked node, " +
        "revoked old root, or no recorded rotation lineage)";
    case "reissue_unreachable":
      return "the fortress was unreachable for the reissue round";
    case "server_root_mismatch":
      return "the fortress returned a different root than the rotation cert " +
        "attests; the server response is never the trust source";
    case "reissued_identity_mismatch":
      return "the reissued cert is not for this node's existing key";
    case "reissued_chain_invalid":
      return "the reissued cert does not chain to the new root the rotation " +
        "cert attests";
    case "persist_failed":
      return "the re-pin could not be written; the old trust anchor is intact";
    default:
      return reason;
  }
}

/**
 * Real planned-adopt driver: open the local fortress headless (keychain-safe,
 * fails closed in a headless session) and run the pure adopt core, wiring the
 * reissue proof-of-possession round to the live HTTP endpoint. Zeroes the master
 * key after use.
 */
export async function performPlannedAdoptFromCli(opts: {
  rotationCert: FederationRootRotationCertificate;
  expectedPinnedMaster: FortressMasterPublicKey;
  fortressUrl: string;
  request: typeof dashboardRequest;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}): Promise<FederationJoinerPlannedRootAdoptResult> {
  const signer = await openOperatorSigner({
    ...(opts.passphrase !== undefined ? { passphrase: opts.passphrase } : {}),
    ...(opts.recoveryKey !== undefined ? { recoveryKey: opts.recoveryKey } : {}),
    ...(opts.fortressPath !== undefined ? { fortressPath: opts.fortressPath } : {}),
  });
  try {
    return await adoptFederationJoinerPlannedRoot({
      storage: signer.storage,
      masterKey: signer.masterKey,
      rotationCert: opts.rotationCert,
      expectedPinnedMaster: opts.expectedPinnedMaster,
      reissue: (req) =>
        reissueNodeCertViaHttp(req, opts.fortressUrl, opts.request),
    });
  } finally {
    signer.masterKey.fill(0);
  }
}

/**
 * Drive the reissue proof-of-possession round against the EXISTING reissue
 * endpoint (challenge -> node-key proof -> complete). The node private key comes
 * from the loaded joiner record and never leaves this process. A 401/403 denial
 * is a fail-closed "denied"; any transport failure is "unreachable".
 */
async function reissueNodeCertViaHttp(
  req: FederationJoinerPlannedRootAdoptReissueRequest,
  fortressUrl: string,
  request: typeof dashboardRequest,
): Promise<FederationJoinerPlannedRootAdoptReissueResult> {
  const ctx: DashboardRequestContext = { dashboardUrl: fortressUrl, authToken: "" };
  const nodeId = req.current.node_id;

  let challenge: { challenge_id?: unknown; challenge?: unknown };
  try {
    challenge = (await request(
      FEDERATION_REISSUE_NODE_CERT_PATH,
      { method: "POST", body: JSON.stringify({ action: "challenge", node_id: nodeId }) },
      ctx,
    )) as { challenge_id?: unknown; challenge?: unknown };
  } catch (cause) {
    return mapReissueTransportError(cause);
  }
  if (
    typeof challenge.challenge_id !== "string" ||
    typeof challenge.challenge !== "string"
  ) {
    return { ok: false, reason: "denied" };
  }

  const proofMessage = buildFederationReissueNodeCertProofMessage({
    fortressId: req.current.fortress_id,
    nodeId,
    challengeId: challenge.challenge_id,
    challenge: challenge.challenge,
    currentNodeCert: req.current.local_node_cert,
    currentIssuingPrincipalCert: req.current.issuing_principal_cert,
    rotationCert: req.rotationCert,
  });
  const signature = ed25519.sign(proofMessage, req.current.local_node_private_key);

  let completed: {
    certificate?: unknown;
    issuing_principal_cert?: unknown;
    pinned_master?: unknown;
  };
  try {
    completed = (await request(
      FEDERATION_REISSUE_NODE_CERT_PATH,
      {
        method: "POST",
        body: JSON.stringify({
          action: "complete",
          node_id: nodeId,
          challenge_id: challenge.challenge_id,
          challenge: challenge.challenge,
          current_node_cert: req.current.local_node_cert,
          current_issuing_principal_cert: req.current.issuing_principal_cert,
          rotation_cert: req.rotationCert,
          node_signature: toBase64url(signature),
        }),
      },
      ctx,
    )) as {
      certificate?: unknown;
      issuing_principal_cert?: unknown;
      pinned_master?: unknown;
    };
  } catch (cause) {
    return mapReissueTransportError(cause);
  } finally {
    signature.fill(0);
  }

  if (
    typeof completed.certificate !== "object" ||
    completed.certificate === null ||
    typeof completed.issuing_principal_cert !== "object" ||
    completed.issuing_principal_cert === null ||
    typeof completed.pinned_master !== "object" ||
    completed.pinned_master === null
  ) {
    return { ok: false, reason: "denied" };
  }
  return {
    ok: true,
    certificate: completed.certificate as NodeIdentityCertificate,
    issuingPrincipalCert: completed.issuing_principal_cert as PrincipalCertificate,
    serverPinnedMaster: completed.pinned_master as FortressMasterPublicKey,
  };
}

function mapReissueTransportError(
  cause: unknown,
): FederationJoinerPlannedRootAdoptReissueResult {
  if (cause instanceof DashboardRequestError) {
    return { ok: false, reason: cause.kind === "auth" ? "denied" : "unreachable" };
  }
  return { ok: false, reason: "unreachable" };
}

/** Read a `--flag <json | @file>` argument. `@path` reads the file; else inline. */
async function readInlineOrFile(value: string): Promise<string | null> {
  if (value.startsWith("@")) {
    try {
      return await readFile(value.slice(1), "utf8");
    } catch {
      return null;
    }
  }
  return value;
}

/** Parse + structurally validate a federation root-rotation certificate JSON. */
function parseRotationCert(
  json: string,
): FederationRootRotationCertificate | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const cert = parsed as Record<string, unknown>;
  if (cert.kind !== "federation-root-rotation") return null;
  if (
    typeof cert.fortress_id !== "string" ||
    cert.fortress_id.length === 0 ||
    typeof cert.old_master_pubkey !== "string" ||
    cert.old_master_pubkey.length === 0 ||
    typeof cert.rotation_serial !== "number" ||
    typeof cert.rotated_at !== "string" ||
    typeof cert.old_master_signature !== "string" ||
    cert.old_master_signature.length === 0 ||
    typeof cert.new_master !== "object" ||
    cert.new_master === null
  ) {
    return null;
  }
  const nm = cert.new_master as Record<string, unknown>;
  if (
    typeof nm.public_key !== "string" ||
    nm.public_key.length === 0 ||
    typeof nm.fortress_id !== "string" ||
    typeof nm.created_at !== "string"
  ) {
    return null;
  }
  // hybrid_rotation (if present) is passed through unchanged so the store's
  // classical-only guard can refuse it LOUDLY rather than silently downgrade.
  return parsed as FederationRootRotationCertificate;
}

// ═══════════════════════════════════════════════════════════════════════
// `sanctuary federation rejoin` (compromise-rotation manual re-join wrapper)
// ═══════════════════════════════════════════════════════════════════════

/** Old-key-signed artifacts a compromise re-join must NEVER accept. */
const REJOIN_FORBIDDEN_FLAGS: readonly string[] = [
  "--rotation-cert",
  "--rotation-certificate",
  "--adoption-bundle",
  "--adoption-attestation",
];

interface RejoinFlags {
  fortressUrl?: string;
  bootstrapTokenJson?: string;
  masterSecretB64?: string;
  pinnedMasterJson?: string;
  revokedOldMaster?: string;
  revocationSerialRaw?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
  forbiddenPresent: string[];
}

function parseRejoinFlags(argv: string[], env: NodeJS.ProcessEnv): RejoinFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    fortressUrl: flag("--fortress-url") ?? env.SANCTUARY_FORTRESS_URL,
    bootstrapTokenJson: flag("--bootstrap-token"),
    masterSecretB64: flag("--master-secret") ?? env.SANCTUARY_FORTRESS_MASTER_SECRET,
    pinnedMasterJson: flag("--pinned-master"),
    revokedOldMaster: flag("--revoked-old-master"),
    revocationSerialRaw: flag("--revocation-serial"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
    forbiddenPresent: REJOIN_FORBIDDEN_FLAGS.filter((name) => argv.includes(name)),
  };
}

/**
 * `sanctuary federation rejoin`. A GUARDED convenience wrapper over
 * `federation join --persist` for the COMPROMISE class. It is a fresh join
 * against the operator-supplied NEW root (K2): it never verifies, adopts, or
 * even accepts any old-key-signed artifact. It REQUIRES the out-of-band K2
 * pinned master + a FRESH bootstrap token + the new master secret, and records
 * the now-dead old root (K1) into the re-joined record with an anti-rollback
 * serial floor so a later K1 (or K1-signed rotation cert) is refused locally.
 *
 * Exit codes are the join catalog: 0 re-joined + persisted, 1 usage, 2 fortress
 * unreachable, 3 join denied / persist refused.
 */
export async function runFederationRejoin(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  request?: typeof dashboardRequest;
  /** Seam: the join ceremony this wraps (defaults to the real one). */
  join?: typeof runFederationJoin;
  /** Seam: the revocation-recording persist (defaults to the real one). */
  persistRejoinedJoinerTrustRoot?: typeof persistRejoinedJoinerTrustRootFromJoin;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const runJoin = args.join ?? runFederationJoin;
  const persistRejoin =
    args.persistRejoinedJoinerTrustRoot ?? persistRejoinedJoinerTrustRootFromJoin;
  const flags = parseRejoinFlags(args.argv, env);

  if (flags.forbiddenPresent.length > 0) {
    err.write(
      `sanctuary federation rejoin: refuses ${flags.forbiddenPresent.join(", ")} ` +
        `-- a compromise re-join NEVER accepts an adoption bundle, a rotation ` +
        `cert, or any old-key-signed artifact; it is a fresh join against the ` +
        `operator-supplied new root\n`,
    );
    return 1;
  }
  if (!flags.fortressUrl) {
    err.write(
      "sanctuary federation rejoin: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n",
    );
    return 1;
  }
  if (!flags.pinnedMasterJson) {
    err.write(
      "sanctuary federation rejoin: --pinned-master <K2 json> is required " +
        "(the OUT-OF-BAND new fortress-master public key; the server response is " +
        "never the trust source)\n",
    );
    return 1;
  }
  const pinnedMaster = parsePinnedMaster(flags.pinnedMasterJson);
  if (pinnedMaster === null) {
    err.write(
      "sanctuary federation rejoin: --pinned-master is not a valid " +
        "FortressMasterPublicKey (needs public_key, fortress_id, created_at)\n",
    );
    return 1;
  }
  if (!flags.bootstrapTokenJson) {
    err.write(
      "sanctuary federation rejoin: a FRESH --bootstrap-token <json> is required " +
        "(a compromise rotation does not grandfather old authorizations)\n",
    );
    return 1;
  }
  if (!flags.masterSecretB64) {
    err.write(
      "sanctuary federation rejoin: the NEW fortress master secret is required " +
        "(--master-secret or SANCTUARY_FORTRESS_MASTER_SECRET, base64url)\n",
    );
    return 1;
  }
  if (!flags.revokedOldMaster) {
    err.write(
      "sanctuary federation rejoin: --revoked-old-master <K1 pubkey> is required " +
        "(recorded into revoked_root_pubkeys so a later K1 is refused locally)\n",
    );
    return 1;
  }
  const revocationSerial = parsePositiveInt(flags.revocationSerialRaw);
  if (revocationSerial === null) {
    err.write(
      "sanctuary federation rejoin: --revocation-serial <positive integer> is " +
        "required (the anti-rollback floor for the recorded revocation)\n",
    );
    return 1;
  }
  if (flags.revokedOldMaster === pinnedMaster.public_key) {
    err.write(
      "sanctuary federation rejoin: --revoked-old-master must not equal the new " +
        "--pinned-master (a fortress cannot re-pin a root it is revoking)\n",
    );
    return 1;
  }
  if (!flags.passphrase && !flags.recoveryKey) {
    err.write(
      "sanctuary federation rejoin: needs an unlocked operator identity to write " +
        "the re-joined trust root (SANCTUARY_PASSPHRASE, --passphrase, or " +
        "SANCTUARY_RECOVERY_KEY)\n",
    );
    return 1;
  }

  const revokedOldMaster = flags.revokedOldMaster;
  const persist: typeof persistJoinerTrustRootFromJoin = (o) =>
    persistRejoin({
      ...o,
      revokedOldMasterPubkey: revokedOldMaster,
      revocationSerial,
    });

  const joinArgv: string[] = [
    "--fortress-url",
    flags.fortressUrl,
    "--bootstrap-token",
    flags.bootstrapTokenJson,
    "--master-secret",
    flags.masterSecretB64,
    "--pinned-master",
    flags.pinnedMasterJson,
    "--persist",
    ...(flags.passphrase !== undefined ? ["--passphrase", flags.passphrase] : []),
    ...(flags.fortressPath !== undefined ? ["--fortress", flags.fortressPath] : []),
  ];

  const code = await runJoin({
    argv: joinArgv,
    env,
    out,
    err,
    ...(args.request !== undefined ? { request: args.request } : {}),
    persistJoinerTrustRoot: persist,
  });

  // LOW-2 (review 2026-07-24): the wrapper's whole reason to exist is recording
  // the dead old root, so report it (observation-shaped, public material only).
  // Design section 7: "re-joined against operator-supplied K2; recorded K1
  // revoked at serial N."
  if (code === 0) {
    out.write(
      `${JSON.stringify(
        {
          rejoined: true,
          result:
            "re-joined against the operator-supplied new root; recorded the old " +
            "root revoked with an anti-rollback serial floor",
          recorded_revoked_old_master: revokedOldMaster,
          revocation_serial: revocationSerial,
        },
        null,
        2,
      )}\n`,
    );
  }
  return code;
}

/**
 * Compromise re-join persist: the same keychain-safe custody-unlocking path the
 * plain join persist uses, but it ALSO records the now-dead old root (K1) into
 * `revoked_root_pubkeys` with the revocation serial as the anti-rollback floor.
 * `persistFederationJoinerTrustRoot` re-runs the full cert-chain verification
 * against the new K2 pinned master and fails closed if K1 equals the pinned
 * master (a fortress cannot re-pin a root it is revoking).
 */
export async function persistRejoinedJoinerTrustRootFromJoin(opts: {
  pinnedMaster: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  localNodeCert: NodeIdentityCertificate;
  localNodePrivateKey: Uint8Array;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
  revokedOldMasterPubkey: string;
  revocationSerial: number;
}): Promise<void> {
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
      revokedRootPubkeys: [opts.revokedOldMasterPubkey],
      highestRevocationSerial: opts.revocationSerial,
    });
  } finally {
    signer.masterKey.fill(0);
  }
}

function parsePositiveInt(raw: string | undefined): number | null {
  if (raw === undefined) return null;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}

interface AdminFlags {
  fortressUrl?: string;
  authToken?: string;
  idempotencyKey?: string;
  nodeId?: string;
  nodeMode: NodeMode;
  nodeModeValid: boolean;
  reason?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
  policyPath?: string;
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
    reason: flag("--reason"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
    policyPath: flag("--policy-path"),
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

type FederationTrustRootRecordForZeroize =
  Awaited<ReturnType<FederationTrustRootStore["load"]>>;

function zeroFederationTrustRootRecordSecrets(
  record: FederationTrustRootRecordForZeroize,
): void {
  record?.master_secret.fill(0);
  record?.master_private_key?.fill(0);
  record?.issuing_principal_private_key.fill(0);
  record?.local_node_private_key.fill(0);
  record?.hybrid?.master_private_keys?.ed25519?.private_key?.fill(0);
  record?.hybrid?.master_private_keys?.ml_dsa_65?.secret_key?.fill(0);
  record?.hybrid?.issuing_principal_private_keys?.ed25519?.private_key?.fill(0);
  record?.hybrid?.issuing_principal_private_keys?.ml_dsa_65?.secret_key?.fill(0);
  record?.hybrid?.local_node_private_keys?.ed25519?.private_key?.fill(0);
  record?.hybrid?.local_node_private_keys?.ml_dsa_65?.secret_key?.fill(0);
}

class PolicyPushInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyPushInputError";
  }
}

async function loadPolicyHashForPush(flags: AdminFlags): Promise<{
  policyVersion: number;
  policyHash: string;
}> {
  const config = await loadConfig();
  const policyPath = flags.policyPath ?? join(config.storage_path, "principal-policy.yaml");
  let content: string;
  try {
    content = await readFileCustody(policyPath, {
      encoding: "utf-8",
      verifyPathIdentity: true,
    });
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new PolicyPushInputError(`could not read principal policy: ${detail}`);
  }
  let policyVersion: number;
  try {
    const policy = parsePolicy(content);
    policyVersion = policy.version;
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new PolicyPushInputError(`principal policy is malformed: ${detail}`);
  }
  if (!Number.isSafeInteger(policyVersion) || policyVersion < 1) {
    throw new PolicyPushInputError("principal policy version must be a positive integer");
  }
  const policyHash = createHash("sha256").update(content, "utf8").digest("base64url");
  return { policyVersion, policyHash };
}

function isFederationEvent(value: unknown): value is FederationEvent {
  if (typeof value !== "object" || value === null) return false;
  const event = value as Record<string, unknown>;
  return (
    typeof event.event_id === "string" &&
    typeof event.origin_node_id === "string" &&
    typeof event.sequence === "number" &&
    Number.isSafeInteger(event.sequence) &&
    typeof event.occurred_at === "string" &&
    typeof event.kind === "string" &&
    typeof event.payload === "object" &&
    event.payload !== null &&
    (event.previous_hash === null || typeof event.previous_hash === "string") &&
    typeof event.event_hash === "string"
  );
}

function sortedAuthorityEvents(
  responseEvents: unknown,
  originNodeId: string,
): FederationEvent[] | null {
  if (!Array.isArray(responseEvents)) return null;
  const authorityEvents: FederationEvent[] = [];
  for (const event of responseEvents) {
    if (!isFederationEvent(event)) return null;
    if (event.origin_node_id === originNodeId) authorityEvents.push(event);
  }
  authorityEvents.sort((a, b) => a.sequence - b.sequence);
  return authorityEvents;
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
    if (cause.kind === "http") {
      err.write(`sanctuary federation ${verb}: ${cause.message}\n`);
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

/**
 * `sanctuary federation revoke`. Operator-signed Tier-1 verb that emits a
 * durable operator-authority node-eviction event on the home fortress via
 * `/v1/federation/revoke`. The server signs the append-only event with issuer
 * authority and folds it through the same revocation chokepoint used by sync.
 */
export async function runFederationRevoke(args: {
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
  const action = "/v1/federation/revoke";
  const flags = parseAdminFlags(args.argv, env);

  if (!flags.fortressUrl) {
    err.write(
      "sanctuary federation revoke: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n",
    );
    return 1;
  }
  if (!flags.nodeId) {
    err.write("sanctuary federation revoke: --node-id <id> is required\n");
    return 1;
  }

  const signer = await openAdminSigner("revoke", flags, err);
  if (typeof signer === "number") return signer;
  try {
    const sessionToken = await resolveAdminSessionToken("revoke", flags, signer, err, openSession);
    if (typeof sessionToken === "number") return sessionToken;
    const signedPayload: Record<string, unknown> = {
      node_id: flags.nodeId,
      reason: flags.reason ?? "operator_revoked",
    };
    if (flags.idempotencyKey !== undefined) {
      signedPayload.idempotency_key = flags.idempotencyKey;
    }
    const operatorSignature = signer.signPayload(action, signedPayload);
    const body = { ...signedPayload, operator_signature: operatorSignature };

    const response = (await request(
      action,
      { method: "POST", body: JSON.stringify(body) },
      adminRequestContext(flags, sessionToken),
    )) as {
      revoked?: unknown;
      node_id?: unknown;
      event_id?: unknown;
      eviction_serial?: unknown;
    };
    if (
      response.revoked !== true ||
      response.node_id !== flags.nodeId ||
      typeof response.event_id !== "string" ||
      typeof response.eviction_serial !== "number"
    ) {
      err.write("sanctuary federation revoke: fortress returned no eviction event summary\n");
      return 3;
    }
    out.write(
      `${JSON.stringify(
        {
          revoked: true,
          node_id: response.node_id,
          event_id: response.event_id,
          eviction_serial: response.eviction_serial,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (cause) {
    return mapAdminRequestError("revoke", cause, flags.fortressUrl, err);
  } finally {
    signer.masterKey.fill(0);
  }
}

/**
 * `sanctuary federation policy-push`. Operator-signed Tier-1 verb that emits an
 * operator-authority policy-bundle event through the existing sync envelope.
 *
 * Custody contract:
 *   - The event carries only {policy_version, policy_hash, hash_algorithm} plus
 *     the Ed25519 signature and public operator-principal id. It never carries
 *     raw policy contents, policy secrets, or private keys.
 *   - The bundle is signed by this fortress's federation issuing principal, so
 *     peers verify it against their pinned federation master before applying the
 *     version marker. Verification failure rejects the event server-side.
 *   - No new /v1 route is added. This command opens a /v1 session and posts the
 *     append-only event to `/v1/federation/sync`.
 */
export async function runFederationPolicyPush(args: {
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
  const action = "/v1/federation/sync";
  const flags = parseAdminFlags(args.argv, env);

  if (!flags.fortressUrl) {
    err.write(
      "sanctuary federation policy-push: --fortress-url (or SANCTUARY_FORTRESS_URL) is required\n",
    );
    return 1;
  }

  const signer = await openAdminSigner("policy-push", flags, err);
  if (typeof signer === "number") return signer;

  let record: FederationTrustRootRecordForZeroize = null;
  try {
    let policy: { policyVersion: number; policyHash: string };
    try {
      policy = await loadPolicyHashForPush(flags);
    } catch (cause) {
      const detail = cause instanceof Error ? cause.message : String(cause);
      err.write(`sanctuary federation policy-push: ${detail}\n`);
      return cause instanceof PolicyPushInputError ? 1 : 3;
    }

    const store = new FederationTrustRootStore(signer.storage, signer.masterKey);
    try {
      record = await store.load();
    } catch (cause) {
      const detail =
        cause instanceof FederationTrustRootStoreError ? cause.message : "decrypt failed";
      err.write(
        `sanctuary federation policy-push: could not load this fortress's federation ` +
          `trust root (${detail}). Refusing.\n`,
      );
      return 3;
    }
    if (record === null) {
      err.write(
        "sanctuary federation policy-push: this fortress has no federation trust " +
          "root (_federation/trust-root-v1). Provision an issuer first. Refusing.\n",
      );
      return 3;
    }

    const sessionToken = await resolveAdminSessionToken(
      "policy-push",
      flags,
      signer,
      err,
      openSession,
    );
    if (typeof sessionToken === "number") return sessionToken;

    const originNodeId = federationOperatorAuthorityOrigin(
      record.pinned_master_pubkey.fortress_id,
    );
    const baseSyncPayload = {
      wire_version: FEDERATION_SYNC_WIRE_VERSION,
      node_id: record.node_id,
      events: [] as FederationEvent[],
      cursor: { node_id: originNodeId },
    };
    const fetchResponse = (await request(
      action,
      {
        method: "POST",
        body: JSON.stringify({
          ...baseSyncPayload,
          operator_signature: signer.signPayload(action, baseSyncPayload),
        }),
      },
      adminRequestContext(flags, sessionToken),
    )) as { events?: unknown };

    const prior = sortedAuthorityEvents(fetchResponse.events, originNodeId);
    if (prior === null) {
      err.write(
        "sanctuary federation policy-push: fortress returned a malformed sync event cursor\n",
      );
      return 3;
    }
    const previous = prior.length > 0 ? prior[prior.length - 1] : null;
    const signedAt = new Date().toISOString();
    const payload = signFederationPolicyBundlePayload({
      fortressId: record.pinned_master_pubkey.fortress_id,
      policyVersion: policy.policyVersion,
      policyHash: policy.policyHash,
      signedAt,
      operatorPrincipalId: record.issuing_principal_cert.principal_id,
      operatorPrincipalPrivateKey: record.issuing_principal_private_key,
    });
    const eventWithoutHash = {
      event_id: `${originNodeId}:${(previous?.sequence ?? 0) + 1}`,
      origin_node_id: originNodeId,
      sequence: (previous?.sequence ?? 0) + 1,
      occurred_at: signedAt,
      kind: FEDERATION_POLICY_BUNDLE_EVENT_KIND,
      payload: payload as unknown as Record<string, unknown>,
      previous_hash: previous?.event_hash ?? null,
    };
    const event: FederationEvent = {
      ...eventWithoutHash,
      event_hash: federationEventHash(eventWithoutHash),
    };
    const pushPayload: Record<string, unknown> = {
      wire_version: FEDERATION_SYNC_WIRE_VERSION,
      node_id: record.node_id,
      events: [event],
    };
    if (flags.idempotencyKey !== undefined) {
      pushPayload.idempotency_key = flags.idempotencyKey;
    }
    const pushResponse = (await request(
      action,
      {
        method: "POST",
        body: JSON.stringify({
          ...pushPayload,
          operator_signature: signer.signPayload(action, pushPayload),
        }),
      },
      adminRequestContext(flags, sessionToken),
    )) as { accepted?: unknown; rejected?: unknown };
    const accepted = Array.isArray(pushResponse.accepted)
      ? pushResponse.accepted
      : [];
    if (!accepted.includes(event.event_id)) {
      err.write(
        "sanctuary federation policy-push: fortress did not accept the signed policy bundle event\n",
      );
      return 3;
    }

    out.write(
      `${JSON.stringify(
        {
          policy_pushed: true,
          policy_version: policy.policyVersion,
          policy_hash: policy.policyHash,
          hash_algorithm: FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM,
          event_id: event.event_id,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (cause) {
    return mapAdminRequestError("policy-push", cause, flags.fortressUrl, err);
  } finally {
    zeroFederationTrustRootRecordSecrets(record);
    signer.masterKey.fill(0);
  }
}

/**
 * `sanctuary federation revoke-push`. Fleet control plane PR-3. Sign a fleet
 * license REVOCATION LIST with this fortress's operator identity and persist it
 * into local custody so the daemon forces a revoked license CLOSED to Community.
 *
 * This is issuer-LOCAL + operator-gated (mirror `provision`): the operator
 * unlocks custody (passphrase / recovery-key, keychain-safe), the list is signed
 * with the SAME operator key the fortress pins for license verification, verified
 * against that pinned key + a strictly-greater monotonic version, and written to
 * the master-MAC'd `_meta` record. NO HTTP call, NO /v1 session (so no exit 2).
 *
 * Flags:
 *   --license-id <id>   a license id to revoke (repeatable; the FULL revoked set)
 *   --version <n>       the monotonic list version (must exceed the stored one)
 *   --passphrase / SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY   custody unlock
 *   --fortress <path>   optional fortress override
 *
 * The revoked set is ABSOLUTE (a full snapshot, not a delta): pass EVERY revoked
 * id each push. NEVER prints key material. NEVER gates security: a revoked
 * license only loses PAID central-console management; every node's wall stays up.
 *
 * Exit codes: 0 signed + persisted · 1 usage (missing/invalid flags) · 3
 * fail-closed custody / verify / persist failure.
 */
export async function runFederationRevokePush(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  openSigner?: typeof openOperatorSigner;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const flags = parseAdminFlags(args.argv, env);

  // Collect ALL --license-id occurrences (the absolute revoked set).
  const licenseIds: string[] = [];
  for (let i = 0; i < args.argv.length; i += 1) {
    if (args.argv[i] === "--license-id" && i + 1 < args.argv.length) {
      const id = args.argv[i + 1];
      if (typeof id === "string" && id.length > 0) licenseIds.push(id);
    }
  }
  const versionRaw = ((): string | undefined => {
    const i = args.argv.indexOf("--version");
    return i >= 0 && i + 1 < args.argv.length ? args.argv[i + 1] : undefined;
  })();
  if (versionRaw === undefined) {
    err.write(
      "sanctuary federation revoke-push: --version <n> is required (the monotonic " +
        "list version; must be greater than the currently stored version)\n",
    );
    return 1;
  }
  const version = Number(versionRaw);
  if (!Number.isSafeInteger(version) || version < 1) {
    err.write(
      "sanctuary federation revoke-push: --version must be a positive integer\n",
    );
    return 1;
  }

  const openSigner = args.openSigner ?? openOperatorSigner;
  let signer: OperatorSigner;
  try {
    signer = await openSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    if (cause instanceof OperatorSigningError) {
      err.write(`sanctuary federation revoke-push: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation revoke-push: unexpected error: ${String(cause)}\n`);
    return 1;
  }

  try {
    const issuer = generateIdentityId(signer.operatorPublicKey);
    // CANONICALIZE the operator's raw argv-order id set (sort + dedupe) BEFORE
    // signing. `verifyPushedRevocationList` recomputes the signed message over the
    // CANONICAL id order, so signing over the raw order would spuriously
    // `bad_signature` any unsorted/duplicated set (exit 3, reading like a key
    // problem). Reject a malformed set up front rather than sign one that can
    // never verify.
    const canonicalIds = canonicalizeRevocationListIds(licenseIds);
    if (canonicalIds === null) {
      err.write(
        "sanctuary federation revoke-push: refusing to sign a malformed " +
          "--license-id set (each id must be a non-empty string)\n",
      );
      return 1;
    }
    const payload: RevocationListPayload = {
      version,
      revokedLicenseIds: canonicalIds,
      issuer,
      issuedAt: new Date().toISOString(),
    };
    // Sign with the operator key via the shared operator-signed message path (the
    // SAME construction `buildRevocationListMessage` verifies).
    const signature = signer.signPayload(REVOCATION_LIST_SIGN_ACTION, payload);
    const signed = { payload, signature };

    // The SINGLE serialized push path (shared with the HTTP route): a
    // cross-process O_EXCL lock re-reads the EXTERNALLY-ANCHORED + witness-bound
    // effective floor INSIDE the lock and re-verifies monotonicity against it, then
    // persists list -> anchor -> custody-MAC'd witness latch in crash-safe order. A
    // corrupt/deleted list file can never roll the floor back to 0, and two
    // concurrent pushes cannot both pass against a stale floor.
    const result = await persistPushedRevocationListSerialized({
      storage: signer.storage,
      master: signer.masterKey,
      signed,
      issuerPublicKey: signer.operatorPublicKey,
    });
    if (!result.ok) {
      // Surface the floor observed inside the lock for the operator's not_newer.
      const floor = await effectiveRevocationVersionFloor(
        signer.storage,
        signer.masterKey,
      );
      err.write(
        `sanctuary federation revoke-push: refusing to persist (${result.reason}` +
          (result.reason === "not_newer"
            ? `; stored version is ${floor}, pushed ${version})\n`
            : ")\n"),
      );
      return 3;
    }
    out.write(
      `${JSON.stringify(
        {
          revocation_list_pushed: true,
          version: result.version,
          revoked_count: result.revokedCount,
          issuer,
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (cause) {
    err.write(
      `sanctuary federation revoke-push: persist failed: ${String(cause)}\n`,
    );
    return 3;
  } finally {
    signer.masterKey.fill(0);
  }
}

/**
 * `sanctuary federation downgrade-log`. Fleet control plane PR-3. Print the
 * operator-visible downgrade log: every tier/cap transition with its reason and
 * the affected node ids, so "these N nodes left the console because the plan
 * lapsed - their walls are still up" is answerable from the CLI. Operator-gated
 * (custody unlock). Read-only; never prints key material; no HTTP call.
 *
 * Exit codes: 0 printed (even an empty log) · 3 fail-closed custody failure.
 */
export async function runFederationDowngradeLog(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  openSigner?: typeof openOperatorSigner;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const flags = parseAdminFlags(args.argv, env);

  const openSigner = args.openSigner ?? openOperatorSigner;
  let signer: OperatorSigner;
  try {
    signer = await openSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    if (cause instanceof OperatorSigningError) {
      err.write(`sanctuary federation downgrade-log: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation downgrade-log: unexpected error: ${String(cause)}\n`);
    return 1;
  }

  try {
    const log = await readDowngradeLog(signer.storage, signer.masterKey);
    out.write(
      `${JSON.stringify(
        {
          readable: log.readable,
          entry_count: log.entries.length,
          // Newest-first for a human scanning "what just changed".
          entries: [...log.entries].reverse(),
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } finally {
    signer.masterKey.fill(0);
  }
}

interface ProvisionFlags {
  nodeId?: string;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
  /**
   * PQC default-on: a fresh federation trust root is provisioned with the hybrid
   * Ed25519+ML-DSA-65 signing master BY DEFAULT. `--classical` (or
   * `--crypto-suite ed25519-v1`) opts back out to the legacy classical-only root;
   * `--pqc-hybrid` (or `--crypto-suite ed25519+ml-dsa-v1`) is the accepted, now
   * no-op-but-explicit way to ask for the default. The two opt-out and opt-in
   * directions are mutually exclusive.
   */
  pqcHybrid: boolean;
  /** True when --crypto-suite was given a value this verb does not understand. */
  cryptoSuiteInvalid: boolean;
  /** True when --classical (or --crypto-suite ed25519-v1) AND --pqc-hybrid (or --crypto-suite ed25519+ml-dsa-v1) both appear. */
  cryptoSuiteConflict: boolean;
}

function parseProvisionFlags(
  argv: string[],
  env: NodeJS.ProcessEnv,
): ProvisionFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  // PQC default-on: hybrid (Ed25519+ML-DSA-65) is the DEFAULT for a fresh
  // federation trust root. Two equivalent OPT-OUTS select the legacy classical
  // root: the boolean --classical, or the explicit --crypto-suite ed25519-v1.
  // Two equivalent (now no-op-but-accepted) OPT-INS name the default explicitly:
  // the boolean --pqc-hybrid, or --crypto-suite ed25519+ml-dsa-v1. Absence of any
  // flag = the hybrid default.
  const cryptoSuite = flag("--crypto-suite");
  const suiteSelectsHybrid = cryptoSuite === FEDERATION_ISSUANCE_SUITE_HYBRID;
  const suiteSelectsClassical = cryptoSuite === FEDERATION_ISSUANCE_SUITE_CLASSICAL;
  const cryptoSuiteInvalid =
    cryptoSuite !== undefined &&
    cryptoSuite !== FEDERATION_ISSUANCE_SUITE_HYBRID &&
    cryptoSuite !== FEDERATION_ISSUANCE_SUITE_CLASSICAL;
  const optOutClassical = argv.includes("--classical") || suiteSelectsClassical;
  const optInHybrid = argv.includes("--pqc-hybrid") || suiteSelectsHybrid;
  // Contradictory selection (e.g. `--classical --pqc-hybrid`) is a usage error,
  // not a silent default: refuse rather than guess which the operator meant.
  const cryptoSuiteConflict = optOutClassical && optInHybrid;
  return {
    nodeId: flag("--node-id"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
    // Default ON: hybrid unless the operator explicitly opts out with --classical
    // (or --crypto-suite ed25519-v1).
    pqcHybrid: !optOutClassical,
    cryptoSuiteInvalid,
    cryptoSuiteConflict,
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
  if (flags.cryptoSuiteInvalid) {
    err.write(
      "sanctuary federation provision: --crypto-suite must be ed25519+ml-dsa-v1 " +
        "(hybrid, the default; same as --pqc-hybrid) or ed25519-v1 (classical " +
        "opt-out; same as --classical)\n",
    );
    return 1;
  }
  if (flags.cryptoSuiteConflict) {
    err.write(
      "sanctuary federation provision: --classical (or --crypto-suite ed25519-v1) " +
        "and --pqc-hybrid (or --crypto-suite ed25519+ml-dsa-v1) are mutually " +
        "exclusive. Hybrid is the default; pass --classical only to opt out.\n",
    );
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
          "(federation status shows fortress_id + node_id). To re-key the signing " +
          "master in place (keeping the fortress_id stable), use " +
          "`sanctuary federation rotate-root --renew` instead.\n",
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
        issuanceSuite: flags.pqcHybrid
          ? FEDERATION_ISSUANCE_SUITE_HYBRID
          : FEDERATION_ISSUANCE_SUITE_CLASSICAL,
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
    //
    // PQC Slice 3: a hybrid-provisioned fortress ALSO prints its hybrid pinned
    // master (PUBLIC: Ed25519 + ML-DSA-65 public keys), the out-of-band anchor a
    // hybrid-capable joiner pins. The classical pinned_master stays so a
    // current-version peer can still verify the Ed25519 chain. NEVER the ML-DSA
    // secret / hybrid private keys.
    const isHybrid = provisioned.context.isHybrid === true;
    out.write(
      `${JSON.stringify(
        {
          provisioned: true,
          fortress_id: provisioned.record.pinned_master_pubkey.fortress_id,
          node_id: provisioned.record.node_id,
          issuance_suite: isHybrid
            ? FEDERATION_ISSUANCE_SUITE_HYBRID
            : FEDERATION_ISSUANCE_SUITE_CLASSICAL,
          pinned_master: { ...provisioned.record.pinned_master_pubkey },
          ...(isHybrid && provisioned.context.hybridPinnedMaster
            ? { hybrid_pinned_master: provisioned.context.hybridPinnedMaster }
            : {}),
        },
        null,
        2,
      )}\n`,
    );
    if (isHybrid) {
      // One honest, non-naggy note on the DEFAULT (now hybrid) path: scope of the
      // hybrid choice (no overclaim) AND the version-requirement trade stated
      // plainly. Printed ONCE, at provision time only (NOT on every command).
      err.write(
        "sanctuary federation provision: provisioned with the DEFAULT hybrid " +
          "Ed25519+ML-DSA-65 federation signing master. This makes ONLY the " +
          "federation trust-root cert chain post-quantum-capable; it does NOT " +
          "make audit, transparency, reputation, custody at-rest, or transport " +
          "post-quantum. TRADE: every machine that joins this fortress's " +
          "federation must run a hybrid-capable Sanctuary version to verify this " +
          "root. If you need to federate with an older (classical-only) peer, " +
          "re-provision a fresh fortress with --classical (or --crypto-suite " +
          "ed25519-v1). NOTE: a hybrid root cannot yet be rotated or " +
          "compromise-revoked in place -- rotate-root refuses on hybrid roots " +
          "(hybrid rotation is a planned follow-up). If you need in-place " +
          "rotation or compromise-recovery today, provision with --classical.\n",
      );
    } else {
      // Inverse note on the --classical opt-out: maximal back-compat, but NO
      // post-quantum protection on the signing master. Printed ONCE, at provision
      // time only. Honest + non-naggy.
      err.write(
        "sanctuary federation provision: provisioned with the OPT-OUT classical " +
          "Ed25519-only federation signing master (--classical). This root has " +
          "NO post-quantum protection, but is verifiable by any peer including " +
          "older (classical-only) Sanctuary versions. For post-quantum resistance " +
          "of the federation trust root, omit --classical to take the default " +
          "hybrid root (which then requires all peers to be hybrid-capable).\n",
      );
    }
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

interface RotateRootFlags {
  renew: boolean;
  compromise: boolean;
  resume: boolean;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseRotateRootFlags(
  argv: string[],
  env: NodeJS.ProcessEnv,
): RotateRootFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    renew: argv.includes("--renew"),
    compromise: argv.includes("--compromise") || argv.includes("--compromised"),
    resume: argv.includes("--resume"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
  };
}

/**
 * `sanctuary federation rotate-root --renew` (Slice 3a, issuer-side, pure-local).
 *
 * Rotates the FEDERATION SIGNING MASTER (the Ed25519 keypair every joiner pins),
 * NOT the custody master. The renewal path mints a NEW keypair K2, keeps the
 * fortress_id + the symmetric master_secret STABLE, re-issues the principal +
 * local node cert under K2, signs a rotation certificate with the OLD key K1
 * (the old->new adoption link a joiner verifies in Slice 3b), and atomically
 * promotes the new root (staged-then-promote journal; `--resume` completes a
 * crashed rotation). The fortress always boots to a valid issuer root.
 *
 * Operator-gated by custody unlock (`openOperatorSigner`, keychain-safe,
 * fail-closed). Audited under the operator pubkey. Prints ONLY safe public
 * material: the NEW pinned master (for out-of-band redistribution) + the rotation
 * cert. NEVER prints/logs a master private key or the master_secret.
 *
 * Exit codes:
 *   0 rotated (or resumed) + promoted · 1 usage · 3 refused (not provisioned /
 *   fail-closed custody / mutual-exclusion / rotation failure). No exit 2 (no
 *   HTTP call).
 */
export async function runFederationRotateRoot(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  /** Test seam: keychain-safe custody-unlock (defaults to the real impl). */
  openSigner?: typeof openOperatorSigner;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const openSigner = args.openSigner ?? openOperatorSigner;
  const flags = parseRotateRootFlags(args.argv, env);

  // --renew and --compromised are mutually exclusive intents.
  if (flags.compromise && flags.renew) {
    err.write(
      "sanctuary federation rotate-root: --renew and --compromised are mutually exclusive; " +
        "pick one (--renew = planned re-key, old key stays trusted; --compromised = revoke the " +
        "old root + rotate the master_secret, old key permanently distrusted)\n",
    );
    return 1;
  }
  if (!flags.renew && !flags.compromise && !flags.resume) {
    err.write(
      "sanctuary federation rotate-root: specify --renew (planned re-key), --compromised " +
        "(revoke a compromised root), or --resume (complete a crashed rotation)\n",
    );
    return 1;
  }

  // Operator gate: keychain-safe custody unlock. Fail closed (exit 3) on no
  // credential, wrong passphrase, or no default operator identity.
  let signer: OperatorSigner;
  try {
    signer = await openSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    // Fail-closed custody. A custody master-rotation in progress (mutual
    // exclusion, defense in depth: the unlock itself refuses) maps to a clear
    // exit 3, not an opaque exit 1.
    if (
      cause instanceof OperatorSigningError ||
      cause instanceof CustodyUnlockError ||
      cause instanceof CustodyRotationInProgressError
    ) {
      err.write(`sanctuary federation rotate-root: ${cause.message}\n`);
      return 3;
    }
    err.write(`sanctuary federation rotate-root: unexpected error: ${String(cause)}\n`);
    return 1;
  }

  const operatorPubkeyB64 = toBase64url(signer.operatorPublicKey);
  const auditLog = new AuditLog(signer.storage, signer.masterKey);
  const audit = async (event: FederationRotateRootAuditEvent): Promise<void> => {
    try {
      await auditLog.append(
        "l2",
        event.operation,
        "federation",
        { ...event.details, operator_pubkey: operatorPubkeyB64 },
        event.result,
      );
    } catch {
      // Federation stays fail-closed; an audit-write failure never masks the
      // verb's rotation/refusal outcome.
    }
  };

  try {
    const resuming = flags.resume && (await federationRotateRootInProgress(signer.storage));
    // --resume with no journal but a fresh-rotate intent also set -> fall through
    // to a fresh rotation. --resume alone with no journal -> nothing to resume.
    if (flags.resume && !resuming && !flags.renew && !flags.compromise) {
      err.write(
        "sanctuary federation rotate-root: no federation rotate-root is in progress on this " +
          "fortress (no journal); nothing to resume\n",
      );
      return 3;
    }

    // Whether the in-progress journal (if any) is a compromise rotate decides
    // which resume to run, regardless of which flag the operator passed.
    const journalIsCompromise =
      resuming &&
      (await federationRotateRootJournalIsCompromise(
        signer.storage,
        signer.masterKey,
      ));
    const compromisePath = resuming ? journalIsCompromise : flags.compromise;

    if (compromisePath) {
      const result = resuming
        ? await resumeFederationRootCompromised({
            storage: signer.storage,
            masterKey: signer.masterKey,
            audit,
            log: (line) => err.write(`${line}\n`),
          })
        : await rotateFederationRootCompromised({
            storage: signer.storage,
            masterKey: signer.masterKey,
            audit,
            log: (line) => err.write(`${line}\n`),
          });

      // Print ONLY safe public material. There is DELIBERATELY no rotation cert
      // for a compromise rotate (downgrade resistance); adoption is out-of-band
      // re-pin of the new pinned_master (Slice 3c-2). NEVER a private key /
      // master_secret.
      out.write(
        `${JSON.stringify(
          {
            rotated: true,
            compromised: true,
            resumed: resuming,
            fortress_id: result.fortress_id,
            revoked_master_pubkey: result.revoked_master_pubkey,
            revocation_serial: result.revocation_serial,
            pinned_master: { ...result.new_pinned_master },
            root_revocation: { ...result.root_revocation },
            adoption: "out-of-band re-pin of pinned_master (no rotation cert is issued for a compromise)",
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    const result = resuming
      ? await resumeFederationRootRotation({
          storage: signer.storage,
          masterKey: signer.masterKey,
          audit,
          log: (line) => err.write(`${line}\n`),
        })
      : await rotateFederationRootRenew({
          storage: signer.storage,
          masterKey: signer.masterKey,
          audit,
          log: (line) => err.write(`${line}\n`),
        });

    // Print ONLY safe public material: the NEW pinned master (the out-of-band
    // trust anchor to redistribute) + the rotation cert (public). NEVER a private
    // key or the master_secret.
    out.write(
      `${JSON.stringify(
        {
          rotated: true,
          resumed: result.resumed,
          fortress_id: result.fortress_id,
          rotation_serial: result.rotation_serial,
          previous_master_pubkey: result.previous_master_pubkey,
          pinned_master: { ...result.new_pinned_master },
          rotation_cert: { ...result.rotation_cert },
        },
        null,
        2,
      )}\n`,
    );
    return 0;
  } catch (cause) {
    if (
      cause instanceof FederationRotateRootError ||
      cause instanceof FederationRotateRootResumeError
    ) {
      err.write(`sanctuary federation rotate-root: ${cause.message}\n`);
      return 3;
    }
    err.write(
      `sanctuary federation rotate-root: failed to rotate the federation root: ${String(cause)}\n`,
    );
    return 3;
  } finally {
    try {
      await auditLog.flush();
    } catch {
      // Audit durability is best-effort; never change the verb's exit code.
    }
    // Constraint 6: the custody master never persists past this call.
    signer.masterKey.fill(0);
  }
}

interface RevealMasterSecretFlags {
  /** Explicit, mandatory disclosure confirmation (matches the repo --yes idiom). */
  confirmed: boolean;
  passphrase?: string;
  recoveryKey?: string;
  fortressPath?: string;
}

function parseRevealMasterSecretFlags(
  argv: string[],
  env: NodeJS.ProcessEnv,
): RevealMasterSecretFlags {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  return {
    // --yes is the repo's confirm idiom (transparency enable, castle-wall boot
    // remove). The long-form alias spells out the consequence so a reviewer
    // reading a script knows EXACTLY what was disclosed.
    confirmed:
      argv.includes("--yes") ||
      argv.includes("-y") ||
      argv.includes("--i-understand-this-reveals-the-master-secret"),
    passphrase: flag("--passphrase") ?? env.SANCTUARY_PASSPHRASE,
    recoveryKey: env.SANCTUARY_RECOVERY_KEY,
    fortressPath: flag("--fortress"),
  };
}

/**
 * `sanctuary federation reveal-master-secret` (issuer-side, pure-local).
 *
 * EXPORTS the fortress issuer MASTER SECRET as base64url to stdout, so the
 * issuer operator can hand it to a joining machine's
 * `federation join --master-secret`. This makes the armed local-mode federation
 * marquee 100% stock-CLI (no out-of-band helper needed to read the secret).
 *
 * The master secret is the 32-byte symmetric HKDF source persisted in the
 * `_federation/trust-root-v1` record (`master_secret`); it is the SAME value the
 * join path consumes (`deriveNodeTransportKey({ fortress_master_secret })`). We
 * read THAT canonical source via the encrypted trust-root store; we never
 * re-derive or fabricate it.
 *
 * SECURITY CONTRACT (this is custody-core: it discloses a master secret):
 *   - CONFIRM-GATED. A sensitive disclosure must be explicit. Without --yes
 *     (alias -y / --i-understand-this-reveals-the-master-secret) the verb refuses
 *     (exit 1) and prints guidance; nothing is read or revealed.
 *   - CUSTODY-GATED (Tier-1). It opens the local fortress headless via the SAME
 *     keychain-safe `openOperatorSigner` path every other gated federation verb
 *     uses (passphrase / recovery-key only; NEVER a keychain modal in headless).
 *     No credential / wrong passphrase / no default operator identity -> exit 3,
 *     fail-closed, never a weaker path.
 *   - ISSUER-ONLY in practice. Only a fortress that ran `provision` holds the
 *     `_federation/trust-root-v1` record carrying `master_secret`. A pure joiner
 *     persists to `_federation/joiner-trust-root-v1`, whose schema forbids the
 *     field, so this verb's `load()` returns null on a joiner and the verb fails
 *     closed (exit 3) revealing nothing. If no trust root exists, or the issuer
 *     record cannot be decrypted, it likewise fails closed WITHOUT revealing
 *     anything.
 *   - AUDITED (DURABLY, BEFORE DISCLOSURE). A Tier-1 master-secret disclosure is
 *     recorded under the resolving operator's PUBLIC key
 *     (`federation_master_secret_reveal`) via the DURABLE `appendCritical()` path
 *     (read-after-write verified), the same barrier the disclosure broker / export
 *     paths use. On the success path the durable audit is committed BEFORE the
 *     secret is written to stdout: if the audit cannot be persisted the verb
 *     aborts fail-closed (exit 3) with NOTHING on stdout, so a master secret never
 *     reaches stdout un-audited. The failure-reason events are durable too.
 *   - ZEROIZED. The base64url string and the decrypted secret Buffer are zeroed
 *     after writing (constraint 6 discipline), AS ARE the record's other private-
 *     key fields -- including, on a hybrid-suite issuer, every hybrid private key
 *     (master / issuing-principal / local-node Ed25519 + ML-DSA-65 secret bytes).
 *     NOTE: a base64url string is an immutable JS primitive that cannot be wiped
 *     in place; the secret BYTES are zeroed, and the disclosure is already on
 *     stdout by design.
 *
 * Exit codes:
 *   0 revealed · 1 usage (missing --yes) · 3 refused (fail-closed custody / not
 *   provisioned / record could not load). No exit 2 -- this verb makes no HTTP call.
 */
export async function runFederationRevealMasterSecret(args: {
  argv: string[];
  env?: NodeJS.ProcessEnv;
  out?: Writable;
  err?: Writable;
  /** Test seam: keychain-safe custody-unlock (defaults to the real impl). */
  openSigner?: typeof openOperatorSigner;
  /**
   * Test seam: construct the audit log (defaults to the real `AuditLog`). Lets a
   * test inject a log whose durable `appendCritical()` rejects, to prove the
   * success path aborts fail-closed with NOTHING on stdout when the disclosure
   * audit cannot be persisted.
   */
  makeAuditLog?: (storage: OperatorSigner["storage"], masterKey: Uint8Array) => AuditLog;
}): Promise<number> {
  const env = args.env ?? process.env;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const openSigner = args.openSigner ?? openOperatorSigner;
  const makeAuditLog =
    args.makeAuditLog ?? ((storage, masterKey) => new AuditLog(storage, masterKey));
  const flags = parseRevealMasterSecretFlags(args.argv, env);

  // Confirm gate FIRST: refuse a sensitive disclosure that was not explicitly
  // requested BEFORE we even unlock custody. Nothing is read or revealed.
  if (!flags.confirmed) {
    err.write(
      "sanctuary federation reveal-master-secret: this PRINTS the fortress master " +
        "secret (the 32-byte value that lets a machine join this federation) to " +
        "stdout. Anyone who captures it can join your mesh. Re-run with --yes " +
        "(alias -y) to confirm you intend to disclose it; redirect the output to a " +
        "secure channel and never paste it where it can be logged.\n",
    );
    return 1;
  }

  // Operator gate: keychain-safe custody unlock. Fail closed (exit 3) on no
  // credential, wrong passphrase, or no default operator identity -- never a
  // keychain modal, never a weaker path.
  let signer: OperatorSigner;
  try {
    signer = await openSigner({
      ...(flags.passphrase !== undefined ? { passphrase: flags.passphrase } : {}),
      ...(flags.recoveryKey !== undefined ? { recoveryKey: flags.recoveryKey } : {}),
      ...(flags.fortressPath !== undefined ? { fortressPath: flags.fortressPath } : {}),
    });
  } catch (cause) {
    if (
      cause instanceof OperatorSigningError ||
      cause instanceof CustodyUnlockError ||
      cause instanceof CustodyRotationInProgressError
    ) {
      err.write(`sanctuary federation reveal-master-secret: ${cause.message}\n`);
      return 3;
    }
    err.write(
      `sanctuary federation reveal-master-secret: unexpected error: ${String(cause)}\n`,
    );
    return 1;
  }

  const operatorPubkeyB64 = toBase64url(signer.operatorPublicKey);
  const auditLog = makeAuditLog(signer.storage, signer.masterKey);
  // DURABLE disclosure audit. This is custody-core: a master-secret disclosure
  // (and the failure reasons that gate it) MUST land durably, so we use the same
  // `appendCritical()` read-after-write barrier the disclosure broker / export
  // paths use. We AWAIT it and let a persist failure REJECT loudly -- a reveal
  // that cannot be audited must NOT proceed (constraint 5: never silently degrade
  // to a less-secure behavior). The operator signer is already resolved here, so
  // a signing identity exists for the critical append.
  const audit = async (result: "success" | "failure", reason?: string): Promise<void> => {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "federation_master_secret_reveal",
      identity_id: "federation",
      result,
      details: {
        operator_pubkey: operatorPubkeyB64,
        ...(reason !== undefined ? { reason } : {}),
      },
    });
  };

  let record: Awaited<ReturnType<FederationTrustRootStore["load"]>> = null;
  let secretBytes: Uint8Array | null = null;
  try {
    // Read the canonical source: the encrypted issuer trust-root record. We do
    // NOT mint and do NOT re-derive -- this is exactly the value the join path
    // consumes via deriveNodeTransportKey({ fortress_master_secret }).
    const store = new FederationTrustRootStore(signer.storage, signer.masterKey);
    try {
      record = await store.load();
    } catch (cause) {
      // A present-but-corrupt / undecryptable record fails closed WITHOUT
      // revealing anything (constraint 5: never degrade to a weaker behavior).
      await audit("failure", "trust_root_load_failed");
      const detail =
        cause instanceof FederationTrustRootStoreError ? cause.message : "decrypt failed";
      err.write(
        `sanctuary federation reveal-master-secret: could not load this fortress's ` +
          `federation trust root (${detail}). Refusing.\n`,
      );
      return 3;
    }

    if (record === null) {
      await audit("failure", "not_provisioned");
      err.write(
        "sanctuary federation reveal-master-secret: this fortress has no federation " +
          "trust root (_federation/trust-root-v1). Provision an issuer first " +
          "(`sanctuary federation provision --node-id <id>`), or you are on a node " +
          "that never provisioned/joined. Refusing.\n",
      );
      return 3;
    }

    // The 32-byte symmetric master secret -- the SAME value a joiner feeds to
    // `join --master-secret`. Only an ISSUER (ran `provision`) holds this
    // `_federation/trust-root-v1` record; a pure joiner persists to
    // `_federation/joiner-trust-root-v1` (no `master_secret`), so `load()`
    // returned null above and we never reach here on a joiner.
    secretBytes = Uint8Array.from(record.master_secret);
    let secretB64 = toBase64url(secretBytes);
    try {
      // AUDIT-BEFORE-DISCLOSE: commit the durable success audit FIRST. If it
      // cannot be persisted, `appendCritical()` rejects, we fall through to the
      // catch below, abort fail-closed (exit 3), and NOTHING is written to
      // stdout. The master secret never reaches stdout un-audited.
      await audit("success");
      // Only now -- with the disclosure durably audited -- print to stdout (the
      // intended output; pipe to the joiner's --master-secret).
      out.write(`${secretB64}\n`);
      return 0;
    } catch (cause) {
      // The durable success audit could not be persisted. Refuse the disclosure
      // (constraint 5: never silently degrade). Nothing was written to stdout.
      const detail = cause instanceof Error ? cause.message : String(cause);
      err.write(
        `sanctuary federation reveal-master-secret: could not durably record the ` +
          `Tier-1 disclosure audit event (${detail}); refusing to reveal the master ` +
          `secret. Nothing was written.\n`,
      );
      return 3;
    } finally {
      // Constraint 6 discipline: drop our reference. A JS string is immutable and
      // cannot be wiped in place, but the secret BYTES are zeroed in the outer
      // finally; the value is already on stdout by design (on the success path).
      secretB64 = "";
    }
  } finally {
    // Zeroize the secret bytes we copied out of the record (constraint 6).
    secretBytes?.fill(0);
    // The store's load() already zeroed its own decrypted plaintext; zero the
    // record's retained secret fields too so nothing lingers past this call.
    record?.master_secret.fill(0);
    record?.master_private_key?.fill(0);
    record?.issuing_principal_private_key.fill(0);
    record?.local_node_private_key.fill(0);
    // On a HYBRID-suite issuer, `record.hybrid` carries LIVE Ed25519 + ML-DSA-65
    // private keys (master, issuing-principal, local-node) decrypted transiently
    // by load(). The classical four fields above do NOT cover them, so zero every
    // hybrid private-key Uint8Array too (constraint 6). Optional chaining makes
    // this a safe no-op on a classical record where `hybrid` is absent.
    record?.hybrid?.master_private_keys?.ed25519?.private_key?.fill(0);
    record?.hybrid?.master_private_keys?.ml_dsa_65?.secret_key?.fill(0);
    record?.hybrid?.issuing_principal_private_keys?.ed25519?.private_key?.fill(0);
    record?.hybrid?.issuing_principal_private_keys?.ml_dsa_65?.secret_key?.fill(0);
    record?.hybrid?.local_node_private_keys?.ed25519?.private_key?.fill(0);
    record?.hybrid?.local_node_private_keys?.ml_dsa_65?.secret_key?.fill(0);
    // Durability already rode on `appendCritical()` above (read-after-write
    // verified before that promise resolved); this flush is a belt-and-suspenders
    // drain of anything else queued and never changes the verb's exit code.
    try {
      await auditLog.flush();
    } catch {
      // Drain is best-effort here; the critical disclosure audit was already
      // durably committed before any secret reached stdout.
    }
    // Constraint 6: the custody master never persists past this call.
    signer.masterKey.fill(0);
  }
}

const FEDERATION_HELP = `sanctuary federation -- cross-machine federation (Wave 1)

Provision (issuer) verb -- custody-unlocked, runs LOCALLY on the home fortress:
  sanctuary federation provision --node-id <id> [--classical] \\
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

              DEFAULT (PQC default-on): a fresh root is a HYBRID Ed25519+ML-DSA-65
              signing master and ALSO prints a hybrid_pinned_master. This makes
              ONLY the federation trust-root cert chain post-quantum-capable; it
              does NOT make audit, transparency, reputation, custody at-rest, or
              transport post-quantum. TRADE: every joining machine must run a
              hybrid-capable Sanctuary version to verify a hybrid root, AND a
              hybrid root cannot yet be rotated or compromise-revoked in place
              (rotate-root refuses on hybrid; hybrid rotation is a planned
              follow-up -- pass --classical if you need in-place rotation today).
              Pass --pqc-hybrid (or --crypto-suite ed25519+ml-dsa-v1) to name the
              default explicitly.

              --classical (alias --crypto-suite ed25519-v1) opts OUT to a legacy
              Ed25519-only root with NO post-quantum protection on the signing
              master, but maximal back-compat (verifiable by older classical-only
              peers). The existing fortresses you already provisioned are
              UNTOUCHED by this default: nothing is re-keyed or upgraded on load.

Rotate-root (issuer) verb -- custody-unlocked, runs LOCALLY on the home fortress:
  sanctuary federation rotate-root --renew \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]
  sanctuary federation rotate-root --compromised ...
  sanctuary federation rotate-root --resume ...

  rotate-root  ROTATE this fortress's federation SIGNING MASTER (the Ed25519
               keypair every joiner pins), NOT the custody master. --renew mints
               a NEW keypair while keeping the fortress_id stable, re-issues the
               principal + local node cert under it, signs a rotation certificate
               with the OLD key (the old->new link a joiner adopts), and
               atomically promotes the new root (journaled; --resume completes a
               crashed rotation). The fortress always boots to a valid root.

               --compromised handles a STOLEN root key: it mints a new keypair
               (stable fortress_id) AND a fresh master_secret (so every derived
               transport/audit key changes), revokes the OLD root permanently via
               a durable, restart-surviving root-revocation signed by the NEW key,
               and issues NO old-key-signed rotation cert (a thief holding the old
               key could forge one). Adoption is an OUT-OF-BAND re-pin of the new
               pinned_master only. After a --compromised rotate, any cert chaining
               to the old root is rejected (sync + join), even one that would
               otherwise verify.

               Custody-gated (SANCTUARY_PASSPHRASE / --passphrase /
               SANCTUARY_RECOVERY_KEY; never prompts the keychain). Refuses if not
               provisioned, or while a custody rotation is in progress. Prints the
               NEW pinned_master (PUBLIC) to redistribute out of band, plus the
               rotation cert (--renew) or the root revocation (--compromised).

               NOTE: a hybrid root (now the DEFAULT for a fresh provision) is NOT
               yet rotatable; rotate-root REFUSES on a hybrid root (rotating now
               would silently drop the ML-DSA key). Provision with --classical if
               you need in-place rotation today. Hybrid rotation is a planned
               follow-up.

Reveal-master-secret (issuer) verb -- custody-unlocked, runs LOCALLY on the home fortress:
  sanctuary federation reveal-master-secret --yes \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]

  reveal-master-secret  PRINT this fortress's federation master secret (base64url)
                        to stdout, so a joining machine can feed it to
                        'federation join --master-secret'. This is the value a
                        local-mode node needs out of band to derive its join proof;
                        exporting it via the stock CLI makes the armed federation
                        marquee fully self-serve (no out-of-band helper).

                        SENSITIVE DISCLOSURE: anyone who captures the master secret
                        can join this mesh. The verb REFUSES without an explicit
                        --yes (alias -y / --i-understand-this-reveals-the-master-secret)
                        and prints guidance instead. Custody-gated (needs an
                        unlocked default operator identity: SANCTUARY_PASSPHRASE /
                        --passphrase / SANCTUARY_RECOVERY_KEY; never prompts the
                        keychain), fails closed if no credential or no provisioned
                        trust root, and DURABLY records a Tier-1 disclosure audit
                        event BEFORE the secret is printed -- if that audit cannot
                        be persisted the reveal aborts (exit 3) with nothing on
                        stdout, so a master secret never reaches stdout un-audited.
                        Redirect the output to a secure channel; never paste it
                        where it can be logged.

Operator (issuer) verbs -- operator-signed, run on the home fortress:
  sanctuary federation enable  --fortress-url <url> [--idempotency-key <s>]
  sanctuary federation disable --fortress-url <url> [--idempotency-key <s>]
  sanctuary federation authorize [init] --fortress-url <url> --node-id <id> \\
    [--node-mode local|operator_cloud|sovereign_tee]
  sanctuary federation admit --fortress-url <url> --node-id <id> \\
    [--node-mode local|operator_cloud|sovereign_tee]
  sanctuary federation revoke --fortress-url <url> --node-id <id> \\
    [--reason <reason>] [--idempotency-key <s>]
  sanctuary federation policy-push --fortress-url <url> \\
    [--policy-path <path>] [--idempotency-key <s>]

  enable / disable   Turn federation on/off for this fortress. Operator-signed
                     Tier-1: needs an unlocked default operator identity
                     (SANCTUARY_PASSPHRASE / --passphrase / SANCTUARY_RECOVERY_KEY).
                     Enable fails closed if the fortress is not provisioned.

  authorize [init]   Mint a bootstrap token for a node you are authorizing to
                     join (POST /v1/federation/authorize/init). Prints the
                     bootstrap token JSON to hand to the joiner's
                     'federation join --bootstrap-token'. Operator-signed Tier-1.

  admit              Alias for authorize/init. Use when working from the fleet
                     admit/revoke mental model; it prints the same bootstrap
                     token JSON.

  revoke             Emit a durable operator-authority node eviction event
                     (POST /v1/federation/revoke). The fortress folds the event
                     into its revoked-node projection before acknowledging it,
                     so future joins/sync for that node fail closed.

  policy-push        Emit a durable operator-authority policy-bundle event
                     through POST /v1/federation/sync (no new route). The bundle
                     carries only the principal-policy version, SHA-256 hash, hash
                     algorithm, and issuing-principal signature. It never carries
                     raw policy contents, policy secrets, or private keys. Peers
                     verify the signature against the pinned federation master
                     before applying the version marker; failed verification is
                     rejected, never downgraded to a warning.

Fleet control plane (PR-3) verbs -- custody-unlocked, run LOCALLY:
  sanctuary federation revoke-push --version <n> [--license-id <id> ...] \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]
  sanctuary federation downgrade-log \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]

  revoke-push        SIGN + persist a fleet license REVOCATION LIST. Pass the FULL
                     set of revoked license ids (--license-id repeats; the set is
                     an absolute snapshot, not a delta) and a strictly-increasing
                     --version. Signed with this fortress's operator identity and
                     verified against the pinned key + monotonic version before it
                     is written, so a replayed OLD list cannot un-revoke a license.
                     A revoked license is then forced to Community (drops from the
                     central console). NEVER gates security: every node's Castle
                     Wall stays up. Prints only public material (never a key).

  downgrade-log      PRINT the operator-visible downgrade log: every tier/cap
                     transition with its reason and the node ids that left the
                     central console (their walls are unaffected). Answers "these N
                     nodes left the console because the plan lapsed" from the CLI.
                     Read-only; prints no key material.

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

Recover after a rotate-root -- run on the joining node:
  Planned rotation (the old root is still honest):
  sanctuary federation adopt --renew --fortress-url <url> \\
    --rotation-cert <json | @file> --pinned-master <K2 json | @file> \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]

  Compromise rotation (the old root is in enemy hands):
  sanctuary federation rejoin --fortress-url <url> \\
    --pinned-master <K2 json> --bootstrap-token <fresh json> --master-secret <new b64url> \\
    --revoked-old-master <K1 pubkey> --revocation-serial <n> \\
    [--passphrase <s> | SANCTUARY_PASSPHRASE | SANCTUARY_RECOVERY_KEY] [--fortress <path>]

  adopt    PLANNED-rotation adopt. After the operator runs 'rotate-root --renew'
           on the home fortress, a machine that was OFFLINE (or a new machine)
           moves from pinning the OLD root to the NEW one. It verifies the
           K1-signed rotation certificate under the root it CURRENTLY pins, then
           asserts the NEW root the cert attests byte-matches the OPERATOR-supplied
           --pinned-master (REQUIRED, out of band): a K1-signed cert alone is not a
           sufficient trust anchor when K1 may be compromised, so the adopted
           anchor is operator-confirmed and a forged K1->K2' cert fails closed even
           against an UNDETECTED compromise. It then runs the node-cert reissue
           proof-of-possession round against the existing endpoint (no new route),
           re-verifies the reissued cert chains to that operator-pinned NEW root
           (never the server response), and atomically re-pins it. Fail-closed: any
           doubt HOLDS the old trust anchor loudly and adopts nothing. Classical-
           only: a HYBRID rotation cert is refused (no silent post-quantum
           downgrade). Prints only PUBLIC material. The fully hands-off convenience
           is intentionally dropped for the unconditional guarantee. Exit: 0
           adopted, 1 usage, 2 fortress unreachable, 3 held.

  rejoin   COMPROMISE-rotation manual re-join. After 'rotate-root --compromised',
           nothing the OLD root signed can be believed, so there is NO automatic
           adoption: this is a fresh join against the operator-supplied NEW root.
           It REQUIRES the OUT-OF-BAND --pinned-master (K2), a FRESH
           --bootstrap-token, the new --master-secret, and --revoked-old-master +
           --revocation-serial so the re-joined record records the dead K1 with an
           anti-rollback floor (a later K1 or K1-signed rotation cert is then
           refused locally). It NEVER accepts an adoption bundle, a rotation cert,
           or any old-key-signed artifact. A guarded wrapper over 'join --persist';
           bare 'join --persist' plus 'revoke' serves the same purpose with more
           footguns. Exit: 0 re-joined, 1 usage, 2 fortress unreachable, 3 denied.
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
  if (sub === "rotate-root") {
    return runFederationRotateRoot({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "reveal-master-secret") {
    return runFederationRevealMasterSecret({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "join") {
    return runFederationJoin({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "adopt") {
    return runFederationAdopt({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "rejoin") {
    return runFederationRejoin({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "enable" || sub === "disable") {
    return runFederationEnableDisable({
      ...args,
      enable: sub === "enable",
      argv: args.argv.slice(1),
    });
  }
  if (sub === "authorize" || sub === "admit") {
    return runFederationAuthorize({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "revoke") {
    return runFederationRevoke({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "policy-push") {
    return runFederationPolicyPush({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "revoke-push") {
    return runFederationRevokePush({ ...args, argv: args.argv.slice(1) });
  }
  if (sub === "downgrade-log") {
    return runFederationDowngradeLog({ ...args, argv: args.argv.slice(1) });
  }
  (args.err ?? process.stderr).write(
    `sanctuary federation: unknown subcommand "${sub}"\n\n${FEDERATION_HELP}`,
  );
  return 1;
}
