/**
 * Federation drill seed (TEST / DRILL ONLY -- Slice 3c).
 *
 * Seeds an isolated fortress with three things, all keychain-free, so the
 * production federation auth + provisioning paths engage end to end:
 *   1. custody   -- `establishMaster` headless, `mintRecoveryKey: false` (the
 *                  validated no-modal seed primitive; no recovery-key disk
 *                  fallback);
 *   2. a DEFAULT operator identity -- the fix for the 06-23 drill failure
 *                  (`Identities loaded: 0`): without a default identity,
 *                  `resolveOperatorPublicKey()` returns null and every
 *                  operator-signed `/v1/federation` action 403s and loopback
 *                  auto-auth never engages;
 *   3. a trust root -- issuer variant via `provisionOrLoadFederationTrustRoot`
 *                  (mints the home `_federation/trust-root-v1`); joiner variant
 *                  via `persistFederationJoinerTrustRoot` (persists only what a
 *                  REAL join yields -- never fabricated issuer material).
 *
 * WHY THIS IS THE REAL FIX, NOT A MASK: it composes the SAME production
 * functions a real boot uses. It does NOT inject an auto-approve approver, does
 * NOT relax any gate, and does NOT short-circuit operator signing. The only
 * test-only affordance is that it runs headless with a known passphrase instead
 * of an interactive operator. (The marquee test supplies its own explicit
 * approval gate when it drives a real join -- that injection is visible in the
 * test, never hidden in this seed.)
 *
 * MUST NEVER be imported from `server/src`. It lives under `server/test/` and
 * the adversarial gate greps for any production import of it.
 */

import { establishMaster } from "../../src/core/master-custody.js";
import type { MasterWriteBarrierLease } from "../../src/storage/cross-process-lock.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import {
  provisionOrLoadFederationTrustRoot,
  type ProvisionedFederationTrustRoot,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  persistFederationJoinerTrustRoot,
  type ProvisionedFederationJoinerTrustRoot,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

export interface SeededOperatorIdentity {
  identityId: string;
  /** Operator public key bytes (matches what `resolveOperatorPublicKey` resolves). */
  publicKey: Uint8Array;
}

/**
 * Seed custody + a DEFAULT operator identity against `storage`. Returns the
 * unlocked master key (caller owns zeroing) and the operator identity. This is
 * the common base of both the issuer and joiner seeds.
 */
export async function seedCustodyAndOperator(opts: {
  storage: StorageBackend;
  passphrase: string;
  operatorLabel?: string;
}): Promise<{
  masterKey: Uint8Array;
  operator: SeededOperatorIdentity;
  // The shared master-rotation reader lease establishMaster now holds until its
  // final write. A same-process caller that will later invoke a rotation (which
  // drains this reader on its exclusive side) MUST release it first to model a
  // separate rotate-master invocation; a real crashed process reaps its own
  // socket, but an in-process test does not. Discarding it (the historical
  // shape) leaks a live reader that a same-process rotateMaster then waits on.
  masterWriteBarrier?: MasterWriteBarrierLease;
}> {
  const { masterKey, masterWriteBarrier } = await establishMaster({
    storage: opts.storage,
    passphrase: opts.passphrase,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });

  const identityManager = new IdentityManager(opts.storage, masterKey);
  await identityManager.load();
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(
    opts.operatorLabel ?? "drill-operator",
    identityEncryptionKey,
    "passphrase",
  );
  // The first identity saved becomes primary automatically (IdentityManager.save),
  // so getDefault() / resolveOperatorPublicKey() now resolve it.
  await identityManager.save(storedIdentity);

  return {
    masterKey,
    operator: {
      identityId: storedIdentity.identity_id,
      publicKey: fromBase64url(storedIdentity.public_key),
    },
    masterWriteBarrier,
  };
}

export interface SeededIssuerFortress {
  masterKey: Uint8Array;
  operator: SeededOperatorIdentity;
  /** The provisioned ISSUER trust root (context carries issuer accessors). */
  trustRoot: ProvisionedFederationTrustRoot;
  fortressId: string;
  /** The out-of-band pinned master a sibling joiner must trust. */
  pinnedMaster: FortressMasterPublicKey;
  /** The 32-byte symmetric fortress master secret (out-of-band to a joiner). */
  masterSecret: Uint8Array;
  /** The issuing principal cert (public). */
  issuingPrincipalCert: PrincipalCertificate;
  /**
   * The held shared master-rotation reader lease from custody establishment.
   * A caller that will later invoke rotateMaster in the SAME process must
   * release this first (see seedCustodyAndOperator's note); otherwise the
   * rotation's exclusive drain waits on this still-live in-process reader.
   */
  masterWriteBarrier?: MasterWriteBarrierLease;
}

/**
 * Seed an ISSUER fortress: custody + default operator identity + a minted
 * `_federation/trust-root-v1`. Returns the materials a sibling joiner seed/CLI
 * needs out of band (pinned master, master secret).
 */
export async function seedFederationIssuerFortress(opts: {
  storage: StorageBackend;
  passphrase: string;
  nodeId: string;
  operatorLabel?: string;
}): Promise<SeededIssuerFortress> {
  const { masterKey, operator, masterWriteBarrier } = await seedCustodyAndOperator({
    storage: opts.storage,
    passphrase: opts.passphrase,
    ...(opts.operatorLabel !== undefined ? { operatorLabel: opts.operatorLabel } : {}),
  });

  const trustRoot = await provisionOrLoadFederationTrustRoot({
    storage: opts.storage,
    masterKey,
    mint: true,
    nodeId: opts.nodeId,
    nodeMode: "local",
    principalId: "principal-root",
  });
  if (trustRoot === null) {
    throw new Error("federation drill seed: issuer trust root mint returned null");
  }

  return {
    masterKey,
    operator,
    trustRoot,
    fortressId: trustRoot.record.pinned_master_pubkey.fortress_id,
    pinnedMaster: { ...trustRoot.record.pinned_master_pubkey },
    masterSecret: Uint8Array.from(trustRoot.record.master_secret),
    issuingPrincipalCert: { ...trustRoot.record.issuing_principal_cert },
    masterWriteBarrier,
  };
}

export interface SeededJoinerFortress {
  masterKey: Uint8Array;
  operator: SeededOperatorIdentity;
  /** The persisted NON-ISSUER joiner trust root (no issuer accessors). */
  joinerTrustRoot: ProvisionedFederationJoinerTrustRoot;
}

/**
 * Seed a JOINER fortress: custody + default operator identity + a persisted
 * `_federation/joiner-trust-root-v1`. The cert + node key MUST come from a REAL
 * join ceremony (this helper persists only what a real join yields; it never
 * fabricates issuer material). The pinned master is the OUT-OF-BAND trust
 * anchor; `persistFederationJoinerTrustRoot` refuses a cert that does not chain
 * to it.
 */
export async function seedFederationJoinerFortress(opts: {
  storage: StorageBackend;
  passphrase: string;
  /** From the real join ceremony: */
  pinnedMaster: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  localNodeCert: NodeIdentityCertificate;
  localNodePrivateKey: Uint8Array;
  operatorLabel?: string;
}): Promise<SeededJoinerFortress> {
  const { masterKey, operator } = await seedCustodyAndOperator({
    storage: opts.storage,
    passphrase: opts.passphrase,
    ...(opts.operatorLabel !== undefined ? { operatorLabel: opts.operatorLabel } : {}),
  });

  const joinerTrustRoot = await persistFederationJoinerTrustRoot({
    storage: opts.storage,
    masterKey,
    pinnedMasterPubkey: opts.pinnedMaster,
    issuingPrincipalCert: opts.issuingPrincipalCert,
    localNodeCert: opts.localNodeCert,
    localNodePrivateKey: opts.localNodePrivateKey,
  });

  return { masterKey, operator, joinerTrustRoot };
}
