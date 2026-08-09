/**
 * Shared /v1 HTTP test rig (PR-A1/A2/A3).
 *
 * Boots a real DashboardApprovalChannel on loopback and provides two ways to
 * open a session that match the PR-A3 attestation model:
 *   - `openDurableSession`: signs a durable Ed25519 operator attestation with
 *     the rig's operator identity key (the credentialed path).
 *   - `openLoopbackSession`: enables post-unlock loopback auto-auth and opens
 *     tokenless (the same-box network-position path).
 */

import { expect } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { FederationSyncStateStore } from "../../src/v1/federation-sync-state-store.js";
import type { IdentityManager } from "../../src/cognitive/tools.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { signOperatorAttestation } from "../../src/v1/operator-attestation.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { getFreePort } from "../helpers/free-port.js";

/** One operator identity reused across the suite (the daemon resolves this). */
export const OPERATOR = (() => {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
})();

export interface TestRig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  auditLog: AuditLog;
  stop: () => Promise<void>;
}

/** Minimal IdentityManager exposing only what the /v1 routes read. */
export function stubIdentityManager(publicKey: Uint8Array): IdentityManager {
  return {
    getDefault: () => ({
      identity_id: "op-1",
      label: "operator",
      did: "did:key:test",
      public_key: toBase64url(publicKey),
      created_at: "2026-06-01T00:00:00.000Z",
      key_type: "ed25519",
      key_protection: "passphrase",
    }),
    getPrimaryIdentityId: () => "op-1",
    get: () => undefined,
  } as unknown as IdentityManager;
}

export async function startRig(opts?: {
  withOperatorIdentity?: boolean;
  /**
   * Resolve the daemon's operator identity to THIS public key instead of the
   * suite-wide {@link OPERATOR}. Used by the CLI session-gap test, where the
   * verb signs with a real seeded-fortress operator key the daemon must accept.
   * Implies `withOperatorIdentity`.
   */
  operatorPublicKey?: Uint8Array;
  syncStateStorage?: StorageBackend;
  syncStateMasterKey?: Uint8Array;
}): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const authToken = `v1-test-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });

  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
    ...(opts?.operatorPublicKey
      ? { identityManager: stubIdentityManager(opts.operatorPublicKey) }
      : opts?.withOperatorIdentity
        ? { identityManager: stubIdentityManager(OPERATOR.publicKey) }
        : {}),
  });
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({
      storage: opts?.syncStateStorage ?? storage,
      masterKey: opts?.syncStateMasterKey ?? masterKey,
    }),
  );

  await dashboard.start();
  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    auditLog,
    stop: async () => {
      await dashboard.stop();
    },
  };
}

/** init → sign challenge → complete, returning the session token. */
async function runCeremony(
  rig: TestRig,
  initBody: (clientPubkey: Uint8Array) => Record<string, unknown>,
): Promise<string> {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  const initRes = await fetch(`${rig.baseUrl}/v1/session/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(initBody(publicKey)),
  });
  expect(initRes.status).toBe(200);
  const init = (await initRes.json()) as {
    challenge: string;
    challenge_id: string;
    attestation_ref: string;
  };
  const message = buildChallengeMessage(
    publicKey,
    fromBase64url(init.challenge),
    init.attestation_ref,
  );
  const completeRes = await fetch(`${rig.baseUrl}/v1/session/complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challenge_id: init.challenge_id,
      client_signature: toBase64url(ed25519.sign(message, privateKey)),
    }),
  });
  expect(completeRes.status).toBe(200);
  const complete = (await completeRes.json()) as { session_token: string };
  return complete.session_token;
}

/** Open a session via the durable operator attestation (needs operator identity). */
export function openDurableSession(rig: TestRig): Promise<string> {
  return runCeremony(rig, (clientPubkey) => ({
    client_pubkey: toBase64url(clientPubkey),
    operator_attestation: signOperatorAttestation({
      operatorPublicKey: OPERATOR.publicKey,
      operatorPrivateKey: OPERATOR.privateKey,
      clientPubkey,
      issuedAtMs: Date.now(),
    }),
  }));
}

/** Open a session via post-unlock loopback auto-auth (no operator identity needed). */
export function openLoopbackSession(rig: TestRig): Promise<string> {
  rig.dashboard.setAutoAuthLocalhost(true);
  return runCeremony(rig, (clientPubkey) => ({
    client_pubkey: toBase64url(clientPubkey),
  }));
}
