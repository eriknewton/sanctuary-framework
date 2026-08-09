// fail-before-exempt: adapted to the shared verifyCapturedOperatorSignature helper
// only; these assertions check signature validity, not the anti-replay spent-set
// behavior, so they pass with or without the fix. Freshness fail-before tests:
// v1/operator-signed.test.ts and v1/federation-http.test.ts.
/**
 * Federation Slice 3b -- operator-signed admin CLI verb tests.
 *
 * Covers `sanctuary federation enable / disable / authorize / revoke` and
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
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  runFederationAuthorize,
  runFederationEnableDisable,
  runFederationJoin,
  runFederationPolicyPush,
  runFederationRevoke,
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
import {
  federationEventHash,
  JoinCeremony,
  type FederationEvent,
} from "../../src/v1/federation.js";
import {
  FEDERATION_SYNC_WIRE_VERSION,
} from "../../src/v1/federation-revocation.js";
import {
  FEDERATION_POLICY_BUNDLE_EVENT_KIND,
  FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM,
  verifyFederationPolicyBundleEvent,
} from "../../src/v1/federation-policy-bundle.js";
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

/**
 * Stub /v1 session-open for the unit tests that inject `request` (they exercise
 * the verb's signature-production contract against a stub responder, not the
 * real ceremony). It records the attestation factory was wired and returns a
 * fixed token. The end-to-end session-gate behavior is covered separately in
 * `federation-cli-admin-session.test.ts` against a REAL booted dashboard.
 */
const STUB_SESSION_TOKEN = "stub-v1-session-token";
const stubOpenSession = (async () =>
  ({ token: STUB_SESSION_TOKEN, expiresAt: 0, capabilities: [] })) as never;

function verifyCapturedOperatorSignature(params: {
  action: string;
  body: Record<string, unknown>;
}): boolean {
  const { operator_signature, ...payload } = params.body;
  return verifyOperatorSignature({
    action: params.action,
    payload,
    signature: operator_signature as string,
    operatorPublicKey: issuer.operator.publicKey,
  });
}

let fortressPath: string;
let issuer: SeededIssuerFortress;
const PASSPHRASE = "slice3b-drill-passphrase";

// Hermeticity guard (de-flake): the admin verbs reach `openOperatorSigner`,
// which sets the PROCESS-GLOBAL `process.env.SANCTUARY_STORAGE_PATH` so
// `loadConfig()` targets the `--fortress` override
// (`src/cli/federation-operator-signing.ts`). vitest runs multiple test files
// in one worker process, and that env var is shared across them. Without
// snapshot/restore this file would leak a pointer at its just-rm'd temp
// fortress into the shared worker, so a SIBLING test that later calls
// `loadConfig()` without its own `--fortress` reads a dead path and races to
// the wrong exit code (the non-hermetic CLI-subprocess/host-state flake class).
// Snapshotting both fortress env keys per test makes this file neither a leaker
// nor a victim. This is isolation only; no assertion is weakened, and the
// production verb behavior (it still sets the env to drive `loadConfig`) is
// untouched. Mirrors the established idiom in
// `test/cli/top-level-fortress-flag.test.ts`.
let savedStoragePath: string | undefined;
let savedFortressPath: string | undefined;

beforeEach(async () => {
  savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  savedFortressPath = process.env.SANCTUARY_FORTRESS_PATH;
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
  // maxRetries/retryDelay: recursive teardown of a just-written fortress dir
  // occasionally races the OS releasing child handles under parallel CI,
  // throwing ENOTEMPTY. Bounded retries are the repo's established mitigation
  // for that class (see audit-log-concurrent-write.test.ts).
  await rm(fortressPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  // Restore the process-global fortress env keys exactly as they were so this
  // file leaves the shared worker env untouched (no dead-path leak to siblings).
  if (savedStoragePath === undefined) {
    delete process.env.SANCTUARY_STORAGE_PATH;
  } else {
    process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
  }
  if (savedFortressPath === undefined) {
    delete process.env.SANCTUARY_FORTRESS_PATH;
  } else {
    process.env.SANCTUARY_FORTRESS_PATH = savedFortressPath;
  }
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
      openSession: stubOpenSession,
      request: async (path, init, ctx) => {
        captured = {
          action: path,
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        };
        // The verb must attach the /v1 session token it opened (the drill gap:
        // it used to send an empty token, 401ing against a real dashboard).
        expect(ctx?.authToken).toBe(STUB_SESSION_TOKEN);
        return { enabled: true };
      },
    });
    expect(code).toBe(0);
    expect(captured).not.toBeNull();
    const { action, body } = captured!;
    expect(action).toBe("/v1/federation/enable");
    expect(typeof body.operator_signature).toBe("string");

    expect(verifyCapturedOperatorSignature({ action, body })).toBe(true);
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
      openSession: stubOpenSession,
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
      openSession: stubOpenSession,
      request: async (path, init, ctx) => {
        captured = {
          action: path,
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        };
        expect(ctx?.authToken).toBe(STUB_SESSION_TOKEN);
        return { bootstrap_token: { intended_node_id: "joiner-linux", nonce: "n" } };
      },
    });
    expect(code).toBe(0);
    const { action, body } = captured!;
    expect(action).toBe("/v1/federation/authorize/init");
    expect(verifyCapturedOperatorSignature({ action, body })).toBe(true);
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
      openSession: stubOpenSession,
      request: async () => ({ bootstrap_token: { intended_node_id: "joiner-linux" } }),
    });
    expect(code).toBe(0);
  });
});

describe("federation revoke -- operator-signed node eviction", () => {
  it("fails closed (exit 3) without an operator credential", async () => {
    const err = capture();
    const code = await runFederationRevoke({
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

  it("signs revoke with the operator key and prints the eviction event summary", async () => {
    let captured: { action: string; body: Record<string, unknown> } | null = null;
    const out = capture();
    const code = await runFederationRevoke({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--node-id",
        "joiner-linux",
        "--reason",
        "operator_removed",
        "--idempotency-key",
        "idem-revoke-1",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
      openSession: stubOpenSession,
      request: async (path, init, ctx) => {
        captured = {
          action: path,
          body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        };
        expect(ctx?.authToken).toBe(STUB_SESSION_TOKEN);
        return {
          revoked: true,
          node_id: "joiner-linux",
          event_id: "operator:fortress:1",
          eviction_serial: 1,
        };
      },
    });
    expect(code).toBe(0);
    const { action, body } = captured!;
    expect(action).toBe("/v1/federation/revoke");
    expect(verifyCapturedOperatorSignature({ action, body })).toBe(true);
    expect(JSON.parse(out.get())).toEqual({
      revoked: true,
      node_id: "joiner-linux",
      event_id: "operator:fortress:1",
      eviction_serial: 1,
    });
  });
});

describe("federation policy-push -- signed operator policy bundle", () => {
  it("signs the current policy hash/version and enqueues it through /v1/federation/sync", async () => {
    const policyYaml = `version: 7
tier1_always_approve:
  - state_export
tier2_anomaly:
  new_namespace_access: approve
  new_counterparty: approve
  frequency_spike_multiplier: 5
  max_signs_per_minute: 10
  bulk_read_threshold: 20
  first_session_policy: approve
tier3_always_allow:
  - state_read
approval_channel:
  type: stderr
  timeout_seconds: 120
`;
    await writeFile(join(fortressPath, "principal-policy.yaml"), policyYaml, {
      mode: 0o600,
    });

    const captured: Array<{ action: string; body: Record<string, unknown> }> = [];
    const out = capture();
    const code = await runFederationPolicyPush({
      argv: [
        "--fortress-url",
        "http://127.0.0.1:9",
        "--fortress",
        fortressPath,
        "--idempotency-key",
        "idem-policy-1",
      ],
      env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
      out: out.stream,
      err: capture().stream,
      openSession: stubOpenSession,
      request: async (path, init, ctx) => {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        captured.push({ action: path, body });
        expect(path).toBe("/v1/federation/sync");
        expect(ctx?.authToken).toBe(STUB_SESSION_TOKEN);
        expect(body.wire_version).toBe(FEDERATION_SYNC_WIRE_VERSION);
        expect(body.node_id).toBe(issuer.trustRoot.record.node_id);
        expect(verifyCapturedOperatorSignature({ action: path, body })).toBe(true);

        if (captured.length === 1) {
          expect(body.events).toEqual([]);
          expect(body.cursor).toEqual({
            node_id: `operator:${issuer.fortressId}`,
          });
          return { accepted: [], rejected: [], events: [] };
        }

        const events = body.events as FederationEvent[];
        expect(events).toHaveLength(1);
        const event = events[0]!;
        const { event_hash: eventHash, ...withoutHash } = event;
        expect(eventHash).toBe(federationEventHash(withoutHash));
        expect(event.kind).toBe(FEDERATION_POLICY_BUNDLE_EVENT_KIND);
        expect(event.origin_node_id).toBe(`operator:${issuer.fortressId}`);
        expect(JSON.stringify(event.payload)).not.toContain("tier1_always_approve");
        expect(JSON.stringify(event.payload)).not.toContain("state_export");

        const verified = verifyFederationPolicyBundleEvent({
          event,
          fortressId: issuer.fortressId,
          pinnedMaster: issuer.pinnedMaster,
          operatorPrincipalCert: issuer.issuingPrincipalCert,
          currentPolicyVersion: null,
        });
        expect(verified.ok).toBe(true);
        if (verified.ok) {
          expect(verified.payload.policy_version).toBe(7);
          expect(verified.payload.policy_hash_algorithm).toBe(
            FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM,
          );
        }
        return { accepted: [event.event_id], rejected: [], events: [] };
      },
    });

    expect(code).toBe(0);
    expect(captured).toHaveLength(2);
    expect("cursor" in captured[1]!.body).toBe(false);
    expect(captured[1]!.body.idempotency_key).toBe("idem-policy-1");
    const printed = JSON.parse(out.get()) as {
      policy_pushed: boolean;
      policy_version: number;
      policy_hash: string;
      hash_algorithm: string;
      event_id: string;
    };
    expect(printed.policy_pushed).toBe(true);
    expect(printed.policy_version).toBe(7);
    expect(printed.policy_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(printed.hash_algorithm).toBe(FEDERATION_POLICY_BUNDLE_HASH_ALGORITHM);
    expect(JSON.stringify(printed)).not.toContain("state_export");
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

  it("passes --fortress=<path> to the joiner persistence layer", async () => {
    const bootstrapToken = new JoinCeremony(issuerContextWithApprover(issuer)).authorizeInit({
      intendedNodeId: "joiner-linux",
      intendedNodeMode: "local",
    });
    const joinerPath = await mkdtemp(join(tmpdir(), "slice3b-joiner-equals-"));
    let capturedFortressPath: string | undefined;
    try {
      const code = await runFederationJoin({
        argv: [
          "--fortress-url",
          "http://127.0.0.1:9",
          "--bootstrap-token",
          JSON.stringify(bootstrapToken),
          "--master-secret",
          toBase64url(issuer.masterSecret),
          "--persist",
          "--pinned-master",
          JSON.stringify(issuer.pinnedMaster),
          `--fortress=${joinerPath}`,
        ],
        env: { SANCTUARY_PASSPHRASE: PASSPHRASE },
        out: capture().stream,
        err: capture().stream,
        request: async () => ({
          certificate: { node_id: "joiner-linux" },
          issuing_principal_cert: { principal_id: "issuer" },
        }),
        persistJoinerTrustRoot: async (params) => {
          capturedFortressPath = params.fortressPath;
        },
      });

      expect(code).toBe(0);
      expect(capturedFortressPath).toBe(joinerPath);
    } finally {
      await rm(joinerPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
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
      await rm(joinerPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  });
});
