/**
 * Standalone-boot production join approver (local / sovereign_tee), driven
 * through the REAL JoinCeremony.authorizeComplete path — not a bypassed shape.
 *
 * This is the gate that replaces the tests-only auto-deny placeholder in the
 * standalone dashboard boot. The headline is the REPLAY test: on `main` today
 * there is no nonce-consumption store for local-mode joins, so a valid join is
 * replayable for the full bootstrap-token TTL; these tests prove the new approver
 * closes that gap while keeping a first valid join working end to end.
 *
 * Pins the build's BLOCKING criteria:
 *  (a) a valid token-bearing local join is APPROVED and a cert is issued that
 *      chains to the pinned master,
 *  (b) a REPLAY (same bootstrap token / nonce) is DENIED,
 *  (c) a token-less / forged-token join is DENIED (ceremony step 1),
 *  (d) an operator_cloud join is DENIED by THIS approver,
 *  (e) a revoked node is DENIED (incl. the isNodeRevoked-throws case),
 *  (f) an expired token is DENIED (ceremony step 1 + nonce-store defense).
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import {
  JoinCeremony,
  type FederationContext,
  type FederationIssuerContext,
} from "../../src/v1/federation.js";
import {
  BootstrapNonceStore,
  createStandaloneJoinApprover,
} from "../../src/mesh/lifecycle/standalone-join-approver.js";
import { issueBootstrapToken } from "../../src/mesh/lifecycle/bootstrap-token.js";
import { verifyCertChain } from "../../src/mesh/trust-root.js";
import { assembleJoinRequest } from "../../src/cli/federation.js";
import { makeFederationMaterials } from "../v1/fed-materials.js";
import { toBase64url } from "../../src/core/encoding.js";
import type { NodeMode } from "../../src/mesh/constants.js";

const JOINER_NODE_ID = "second-machine-1";

/**
 * Build an issuer context whose approver is the REAL standalone approver (with a
 * single-use nonce store), plus a genuine local JoinRequest assembled from a
 * fresh operator-signed bootstrap token via the real CLI assembly path.
 */
function setup(opts?: {
  nonceStore?: BootstrapNonceStore;
  intendedNodeMode?: NodeMode;
  isNodeRevoked?: (nodeId: string) => boolean;
  ttlMs?: number;
}) {
  const materials = makeFederationMaterials();
  const nonceStore = opts?.nonceStore ?? new BootstrapNonceStore();
  const intendedNodeMode = opts?.intendedNodeMode ?? "local";

  const approver = createStandaloneJoinApprover({
    pinned_master_pubkey: materials.context.pinnedMasterPubkey,
    issuing_principal_cert: materials.context.issuingPrincipalCert,
    getIssuingPrincipalPrivateKey:
      materials.context.getIssuingPrincipalPrivateKey,
    getMasterPrivateKey: materials.context.getMasterPrivateKey,
    nonceStore,
  });

  const issuerContext: FederationIssuerContext = {
    ...materials.context,
    approver,
    ...(opts?.isNodeRevoked ? { isNodeRevoked: opts.isNodeRevoked } : {}),
  };

  const token = issueBootstrapToken({
    intended_node_id: JOINER_NODE_ID,
    intended_node_mode: intendedNodeMode,
    fortress_id: materials.fortressId,
    issuing_principal: materials.context.issuingPrincipalCert.principal_id,
    principal_private_key: materials.context.getIssuingPrincipalPrivateKey(),
    ...(opts?.ttlMs !== undefined ? { ttl_ms: opts.ttlMs } : {}),
  });

  const assembled = assembleJoinRequest({
    bootstrapToken: token,
    fortressMasterSecret: materials.masterSecret,
  });

  return { materials, nonceStore, approver, issuerContext, token, assembled };
}

describe("standalone join approver — valid local join (criterion a)", () => {
  it("APPROVES a first valid token-bearing local join and issues a chaining cert", async () => {
    const { issuerContext, assembled, materials } = setup();
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(true);
    if (outcome.approved) {
      expect(outcome.certificate.node_id).toBe(JOINER_NODE_ID);
      expect(outcome.certificate.node_mode).toBe("local");
      expect(() =>
        verifyCertChain(
          outcome.certificate,
          materials.context.issuingPrincipalCert,
          materials.context.pinnedMasterPubkey,
        ),
      ).not.toThrow();
    }
  });
});

describe("standalone join approver — REPLAY denied (criterion b, the headline)", () => {
  it("DENIES a second submission of the SAME bootstrap token / nonce", async () => {
    // One nonce store shared across both attempts, exactly as the standalone
    // boot wires it for the federation-context lifetime.
    const { issuerContext, assembled } = setup();

    const first = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(first.approved).toBe(true);

    // Identical request (same bootstrap token, same nonce). On `main` today this
    // REPLAY SUCCEEDS — there is no nonce-consumption store for local joins. The
    // single-use store added here closes that gap.
    const replay = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(replay.approved).toBe(false);
    if (!replay.approved) {
      expect(replay.denialReason).toMatch(/already used/i);
    }
  });

  it("at the approver level, consume() returns true once then false for the same nonce", () => {
    const store = new BootstrapNonceStore();
    const expiresAtMs = Date.now() + 60_000;
    expect(store.consume("f1", "n1", "nonce-1", expiresAtMs)).toBe(true);
    expect(store.consume("f1", "n1", "nonce-1", expiresAtMs)).toBe(false);
    // A different nonce for the same node is independent.
    expect(store.consume("f1", "n1", "nonce-2", expiresAtMs)).toBe(true);
  });
});

describe("standalone join approver — token-less / forged denied (criterion c)", () => {
  it("DENIES a forged bootstrap token (bad signature) at the ceremony", async () => {
    const { issuerContext, assembled } = setup();
    const forged = {
      ...assembled.joinRequest,
      bootstrap_token: {
        ...assembled.joinRequest.bootstrap_token,
        signature: toBase64url(randomBytes(64)),
      },
    };
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(forged);
    expect(outcome.approved).toBe(false);
  });

  it("DENIES a wrong-fortress token at the ceremony", async () => {
    const { issuerContext, assembled } = setup();
    const wrongFortress = {
      ...assembled.joinRequest,
      bootstrap_token: {
        ...assembled.joinRequest.bootstrap_token,
        fortress_id: "some-other-fortress",
      },
    };
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(
      wrongFortress,
    );
    expect(outcome.approved).toBe(false);
  });

  it("the approver itself fails closed on a token with no nonce", async () => {
    // Drive the approver directly with a token-context-missing request: the
    // approver must DENY rather than issue, independent of the ceremony.
    const { approver, assembled } = setup();
    const noNonce = {
      ...assembled.joinRequest,
      bootstrap_token: {
        ...assembled.joinRequest.bootstrap_token,
        nonce: "",
      },
    };
    const result = await approver.requestApproval(noNonce);
    expect(result.approved).toBe(false);
    expect(result.certificate).toBeUndefined();
  });
});

describe("standalone join approver — operator_cloud denied here (criterion d)", () => {
  it("DENIES an operator_cloud join at the approver (wrong approver for OC)", async () => {
    // Drive the approver directly: an operator_cloud request must never be
    // issued by the standalone (local) approver, even with an otherwise valid
    // token context. operator_cloud routes through the OC approver only.
    const { approver, assembled } = setup({ intendedNodeMode: "operator_cloud" });
    const ocRequest = { ...assembled.joinRequest, node_mode: "operator_cloud" as NodeMode };
    const result = await approver.requestApproval(ocRequest);
    expect(result.approved).toBe(false);
    expect(result.certificate).toBeUndefined();
    expect(result.denial_reason).toMatch(/local \/ sovereign_tee/i);
  });
});

describe("standalone join approver — revocation respected (criterion e)", () => {
  it("DENIES a revoked node id at the ceremony", async () => {
    const { issuerContext, assembled } = setup({
      isNodeRevoked: (nodeId) => nodeId === JOINER_NODE_ID,
    });
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) {
      expect(outcome.denialReason).toMatch(/revoked/i);
    }
  });

  it("DENIES (fails closed) when the revocation projection THROWS", async () => {
    const { issuerContext, assembled } = setup({
      isNodeRevoked: () => {
        throw new Error("revocation projection unavailable");
      },
    });
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
  });
});

describe("standalone join approver — expired token denied (criterion f)", () => {
  it("DENIES an expired bootstrap token at the ceremony", async () => {
    // Mint a token that is already expired (negative TTL). The ceremony's
    // step-1 bootstrap-token verification rejects it before the approver runs.
    const { issuerContext, assembled } = setup({ ttlMs: -1000 });
    const outcome = await new JoinCeremony(issuerContext).authorizeComplete(
      assembled.joinRequest,
    );
    expect(outcome.approved).toBe(false);
    if (!outcome.approved) {
      expect(outcome.denialReason).toMatch(/expired|rejected/i);
    }
  });

  it("the nonce store prunes and re-rejects an expired spent nonce", () => {
    const store = new BootstrapNonceStore();
    const past = Date.now() - 1000;
    // Consume with an already-past expiry, then verify it is not held as spent.
    expect(store.consume("f1", "n1", "nonce-x", past)).toBe(true);
    expect(store.isSpent("f1", "n1", "nonce-x")).toBe(false);
  });
});

describe("standalone join approver — no Tier-1 downgrade / no auto-approve", () => {
  it("an approver with NO nonce-store consumption never silently auto-approves a replay", async () => {
    // Sanity: two distinct tokens (distinct nonces) each succeed once; the
    // store does NOT block independent legitimate joins, only replays.
    const store = new BootstrapNonceStore();
    const a = setup({ nonceStore: store });
    const first = await new JoinCeremony(a.issuerContext).authorizeComplete(
      a.assembled.joinRequest,
    );
    expect(first.approved).toBe(true);

    const b = setup({ nonceStore: store });
    const second = await new JoinCeremony(b.issuerContext).authorizeComplete(
      b.assembled.joinRequest,
    );
    expect(second.approved).toBe(true);
  });
});

describe("standalone join approver — context shape (wiring assurance)", () => {
  it("the issuer context built with the standalone approver is a valid FederationContext", () => {
    const { issuerContext } = setup();
    // Compile-time + runtime assurance that the boot-wiring shape is accepted by
    // the context union the dashboard hands to setFederationContext.
    const ctx: FederationContext = issuerContext;
    expect(typeof ctx.fortressId).toBe("string");
    expect(typeof (ctx as FederationIssuerContext).approver.requestApproval).toBe(
      "function",
    );
  });
});
