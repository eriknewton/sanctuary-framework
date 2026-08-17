/**
 * Envelope-rejection boundary regression suite — UEK-02, UEK-03, QI-02-F12.
 *
 * CAPABILITY UNDER TEST. When this node refuses an incoming event, the
 * operator-facing alert and the per-origin state it feeds are attributed to an
 * identity this node itself authenticated, that state is bounded, and the
 * refusal's REASON decides its severity. Three properties, one boundary:
 *
 *   1. ATTRIBUTION (rule 7). An identity string carried inside an event whose
 *      verification failed is data, never attribution. It appears in an alert's
 *      `detail` under a key that names it as unverified, and never as
 *      `target_node`, never as a per-origin map key, and never as the subject
 *      of an operator-facing sentence.
 *   2. KEY POPULATION (rule 8). The detector's per-origin signal map does not
 *      grow with the number of distinct identities an inbound stream CLAIMS.
 *      Not a cap: a cap over a map nothing removes from is a terminal refusal,
 *      so the growth these tests close is the claim-driven one, and the
 *      retention bound stays open under bare id UEK-02.
 *   3. SEVERITY (QI-02-F12). Only a compromise-class refusal produces a
 *      COMPROMISED alert. A freshness or capacity refusal produces
 *      PEER_REFUSED, which the Mesh Health rollup MAPS to `degraded` — an
 *      explicit per-mode row, asserted as such, not a value the mode happens
 *      to inherit from an "any flag at all" fallthrough.
 *
 *   4. CONTAINMENT. A reserved node id is refused at the two ADMISSION
 *      chokepoints, and no handler fault on the broadcast receive path escapes
 *      into the `void` its caller invokes it with — for a SYNCHRONOUS throw
 *      and for an ASYNC rejection alike, which are separate frames below
 *      because they are contained by different code and one guard does not
 *      imply the other.
 *
 * WHAT DRIVES WHAT, counted exactly rather than described in aggregate,
 * because "these tests drive the production graph" is the kind of claim that
 * is true of most of a file and then quietly false of the rest. Of the
 * EIGHTEEN tests below:
 *   - TWELVE drive the PRODUCTION object graph: the real transport, the real
 *     `handleIncomingBroadcast` / `handleIncomingUnicast` / `applySync` receive
 *     paths, and the real `FailureModeDetector` wired to a real bootstrapped
 *     `MeshNode` (AGENTS.md rule 4 — a capability with no production consumer
 *     is not shipped, whatever its own unit tests say);
 *   - TWO call `onEnvelopeRejected` directly and say why at the site: one
 *     asserts the freshness class, whose production-path assertion lives in
 *     `qi-sibling-02-master-rotation-freshness.test.ts`; the other asserts the
 *     severity table rather than a receive path;
 *   - FOUR are unit tests over a single function: the mint, the reason-class
 *     mapping, certificate issuance, and roster admission.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { MeshSignatureError } from "../../src/mesh/errors.js";
import { InMemoryTransport } from "../../src/mesh/in-memory-transport.js";
import { packSignedEvent } from "../../src/mesh/envelope.js";
import {
  InMemoryCounterStore,
  InMemoryNodeKeyStore,
  MeshNode,
  NodeRoster,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import {
  NO_AUTHENTICATED_PEER,
  REJECTION_REASON_CLASS,
  authenticatedPeer,
  isCompromiseSignal,
} from "../../src/mesh/lifecycle/envelope-rejection.js";
import {
  FAILURE_MODE,
  FailureModeDetector,
  type AlertEmitContext,
  type FailureModeAlert,
} from "../../src/mesh/failure-modes/index.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  NodeJoinPayload,
  PolicyUpdatePayload,
  PrincipalCertificate,
  SignedEvent,
} from "../../src/mesh/types.js";

/**
 * The node an attacker wants blamed. Never joined, never certified, never
 * authenticated by anyone — it exists only as a string inside forged traffic,
 * which is precisely the point: if any assertion below finds it in an alert's
 * `target_node`, a peer has succeeded in naming a third party.
 */
const INNOCENT = "innocent-node";

interface Rig {
  node: MeshNode;
  principal_id: string;
  bootstrap: Awaited<
    ReturnType<typeof MeshNode.bootstrapFirstNode>
  >["bootstrap"];
  detector: FailureModeDetector;
  alerts: FailureModeAlert[];
  transport: InMemoryTransport;
  fortress_id: string;
}

async function makeRig(): Promise<Rig> {
  const transport = new InMemoryTransport();
  const handle = transport.attach("node-1");
  const placeholder = createAutoApproveJoinApprover({
    pinned_master_pubkey: {} as FortressMasterPublicKey,
    issuing_principal_cert: {} as PrincipalCertificate,
    issuing_principal_private_key: new Uint8Array(32),
  });
  const result = await MeshNode.bootstrapFirstNode({
    node_id: "node-1",
    node_mode: "local",
    transport: handle,
    approver: placeholder,
    key_store: new InMemoryNodeKeyStore(),
  });
  const counters = new InMemoryCounterStore();
  for (let i = 0; i < 10; i++) counters.next("envelope_monotonic_seq");
  const emit_ctx: AlertEmitContext = {
    emitter_node: "node-1",
    emitter_principal: result.bootstrap.root_principal_certificate.principal_id,
    fortress_id: result.bootstrap.master_public.fortress_id,
    node_private_key: result.bootstrap.node_private_key,
    principal_private_key: result.bootstrap.root_principal_private_key,
    counters,
  };
  const alerts: FailureModeAlert[] = [];
  const detector = new FailureModeDetector(
    result.node,
    { emit_context: emit_ctx },
    {
      canonical_audit_node_id: "node-1",
      tick_interval_ms: 60_000,
      on_alert: (a) => alerts.push(a),
    }
  );
  return {
    node: result.node,
    principal_id: result.bootstrap.root_principal_certificate.principal_id,
    bootstrap: result.bootstrap,
    detector,
    alerts,
    transport,
    fortress_id: result.bootstrap.master_public.fortress_id,
  };
}

/**
 * A structurally-valid `policy_update` envelope signed by a key nobody trusts,
 * claiming to come from `claimedEmitter`. Verification fails on the emitter
 * certificate lookup, which is exactly the state in which `emitter_node` is
 * attacker-authored text.
 */
function forgedPolicyUpdate(
  fortressId: string,
  claimedEmitter: string,
  seq: number
): SignedEvent<PolicyUpdatePayload> {
  const strangerKp = generateKeypair();
  return packSignedEvent<PolicyUpdatePayload>({
    event_type: "policy_update",
    emitter_node: claimedEmitter,
    emitter_principal: "stranger-principal",
    fortress_id: fortressId,
    payload: {
      agent_id: "agent-x",
      policy_version: seq,
      policy_blob: "",
      policy_hash: "",
    } as unknown as PolicyUpdatePayload,
    monotonic_seq: seq,
    node_private_key: strangerKp.privateKey,
  });
}

// ═══════════════════════════════════════════════════════════════════════
// 1. ATTRIBUTION — a forged claim cannot name an innocent node
// ═══════════════════════════════════════════════════════════════════════

describe("UEK-02 attribution: a claimed emitter is data, never attribution", () => {
  it("a forged BROADCAST naming an innocent node raises no alert against it", async () => {
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");

    // Real production path: transport -> handleIncomingBroadcast ->
    // verifyOrThrow fails -> onEnvelopeRejected -> detector.
    await attacker.broadcast(forgedPolicyUpdate(rig.fortress_id, INNOCENT, 1));

    expect(rig.alerts.length).toBeGreaterThanOrEqual(1);
    // THE assertion this whole change exists for.
    expect(rig.alerts.map((a) => a.target_node)).not.toContain(INNOCENT);
    for (const a of rig.alerts) {
      expect(a.target_node).toBe(NO_AUTHENTICATED_PEER);
      // The claim is retained, and its key says it is not to be trusted.
      expect(a.detail.claimed_emitter_node_unverified).toBe(INNOCENT);
      // The claim never becomes the SUBJECT of the operator's sentence. The
      // verifier's own error text does name the claimed id ("emitter_node
      // innocent-node is not in local roster"), and that is correct: it
      // reports what the claim was and why it did not resolve. What must
      // never appear is the attribution phrasing `from node <id>`, which the
      // detector produces only for a genuinely authenticated origin.
      expect(a.message).not.toContain(`from node ${INNOCENT}`);
      expect(a.message).toContain("unauthenticated sender");
    }
    // Nor does it become a per-origin bucket key.
    expect(rig.detector.listCompromisedOrigins()).toEqual([
      NO_AUTHENTICATED_PEER,
    ]);
  });

  it("a forged event RELAYED inside a sync response is attributed to the relaying peer", async () => {
    const rig = await makeRig();
    const relay = authenticatedPeer("relay-peer");

    // Production entry point: `handleIncomingUnicast` calls exactly this after
    // verifying the outer sync_response envelope.
    await rig.node.applySync(
      {
        kind: "delta_sync",
        policy_updates: [forgedPolicyUpdate(rig.fortress_id, INNOCENT, 7)],
      },
      new Date(),
      relay
    );

    const rejected = rig.alerts.filter(
      (a) => a.detail.signal === "envelope_rejected"
    );
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.target_node).toBe(relay);
    expect(rejected[0]!.target_node).not.toBe(INNOCENT);
    expect(rejected[0]!.detail.claimed_emitter_node_unverified).toBe(INNOCENT);
    expect(rig.detector.listCompromisedOrigins()).toEqual([relay]);
  });

  it("the sentinel is never rendered as if it were a node name", async () => {
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");
    await attacker.broadcast(forgedPolicyUpdate(rig.fortress_id, INNOCENT, 1));
    // "Node unknown-relaying-peer has ..." would read to an operator as a node
    // actually called that. The sentinel only ever appears through the
    // unauthenticated-sender phrasing.
    for (const a of rig.alerts) {
      expect(a.message).not.toContain(NO_AUTHENTICATED_PEER);
      expect(a.message).toMatch(/unauthenticated sender/);
    }
  });

  it("the sentinel cannot be minted as an authenticated peer (collision closure)", () => {
    // Last line of defence only: the real closure is at the two admission
    // chokepoints asserted in section 4, because a throw HERE lands on a
    // receive path invoked as `void` and would surface as a process fault
    // rather than a refusal.
    expect(() => authenticatedPeer(NO_AUTHENTICATED_PEER)).toThrow(/reserved/);
    expect(() => authenticatedPeer("")).toThrow(/reserved/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. BOUNDEDNESS — rotated claims cannot grow retained state (rule 8)
// ═══════════════════════════════════════════════════════════════════════

describe("UEK-02 boundedness: rotated claims cannot grow retained state", () => {
  it("500 forged broadcasts with a ROTATED claimed emitter add exactly ONE origin", async () => {
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");

    // `ROTATIONS` is the adversarial schedule, not a capacity number — the
    // assertion is that the map does not track distinct claims at all, so the
    // count it grows by is zero rather than merely small.
    const ROTATIONS = 500;
    for (let i = 0; i < ROTATIONS; i++) {
      await attacker.broadcast(
        forgedPolicyUpdate(rig.fortress_id, `victim-${i}`, i + 1)
      );
    }

    expect(rig.alerts.length).toBeGreaterThanOrEqual(ROTATIONS);
    // Growth is O(1) in the number of distinct claims, not O(n).
    expect(rig.detector.listCompromisedOrigins()).toEqual([
      NO_AUTHENTICATED_PEER,
    ]);
    // And no claim was ever promoted to an attribution.
    const targets = new Set(rig.alerts.map((a) => a.target_node));
    expect([...targets]).toEqual([NO_AUTHENTICATED_PEER]);
  });

  it("rotated claims relayed through sync stay in the relaying peer's ONE bucket", async () => {
    const rig = await makeRig();
    const relay = authenticatedPeer("relay-peer");
    for (let i = 0; i < 200; i++) {
      await rig.node.applySync(
        {
          kind: "delta_sync",
          policy_updates: [
            forgedPolicyUpdate(rig.fortress_id, `victim-${i}`, i + 1),
          ],
        },
        new Date(),
        relay
      );
    }
    expect(rig.detector.listCompromisedOrigins()).toEqual([relay]);
    // The per-origin tally is what a flooding peer pays into — its OWN.
    expect(
      rig.alerts.every((a) => a.target_node === relay)
    ).toBe(true);
  });

});

// ═══════════════════════════════════════════════════════════════════════
// 3. SEVERITY — a local refusal is not an accusation (QI-02-F12)
// ═══════════════════════════════════════════════════════════════════════

describe("QI-02-F12 severity: a freshness or capacity refusal is not a compromise", () => {
  it("classifies the reason classes into compromise and non-compromise", () => {
    // The ONE mapping, asserted directly so a later reason class cannot be
    // added on one side of it and read the other way at a consumer.
    expect(
      isCompromiseSignal(REJECTION_REASON_CLASS.ENVELOPE_UNVERIFIED)
    ).toBe(true);
    expect(
      isCompromiseSignal(REJECTION_REASON_CLASS.PEER_AUTHORIZATION_REFUSED)
    ).toBe(true);
    expect(isCompromiseSignal(REJECTION_REASON_CLASS.FRESHNESS_REFUSED)).toBe(
      false
    );
    expect(isCompromiseSignal(REJECTION_REASON_CLASS.CAPACITY_REFUSED)).toBe(
      false
    );
  });

  it("a FRESHNESS refusal reads as degraded, not compromised, and adds no tally", async () => {
    const rig = await makeRig();
    const peer = authenticatedPeer("clock-skewed-initiator");
    // The pre-fix behaviour: a receiver whose clock had drifted reported this
    // authentic peer as COMPROMISED. (The production path that produces this
    // class — a lapsed master-rotation collection window — is asserted at the
    // boundary in `qi-sibling-02-master-rotation-freshness.test.ts`; this test
    // owns the DETECTOR half of the same property.)
    rig.node.onEnvelopeRejected({
      error: new Error("quorum context window has lapsed"),
      event_type: "master_rotation",
      rejection_origin: peer,
      reason_class: REJECTION_REASON_CLASS.FRESHNESS_REFUSED,
    });

    const alerts = rig.alerts.filter((a) => a.target_node === peer);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.mode).toBe(FAILURE_MODE.PEER_REFUSED);
    expect(alerts[0]!.mode).not.toBe(FAILURE_MODE.COMPROMISED);
    // The operator is pointed at the actual likely cause.
    expect(alerts[0]!.message).toMatch(/clock/i);
    // The Mesh Health rollup must read `degraded`, never `compromised`.
    expect(
      rig.detector
        .snapshot(Date.now())
        .open_alerts.filter((a) => a.mode === FAILURE_MODE.COMPROMISED)
    ).toHaveLength(0);
    // No compromise tally is accumulated, so repeated benign skew can never
    // add up into an accusation.
    expect(rig.detector.listCompromisedOrigins()).toHaveLength(0);
  });

  it("an UNCORRELATED sync_response is a capacity refusal, over the real receive path", async () => {
    const rig = await makeRig();
    // Production path: a `sync_response` this node never requested. The
    // envelope VERIFIES (node-1 signs it to itself here, so the emitter cert
    // resolves); what refuses it is node-1's own outstanding-request table.
    const evt = packSignedEvent({
      event_type: "sync_response",
      emitter_node: "node-1",
      emitter_principal: rig.principal_id,
      fortress_id: rig.fortress_id,
      payload: { kind: "delta_sync", request_id: "never-requested" },
      monotonic_seq: 9_000,
      node_private_key: rig.node["nodePrivateKey"] as Uint8Array,
    });
    await rig.node["handleIncomingUnicast"](
      JSON.stringify({ kind: "sync_response", evt })
    );

    const rejected = rig.alerts.filter(
      (a) => a.detail.signal === "envelope_rejected"
    );
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.detail.reason_class).toBe(
      REJECTION_REASON_CLASS.CAPACITY_REFUSED
    );
    // A local correlation-table miss is not evidence about the peer.
    expect(rejected[0]!.mode).toBe(FAILURE_MODE.PEER_REFUSED);
    expect(rejected[0]!.target_node).toBe("node-1");
  });

  it("the Mesh Health row for a peer_refused node rolls up DEGRADED, over the real receive path", async () => {
    const rig = await makeRig();
    // Same production frame as the capacity test above — an uncorrelated
    // `sync_response` refused by node-1's own outstanding-request table — but
    // asserted one layer further out, at the row an operator actually reads.
    const evt = packSignedEvent({
      event_type: "sync_response",
      emitter_node: "node-1",
      emitter_principal: rig.principal_id,
      fortress_id: rig.fortress_id,
      payload: { kind: "delta_sync", request_id: "never-requested" },
      monotonic_seq: 9_100,
      node_private_key: rig.node["nodePrivateKey"] as Uint8Array,
    });
    await rig.node["handleIncomingUnicast"](
      JSON.stringify({ kind: "sync_response", evt })
    );

    const row = rig.detector
      .snapshot(Date.now())
      .nodes.find((n) => n.node_id === "node-1")!;
    expect(row.flags).toContain(FAILURE_MODE.PEER_REFUSED);
    // THE pin. `peer_refused` reaching `degraded` through an "any flag at all"
    // fallthrough is not the same property as `peer_refused` MAPPING to
    // `degraded`: the first still holds if someone re-decides the mode's
    // severity, the second does not. This asserts the second — flipping the
    // mode's row in `MODE_ROLLUP` turns this test RED.
    expect(row.rollup).toBe("degraded");
    expect(row.rollup).not.toBe("compromised");
    // BOUND, stated because a reader will assume more than is true: this pins
    // the mode's VALUE in the table and (with the companion test below) that
    // the table is not uniformly degraded. It does NOT pin that `computeRollup`
    // reads the table at all — today `compromised` is the only escalating row,
    // so swapping the lookup back for a hard-coded `includes(COMPROMISED)`
    // produces identical output and no test here can see it. What guards the
    // table is the compile-time totality of `Record<FailureMode, ...>`: a mode
    // added without a severity fails typecheck. Two different guarantees; do
    // not read this test as giving the second one.
  });

  it("the severity table is not uniformly degraded — a compromise flag still escalates the same row", async () => {
    // The contrast the pin above needs in order to mean anything: if every
    // mode mapped to `degraded`, the previous test would pass for the wrong
    // reason. Driven through the hook because what is under test is the table,
    // not a receive path — the COMPROMISED arm's own production frames are
    // asserted elsewhere in this file.
    const rig = await makeRig();
    rig.node.onEnvelopeRejected({
      error: new MeshSignatureError("bad signature"),
      event_type: "policy_update",
      rejection_origin: authenticatedPeer("node-1"),
      reason_class: REJECTION_REASON_CLASS.ENVELOPE_UNVERIFIED,
    });
    const row = rig.detector
      .snapshot(Date.now())
      .nodes.find((n) => n.node_id === "node-1")!;
    expect(row.flags).toContain(FAILURE_MODE.COMPROMISED);
    expect(row.rollup).toBe("compromised");
  });

  it("an envelope-verification failure still reads as COMPROMISED", async () => {
    // The de-escalation must not have de-escalated the class that matters.
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");
    await attacker.broadcast(forgedPolicyUpdate(rig.fortress_id, INNOCENT, 1));
    expect(
      rig.alerts.filter((a) => a.mode === FAILURE_MODE.COMPROMISED)
    ).not.toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. CONTAINMENT — a reserved id is refused upstream, and no handler fault
//    reaches the void (rule 8 availability; MUST-NEVER #5)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run `frame` and report every unhandled promise rejection it produced.
 *
 * WHY THIS INSTALLS ITS OWN LISTENER. Vitest registers a process-level
 * `unhandledRejection` handler of its own, so under the runner an escaped
 * rejection may be attributed to a later test, or absorbed entirely — the
 * suite is structurally unable to see this class. Production has no such
 * handler: Node's default for an unhandled rejection is to terminate the
 * process. Observing the rejections directly is therefore the only way a test
 * can assert the property the shipped binary depends on.
 *
 * The `setTimeout` drains a macrotask: Node decides a rejection is unhandled
 * only after the microtask queue empties, so an assertion made synchronously
 * after `frame()` would pass whether or not the rejection happened.
 */
async function unhandledRejectionsDuring(
  frame: () => Promise<void> | void
): Promise<unknown[]> {
  const captured: unknown[] = [];
  const listener = (reason: unknown): void => {
    captured.push(reason);
  };
  process.on("unhandledRejection", listener);
  try {
    await frame();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    process.off("unhandledRejection", listener);
  }
  return captured;
}

/**
 * Build a node certificate that PASSES `verifyCertChain` for `nodeId`, by
 * signing the exact body `issueNodeIdentityCertificate` signs with the
 * fortress's own root principal key.
 *
 * MUST MATCH the body in `mesh/trust-root.ts::issueNodeIdentityCertificate`.
 * A drift there makes this cert fail chain verification, at which point the
 * test above stops exercising roster admission and silently starts asserting
 * nothing — the failure mode is a green test, so re-check this body whenever
 * the issuer's changes.
 */
function forgeChainValidNodeCert(
  rig: Rig,
  nodeId: string,
  nodePubkey: Uint8Array
): NodeIdentityCertificate {
  const principalCert = rig.bootstrap.root_principal_certificate;
  const body = {
    certificate_version: undefined,
    node_id: nodeId,
    node_pubkey: toBase64url(nodePubkey),
    node_mode: "local" as const,
    fortress_id: rig.fortress_id,
    joined_at: new Date().toISOString(),
    expires_at: undefined,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: rig.bootstrap.master_public.public_key,
      principal_id: principalCert.principal_id,
      principal_pubkey: principalCert.principal_pubkey,
    },
    tee_attestation_hash: undefined,
    delegated_grants: [] as unknown[],
    attestation_lineage_chain: [] as unknown[],
  };
  const signature = ed25519.sign(
    canonicalizeToBytes(body),
    rig.bootstrap.root_principal_private_key
  );
  return {
    ...body,
    principal_signature: toBase64url(signature),
  } as unknown as NodeIdentityCertificate;
}

describe("UEK-02 containment: a reserved node id never reaches a mint site", () => {
  it("certificate issuance refuses the sentinel literal and the empty id", () => {
    const kp = generateKeypair();
    const principal = generateKeypair();
    const issue = (nodeId: string): NodeIdentityCertificate =>
      issueNodeIdentityCertificate({
        node_id: nodeId,
        node_pubkey: kp.publicKey,
        node_mode: "local",
        fortress_id: "fortress-x",
        capabilities: 1,
        parent_chain: {
          fortress_master_pubkey: "master-pubkey",
          principal_id: "principal-x",
          principal_pubkey: toBase64url(principal.publicKey),
        },
        principal_private_key: principal.privateKey,
      });
    // The mint side of the chokepoint pair: an id that never reaches a
    // certificate never reaches a roster, an envelope, or an alert subject.
    expect(() => issue(NO_AUTHENTICATED_PEER)).toThrow(/reserved/);
    expect(() => issue("")).toThrow(/reserved/);
    // The guard is narrow: an ordinary id still issues.
    expect(issue("node-ordinary").node_id).toBe("node-ordinary");
  });

  it("roster admission refuses a reserved node id even for a cert it did not issue", () => {
    const roster = new NodeRoster();
    const cert = (nodeId: string): NodeIdentityCertificate =>
      ({
        node_id: nodeId,
        node_pubkey: "irrelevant",
        node_mode: "local",
        fortress_id: "fortress-x",
        joined_at: new Date().toISOString(),
        capabilities: 1,
        parent_chain: {},
        principal_signature: "irrelevant",
      }) as unknown as NodeIdentityCertificate;
    // The relying side of the pair. Issuance is not enough on its own: a
    // certificate minted anywhere else still has to pass here before it can
    // make a node id authenticatable.
    expect(() => roster.add(cert(NO_AUTHENTICATED_PEER))).toThrow(/reserved/);
    expect(() => roster.add(cert(""))).toThrow(/reserved/);
    roster.add(cert("node-ordinary"));
    expect(roster.size()).toBe(1);
  });

  it.each([
    ["the sentinel literal", NO_AUTHENTICATED_PEER],
    ["an empty node id", ""],
  ])(
    "a node_join carrying a CHAIN-VALID cert for %s is refused, and crashes nothing",
    async (_label, reservedNodeId) => {
      const rig = await makeRig();
      const attacker = rig.transport.attach("attacker");
      const joinerKp = generateKeypair();

      // The certificate is signed by the fortress's OWN root principal and
      // chains to the pinned master, so `verifyNodeJoinBeforeRosterMutation`
      // accepts it and `roster.add` is the only thing left that can refuse.
      // Forged by hand rather than through `issueNodeIdentityCertificate`
      // precisely BECAUSE that issuer now refuses these ids — the frame under
      // test is a certificate that reached this node without passing the mint
      // chokepoint, which is what makes roster admission the relying-side
      // backstop rather than a duplicate of it.
      const certificate = forgeChainValidNodeCert(
        rig,
        reservedNodeId,
        joinerKp.publicKey
      );

      // `void this.handleIncomingBroadcast(evt)` is how the transport
      // subscription invokes the receive path, so a throw anywhere inside it
      // — including from a mint downstream of an admitted reserved id —
      // becomes an unhandled rejection, which terminates the process under
      // Node's default behaviour.
      const captured = await unhandledRejectionsDuring(async () => {
        await attacker.broadcast(
          packSignedEvent<NodeJoinPayload>({
            event_type: "node_join",
            emitter_node: reservedNodeId,
            emitter_principal: rig.principal_id,
            fortress_id: rig.fortress_id,
            payload: { certificate, bootstrap_token_ref: "token-ref" },
            monotonic_seq: 1,
            node_private_key: joinerKp.privateKey,
          })
        );
        // The second half of the frame, and the one that actually reaches a
        // mint: a heartbeat from the same peer. Its router handler brands
        // `evt.emitter_node`, so if the join above were admitted this line is
        // where the reserved id turns into a throw on a `void`-invoked path.
        await attacker.broadcast(
          packSignedEvent({
            event_type: "heartbeat",
            emitter_node: reservedNodeId,
            emitter_principal: rig.principal_id,
            fortress_id: rig.fortress_id,
            payload: {
              node_state: "active",
              policy_version_vector: {},
              audit_seq: 0,
              agent_count: 0,
              uptime_seconds: 1,
            },
            monotonic_seq: 2,
            node_private_key: joinerKp.privateKey,
          })
        );
      });

      expect(captured).toEqual([]);
      // Refused, so the reserved id never became an authenticatable identity.
      expect(rig.node.getRoster().lookupNodeCert(reservedNodeId)).toBe(
        undefined
      );
      // The roster still holds only this node — the join added nothing. (Not
      // asserted via `listCompromisedOrigins`: for the sentinel case a bucket
      // under that exact key is the CORRECT outcome of the refused frames, so
      // the roster is the surface that distinguishes admitted from refused.)
      expect(rig.node.getRoster().size()).toBe(1);
      // And the node is still serving: a later frame is still processed.
      await attacker.broadcast(
        forgedPolicyUpdate(rig.fortress_id, INNOCENT, 5)
      );
      expect(rig.alerts.length).toBeGreaterThanOrEqual(1);
    }
  );

  it("an ASYNC faulting dispatch handler does not escape either", async () => {
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");

    // THE SHAPE THE SYNC TEST CANNOT SEE. `V01Handler` returns
    // `void | Promise<void>`, so a registered handler is one typecheck-clean
    // `async` away from failing as a REJECTED PROMISE rather than a throw —
    // and `handleIncomingBroadcast`'s `try` has already returned by the time
    // that settles, so it catches nothing. The containment for this half lives
    // on the promise `dispatch` gets back.
    //
    // Registering over the real router (rather than editing the production
    // registration) is what keeps this a permanent frame instead of a
    // one-off mutation: it replaces the heartbeat handler on THIS node
    // instance, and the event still travels the real transport and the real
    // `handleIncomingBroadcast`.
    (
      rig.node as unknown as { router: { register: (t: string, h: () => Promise<void>) => void } }
    ).router.register("heartbeat", async () => {
      throw new Error("async operator hook faulted");
    });

    const captured = await unhandledRejectionsDuring(async () => {
      await attacker.broadcast(
        packSignedEvent({
          event_type: "heartbeat",
          emitter_node: "node-1",
          emitter_principal: rig.principal_id,
          fortress_id: rig.fortress_id,
          payload: {
            node_state: "active",
            policy_version_vector: {},
            audit_seq: 0,
            agent_count: 0,
            uptime_seconds: 1,
          },
          monotonic_seq: 8_100,
          node_private_key: rig.node["nodePrivateKey"] as Uint8Array,
        })
      );
    });

    expect(captured).toEqual([]);
    // Contained, not disabled: the node keeps serving the next frame.
    await attacker.broadcast(forgedPolicyUpdate(rig.fortress_id, INNOCENT, 1));
    expect(
      rig.alerts.filter((a) => a.detail.signal === "envelope_rejected")
    ).toHaveLength(1);
  });

  it("a faulting dispatch handler does not escape into the transport's void", async () => {
    const rig = await makeRig();
    const attacker = rig.transport.attach("attacker");

    // A caller-supplied hook that throws stands in for every fault this node
    // cannot predict inside a router handler. The broadcast is genuine — the
    // envelope verifies, so dispatch is actually reached — which is what makes
    // this the production frame rather than a direct call.
    rig.node.onHeartbeatReceived = () => {
      throw new Error("operator hook faulted");
    };

    const captured = await unhandledRejectionsDuring(async () => {
      await attacker.broadcast(
        packSignedEvent({
          event_type: "heartbeat",
          emitter_node: "node-1",
          emitter_principal: rig.principal_id,
          fortress_id: rig.fortress_id,
          payload: {
            node_state: "active",
            policy_version_vector: {},
            audit_seq: 0,
            agent_count: 0,
            uptime_seconds: 1,
          },
          monotonic_seq: 8_000,
          node_private_key: rig.node["nodePrivateKey"] as Uint8Array,
        })
      );
    });

    expect(captured).toEqual([]);
    // Contained, not disabled: the node keeps serving the next frame.
    await attacker.broadcast(forgedPolicyUpdate(rig.fortress_id, INNOCENT, 1));
    expect(
      rig.alerts.filter((a) => a.detail.signal === "envelope_rejected")
    ).toHaveLength(1);
  });
});
