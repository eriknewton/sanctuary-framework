/**
 * CAPABILITY (STATE-DISCLOSE-UNATTRIB-01): an operator-approved surface that
 * discloses the content of a state entry whose writer the fortress cannot
 * establish, so an owner who no longer holds the writer identity still reaches
 * their own data.
 *
 * These tests assert the MECHANISM, and the mechanism that matters most here is
 * the SHAPE. The alternative design was the verified read's shape with a flag
 * attached, and a flag almost no consumer reads is indistinguishable from no
 * flag, so the separation has to be one the type system holds:
 *
 *   - the surface returns content the enforcing read refuses, which is the
 *     whole reason it exists;
 *   - its result is mutually non-assignable with the verified read's result, in
 *     both directions, asserted at compile time and again on the runtime keys;
 *   - it is Tier-1 gated through the force-pinned set, so a hostile policy file
 *     that lists the operation as auto-allow still classifies it Tier 1, and a
 *     channel that denies stops it;
 *   - every invocation appends an audit record naming the namespace and the
 *     key;
 *   - it performs no durable side effect: the stored bytes and the version
 *     anchor record are compared byte-for-byte across the call;
 *   - it REFUSES an entry whose writer can be established, so it can never be
 *     used to skip verification on an entry that does not need it, and it
 *     performs no durable side effect on THAT path either;
 *   - the namespace firewall is part of the shared operation rather than part
 *     of one transport, so both transports refuse the same namespaces;
 *   - it carries the entry's own unverified writer-id claim, so the remedy it
 *     advertises names something an owner can act on.
 */
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { encrypt } from "../../src/core/encryption.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import {
  generateIdentityId,
  publicKeyToDid,
  type StoredIdentity,
} from "../../src/core/identity.js";
import { hashToString } from "../../src/core/hashing.js";
import {
  deriveNamespaceKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import {
  StateStore,
  UNATTRIBUTED_DISCLOSURE_NOTICE,
  type ReadResult,
  type StateEntry,
  type UnattributedStateDisclosure,
} from "../../src/cognitive/state-store.js";
import {
  discloseUnattributedState,
  UNATTRIBUTED_DISCLOSURE_OPERATION,
} from "../../src/cognitive/unattributed-disclosure.js";
import { OpaqueNamespaceRegistry } from "../../src/agent-native/safety-base.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  AutoApproveChannel,
  type ApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import {
  NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS,
  enforceForcedTiers,
  parsePolicy,
} from "../../src/principal-policy/loader.js";
import type {
  ApprovalResponse,
  PrincipalPolicy,
} from "../../src/principal-policy/types.js";

const MASTER_KEY = new Uint8Array([
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
]);
const WRITER_PRIVATE_KEY = new Uint8Array([
  0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
  0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
  0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
  0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
]);

// CONTRACT PIN (server/src/cognitive/state-store.ts
// `STATE_ENVELOPE_VERSION_ANCHORS_KEY`): the anchor record's `_meta` key is not
// exported, so this test mirrors it. Must match that constant.
const ANCHORS_NAMESPACE = "_meta";
const ANCHORS_KEY = "state-envelope-version-anchors-v1";

const NAMESPACE = "memories";

function makeStoredIdentity(identityEncKey: Uint8Array): StoredIdentity {
  const publicKey = ed25519.getPublicKey(WRITER_PRIVATE_KEY);
  return {
    identity_id: generateIdentityId(publicKey),
    label: "disclosure-fixture-writer",
    public_key: toBase64url(publicKey),
    did: publicKeyToDid(publicKey),
    created_at: "2026-08-18T00:00:00.000Z",
    key_type: "ed25519",
    key_protection: "recovery-key",
    encrypted_private_key: encrypt(WRITER_PRIVATE_KEY, identityEncKey),
    rotation_history: [],
  };
}

async function makeRig() {
  const storage = new MemoryStorage();
  const stateStore = new StateStore(storage, MASTER_KEY);
  const auditLog = new AuditLog(storage, MASTER_KEY);
  const identityEncKey = derivePurposeKey(MASTER_KEY, "identity-encryption");
  const identity = makeStoredIdentity(identityEncKey);
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(
      JSON.stringify(
        encrypt(stringToBytes(JSON.stringify(identity)), identityEncKey)
      )
    )
  );
  return { storage, stateStore, auditLog, identityEncKey, identity };
}

/**
 * Plant a legacy (schema-1) entry whose `kid` resolves to NO stored identity
 * and to no AUTHENTICATED registry key: the one persisted shape for which
 * verification finishes without establishing a writer, which is exactly the set
 * this surface serves. Mirrors the fixture in
 * `state-read-refuses-unverified.test.ts`.
 */
async function plantUnattributableLegacyEntry(args: {
  storage: MemoryStorage;
  namespace: string;
  key: string;
  value: string;
  version: number;
}): Promise<void> {
  const plaintext = stringToBytes(args.value);
  const payload = encrypt(
    plaintext,
    deriveNamespaceKey(MASTER_KEY, args.namespace)
  );
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: args.version,
    // ED25519_SIGNATURE_BYTES = 64; the value is irrelevant because no key
    // resolves for `kid`, which is the point of this fixture.
    sig: toBase64url(new Uint8Array(64)),
    kid: "sanctuary-no-such-writer-identity",
    integrity_hash: hashToString(plaintext),
    metadata: { written_at: "2026-08-18T00:00:02.000Z" },
  };
  await args.storage.write(
    args.namespace,
    args.key,
    stringToBytes(JSON.stringify(entry))
  );
}

/**
 * Plant a legacy (schema-1) entry whose writer IS establishable: `kid` names a
 * stored identity and the signature over the CIPHERTEXT verifies under it.
 *
 * This is the fixture the read-only conjunct needs. On the DISCLOSED path
 * `signatureVerified` is always false, so `&& options.unattributedDisclosure
 * !== true` is redundant there and every test built on an unattributable entry
 * passes with the conjunct deleted. It is load-bearing only HERE, on the
 * refusal path: `readUnattributed` throws `writer_is_establishable` only AFTER
 * `readInternal` has returned, so without the conjunct this entry gets migrated
 * to schema 2 on disk and its anchor raised by a call that then discloses
 * nothing.
 *
 * The signature is made with `ed25519.sign` over `fromBase64url(payload.ct)`,
 * which is the exact preimage a v1 signature binds; `core/identity.sign` signs
 * a different preimage and would not verify here.
 */
async function plantAttributableLegacyEntry(args: {
  storage: MemoryStorage;
  identityId: string;
  namespace: string;
  key: string;
  value: string;
  version: number;
}): Promise<void> {
  const plaintext = stringToBytes(args.value);
  const payload = encrypt(
    plaintext,
    deriveNamespaceKey(MASTER_KEY, args.namespace)
  );
  const entry: StateEntry = {
    v: 1,
    payload,
    ver: args.version,
    sig: toBase64url(
      ed25519.sign(fromBase64url(payload.ct), WRITER_PRIVATE_KEY)
    ),
    kid: args.identityId,
    integrity_hash: hashToString(plaintext),
    metadata: { written_at: "2026-08-18T00:00:07.000Z" },
  };
  await args.storage.write(
    args.namespace,
    args.key,
    stringToBytes(JSON.stringify(entry))
  );
}

/** A policy that tries as hard as a policy file can to make this auto-allow. */
const hostilePolicy = (operation: string): PrincipalPolicy => ({
  version: 1,
  tier1_always_approve: [],
  tier2_anomaly: {
    new_namespace_access: "allow",
    new_counterparty: "allow",
    frequency_spike_multiplier: 1_000,
    max_signs_per_minute: 1_000,
    bulk_read_threshold: 1_000,
    first_session_policy: "allow",
  },
  tier3_always_allow: [operation],
  approval_channel: { type: "stderr", timeout_seconds: 300 },
});

class DenyingChannel implements ApprovalChannel {
  calls = 0;
  async requestApproval(): Promise<ApprovalResponse> {
    this.calls += 1;
    return {
      decision: "deny",
      decided_at: "2026-08-18T00:00:03.000Z",
      decided_by: "human",
    };
  }
}

function makeGate(policy: PrincipalPolicy, channel: ApprovalChannel): ApprovalGate {
  const storage = new MemoryStorage();
  return new ApprovalGate(
    policy,
    new BaselineTracker(storage, MASTER_KEY),
    channel,
    new AuditLog(storage, MASTER_KEY)
  );
}

describe("the operator unattributed-disclosure surface", () => {
  it("returns content for an entry the enforcing read refuses", async () => {
    const { storage, stateStore } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "the-owner-must-still-read-this",
      version: 1,
    });

    // Same store, same entry: the enforcing path refuses it and this surface
    // returns it. Asserting both in one test is what makes the pair meaningful;
    // either half alone could pass while the other silently changed.
    await expect(stateStore.read(NAMESPACE, "orphaned")).rejects.toMatchObject({
      classification: "writer_unverified",
    });
    const disclosure = await stateStore.readUnattributed(NAMESPACE, "orphaned");
    expect(disclosure?.unattributed_content).toBe(
      "the-owner-must-still-read-this"
    );
    expect(disclosure?.writer).toBe("not_established");
    expect(disclosure?.notice).toBe(UNATTRIBUTED_DISCLOSURE_NOTICE);
  });

  it("returns a shape structurally distinct from a verified read", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig();
    await stateStore.write(
      NAMESPACE,
      "attributable",
      "routine-value",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "unattributed-value",
      version: 1,
    });

    const verified = (await stateStore.read(NAMESPACE, "attributable"))!;
    const disclosure = (await stateStore.readUnattributed(
      NAMESPACE,
      "orphaned"
    ))!;

    // COMPILE-TIME HALF, PROPERTY ONE: MUTUAL NON-ASSIGNABILITY. Each
    // `@ts-expect-error` FAILS THE TYPECHECK if its error disappears, so the
    // two types cannot become interchangeable silently.
    //
    // READ THE BOUND ON THIS PAIR BEFORE TRUSTING IT, because an adversarial
    // gate on this change disproved the stronger reading. These directives do
    // NOT pin "the disclosure has no `value`". They are satisfied by ANY
    // remaining difference, and there are four; the gate added `readonly value:
    // string` here and populated it, and added `readonly value?: string` here
    // and did not, and BOTH kept `npm run typecheck` green, because the type
    // still lacked `signature_verified` / `merkle_proof` / `integrity_verified`
    // and so stayed non-assignable with the directives still "used". Property
    // two is pinned separately, directly below.
    // @ts-expect-error a disclosure is not assignable to a verified ReadResult
    const notARead: ReadResult = disclosure;
    // @ts-expect-error a verified ReadResult is not assignable to a disclosure
    const notADisclosure: UnattributedStateDisclosure = verified;
    expect(notARead).toBeDefined();
    expect(notADisclosure).toBeDefined();

    // COMPILE-TIME HALF, PROPERTY TWO: THE VERIFIED SPELLINGS ARE ABSENT. This
    // is the property the security argument actually rests on, and it is a
    // different statement from non-assignability. `keyof` sees OPTIONAL keys,
    // so `readonly value?: string` collapses this alias to `never` and the
    // `true` below stops compiling - which is precisely the widening the
    // runtime `Object.keys` check underneath walks straight past.
    //
    // The primary pin for this property is in `src`, not here:
    // `DisclosureWithoutVerifiedReadFields` in `cognitive/state-store.ts` is
    // the type `readUnattributed` constructs through, so the mutation reds
    // under `tsc --noEmit` over `src`. This copy is the second line of defence
    // and documents the property at the point a reader looks for it.
    type ForbiddenSpelling = Extract<
      keyof UnattributedStateDisclosure,
      | "value"
      | "signature_verified"
      | "integrity_verified"
      | "written_by"
      | "merkle_proof"
    >;
    type CarriesNoVerifiedReadField = [ForbiddenSpelling] extends [never]
      ? true
      : never;
    const carriesNoVerifiedReadField: CarriesNoVerifiedReadField = true;
    expect(carriesNoVerifiedReadField).toBe(true);

    // RUNTIME HALF, kept because it catches a POPULATED widening at the value
    // level, but it is the weaker of the two: it cannot see an optional field
    // that is declared and never set.
    expect(Object.keys(verified)).toContain("value");
    expect(Object.keys(verified)).toContain("signature_verified");
    expect(Object.keys(disclosure)).not.toContain("value");
    expect(Object.keys(disclosure)).not.toContain("signature_verified");
    expect(Object.keys(disclosure)).not.toContain("written_by");
    expect(Object.keys(disclosure)).not.toContain("merkle_proof");
    expect(disclosure.disclosure_kind).toBe("unattributed_state_content");
    expect(Object.keys(verified)).not.toContain("disclosure_kind");

    // The trust field is a single-inhabitant literal, not a boolean: there is
    // no `true` spelling of it for a later change to drift toward.
    expect(disclosure.writer).toBe("not_established");
    expect(typeof disclosure.writer).toBe("string");
  });

  it("refuses when the writer IS resolvable, so it is not a general bypass", async () => {
    const { stateStore, identity, identityEncKey } = await makeRig();
    await stateStore.write(
      NAMESPACE,
      "attributable",
      "routine-value",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );

    // The ordinary read succeeds on this entry, so the disclosure surface must
    // decline rather than hand back the same content unattributed: the sets it
    // serves and the enforcing read serves are disjoint by construction.
    const refusal = await stateStore
      .readUnattributed(NAMESPACE, "attributable")
      .then(() => null)
      .catch((err: unknown) => err as { name?: string; classification?: string });
    expect(refusal?.name).toBe("StateVerificationError");
    expect(refusal?.classification).toBe("writer_is_establishable");

    // And the discriminator is distinct from the refusal the enforcing path
    // raises, so an operator can tell "you asked the wrong surface" apart from
    // "this entry cannot be attributed".
    expect(refusal?.classification).not.toBe("writer_unverified");
  });

  it("writes an audit entry naming the namespace and key on every invocation", async () => {
    const { storage, stateStore, auditLog } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "audited-content",
      version: 1,
    });

    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace: NAMESPACE,
      key: "orphaned",
      identityId: "principal",
    });
    expect(outcome.status).toBe("disclosed");

    const audit = await auditLog.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({
      namespace: NAMESPACE,
      key: "orphaned",
    });
  });

  it("audits the refusal too, so a declined use is distinguishable from none", async () => {
    const { stateStore, auditLog, identity, identityEncKey } = await makeRig();
    await stateStore.write(
      NAMESPACE,
      "attributable",
      "routine-value",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );

    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace: NAMESPACE,
      key: "attributable",
      identityId: "principal",
    });
    expect(outcome.status).toBe("refused_writer_is_establishable");

    const refused = await auditLog.query({
      operation_type: "state_disclose_unattributed_refused",
    });
    expect(refused.entries).toHaveLength(1);
    expect(refused.entries[0]!.details).toMatchObject({
      namespace: NAMESPACE,
      key: "attributable",
      classification: "writer_is_establishable",
    });
  });

  it("does not migrate, re-sign, or move the anchor", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig();

    // A neighbouring VERIFIED entry establishes a real anchor record on disk,
    // so "the anchor record is unchanged" is a comparison against something
    // rather than against absence.
    await stateStore.write(
      NAMESPACE,
      "neighbour",
      "anchored",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "must-not-be-rewritten",
      version: 1,
    });

    const bytesBefore = await storage.read(NAMESPACE, "orphaned");
    const anchorsBefore = await storage.read(ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(bytesBefore).not.toBeNull();
    expect(anchorsBefore).not.toBeNull();

    const disclosure = await stateStore.readUnattributed(NAMESPACE, "orphaned");
    expect(disclosure?.unattributed_content).toBe("must-not-be-rewritten");

    // BYTE-FOR-BYTE on the entry: a migration would rewrite it as a schema-2
    // signed envelope, so comparing the parsed schema version alone could miss
    // a re-sign that preserved it.
    const bytesAfter = await storage.read(NAMESPACE, "orphaned");
    expect(bytesToString(bytesAfter!)).toBe(bytesToString(bytesBefore!));
    expect(
      (JSON.parse(bytesToString(bytesAfter!)) as StateEntry).v
    ).toBe(1);

    // And the anchor record: a raise would rewrite it (and re-MAC it), so an
    // identical serialization is the strongest available statement that the
    // durable-side-effect half never ran.
    const anchorsAfter = await storage.read(ANCHORS_NAMESPACE, ANCHORS_KEY);
    expect(bytesToString(anchorsAfter!)).toBe(bytesToString(anchorsBefore!));
  });

  it("reports a rollback rather than disclosing, when the entry is also below its anchor", async () => {
    const { storage, stateStore, identity, identityEncKey } = await makeRig();
    for (let version = 1; version <= 3; version += 1) {
      await stateStore.write(
        NAMESPACE,
        "policy",
        `ALLOW=v${version}`,
        identity.identity_id,
        identity.encrypted_private_key,
        identityEncKey
      );
    }
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "policy",
      value: "ALLOW=nobody",
      version: 1,
    });

    // Cold process: the in-memory version cache is empty, so the persisted
    // anchor is the discriminator. The disclosure surface must not become the
    // door through which a rolled-back value is handed to an operator as
    // "their data"; the anchor check runs above it and still wins.
    const restarted = new StateStore(storage, MASTER_KEY);
    await expect(
      restarted.readUnattributed(NAMESPACE, "policy")
    ).rejects.toMatchObject({ classification: "rollback_detected" });
  });

  it("returns null for an entry that does not exist", async () => {
    const { stateStore } = await makeRig();
    expect(await stateStore.readUnattributed(NAMESPACE, "absent")).toBeNull();
  });

  it("performs no durable side effect on the REFUSAL path either", async () => {
    // THE TEST FOR THE READ-ONLY CONJUNCT. Every other durability test in this
    // file uses an UNATTRIBUTABLE entry, where `signatureVerified` is false and
    // `&& options.unattributedDisclosure !== true` therefore changes nothing:
    // an adversarial gate deleted that conjunct and all of them stayed green.
    // This entry's writer CAN be established, so `readInternal` reaches its
    // durable half with verification succeeding, and only the conjunct stops
    // the migration and the anchor raise. The call still refuses - which is the
    // point: a call that discloses nothing must also REPAIR nothing.
    const { storage, stateStore, identity, identityEncKey } = await makeRig();

    // A neighbouring verified write establishes a real anchor record, so
    // "the anchor is unchanged" is a comparison against something.
    await stateStore.write(
      NAMESPACE,
      "neighbour",
      "anchored",
      identity.identity_id,
      identity.encrypted_private_key,
      identityEncKey
    );
    await plantAttributableLegacyEntry({
      storage,
      identityId: identity.identity_id,
      namespace: NAMESPACE,
      key: "legacy-attributable",
      value: "must-not-be-migrated-by-a-call-that-refuses",
      version: 1,
    });

    const bytesBefore = bytesToString(
      (await storage.read(NAMESPACE, "legacy-attributable"))!
    );
    const anchorsBefore = bytesToString(
      (await storage.read(ANCHORS_NAMESPACE, ANCHORS_KEY))!
    );

    await expect(
      stateStore.readUnattributed(NAMESPACE, "legacy-attributable")
    ).rejects.toMatchObject({ classification: "writer_is_establishable" });

    const bytesAfter = bytesToString(
      (await storage.read(NAMESPACE, "legacy-attributable"))!
    );
    // The schema version is the loudest discriminator (a migration rewrites the
    // entry as a schema-2 signed envelope), and the byte comparison catches a
    // re-sign that preserved it.
    expect((JSON.parse(bytesAfter) as StateEntry).v).toBe(1);
    expect(bytesAfter).toBe(bytesBefore);
    expect(
      bytesToString((await storage.read(ANCHORS_NAMESPACE, ANCHORS_KEY))!)
    ).toBe(anchorsBefore);
  });

  it("names the identity to restore, as a claim and never as attribution", async () => {
    // The remedy every layer of this surface advertises is "restore the writer
    // identity". Without this field nothing tells the owner WHICH one: the
    // disclosure omits the attested `written_by` by design and `list` carries
    // no key id, so the instruction had no handle to act on.
    const { storage, stateStore } = await makeRig();
    await plantUnattributableLegacyEntry({
      storage,
      namespace: NAMESPACE,
      key: "orphaned",
      value: "content",
      version: 1,
    });

    const disclosure = (await stateStore.readUnattributed(
      NAMESPACE,
      "orphaned"
    ))!;
    expect(disclosure.claimed_writer_id).toBe(
      "sanctuary-no-such-writer-identity"
    );
    // Spelled `claimed_`, like `claimed_written_at`, and NOT under the attested
    // spelling: nothing on this path established it, so a consumer reaching for
    // the verified name must still find nothing.
    expect(Object.keys(disclosure)).not.toContain("written_by");
    expect(Object.keys(disclosure)).toContain("claimed_writer_id");
  });

  it("audits a miss as a miss, not as a disclosure", async () => {
    // The pre-read record is appended BEFORE the read (that ordering is the
    // contract), so on its own a missing key leaves a log entry byte-identical
    // in shape to a disclosure that actually handed content to an operator.
    const { stateStore, auditLog } = await makeRig();

    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace: NAMESPACE,
      key: "absent",
      identityId: "principal",
    });
    expect(outcome.status).toBe("not_found");

    const refused = await auditLog.query({
      operation_type: "state_disclose_unattributed_refused",
    });
    expect(refused.entries).toHaveLength(1);
    expect(refused.entries[0]!.details).toMatchObject({
      namespace: NAMESPACE,
      key: "absent",
      classification: "not_found",
    });
  });
});

describe("the namespace firewall belongs to the operation, not to one transport", () => {
  // Both checks are transport-independent, so they live in the shared
  // operation rather than in either caller: that is the only place a transport
  // cannot skip one by forgetting it. These assert the checks THERE; the
  // transport-level tests assert that each caller renders the refusal.

  it("refuses a reserved namespace, before it audits and before it reads", async () => {
    const { stateStore, auditLog } = await makeRig();

    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace: "_reputation",
      key: "anything",
      identityId: "principal",
    });
    expect(outcome.status).toBe("refused_namespace_reserved");
    expect(
      (outcome as { reservedPrefix?: string }).reservedPrefix
    ).toBe("_reputation");

    // No `success` record for a call that was never a disclosure attempt
    // against a servable namespace.
    const audit = await auditLog.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(audit.entries).toHaveLength(0);
  });

  it("refuses an uncurated underscore namespace too, on the blanket rule", async () => {
    const { stateStore, auditLog } = await makeRig();
    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: new OpaqueNamespaceRegistry(),
      namespace: "_not_on_the_curated_list",
      key: "anything",
      identityId: "principal",
    });
    expect(outcome.status).toBe("refused_namespace_reserved");
  });

  it("refuses an opaque memory handle this caller does not own, and audits the denial", async () => {
    const { stateStore, auditLog } = await makeRig();
    const registry = new OpaqueNamespaceRegistry();
    const someoneElsesHandle = registry.issueMemoryHandle("another-identity");

    // No session binding: there is no live session to own the handle with, so
    // the assertion fails closed rather than treating "no session" as "no
    // owner to check against".
    const outcome = await discloseUnattributedState({
      auditLog,
      stateStore,
      namespaceRegistry: registry,
      namespace: someoneElsesHandle,
      key: "anything",
      identityId: "principal",
    });
    expect(outcome.status).toBe("refused_namespace_unavailable");

    const audit = await auditLog.query({
      operation_type: UNATTRIBUTED_DISCLOSURE_OPERATION,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.result).toBe("failure");
    expect(audit.entries[0]!.details).toMatchObject({
      denial_class: "namespace_unavailable",
    });
  });
});

describe("the disclosure surface is Tier-1 gated and the gate is not relaxable", () => {
  const operation = NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS[0];

  it("single-sources exactly the disclosure operation", () => {
    expect([...NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS]).toEqual([
      "state_disclose_unattributed",
    ]);
    // The wire name the transports use is the same string, so the tier cannot
    // be pinned to an operation nobody calls.
    expect(UNATTRIBUTED_DISCLOSURE_OPERATION).toBe(operation);
  });

  it("policy load and direct mutation cannot relax it out of Tier 1", () => {
    const hostile = parsePolicy(
      [
        "tier1_always_approve:",
        "  - state_export",
        "tier3_always_allow:",
        `  - ${operation}`,
        "approval_channel:",
        "  type: stderr",
      ].join("\n")
    );
    expect(hostile.tier1_always_approve).toContain(operation);
    expect(hostile.tier3_always_allow).not.toContain(operation);

    const normalized = enforceForcedTiers(hostilePolicy(operation));
    expect(normalized.tier1_always_approve).toContain(operation);
    expect(normalized.tier3_always_allow).not.toContain(operation);
  });

  it("classifies Tier 1 at runtime even against a policy object that was never normalized", () => {
    // The force-pin is checked by the runtime classifier too, so a policy
    // handed straight to the gate (never routed through the loader) still
    // resolves Tier 1. This is the half a downgradable list would not have.
    expect(
      makeGate(hostilePolicy(operation), new AutoApproveChannel()).classifyRiskTier(
        operation,
        {}
      )
    ).toBe(1);
  });

  it("requires the approval rather than merely classifying it: a denying channel stops the call", async () => {
    // PROOF, not assertion. The gate is driven with the same hostile
    // auto-allow policy and a channel that always denies; if the tier were
    // relaxable, or the approval were classified but never requested, the
    // channel would never be consulted and `allowed` would be true.
    const channel = new DenyingChannel();
    const gate = makeGate(hostilePolicy(operation), channel);
    const decision = await gate.evaluate(operation, {
      namespace: NAMESPACE,
      key: "orphaned",
    });
    expect(channel.calls).toBe(1);
    expect(decision.tier).toBe(1);
    expect(decision.approval_required).toBe(true);
    expect(decision.allowed).toBe(false);
  });
});
