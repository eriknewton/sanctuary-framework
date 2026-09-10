import { describe, expect, it } from "vitest";
import { ed25519, ED25519_TORSION_SUBGROUP } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { concatBytes } from "@noble/hashes/utils";
import {
  isStrictEd25519PointEncoding,
  sign as identitySign,
  verify as identityVerify,
} from "../src/core/identity.js";
import { fromBase64url, stringToBytes, toBase64url } from "../src/core/encoding.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { generateRandomKey } from "../src/core/random.js";
import { StateStore } from "../src/cognitive/state-store.js";
import {
  AUDIT_EVENT_SIGNING_DOMAIN,
  INTERNAL_RECEIPT_SIGNING_DOMAIN,
  createL1Tools,
  domainSeparatedSigningBytes,
  type AuditEventSigningPayload,
  type InternalReceiptSigningPayload,
} from "../src/cognitive/tools.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { MemoryStorage } from "../src/storage/memory.js";

/** Decode one of @noble's `ED25519_TORSION_SUBGROUP` hex strings to raw bytes. */
function hexToTorsionBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function callTool(
  tools: Array<{
    name: string;
    handler: (
      args: Record<string, unknown>
    ) => Promise<{ content: Array<{ type: string; text: string }> }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

function makeRig() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const l1 = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { ...l1, masterKey };
}

const auditPayload: AuditEventSigningPayload = {
  event_id: "audit-evt-1",
  layer: "l2",
  operation: "gate_allow:state_read",
  actor: "system",
  timestamp: "2026-05-15T12:00:00.000Z",
  event_hash: `sha256:${"a".repeat(64)}`,
  previous_event_hash: `sha256:${"b".repeat(64)}`,
};

const receiptPayload: InternalReceiptSigningPayload = {
  receipt_id: "receipt-1",
  receipt_type: "approval",
  subject: "identity_sign",
  issued_at: "2026-05-15T12:00:00.000Z",
  status: "approved",
  body_hash: `sha256:${"c".repeat(64)}`,
};

describe("internal identity signing helpers", () => {
  it("rejects the constructive identity-key equation forgery and malformed subgroups", () => {
    const message = stringToBytes("arbitrary Castle Wall authority message");
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const scalarOne = new Uint8Array(32);
    scalarOne[0] = 1;
    const signature = new Uint8Array(64);
    signature.set(ed25519.Point.BASE.toBytes(), 0);
    signature.set(scalarOne, 32);
    expect(ed25519.verify(signature, message, identity)).toBe(true);
    expect(identityVerify(message, signature, identity)).toBe(false);

    const noncanonicalIdentity = new Uint8Array(identity);
    noncanonicalIdentity[31] = 0x80;
    expect(isStrictEd25519PointEncoding(noncanonicalIdentity)).toBe(false);

    const orderTwo = new Uint8Array(32).fill(0xff);
    orderTwo[0] = 0xec;
    orderTwo[31] = 0x7f;
    const torsionBearing = ed25519.Point.BASE.add(
      ed25519.Point.fromBytes(orderTwo, false)
    ).toBytes();
    expect(ed25519.Point.fromBytes(torsionBearing, false).isSmallOrder()).toBe(false);
    expect(isStrictEd25519PointEncoding(torsionBearing)).toBe(false);
  });

  it("drives the shared verify funnel with a valid key and mutated commitments", () => {
    // Every constant below comes from a @noble export, not a hand-typed byte
    // string: ED25519_TORSION_SUBGROUP is @noble's own documented 8-torsion
    // subgroup (node_modules/@noble/curves/esm/ed25519.js, the
    // ED25519_TORSION_SUBGROUP array; index 3 is its generator T, per that
    // file's doc comment: "All 8 ed25519 points of 8-torsion subgroup can be
    // generated from the point T"), and CURVE.n is @noble's own scalar group
    // order L.
    const message = stringToBytes("funnel regression message");
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const signature = ed25519.sign(message, privateKey);
    const R = signature.subarray(0, 32);
    const S = signature.subarray(32, 64);

    // (d) baseline: an untouched signature over a valid key verifies true
    // through the funnel. Every other case in this test mutates one field
    // away from this baseline.
    expect(identityVerify(message, signature, publicKey)).toBe(true);

    // (a) R mutated to a mixed-order point: a genuine prime-order R (from the
    // real signature above) plus the 8-torsion generator T. `T` has order 8,
    // so `R + T` is neither prime-order nor itself small-order; it is a point
    // whose order is a multiple of both. Adding T to R changes R's encoded
    // bytes, so the funnel's own gate must reject it before @noble ever runs
    // (the funnel checks R's subgroup membership independently of what @noble
    // decides); this is not an assertion about whether @noble treats it as a
    // forgery.
    const torsionGenerator = ed25519.Point.fromBytes(
      hexToTorsionBytes(ED25519_TORSION_SUBGROUP[3]!),
      true
    );
    const mixedOrderR = ed25519.Point.fromBytes(R, false)
      .add(torsionGenerator)
      .toBytes();
    expect(
      ed25519.Point.fromBytes(mixedOrderR, true).isSmallOrder()
    ).toBe(false);
    expect(
      ed25519.Point.fromBytes(mixedOrderR, true).isTorsionFree()
    ).toBe(false);
    const mixedOrderSignature = new Uint8Array(64);
    mixedOrderSignature.set(mixedOrderR, 0);
    mixedOrderSignature.set(S, 32);
    // Recorded, not asserted as a precondition: recomputing the challenge
    // `k = H(R'||A||M)` from the mutated R bytes changes k, so @noble's own
    // cofactored equation also fails to hold on this construction with
    // `zip215: false` (verified empirically against @noble/curves 1.9.7;
    // a different key or message need not reproduce this). The funnel's
    // rejection below does not depend on that outcome.
    expect(
      ed25519.verify(mixedOrderSignature, message, publicKey, {
        zip215: false,
      })
    ).toBe(false);
    expect(identityVerify(message, mixedOrderSignature, publicKey)).toBe(
      false
    );

    // (a2) The essential-gate case: a signature the curve library ACCEPTS and
    // the funnel REJECTS. Built the way a signer would, except that the
    // commitment carries an 8-torsion component: R' = rB + T, then the
    // challenge k = H(R' || A || M) is computed over the mutated R', and
    // S = r + k*a. Under the library's cofactored equation,
    // [8](R' + kA - SB) = [8]T = 0, so @noble accepts it with zip215 false
    // and true alike; only the funnel's torsion-free gate on R refuses it.
    // This is the case that proves the gates are load-bearing rather than
    // redundant with an option flag. r is derived from the secret prefix and
    // the message exactly as RFC 8032 section 5.1.6 step 2 derives it.
    const extended = ed25519.utils.getExtendedPublicKey(privateKey);
    const bytesToScalarLE = (bytes: Uint8Array): bigint => {
      let n = 0n;
      for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
      return n;
    };
    const scalarToBytesLE = (n: bigint): Uint8Array => {
      const out = new Uint8Array(32);
      let rest = n;
      for (let i = 0; i < 32; i++) {
        out[i] = Number(rest & 0xffn);
        rest >>= 8n;
      }
      expect(rest).toBe(0n);
      return out;
    };
    const order = ed25519.CURVE.n;
    const nonce =
      bytesToScalarLE(sha512(concatBytes(extended.prefix, message))) % order;
    const torsionCommitment = ed25519.Point.BASE.multiply(nonce)
      .add(torsionGenerator)
      .toBytes();
    const challenge =
      bytesToScalarLE(
        sha512(concatBytes(torsionCommitment, publicKey, message))
      ) % order;
    const torsionS = (nonce + challenge * extended.scalar) % order;
    const torsionSignature = concatBytes(
      torsionCommitment,
      scalarToBytesLE(torsionS)
    );
    expect(
      ed25519.Point.fromBytes(torsionCommitment, true).isTorsionFree()
    ).toBe(false);
    expect(
      ed25519.verify(torsionSignature, message, publicKey, { zip215: false })
    ).toBe(true);
    expect(identityVerify(message, torsionSignature, publicKey)).toBe(false);

    // (b) R replaced outright by one of the eight canonical small-order
    // points (index 3, the same T as above, used directly as R rather than
    // added to it).
    const smallOrderSignature = new Uint8Array(64);
    smallOrderSignature.set(hexToTorsionBytes(ED25519_TORSION_SUBGROUP[3]!), 0);
    smallOrderSignature.set(S, 32);
    expect(identityVerify(message, smallOrderSignature, publicKey)).toBe(
      false
    );

    // (c) S mutated to S + L (>= the scalar group order L, so non-canonical).
    // R is left untouched.
    const scalarL = ed25519.CURVE.n;
    let sAsScalar = 0n;
    for (let i = 31; i >= 0; i--) sAsScalar = (sAsScalar << 8n) | BigInt(S[i]!);
    const oversizedS = sAsScalar + scalarL;
    const oversizedSBytes = new Uint8Array(32);
    let remaining = oversizedS;
    for (let i = 0; i < 32; i++) {
      oversizedSBytes[i] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    // oversizedS must still fit in 32 little-endian bytes for this to be a
    // well-formed 64-byte signature; a nonzero remainder would mean the test
    // itself constructed an invalid fixture rather than exercising the gate.
    expect(remaining).toBe(0n);
    const oversizedSSignature = new Uint8Array(64);
    oversizedSSignature.set(R, 0);
    oversizedSSignature.set(oversizedSBytes, 32);
    expect(identityVerify(message, oversizedSSignature, publicKey)).toBe(
      false
    );
  });

  it("keeps typed signing helpers off the MCP tool surface", () => {
    const { tools } = makeRig();
    const names = tools.map((tool) => tool.name);

    expect(names).toContain("identity_sign");
    expect(names).toContain("identity_verify");
    expect(names).not.toContain("audit_event_sign");
    expect(names).not.toContain("internal_receipt_sign");
  });

  it("signs audit events and internal receipts without using operator approval", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "internal-signer",
    });

    const auditSigned = await internalSigning.audit_event_sign(auditPayload, {
      identity_id: identity.identity_id as string,
    });
    const receiptSigned = await internalSigning.internal_receipt_sign(receiptPayload, {
      identity_id: identity.identity_id as string,
    });

    expect(auditSigned.domain).toBe(AUDIT_EVENT_SIGNING_DOMAIN);
    expect(receiptSigned.domain).toBe(INTERNAL_RECEIPT_SIGNING_DOMAIN);
    expect(auditSigned.signature).toEqual(expect.any(String));
    expect(receiptSigned.signature).toEqual(expect.any(String));
  });

  it("rejects arbitrary bytes smuggled through the receipt schema", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "receipt-schema",
    });

    expect(() =>
      internalSigning.internal_receipt_sign(
        {
          ...receiptPayload,
          payload: "raw arbitrary commitment",
        } as unknown as InternalReceiptSigningPayload,
        { identity_id: identity.identity_id as string }
      )
    ).toThrow(/unsupported field: payload/);
  });

  it("domain-separated signatures cannot be replayed across audit and receipt domains", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "domain-separation",
    });

    const signed = await internalSigning.audit_event_sign(auditPayload, {
      identity_id: identity.identity_id as string,
    });
    const signature = fromBase64url(signed.signature);
    const publicKey = fromBase64url(identity.public_key as string);

    const auditBytes = domainSeparatedSigningBytes(
      AUDIT_EVENT_SIGNING_DOMAIN,
      auditPayload as unknown as Record<string, unknown>
    );
    const receiptBytes = domainSeparatedSigningBytes(
      INTERNAL_RECEIPT_SIGNING_DOMAIN,
      auditPayload as unknown as Record<string, unknown>
    );

    expect(identityVerify(auditBytes, signature, publicKey)).toBe(true);
    expect(identityVerify(receiptBytes, signature, publicKey)).toBe(false);
  });

  it("keeps identity_verify available for arbitrary payload verification", async () => {
    const { tools, identityManager, masterKey } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "verify-only",
    });
    const storedIdentity = identityManager.get(identity.identity_id as string);
    if (!storedIdentity) throw new Error("identity was not saved");

    const payloadBytes = stringToBytes("verify this arbitrary external payload");
    const payload = toBase64url(payloadBytes);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const signature = identitySign(
      payloadBytes,
      storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const verified = await callTool(tools, "identity_verify", {
      public_key: identity.public_key,
      payload,
      signature: toBase64url(signature),
    });

    expect(verified.valid).toBe(true);
  });
});
