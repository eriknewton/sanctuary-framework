/**
 * The identity adapter, fed generated certificates directly. Each certificate
 * keeps the real 1.8.4 leaf's fields and replaces its extension list, so every
 * pinned extension can be removed, altered, re-encoded or duplicated alone.
 * These certificates never pass through the Sigstore verifier.
 */
import { X509Certificate } from "@sigstore/core";
import { describe, expect, it } from "vitest";
import { FULCIO_OID, PINNED_WORKFLOW_IDENTITY } from "../../src/verify-release/constants.js";
import { IDENTITY_PINS, decodeDerUtf8String, state_IDENTITY } from "../../src/verify-release/identity.js";
import { certificateViewOf } from "../../src/verify-release/sigstore.js";
import { certificateWithExtensions, denyAllNetwork, derExtension, derSanUri, derUtf8, slsaBundle184, tlv } from "./helpers.js";

denyAllNetwork();

const REAL_DER = Buffer.from(slsaBundle184().verificationMaterial.certificate.rawBytes, "base64");
const REAL = X509Certificate.parse(REAL_DER);
const SAN_OID = "2.5.29.17";

/** The real leaf's extensions as [oid, DER] pairs, in order. */
const REAL_EXTENSIONS: Array<[string, Buffer]> = REAL.extensions.map(extension => [extension.subs[0]!.toOID(), extension.toDER()]);

function viewWith(edit: (extensions: Array<[string, Buffer]>) => Array<[string, Buffer]>) {
  const der = certificateWithExtensions(REAL_DER, edit([...REAL_EXTENSIONS]).map(([, item]) => item));
  return certificateViewOf(X509Certificate.parse(Buffer.from(der)));
}
const replace = (oid: string, item: Buffer) => (extensions: Array<[string, Buffer]>) =>
  extensions.map(([o, d]) => (o === oid ? [o, item] as [string, Buffer] : [o, d] as [string, Buffer]));

describe("identity adapter over the real 1.8.4 leaf", () => {
  it("accepts the real certificate's SAN and every pinned V2 extension", () => {
    expect(state_IDENTITY(certificateViewOf(REAL))).toMatchObject({ ok: true });
  });

  it("accepts the same extensions re-encoded through the generator (the generator is faithful)", () => {
    expect(state_IDENTITY(viewWith(e => e))).toMatchObject({ ok: true });
  });

  it("pins exactly the nine V2 extensions of the release identity", () => {
    expect(IDENTITY_PINS.map(pin => pin.oid).sort()).toEqual(Object.values(FULCIO_OID).sort());
  });
});

describe.each(IDENTITY_PINS.map(pin => [pin.name, pin] as const))("extension %s", (name, pin) => {
  it("absent refuses identity-extension-absent", () => {
    expect(state_IDENTITY(viewWith(e => e.filter(([oid]) => oid !== pin.oid)))).toEqual({ ok: false, reason: `identity-extension-absent:${name}` });
  });
  it("altered refuses identity-mismatch", () => {
    expect(state_IDENTITY(viewWith(replace(pin.oid, derExtension(pin.oid, derUtf8(`${pin.value}x`)))))).toEqual({ ok: false, reason: `identity-mismatch:${name}` });
  });
  it("encoded as a raw string rather than a DER UTF8String refuses identity-mismatch", () => {
    expect(state_IDENTITY(viewWith(replace(pin.oid, derExtension(pin.oid, Buffer.from(pin.value, "utf8")))))).toEqual({ ok: false, reason: `identity-mismatch:${name}` });
  });
  it("encoded as an IA5String refuses identity-mismatch", () => {
    expect(state_IDENTITY(viewWith(replace(pin.oid, derExtension(pin.oid, tlv(0x16, Buffer.from(pin.value, "ascii"))))))).toEqual({ ok: false, reason: `identity-mismatch:${name}` });
  });
  it("duplicated refuses identity-mismatch", () => {
    expect(state_IDENTITY(viewWith(e => [...e, [pin.oid, derExtension(pin.oid, derUtf8(pin.value))]]))).toEqual({ ok: false, reason: `identity-mismatch:${name}` });
  });
});

describe("subject alternative name", () => {
  it("another workflow identity refuses identity-mismatch:san", () => {
    const other = PINNED_WORKFLOW_IDENTITY.replace("publish-on-tag.yml", "other.yml");
    expect(state_IDENTITY(viewWith(replace(SAN_OID, derExtension(SAN_OID, derSanUri(other), true))))).toEqual({ ok: false, reason: "identity-mismatch:san" });
  });
  it("a SAN that differs only by a ref suffix refuses: exact equality, never a pattern", () => {
    const longer = `${PINNED_WORKFLOW_IDENTITY}-evil`;
    expect(state_IDENTITY(viewWith(replace(SAN_OID, derExtension(SAN_OID, derSanUri(longer), true))))).toEqual({ ok: false, reason: "identity-mismatch:san" });
  });
  it("absent refuses identity-extension-absent:san", () => {
    expect(state_IDENTITY(viewWith(e => e.filter(([oid]) => oid !== SAN_OID)))).toEqual({ ok: false, reason: "identity-extension-absent:san" });
  });
  it("duplicated refuses identity-mismatch:san", () => {
    expect(state_IDENTITY(viewWith(e => [...e, [SAN_OID, derExtension(SAN_OID, derSanUri(PINNED_WORKFLOW_IDENTITY), true)]]))).toEqual({ ok: false, reason: "identity-mismatch:san" });
  });
  it("the deprecated V1 issuer is never read: removing it changes nothing", () => {
    expect(state_IDENTITY(viewWith(e => e.filter(([oid]) => oid !== "1.3.6.1.4.1.57264.1.1")))).toMatchObject({ ok: true });
  });
});

describe("DER UTF8String decoding", () => {
  it("decodes short and long length forms", () => {
    expect(decodeDerUtf8String(derUtf8("abc"))).toBe("abc");
    const long = "a".repeat(200);
    expect(decodeDerUtf8String(derUtf8(long))).toBe(long);
    const longer = "b".repeat(300);
    expect(decodeDerUtf8String(derUtf8(longer))).toBe(longer);
  });
  it("refuses a non-minimal long form, trailing bytes, a short buffer, and invalid UTF-8", () => {
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x81, 0x03, 0x61, 0x62, 0x63]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x82, 0x00, 0x81, ...Buffer.alloc(0x81, 0x61)]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.concat([derUtf8("abc"), Buffer.from([0x00])]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x05, 0x61]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x02, 0xc3, 0x28]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x80]))).toBeNull();
    expect(decodeDerUtf8String(Buffer.from([0x0c, 0x83, 0x01, 0x00, 0x00]))).toBeNull();
  });
});
