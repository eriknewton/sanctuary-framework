import { describe, it, expect, vi } from "vitest";
import { randomBytes, createHash } from "node:crypto";
import { z } from "zod";
import { ed25519 } from "@noble/curves/ed25519";
import * as contract from "../../src/signing/contract.js";
import { ROLE_REGISTRY, canonicalBytes, recordMessage, ROLE_SIGNATURE_SCHEME, safeInteger } from "../../src/signing/contract.js";
import { createRecordSigner } from "../../src/signing/record-signer.js";
import { EncryptedIdentityProvider } from "../../src/signing/identity-provider.js";
import { prepareRoleIdentity } from "../../src/signing/provision.js";
import { verifyRecord } from "../../src/signing/strict-verifier.js";
import { INTERNAL_SIGNING_DOMAIN_PREFIXES } from "../../src/core/signing-domains.js";
import {encodeSignerFrame} from "../../src/linux-business/producer-custody.js";
import { decrypt } from "../../src/core/encryption.js";

const schema = z.object({count: safeInteger}).strict();
function fixture(role = ROLE_REGISTRY[0].role as typeof ROLE_REGISTRY[number]["role"]) {
  const key = randomBytes(32);
  const {storedIdentity, pin} = prepareRoleIdentity(role, 1, "a".repeat(32), key, [], []);
  const grant = {...pin, activation_id: "b".repeat(32), lease_id: "c".repeat(32), generation: 1};
  const provider = new EncryptedIdentityProvider(storedIdentity, key, pin);
  const body = {signature_scheme: ROLE_SIGNATURE_SCHEME, role, record_kind: (contract.roleEntry(role).record_kinds ?? ["append"])[0], epoch: 1, kid: pin.kid, identity_id: pin.identity_id, machine_id: pin.machine_id,
    ...(role.startsWith("extension:linux-business-") ? {activation_id: grant.activation_id, lease_id: grant.lease_id, generation: grant.generation,
    boot_id: "d".repeat(32), sequence: 1, prior_commitment: "GENESIS", captured_at_unix_ms: 1, captured_at_boottime_ns: "1",
    policy_digest: "sha256:" + "a".repeat(64), runtime_digest: "sha256:" + "b".repeat(64), config_digest: "sha256:" + "c".repeat(64)} : {}), payload: {count: 1}};
  return {key, storedIdentity, pin, grant, provider, body, preimage: canonicalBytes(body), close() {provider.close(); key.fill(0);}};
}
describe("K1 role signer contract", () => {
  it.each(ROLE_REGISTRY)("adds exact domain itself for $role", ({role}) => {
    const f = fixture(role); const seen: Uint8Array[] = [];
    try {
      const seed = decrypt(f.storedIdentity.encrypted_private_key, f.key);
      const raw = ed25519.sign(f.preimage, seed);
      const digest = ed25519.sign(createHash("sha256").update(recordMessage(role, f.preimage)).digest(), seed);
      const doubled = f.provider.sign(recordMessage(role, recordMessage(role, f.preimage)));
      seed.fill(0);
      for (const sig of [raw, digest, doubled]) expect(verifyRecord(f.preimage, Buffer.from(sig).toString("base64url"), f.pin, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0])).toBe(false);
      const signer = createRecordSigner(f.grant, {sign(message) {seen.push(message); return f.provider.sign(recordMessage(role, f.preimage));}}, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]);
      const result = signer.signRecord({role, epoch: 1, preimage_bytes: f.preimage});
      expect(seen).toHaveLength(1);
      expect(Buffer.from(seen[0])).toEqual(Buffer.concat([Buffer.from(ROLE_REGISTRY.find(row => row.role === role)!.domain), f.preimage]));
      expect(verifyRecord(f.preimage, result.signature, f.pin, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0])).toBe(true);
      expect(result.kid).toMatch(/^k1:sha256:[a-f0-9]{64}$/);

    } finally {f.close();}
  });
  it.each(INTERNAL_SIGNING_DOMAIN_PREFIXES)("refuses registered prefix before schema dispatch %s", prefix => {
    const f = fixture(); const sign = vi.spyOn(f.provider, "sign"); const parse = vi.spyOn(contract, "parseRecord");
    try {
      expect(() => createRecordSigner(f.grant, f.provider, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord({role: f.pin.role, epoch: 1, preimage_bytes: Buffer.concat([Buffer.from(prefix),f.preimage])})).toThrow("K1_REFUSED");
      expect(parse).not.toHaveBeenCalled(); expect(sign).not.toHaveBeenCalled();
    } finally {parse.mockRestore(); sign.mockRestore(); f.close();}
  });
  it.each(["unknown", "duplicate", "trailing", "utf8", "float", "digest", "unsafe", "noncanonical"])("rejects %s before signing", kind => {
    const f=fixture(); const sign=vi.spyOn(f.provider,"sign");
    try {
      const text=Buffer.from(f.preimage).toString();
      const inputs: Record<string,Uint8Array> = {
        unknown: canonicalBytes({...f.body, surprise: 1}), duplicate: Buffer.from(text.replace('"epoch":1','"epoch":1,"epoch":1')),
        trailing: Buffer.from(text+" "), utf8: Buffer.concat([f.preimage,Buffer.from([255])]),
        float: canonicalBytes({...f.body,payload:{count:1.5}}), digest: createHash("sha256").update(f.preimage).digest(),
        unsafe: Buffer.from(text.replace('"count":1','"count":9007199254740992')), noncanonical: Buffer.from(JSON.stringify(f.body)),
      };
      expect(() => createRecordSigner(f.grant,f.provider,schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord({role:f.pin.role,epoch:1,preimage_bytes:inputs[kind]})).toThrow("K1_REFUSED");
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it.each(["role","epoch","machine_id","identity_id","kid","activation_id","lease_id","generation"])("binds immutable grant %s", field => {
    const f=fixture(); const sign=vi.spyOn(f.provider,"sign");
    try {
      const bad={...f.body,[field]:field==="epoch"||field==="generation"?2:field==="role"?ROLE_REGISTRY[1].role:"f".repeat(32)};
      expect(() => createRecordSigner(f.grant,f.provider,schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord({role:f.pin.role,epoch:1,preimage_bytes:canonicalBytes(bad)})).toThrow();
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it("enforces safe integers even when a trusted payload adapter accepts fractions", () => {
    const f=fixture();
    try {
      const signer=createRecordSigner(f.grant,f.provider,z.object({count:z.number()}).strict(), (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]);
      expect(()=>signer.signRecord({role:f.pin.role,epoch:1,preimage_bytes:canonicalBytes({...f.body,payload:{count:1.5}})})).toThrow("K1_REFUSED");
    } finally {f.close();}
  });
  it("counts final wrapper bytes before a provider call", () => {
    const f=fixture(); const sign=vi.spyOn(f.provider,"sign");
    const largeSchema=z.object({text:z.string()}).strict();
    try {
      let body={...f.body,payload:{text:""}};
      const overhead=canonicalBytes(body).length; body={...body,payload:{text:"a".repeat(4096-overhead)}};
      expect(canonicalBytes(body).length).toBe(4096);
      expect(() => createRecordSigner(f.grant,f.provider,largeSchema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord({role:f.pin.role,epoch:1,preimage_bytes:canonicalBytes(body)})).toThrow();
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it("legacy scheme and legacy kid refuse even with a valid mathematical signature", () => {
    const f=fixture();
    try {
      for(const changes of [{signature_scheme:"ed25519-v1"},{kid:"cw-audit-producer-v1"}]) {
        const bytes=canonicalBytes({...f.body,...changes}); const sig=f.provider.sign(recordMessage(f.pin.role,bytes));
        expect(ed25519.verify(sig,recordMessage(f.pin.role,bytes),Buffer.from(f.pin.public_key,"base64url"))).toBe(true);
        expect(verifyRecord(bytes,Buffer.from(sig).toString("base64url"),f.pin,schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0])).toBe(false);
      }
    } finally {f.close();}
  });
  it("has no key bytes in result, frame-like requests, logs or sanitized errors", () => {
    const f=fixture(); const seed=decrypt(f.storedIdentity.encrypted_private_key,f.key);
    const logs:string[]=[]; const spies=[vi.spyOn(console,"log"),vi.spyOn(console,"warn"),vi.spyOn(console,"error")].map(spy=>spy.mockImplementation((...args)=>{logs.push(JSON.stringify(args));}));
    try {
      const signer=createRecordSigner(f.grant,f.provider,schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]);
      const request={role:f.pin.role,epoch:1,preimage_bytes:f.preimage};
      const result=signer.signRecord(request);
      let error="";
      try {createRecordSigner(f.grant,{sign(){throw new Error(Buffer.from(seed).toString("hex"));}},schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord(request);}catch(e){error=String(e);}
      const frame=encodeSignerFrame({v:1,protocol:contract.SIGNER_PROTOCOL,request_id:"e".repeat(32),activation_id:f.grant.activation_id,lease_id:f.grant.lease_id,generation:1,epoch:1,role:f.pin.role,deadline_boottime_ns:"1",preimage_length:f.preimage.length},f.preimage);
      const observed=JSON.stringify({request,result,logs,error,frame:Buffer.from(frame).toString("hex"),provider:f.provider});
      for(const secret of [seed,f.key]) for(const representation of [Buffer.from(secret).toString("hex"),Buffer.from(secret).toString("base64"),Buffer.from(secret).toString("base64url"),JSON.stringify([...secret])]) expect(observed.includes(representation)).toBe(false);
      expect(error).toBe("Error: K1_REFUSED"); expect(logs).toEqual([]);
    } finally {seed.fill(0);spies.forEach(spy=>spy.mockRestore());f.close();}
  });
  it("copies grant and encrypted identity and closes permanently", () => {
    const f=fixture(); const signer=createRecordSigner(f.grant,f.provider,schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]);
    try {
      f.grant.generation=9; f.storedIdentity.public_key="broken";
      expect(signer.signRecord({role:f.pin.role,epoch:1,preimage_bytes:f.preimage}).kid).toBe(f.pin.kid);
      f.provider.close(); expect(()=>signer.signRecord({role:f.pin.role,epoch:1,preimage_bytes:f.preimage})).toThrow();
    } finally {f.close();}
  });
  it("refuses mismatched seed-derived public key", () => {
    const f=fixture(); const other=fixture();
    try {expect(()=>new EncryptedIdentityProvider({...f.storedIdentity,public_key:other.pin.public_key},f.key,{...other.pin,identity_id:f.pin.identity_id})).toThrow();}
    finally {f.close();other.close();}
  });
});

describe("role boundary witnesses", () => {
  it("refuses arbitrary and foreign messages at the provider", () => {
    const f = fixture();
    try {
      for (const message of [f.preimage, new Uint8Array(32), recordMessage(ROLE_REGISTRY[1].role, f.preimage)])
        expect(() => f.provider.sign(message)).toThrow("K1_REFUSED");
      for (const domain of [contract.PRODUCER_ROTATION_DOMAIN, contract.PRODUCER_DESCRIPTOR_DOMAIN, contract.UNLOCK_CHALLENGE_DOMAIN])
        expect(f.provider.sign(Buffer.concat([Buffer.from(domain), f.preimage]))).toHaveLength(64);
    } finally { f.close(); }
  });
  it.each(["role", "epoch"])("binds request %s independently of the signed body", field => {
    const f = fixture(); const sign = vi.spyOn(f.provider, "sign");
    try {
      const request = {role: f.pin.role, epoch: 1, preimage_bytes: f.preimage,
        [field]: field === "role" ? ROLE_REGISTRY[1].role : 2};
      expect(() => createRecordSigner(f.grant, f.provider, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord(request)).toThrow("K1_REFUSED");
      expect(sign).not.toHaveBeenCalled();
    } finally { f.close(); }
  });
  it("binds a syntactically valid kid to the pinned key", () => {
    const f = fixture();
    try {
      const bytes = canonicalBytes({...f.body, kid: "k1:sha256:" + "0".repeat(64)});
      const signature = Buffer.from(f.provider.sign(recordMessage(f.pin.role, bytes))).toString("base64url");
      expect(verifyRecord(bytes, signature, f.pin, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0])).toBe(false);
    } finally { f.close(); }
  });
  it.each(["history", "kid"])("checks provider %s before exposing a signer", kind => {
    const f = fixture();
    try {
      const identity = {...f.storedIdentity, rotation_history: kind === "history" ? [{} as never] : []};
      const pin = {...f.pin, kid: kind === "kid" ? "k1:sha256:" + "0".repeat(64) : f.pin.kid};
      expect(() => new EncryptedIdentityProvider(identity, f.key, pin)).toThrow("K1_REFUSED");
    } finally { f.close(); }
  });
  it("takes a private copy of a shared backing buffer before parsing", () => {
    const f = fixture(); const shared = new SharedArrayBuffer(f.preimage.length);
    new Uint8Array(shared).set(f.preimage);
    const original = contract.parseRecord;
    const parse = vi.spyOn(contract, "parseRecord").mockImplementation((bytes, role, payload, kind) => {
      new Uint8Array(shared).fill(0);
      return original(bytes, role, payload, kind);
    });
    try {
      expect(() => createRecordSigner(f.grant, f.provider, schema, (contract.roleEntry(f.pin.role).record_kinds ?? ["append"])[0]).signRecord({role: f.pin.role, epoch: 1,
        preimage_bytes: shared as unknown as Uint8Array})).not.toThrow();
    } finally { parse.mockRestore(); f.close(); }
  });
});

it.each(ROLE_REGISTRY)("binds every registered kind for $role", entry => {
  const f = fixture(entry.role);
  try {
    expect(entry.record_kinds).toBeDefined();
    for (const kind of entry.record_kinds) {
      const bytes = canonicalBytes({...f.body, record_kind: kind});
      const result = createRecordSigner(f.grant, f.provider, schema, kind).signRecord({role: f.pin.role, epoch: 1, preimage_bytes: bytes});
      expect(verifyRecord(bytes, result.signature, f.pin, schema, kind)).toBe(true);
      for (const other of entry.record_kinds.filter(value => value !== kind))
        expect(verifyRecord(bytes, result.signature, f.pin, schema, other)).toBe(false);
    }
    expect(() => createRecordSigner(f.grant, f.provider, schema, "unregistered").signRecord({role: f.pin.role, epoch: 1,
      preimage_bytes: canonicalBytes({...f.body, record_kind: "unregistered"})})).toThrow("K1_REFUSED");
  } finally { f.close(); }
});
import {sign as identitySign} from "../../src/core/identity.js";
it.each(["other role", "relabelled other role"])("refuses a provider signing with an %s key", kind => {
  const f = fixture(); const other = fixture(ROLE_REGISTRY[3].role);
  try {
    const provider = {sign: (message: Uint8Array) => identitySign(message, other.storedIdentity.encrypted_private_key, other.key)};
    // The relabelled case keeps the model-recorder role key and changes only a label the provider never reads.
    if (kind === "relabelled other role") other.storedIdentity.label = "ordinary operator";
    expect(() => createRecordSigner(f.grant, provider, schema, "append").signRecord({role: f.pin.role, epoch: 1, preimage_bytes: f.preimage})).toThrow("K1_REFUSED");
  } finally { f.close(); other.close(); }
});

import {strictVerify} from "../../src/signing/strict-verifier.js";
it.each(ROLE_REGISTRY)("real provider signature from signRecord covers only the $role domain plus preimage", ({role}) => {
  const f = fixture(role); const sign = vi.spyOn(f.provider, "sign");
  try {
    const result = createRecordSigner(f.grant, f.provider, schema, f.body.record_kind).signRecord({role, epoch: 1, preimage_bytes: f.preimage});
    expect(sign).toHaveBeenCalledTimes(1);
    const signature = Buffer.from(result.signature, "base64url"), publicKey = Buffer.from(f.pin.public_key, "base64url");
    // The signer, not its caller, prepends the role domain, so the signature binds exactly that domain and the preimage.
    expect(strictVerify(recordMessage(role, f.preimage), signature, publicKey)).toBe(true);
    expect(strictVerify(f.preimage, signature, publicKey)).toBe(false);
    for (const other of ROLE_REGISTRY.filter(row => row.role !== role))
      expect(strictVerify(Buffer.concat([Buffer.from(other.domain), f.preimage]), signature, publicKey)).toBe(false);
  } finally { sign.mockRestore(); f.close(); }
});
it.each([contract.PRODUCER_ROTATION_DOMAIN, contract.PRODUCER_DESCRIPTOR_DOMAIN, contract.UNLOCK_CHALLENGE_DOMAIN])("binds lifecycle domain %j to the provider role and machine", domain => {
  const f = fixture(ROLE_REGISTRY[3].role);
  try {
    const own = {role: f.pin.role, machine_id: f.pin.machine_id, v: 1};
    const message = (body: Uint8Array) => Buffer.concat([Buffer.from(domain), body]);
    expect(f.provider.sign(message(canonicalBytes(own)))).toHaveLength(64);
    for (const body of [canonicalBytes({...own, role: ROLE_REGISTRY[0].role}), canonicalBytes({...own, machine_id: "f".repeat(32)}),
      canonicalBytes({v: 1, machine_id: f.pin.machine_id}), Buffer.from(JSON.stringify({v: 1, role: own.role, machine_id: own.machine_id})),
      Buffer.from('{"machine_id":"' + own.machine_id + '","role":"' + own.role + '","role":"' + own.role + '","v":1}'),
      canonicalBytes([own]), new Uint8Array(32)])
      expect(() => f.provider.sign(message(body))).toThrow("K1_REFUSED");
  } finally { f.close(); }
});
it("verifyRecord refuses a validly signed duplicate-key preimage, matching Rust verify_role", () => {
  const f = fixture();
  try {
    const text = Buffer.from(f.preimage).toString();
    const duplicate = Buffer.from(text.replace('"record_kind":"append"', '"record_kind":"append","record_kind":"control"'));
    expect(duplicate.equals(Buffer.from(f.preimage))).toBe(false);
    const signature = Buffer.from(f.provider.sign(recordMessage(f.pin.role, duplicate))).toString("base64url");
    for (const kind of ["append", "control"]) expect(verifyRecord(duplicate, signature, f.pin, schema, kind)).toBe(false);
  } finally { f.close(); }
});
