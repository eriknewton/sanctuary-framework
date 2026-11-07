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
  const body = {signature_scheme: ROLE_SIGNATURE_SCHEME, role, epoch: 1, kid: pin.kid, identity_id: pin.identity_id, machine_id: pin.machine_id,
    ...(role.startsWith("extension:linux-business-") ? {activation_id: grant.activation_id, lease_id: grant.lease_id, generation: grant.generation,
    boot_id: "d".repeat(32), sequence: 1, prior_commitment: "GENESIS", captured_at_unix_ms: 1, captured_at_boottime_ns: "1",
    policy_digest: "sha256:" + "a".repeat(64), runtime_digest: "sha256:" + "b".repeat(64), config_digest: "sha256:" + "c".repeat(64)} : {}), payload: {count: 1}};
  return {key, storedIdentity, pin, grant, provider, body, preimage: canonicalBytes(body), close() {provider.close(); key.fill(0);}};
}
describe("K1 role signer contract", () => {
  it.each(ROLE_REGISTRY)("adds exact domain itself for $role", ({role}) => {
    const f = fixture(role); const seen: Uint8Array[] = [];
    try {
      const signer = createRecordSigner(f.grant, {sign(message) {seen.push(message); return f.provider.sign(message);}}, schema);
      const result = signer.signRecord({role, epoch: 1, preimage_bytes: f.preimage});
      expect(seen).toHaveLength(1);
      expect(Buffer.from(seen[0])).toEqual(Buffer.concat([Buffer.from(ROLE_REGISTRY.find(row => row.role === role)!.domain), f.preimage]));
      expect(verifyRecord(f.preimage, result.signature, f.pin, schema)).toBe(true);
      expect(result.kid).toMatch(/^k1:sha256:[a-f0-9]{64}$/);
      const raw = f.provider.sign(f.preimage);
      const digest = f.provider.sign(createHash("sha256").update(recordMessage(role, f.preimage)).digest());
      const doubled = f.provider.sign(recordMessage(role, recordMessage(role, f.preimage)));
      for (const sig of [raw, digest, doubled]) expect(verifyRecord(f.preimage, Buffer.from(sig).toString("base64url"), f.pin, schema)).toBe(false);
    } finally {f.close();}
  });
  it.each(INTERNAL_SIGNING_DOMAIN_PREFIXES)("refuses registered prefix before schema dispatch %s", prefix => {
    const f = fixture(); const sign = vi.spyOn(f.provider, "sign"); const parse = vi.spyOn(contract, "parseRecord");
    try {
      expect(() => createRecordSigner(f.grant, f.provider, schema).signRecord({role: f.pin.role, epoch: 1, preimage_bytes: Buffer.concat([Buffer.from(prefix),f.preimage])})).toThrow("K1_REFUSED");
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
      expect(() => createRecordSigner(f.grant,f.provider,schema).signRecord({role:f.pin.role,epoch:1,preimage_bytes:inputs[kind]})).toThrow("K1_REFUSED");
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it.each(["role","epoch","machine_id","identity_id","kid","activation_id","lease_id","generation"])("binds immutable grant %s", field => {
    const f=fixture(); const sign=vi.spyOn(f.provider,"sign");
    try {
      const bad={...f.body,[field]:field==="epoch"||field==="generation"?2:field==="role"?ROLE_REGISTRY[1].role:"f".repeat(32)};
      expect(() => createRecordSigner(f.grant,f.provider,schema).signRecord({role:f.pin.role,epoch:1,preimage_bytes:canonicalBytes(bad)})).toThrow();
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it("enforces safe integers even when a trusted payload adapter accepts fractions", () => {
    const f=fixture();
    try {
      const signer=createRecordSigner(f.grant,f.provider,z.object({count:z.number()}).strict());
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
      expect(() => createRecordSigner(f.grant,f.provider,largeSchema).signRecord({role:f.pin.role,epoch:1,preimage_bytes:canonicalBytes(body)})).toThrow();
      expect(sign).not.toHaveBeenCalled();
    } finally {f.close();}
  });
  it("legacy scheme and legacy kid refuse even with a valid mathematical signature", () => {
    const f=fixture();
    try {
      for(const changes of [{signature_scheme:"ed25519-v1"},{kid:"cw-audit-producer-v1"}]) {
        const bytes=canonicalBytes({...f.body,...changes}); const sig=f.provider.sign(recordMessage(f.pin.role,bytes));
        expect(ed25519.verify(sig,recordMessage(f.pin.role,bytes),Buffer.from(f.pin.public_key,"base64url"))).toBe(true);
        expect(verifyRecord(bytes,Buffer.from(sig).toString("base64url"),f.pin,schema)).toBe(false);
      }
    } finally {f.close();}
  });
  it("has no key bytes in result, frame-like requests, logs or sanitized errors", () => {
    const f=fixture(); const seed=decrypt(f.storedIdentity.encrypted_private_key,f.key);
    const logs:string[]=[]; const spies=[vi.spyOn(console,"log"),vi.spyOn(console,"warn"),vi.spyOn(console,"error")].map(spy=>spy.mockImplementation((...args)=>{logs.push(JSON.stringify(args));}));
    try {
      const signer=createRecordSigner(f.grant,f.provider,schema);
      const request={role:f.pin.role,epoch:1,preimage_bytes:f.preimage};
      const result=signer.signRecord(request);
      let error="";
      try {createRecordSigner(f.grant,{sign(){throw new Error(Buffer.from(seed).toString("hex"));}},schema).signRecord(request);}catch(e){error=String(e);}
      const frame=encodeSignerFrame({v:1,protocol:contract.SIGNER_PROTOCOL,request_id:"e".repeat(32),activation_id:f.grant.activation_id,lease_id:f.grant.lease_id,generation:1,epoch:1,role:f.pin.role,deadline_boottime_ns:"1",preimage_length:f.preimage.length},f.preimage);
      const observed=JSON.stringify({request,result,logs,error,frame:Buffer.from(frame).toString("hex"),provider:f.provider});
      for(const secret of [seed,f.key]) for(const representation of [Buffer.from(secret).toString("hex"),Buffer.from(secret).toString("base64"),Buffer.from(secret).toString("base64url"),JSON.stringify([...secret])]) expect(observed.includes(representation)).toBe(false);
      expect(error).toBe("Error: K1_REFUSED"); expect(logs).toEqual([]);
    } finally {seed.fill(0);spies.forEach(spy=>spy.mockRestore());f.close();}
  });
  it("copies grant and encrypted identity and closes permanently", () => {
    const f=fixture(); const signer=createRecordSigner(f.grant,f.provider,schema);
    try {
      f.grant.generation=9; f.storedIdentity.public_key="broken";
      expect(signer.signRecord({role:f.pin.role,epoch:1,preimage_bytes:f.preimage}).kid).toBe(f.pin.kid);
      f.provider.close(); expect(()=>signer.signRecord({role:f.pin.role,epoch:1,preimage_bytes:f.preimage})).toThrow();
    } finally {f.close();}
  });
  it("refuses mismatched seed-derived public key", () => {
    const f=fixture(); const other=fixture();
    try {expect(()=>new EncryptedIdentityProvider({...f.storedIdentity,identity_id:other.pin.identity_id,public_key:other.pin.public_key},f.key,other.pin)).toThrow();}
    finally {f.close();other.close();}
  });
});
