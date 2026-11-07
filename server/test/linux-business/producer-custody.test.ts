import {describe,it,expect,vi} from "vitest";
import {randomBytes} from "node:crypto";
import {z} from "zod";
import {encodeSignerFrame,decodeSignerFrame,verifyIndexedRecord,type SignerHeader} from "../../src/linux-business/producer-custody.js";
import {ROLE_REGISTRY,ROLE_SIGNATURE_SCHEME,SIGNER_PROTOCOL,canonicalBytes,safeInteger} from "../../src/signing/contract.js";
import {prepareRoleIdentity} from "../../src/signing/provision.js";
import {EncryptedIdentityProvider} from "../../src/signing/identity-provider.js";
import {createRecordSigner} from "../../src/signing/record-signer.js";
const header:SignerHeader={v:1 as const,protocol:SIGNER_PROTOCOL,request_id:"a".repeat(32),activation_id:"b".repeat(32),lease_id:"c".repeat(32),generation:1,epoch:1,role:ROLE_REGISTRY[0].role,deadline_boottime_ns:"1234",preimage_length:3};
describe("Linux business contract fixtures",()=>{
  it("roundtrips a bounded exact inline frame",()=>{
    const preimage=Buffer.from("abc");const frame=encodeSignerFrame(header,preimage);const decoded=decodeSignerFrame(frame);
    expect(decoded.header).toEqual(header);expect(Buffer.from(decoded.preimage)).toEqual(preimage);
  });
  it.each(["truncated","oversized","header-length","trailing","length-mismatch","unknown"])("refuses %s frame",kind=>{
    let frame=Buffer.from(encodeSignerFrame(header,Buffer.from("abc")));
    if(kind==="truncated")frame=frame.subarray(0,-1);if(kind==="oversized")frame=Buffer.alloc(66565);
    if(kind==="header-length")frame.writeUInt32BE(1025);if(kind==="trailing")frame=Buffer.concat([frame,Buffer.from([0])]);
    if(kind==="length-mismatch")frame=Buffer.from(frame.toString().replace('"preimage_length":3','"preimage_length":2'));
    if(kind==="unknown")expect(()=>encodeSignerFrame({...header,secret:"forbidden"} as typeof header,Buffer.from("abc"))).toThrow();
    else expect(()=>decodeSignerFrame(frame)).toThrow("K1_REFUSED");
  });
  it("checks every signed outer index and verifies without another signature",()=>{
    const key=randomBytes(32);const prepared=prepareRoleIdentity(ROLE_REGISTRY[0].role,1,"a".repeat(32),key,[],[]);
    const provider=new EncryptedIdentityProvider(prepared.storedIdentity,key,prepared.pin);
    const outer={machine_id:prepared.pin.machine_id,boot_id:"d".repeat(32),activation_id:header.activation_id,lease_id:header.lease_id,generation:1,sequence:1,prior_commitment:"GENESIS",captured_at_unix_ms:1,captured_at_boottime_ns:"1"};
    const body={...outer,signature_scheme:ROLE_SIGNATURE_SCHEME,role:prepared.pin.role,record_kind:"append",epoch:1,kid:prepared.pin.kid,identity_id:prepared.pin.identity_id,
      policy_digest:"sha256:"+"a".repeat(64),runtime_digest:"sha256:"+"b".repeat(64),config_digest:"sha256:"+"c".repeat(64),payload:{count:1}};
    const schema=z.object({count:safeInteger}).strict();const bytes=canonicalBytes(body);
    try{
      const signature=createRecordSigner({...prepared.pin,...outer},provider,schema,"append").signRecord({role:prepared.pin.role,epoch:1,preimage_bytes:bytes}).signature;
      const sign=vi.spyOn(provider,"sign");
      expect(verifyIndexedRecord(bytes,signature,prepared.pin,outer,schema,"append")).toBe(true);
      provider.close();expect(verifyIndexedRecord(bytes,signature,prepared.pin,outer,schema,"append")).toBe(true);
      for(const field of Object.keys(outer) as (keyof typeof outer)[])expect(verifyIndexedRecord(bytes,signature,prepared.pin,{...outer,[field]:typeof outer[field]==="number"?2:"different"},schema,"append")).toBe(false);
      expect(verifyIndexedRecord(bytes,signature,{...prepared.pin,role:ROLE_REGISTRY[2].role},outer,schema,"append")).toBe(false);
      expect(sign).not.toHaveBeenCalled();
    }finally{provider.close();key.fill(0);}
  });
});
import {verifyRecord} from "../../src/signing/strict-verifier.js";
it("refuses a correctly signed retrospective record as live indexed evidence", () => {
  const key = randomBytes(32);
  const prepared = prepareRoleIdentity(ROLE_REGISTRY[2].role, 1, "a".repeat(32), key, [], []);
  const provider = new EncryptedIdentityProvider(prepared.storedIdentity, key, prepared.pin);
  const outer = {machine_id: prepared.pin.machine_id, boot_id: "d".repeat(32), activation_id: header.activation_id,
    lease_id: header.lease_id, generation: 1, sequence: 1, prior_commitment: "GENESIS", captured_at_unix_ms: 1, captured_at_boottime_ns: "1"};
  const bytes = canonicalBytes({...outer, signature_scheme: ROLE_SIGNATURE_SCHEME, role: prepared.pin.role, record_kind: "retrospective",
    epoch: 1, kid: prepared.pin.kid, identity_id: prepared.pin.identity_id, policy_digest: "sha256:" + "a".repeat(64),
    runtime_digest: "sha256:" + "b".repeat(64), config_digest: "sha256:" + "c".repeat(64), payload: {signed_at_append: false}});
  const schema = z.object({signed_at_append: z.literal(false)}).strict();
  try {
    const {signature} = createRecordSigner({...prepared.pin, ...outer}, provider, schema, "retrospective")
      .signRecord({role: prepared.pin.role, epoch: 1, preimage_bytes: bytes});
    expect(verifyRecord(bytes, signature, prepared.pin, schema, "retrospective")).toBe(true);
    expect(verifyIndexedRecord(bytes, signature, prepared.pin, outer, schema, "retrospective")).toBe(false);
  } finally { provider.close(); key.fill(0); }
});
