import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { z } from "zod";
import { ed25519 } from "@noble/curves/ed25519";
import { BUSINESS_SCHEMA_AST, BUSINESS_SCHEMA_DIGEST, BUSINESS_KINDS, validateBusinessRecord } from "../../src/signing/linux-business-records.js";
import { canonicalBytes, parseRecord, recordMessage, roleKid, ROLE_REGISTRY } from "../../src/signing/contract.js";
import { verifyRecord } from "../../src/signing/strict-verifier.js";
import { createRecordSigner } from "../../src/signing/record-signer.js";
import { businessBodies } from "../fixtures/k1-service.js";

const bodies = businessBodies();
const role = ROLE_REGISTRY[0].role;
describe("generated business schema", () => {
  it("pins the full AST, source bytes, digest and all seven kinds", () => {
    const bytes = readFileSync("src/signing/linux-business-records.schema.json");
    expect(JSON.parse(bytes.toString())).toEqual(BUSINESS_SCHEMA_AST);
    expect(readFileSync("../castle-wall-daemon/src/business_profile/records_schema.json")).toEqual(bytes);
    expect(BUSINESS_SCHEMA_DIGEST).toBe("sha256:" + createHash("sha256").update(bytes).digest("hex"));
    expect([...new Set(bodies.map(b => b.record_kind))]).toEqual(BUSINESS_KINDS);
  });
  it.each(bodies.map((body,index)=>({body,index})))("accepts and verifies strict branch $index", ({body}) => {
    expect(validateBusinessRecord(body)).toBe(true);
    const seed = new Uint8Array(32).fill(7), public_key = Buffer.from(ed25519.getPublicKey(seed)).toString("base64url");
    const pin = {role,epoch:1,public_key,kid:roleKid(role,1,public_key),identity_id:body.identity_id as string,machine_id:body.machine_id as string};
    const signed: Record<string, unknown> = {...body, ...pin}; delete signed.public_key;
    const bytes = canonicalBytes(signed), signature = Buffer.from(ed25519.sign(recordMessage(role,bytes),seed)).toString("base64url");
    expect(verifyRecord(bytes,signature,pin,z.unknown(),body.record_kind as string)).toBe(true);
    expect(verifyRecord(canonicalBytes({...signed,payload:{...(signed.payload as object),extra:true}}),signature,pin,z.unknown(),body.record_kind as string)).toBe(false);
  });
  it.each(["eq", "le", "reverse_tuple", "address_family"])("enforces the %s branch predicate", op => {
    const body = structuredClone(bodies.find(b => b.record_kind === (op === "le" ? "allowance" : "open"))!);
    const p = body.payload as {context:{flow:{machine_id:string};original:{family:string;src_ip:string};reply:{src_ip:string}};expires_ns:string};
    if(op === "eq") p.context.flow.machine_id = "c".repeat(32);
    if(op === "le") p.expires_ns = "0";
    if(op === "reverse_tuple") p.context.reply.src_ip = "192.0.2.2";
    if(op === "address_family") { p.context.original.src_ip = "2001:db8::1"; (p.context.reply as Record<string,string>).dst_ip = "2001:db8::1"; }
    expect(validateBusinessRecord(body)).toBe(false);
    expect(() => parseRecord(canonicalBytes(body),role,z.unknown(),body.record_kind as string)).toThrow("K1_REFUSED");
  });
  it("rejects nested extra keys, unsafe integers, noncanonical addresses and u64 overflow", () => {
    const base = bodies.find(b=>b.record_kind==="open")!;
    const change = (path: string, value: unknown) => {const b=structuredClone(base);let o=b;const keys=path.split('.');for(const k of keys.slice(0,-1))o=o[k] as Record<string,unknown>;o[keys.at(-1)!]=value;return b;};
    for(const [path,value] of [["payload.context.flow.extra",true],["sequence",Number.MAX_SAFE_INTEGER+1],["payload.context.socket_cookie","18446744073709551616"],["payload.context.original.src_ip","192.000.2.1"]] as const) expect(validateBusinessRecord(change(path,value))).toBe(false);
  });
  it("business constructors refuse before the provider while inert count continues", () => {
    let calls=0;
    const seed=new Uint8Array(32).fill(7), public_key=Buffer.from(ed25519.getPublicKey(seed)).toString("base64url");
    const grant={role,epoch:1,public_key,kid:roleKid(role,1,public_key),identity_id:"a".repeat(32),machine_id:"a".repeat(32),activation_id:"a".repeat(32),lease_id:"a".repeat(32),generation:0};
    const provider={sign(message:Uint8Array){calls++;return ed25519.sign(message,seed);}};
    for(const kind of BUSINESS_KINDS.filter(k=>k!=="counter")) expect(()=>createRecordSigner(grant,provider,z.unknown(),kind)).toThrow("K1_REFUSED");
    const signer=createRecordSigner(grant,provider,z.unknown(),"counter");
    const business={...bodies.find(b=>b.record_kind==="counter")!,kid:grant.kid};
    expect(()=>signer.signRecord({role,epoch:1,preimage_bytes:canonicalBytes(business)})).toThrow("K1_REFUSED");
    expect(calls).toBe(0);
    const inert={...business,payload:{count:1}};
    expect(signer.signRecord({role,epoch:1,preimage_bytes:canonicalBytes(inert)}).kid).toBe(grant.kid);
    expect(calls).toBe(1);
  });
});
