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

// Must match closure_vectors.json and linux_business_schema.rs: every shared body executes with its original id.
type ClosureBody = Record<string, unknown> & {identity_id: string; machine_id: string; activation_id: string; lease_id: string; generation: number; record_kind: string};
const closure = JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/closure_vectors.json", "utf8")) as {
  schema: Array<{id: string; body: ClosureBody; accept: boolean}>;
  verify: Array<{id: string; body: ClosureBody; pin_change: Partial<ClosureBody>; accept: boolean}>;
  coverage: string[];
};
it("shared schema corpus has complete unique ids", () => {
  for (const group of [closure.schema, closure.verify]) expect([...new Set(group.map(c => c.id))].sort()).toEqual(group.map(c => c.id).sort());
});
it.each(closure.schema)("closure schema $id", c => {
  expect(validateBusinessRecord(c.body)).toBe(c.accept);
  const seed = new Uint8Array(32).fill(7), public_key = Buffer.from(ed25519.getPublicKey(seed)).toString("base64url");
  const pin = {role, epoch: 1, public_key, kid: roleKid(role, 1, public_key), identity_id: c.body.identity_id, machine_id: c.body.machine_id};
  const body = {...c.body, kid: pin.kid};
  const bytes = canonicalBytes(body), signature = Buffer.from(ed25519.sign(recordMessage(role, bytes), seed)).toString("base64url");
  expect(verifyRecord(bytes, signature, pin, z.unknown(), body.record_kind)).toBe(c.accept);
});

it.each(closure.verify)("closure signing pin $id", c => {
  const seed = new Uint8Array(32).fill(7), public_key = Buffer.from(ed25519.getPublicKey(seed)).toString("base64url");
  const grant = {role, epoch: 1, public_key, kid: roleKid(role, 1, public_key), identity_id: c.body.identity_id, machine_id: c.body.machine_id, activation_id: c.body.activation_id, lease_id: c.body.lease_id, generation: c.body.generation, ...c.pin_change};
  const signer = createRecordSigner(grant, {sign: message => ed25519.sign(message, seed)}, z.unknown(), "counter");
  const bytes = canonicalBytes({...c.body, record_kind: "counter", payload: {count: 1}, kid: grant.kid});
  if (c.accept) expect(signer.signRecord({role, epoch: 1, preimage_bytes: bytes}).kid).toBe(grant.kid);
  else expect(() => signer.signRecord({role, epoch: 1, preimage_bytes: bytes})).toThrow("K1_REFUSED");
});

import {execFileSync} from "node:child_process";
import {mkdtempSync, writeFileSync, unlinkSync, rmdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
const generatorVectors = JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/generator_vectors.json", "utf8")) as {
  cases: Array<{id: string; changes: Array<{path: Array<string | number>; value: unknown}>}>;
};
it.each(generatorVectors.cases)("generator refuses $id", c => {
  const source = JSON.parse(readFileSync("src/signing/linux-business-records.schema.json", "utf8"));
  for (const change of c.changes) {
    let target = source;
    for (const key of change.path.slice(0, -1)) target = target[key];
    target[change.path.at(-1)!] = change.value;
  }
  const directory = mkdtempSync(join(tmpdir(), "k1-schema-")), path = join(directory, "schema.json");
  try {
    writeFileSync(path, JSON.stringify(source));
    let error = "";
    try { execFileSync(process.execPath, [resolve("../scripts/generate-record-signer-contract.mjs"), "--check", "--validate-schema", path], {stdio: "pipe"}); }
    catch (failure) { error = String((failure as {stderr: Buffer}).stderr); }
    expect(error).toContain("BUSINESS_SCHEMA_REFUSED");
    expect(error).not.toContain("generated bytes");
  } finally { unlinkSync(path); rmdirSync(directory); }
});

it("shared positive bodies cover the full nested choice set", () => {
  // Must match linux_business_schema.rs: coverage is derived from the schema and the accepted bodies, never a constraint list.
  const schema = JSON.parse(readFileSync("src/signing/linux-business-records.schema.json", "utf8"));
  type Node = {type: string; name: string; value: unknown; values: unknown[]; branches: Node[]; fields: Record<string, Node>; encoding: string};
  function fits(n: Node, v: unknown): boolean {
    if (n.type === "ref") return fits(schema.definitions[n.name], v);
    if (n.type === "literal") return n.value === v;
    if (n.type === "enum") return n.values.includes(v);
    if (n.type === "union") return n.branches.some(b => fits(b, v));
    if (n.type === "object") return v !== null && typeof v === "object" && Object.entries(n.fields).every(([k,b]) => fits(b, (v as Record<string, unknown>)[k]));
    if (n.type === "integer") return typeof v === "number";
    if (typeof v !== "string") return false;
    if (n.encoding === "ipv4") return v.includes(".");
    if (n.encoding === "ipv6") return v.includes(":");
    if (n.encoding === "digest") return v.startsWith("sha256:");
    return true;
  }
  function walk(n: Node, path: string, target: Set<string>, value?: unknown, all = false) {
    if (n.type === "ref") return walk(schema.definitions[n.name], "definitions." + n.name, target, value, all);
    if (n.type === "enum") n.values.forEach((v,i) => {if (all || v === value) target.add(path + ":" + i);});
    if (n.type === "union") n.branches.forEach((b,i) => {if (all || fits(b,value)) {target.add(path + ":" + i); walk(b, path + ".branches." + i, target, value, all);}});
    if (n.type === "object") for (const [k,b] of Object.entries(n.fields)) walk(b, path + ".fields." + k, target, (value as Record<string,unknown> | undefined)?.[k], all);
  }
  const expected = new Set<string>(), actual = new Set<string>();
  walk(schema.record, "record", expected, undefined, true);
  for (const c of closure.schema.filter((c: {accept: boolean}) => c.accept)) walk(schema.record, "record", actual, c.body);
  expect([...actual].sort()).toEqual([...expected].sort());
  expect([...actual].sort()).toEqual(closure.coverage);
});
