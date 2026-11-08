import {describe,it,expect} from "vitest";
import {readFileSync,readdirSync} from "node:fs";
import {resolve,join} from "node:path";
import {fileURLToPath} from "node:url";
import {execFileSync} from "node:child_process";
import {assertAdmissibleIdentityLabel} from "../../src/signing/reserved-label.js";
import {ROLE_REGISTRY,COMMON_FIELDS,LINUX_FIELDS,PRODUCER_DESCRIPTOR_DOMAIN,PRODUCER_ROTATION_DOMAIN,UNLOCK_CHALLENGE_DOMAIN} from "../../src/signing/contract.js";
import {K1_SIGNING_DOMAIN_PREFIXES} from "../../src/core/signing-domains.js";
const root=resolve(fileURLToPath(import.meta.url),"../../../..");
describe("isolated K1 boundaries",()=>{
  it("generated Rust matches the full TS role, schema and constant sets",()=>{
    expect(()=>execFileSync(process.execPath,[join(root,"scripts/generate-record-signer-contract.mjs"),"--check"])).not.toThrow();
    const rust=readFileSync(join(root,"castle-wall-daemon/src/business_profile/signer_contract.rs"),"utf8");
    const rows=[...rust.matchAll(/\("([^"]+)", "([^"]+)", (\d+)\)/g)].map(match=>({role:match[1],domain:JSON.parse('"'+match[2]+'"'),envelope_max_bytes:Number(match[3])}));
    expect(ROLE_REGISTRY.every(row => Object.isFrozen(row.record_kinds))).toBe(true);
    expect(rows).toEqual(ROLE_REGISTRY.map(({role,domain,envelope_max_bytes})=>({role,domain,envelope_max_bytes})));
    const kinds=[...rust.matchAll(/\("([^\"]+)", &\[([^\]]+)\]\)/g)].map(match=>({role:match[1],record_kinds:JSON.parse("["+match[2]+"]")}));
    expect(kinds).toEqual(ROLE_REGISTRY.map(({role,record_kinds})=>({role,record_kinds})));
    for(const name of ["COMMON_FIELDS","LINUX_FIELDS"]){const found=rust.match(new RegExp('pub const '+name+': &\\[&str\\] = &('+'\\[[^;]+\\]'+');'));
      expect(found).not.toBeNull();expect(JSON.parse(found![1])).toEqual(name==="COMMON_FIELDS"?COMMON_FIELDS:LINUX_FIELDS);}
  });
  it("refusal registry covers every role and lifecycle domain",()=>{
    expect([...K1_SIGNING_DOMAIN_PREFIXES].sort()).toEqual([...ROLE_REGISTRY.map(row=>row.domain),PRODUCER_DESCRIPTOR_DOMAIN,PRODUCER_ROTATION_DOMAIN,UNLOCK_CHALLENGE_DOMAIN].sort());
  });
  it("contract is unwired and imports no raw loader or operator resolver",()=>{
    const paths=["server/src/signing","server/src/linux-business"];
    const source=paths.flatMap(path=>readdirSync(join(root,path)).filter(name=>name.endsWith(".ts")).map(name=>readFileSync(join(root,path,name),"utf8"))).join("\n");
    for(const forbidden of ["load_or_generate","from_signing_key","IdentityManager","getDefault(","node:net","console.","process.env"]) {
      const code=source.split("\n").filter(line=>!line.trimStart().startsWith("//")&&!line.trimStart().startsWith("/**")).join("\n");expect(code).not.toContain(forbidden);
    }
    for (const name of readdirSync(join(root,"server/src/signing")).filter(name => name.endsWith(".ts") && name !== "service.ts"))
      expect(readFileSync(join(root,"server/src/signing",name),"utf8")).not.toContain("node:child_process");
    for(const path of ["castle-wall-daemon/src/main.rs","castle-wall-daemon/src/daemon.rs"]){expect(readFileSync(join(root,path),"utf8")).not.toContain("business_profile");}
    const tsup=readFileSync(join(root,"server/tsup.config.ts"),"utf8");expect(tsup).toContain('entryPoints: ["src/signing/worker.ts"]');
  });
});

import * as runtimeContract from "../../src/signing/contract.js";
import * as signingBarrel from "../../src/signing/index.js";
it("keeps the raw provider private to its implementation module", () => {
  expect(signingBarrel).not.toHaveProperty("EncryptedIdentityProvider");
  const sourceRoot = join(root, "server/src");
  const importers = readdirSync(sourceRoot, {recursive: true}).filter((name): name is string => typeof name === "string" && name.endsWith(".ts"))
    .filter(name => /from\s+["'][^"']*identity-provider\.js["']/.test(readFileSync(join(sourceRoot, name), "utf8")));
  expect(importers.filter(name => !["signing/record-signer.ts", "signing/rotation.ts", "signing/lifecycle.ts", "signing/service.ts"].includes(name))).toEqual([]);
});
it("keeps the pure contract portable and agent launch Linux only", () => {
  const source = readFileSync(join(root, "castle-wall-daemon/src/lib.rs"), "utf8");
  expect(source).toMatch(/#\[cfg\(target_os = "linux"\)\]\s*pub mod agent_launch;/);
  expect(source).not.toMatch(/#\[cfg\(target_os = "linux"\)\]\s*[^;]*pub mod business_profile;/);
});
it("pins every evaluated primitive including a derived frame bound", () => {
  const rust = readFileSync(join(root, "castle-wall-daemon/src/business_profile/signer_contract.rs"), "utf8");
  const actual = Object.fromEntries([...rust.matchAll(/pub const ([A-Z_0-9]+): (?:&str|usize) = (.*);/g)]
    .map(([, name, value]) => [name, JSON.parse(value)]));
  const expected = Object.fromEntries(Object.entries(runtimeContract).filter(([, value]) => typeof value === "string" || typeof value === "number"));
  expect(actual).toEqual(expected);
  expect(readFileSync(join(root, "server/src/signing/contract.ts"), "utf8")).toContain("SIGNER_HEADER_MAX_BYTES + SIGNER_PREIMAGE_MAX_BYTES + 4");
});
// Must match castle-wall-daemon/src/business_profile/pinned_kid.txt, which the Rust PINNED_KID in mod.rs includes and checks against role_kid over the same inputs.
const PINNED_KID_VECTOR = {role: ROLE_REGISTRY[0].role, epoch: 2, public_key: Buffer.alloc(32, 7).toString("base64url"),
  kid: "k1:sha256:e09fa5a1f32e54219ade30b8ee6b5cb8367089d6a6aedfad3bf8c875b08fb411"};
it("evaluates the pinned canonical kid vector shared with Rust and keeps vectors crate-local", () => {
  expect(runtimeContract.roleKid(PINNED_KID_VECTOR.role, PINNED_KID_VECTOR.epoch, PINNED_KID_VECTOR.public_key)).toBe(PINNED_KID_VECTOR.kid);
  const source = readFileSync(join(root, "castle-wall-daemon/src/business_profile/mod.rs"), "utf8");
  // The Rust test compares its executed role_kid with these exact file bytes through include_str!, so reading the file,
  // never parsing Rust source text, ties both languages to one value that a comment cannot hide or replace.
  expect(readFileSync(join(root, "castle-wall-daemon/src/business_profile/pinned_kid.txt"), "utf8")).toBe(PINNED_KID_VECTOR.kid);
  expect(source).not.toContain("../../../server/");
});
it("keeps every K1 signing domain prefix-free so a domain match cannot select the wrong lifecycle body", () => {
  const domains = [...K1_SIGNING_DOMAIN_PREFIXES];
  for (const a of domains) for (const b of domains) if (a !== b) expect(b.startsWith(a)).toBe(false);
});

it("refuses a non-string label at admission instead of skipping the reserved-prefix check", () => {
  for (const bad of [undefined, null, 7, {toString: () => "k1-role:x"}, new String("k1-role:x")]) expect(() => assertAdmissibleIdentityLabel(bad)).toThrow("K1_ROLE_IDENTITY_REFUSED");
  expect(() => assertAdmissibleIdentityLabel("operator")).not.toThrow();
});

it("keeps the reserved role label literal in its one shared helper", () => {
  const sourceRoot = join(root, "server/src");
  const users = readdirSync(sourceRoot, {recursive: true}).filter((name): name is string => typeof name === "string" && name.endsWith(".ts"))
    .filter(name => readFileSync(join(sourceRoot, name), "utf8").includes('"k1-role:"'));
  expect(users).toEqual(["signing/reserved-label.ts"]);
});

it("documents the message bound and scalar and signature derivations", () => {
  const contract = readFileSync(join(root, "server/src/signing/contract.ts"), "utf8");
  expect(contract).toContain("SIGNER_PREIMAGE_MAX_BYTES + SIGNER_DOMAIN_MAX_BYTES");
  expect(contract).toContain("ceil(64 * 8 / 6) = 86");
  expect(readFileSync(join(root, "server/src/signing/strict-verifier.ts"), "utf8")).toContain("2^252 + 27742317777372353535851937790883648493");
});
