import {describe,it,expect} from "vitest";
import {readFileSync,readdirSync} from "node:fs";
import {resolve,join} from "node:path";
import {fileURLToPath} from "node:url";
import {execFileSync} from "node:child_process";
import {ROLE_REGISTRY,COMMON_FIELDS,LINUX_FIELDS,PRODUCER_DESCRIPTOR_DOMAIN,PRODUCER_ROTATION_DOMAIN,UNLOCK_CHALLENGE_DOMAIN} from "../../src/signing/contract.js";
import {K1_SIGNING_DOMAIN_PREFIXES} from "../../src/core/signing-domains.js";
const root=resolve(fileURLToPath(import.meta.url),"../../../..");
describe("isolated K1 boundaries",()=>{
  it("generated Rust matches the full TS role, schema and constant sets",()=>{
    expect(()=>execFileSync(process.execPath,[join(root,"scripts/generate-record-signer-contract.mjs"),"--check"])).not.toThrow();
    const rust=readFileSync(join(root,"castle-wall-daemon/src/business_profile/signer_contract.rs"),"utf8");
    const rows=[...rust.matchAll(/\("([^"]+)", "([^"]+)", (\d+)\)/g)].map(match=>({role:match[1],domain:JSON.parse('"'+match[2]+'"'),envelope_max_bytes:Number(match[3])}));
    expect(rows).toEqual(ROLE_REGISTRY);
    for(const name of ["COMMON_FIELDS","LINUX_FIELDS"]){const found=rust.match(new RegExp('pub const '+name+': &\\[&str\\] = &('+'\\[[^;]+\\]'+');'));
      expect(found).not.toBeNull();expect(JSON.parse(found![1])).toEqual(name==="COMMON_FIELDS"?COMMON_FIELDS:LINUX_FIELDS);}
  });
  it("refusal registry covers every role and lifecycle domain",()=>{
    expect([...K1_SIGNING_DOMAIN_PREFIXES].sort()).toEqual([...ROLE_REGISTRY.map(row=>row.domain),PRODUCER_DESCRIPTOR_DOMAIN,PRODUCER_ROTATION_DOMAIN,UNLOCK_CHALLENGE_DOMAIN].sort());
  });
  it("contract is unwired and imports no raw loader or operator resolver",()=>{
    const paths=["server/src/signing","server/src/linux-business"];
    const source=paths.flatMap(path=>readdirSync(join(root,path)).filter(name=>name.endsWith(".ts")).map(name=>readFileSync(join(root,path,name),"utf8"))).join("\n");
    for(const forbidden of ["load_or_generate","from_signing_key","IdentityManager","getDefault(","node:net","node:child_process","console.","process.env"]) {
      const code=source.split("\n").filter(line=>!line.trimStart().startsWith("//")&&!line.trimStart().startsWith("/**")).join("\n");expect(code).not.toContain(forbidden);
    }
    for(const path of ["castle-wall-daemon/src/main.rs","castle-wall-daemon/src/daemon.rs"]){expect(readFileSync(join(root,path),"utf8")).not.toContain("business_profile");}
    const tsup=readFileSync(join(root,"server/tsup.config.ts"),"utf8");expect(tsup).not.toContain("signing/");
  });
});
