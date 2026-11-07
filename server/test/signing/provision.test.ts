import {describe,it,expect,vi} from "vitest";
import {randomBytes} from "node:crypto";
import {validateCustodyProfile,validatePassphrase,prepareRoleIdentity,enrollmentKeyAvailable} from "../../src/signing/provision.js";
import {ROLE_REGISTRY} from "../../src/signing/contract.js";
import {createIdentity,rotateKeys} from "../../src/core/identity.js";
import * as encryption from "../../src/core/encryption.js";
import * as random from "../../src/core/random.js";
import type {CustodyEnvelope} from "../../src/core/master-custody.js";
function profile():CustodyEnvelope {
  const payload={v:1,alg:"aes-256-gcm" as const,iv:"",ct:"",ts:""};
  return {v:1,mac:"synthetic authenticated-profile fixture",install_mode:"interactive",created_at:"",wraps:[
    {id:"p",type:"passphrase",verified:true,created_at:"",payload,kdf:{alg:"argon2id",m:65536,t:3,p:4,l:32,salt:randomBytes(32).toString("base64url")}},
    {id:"r",type:"recovery-key",verified:true,created_at:"",payload},
  ]};
}
describe("role preparation predicates",()=>{
  it("accepts the exact authenticated profile",()=>{expect(()=>validateCustodyProfile(profile())).not.toThrow();});
  it.each(["one-wrap","keychain","noninteractive","unverified","memory","time","lanes","length","salt"])("rejects %s profile",kind=>{
    const value=profile();
    if(kind==="one-wrap")value.wraps.pop();
    if(kind==="keychain")value.wraps[1].type="keychain";
    if(kind==="noninteractive")value.install_mode="headless" as CustodyEnvelope["install_mode"];
    if(kind==="unverified")value.wraps[1].verified=false;
    const kdf=value.wraps[0].kdf!;
    if(kind==="memory")kdf.m=32768;if(kind==="time")kdf.t=2;if(kind==="lanes")kdf.p=1;if(kind==="length")kdf.l=16;if(kind==="salt")kdf.salt+="=";
    expect(()=>validateCustodyProfile(value)).toThrow();
  });
  it.each(["short"," ".repeat(24),"x".repeat(24),"long ".repeat(300)])("refuses weak or oversized passphrase",passphrase=>{expect(()=>validatePassphrase(passphrase)).toThrow();});
  it("accepts the bounded passphrase floor without claiming entropy",()=>{expect(()=>validatePassphrase("a synthetic passphrase for fixtures")).not.toThrow();});
  it("prepares dedicated encrypted role identity and denies key reuse",()=>{
    const key=randomBytes(32);
    try {
      const {storedIdentity,pin}=prepareRoleIdentity(ROLE_REGISTRY[0].role,1,"a".repeat(32),key,[],[]);
      expect(storedIdentity.label).toBe("k1-role:"+pin.role);expect(storedIdentity.rotation_history).toEqual([]);
      expect(enrollmentKeyAvailable(pin.public_key,[],[])).toBe(true);
      expect(enrollmentKeyAvailable(pin.public_key,[pin],[])).toBe(false);
      expect(enrollmentKeyAvailable(pin.public_key,[],[pin.public_key])).toBe(false);
      expect(()=>prepareRoleIdentity(pin.role,257,pin.machine_id,key,Array(256).fill(pin),[])).toThrow();
    } finally {key.fill(0);}
  });
  it.each(["create-encrypt","rotate-encrypt","rotate-old-sign"])("wipes generated seed after %s throws",kind=>{
    const key=randomBytes(32);const initial=createIdentity("fixture",key,"passphrase").storedIdentity;
    const seed=randomBytes(32);const rng=vi.spyOn(random,"randomBytes").mockReturnValue(seed);
    const enc=kind==="rotate-old-sign"?undefined:vi.spyOn(encryption,"encrypt").mockImplementation(()=>{throw new Error("synthetic failure");});
    try {
      expect(()=>kind==="create-encrypt"?createIdentity("fixture",key,"passphrase"):rotateKeys(kind==="rotate-old-sign"?{...initial,encrypted_private_key:{...initial.encrypted_private_key,ct:"invalid"}}:initial,key,"fixture")).toThrow();
      expect(seed.every(byte=>byte===0)).toBe(true);
    } finally {rng.mockRestore();enc?.mockRestore();seed.fill(0);key.fill(0);}
  });
});
