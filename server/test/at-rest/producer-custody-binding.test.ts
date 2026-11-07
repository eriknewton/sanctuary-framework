import {describe,it,expect} from "vitest";
import {gcm} from "@noble/ciphers/aes.js";
import {randomBytes} from "node:crypto";
import {mkdtemp,writeFile,readFile,unlink,rmdir} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {encryptBinding,decryptBinding,type CustodyBinding} from "../../src/signing/binding-store.js";
import {ROLE_REGISTRY,canonicalBytes,PRODUCER_CUSTODY_BINDING_AAD} from "../../src/signing/contract.js";
import {derivePurposeKey} from "../../src/core/key-derivation.js";
import {encrypt,decrypt} from "../../src/core/encryption.js";
const context={fortress_id:"a".repeat(32),machine_id:"b".repeat(32),role:ROLE_REGISTRY[0].role};
const binding:CustodyBinding={identity_id:"c".repeat(32),role:context.role,machine_id:context.machine_id,epoch:1,kid:"k1:sha256:"+"d".repeat(64),roster_digest:"sha256:"+"e".repeat(64),high_water:9,transaction_state:"LOCKED"};
describe("producer custody binding codec",()=>{
  it("decrypts retained ciphertext with the exact purpose and AAD after reopening",async()=>{
    const root=await mkdtemp(join(tmpdir(),"k1-"));const file=join(root,"binding.enc");const master=randomBytes(32);
    try {
      const referenceKey=derivePurposeKey(master,"producer-custody-binding-v1");
      try {
        // Independent writer pins the retained codec even if the implementation changes both its writer and reader.
        const referenceAad=Buffer.concat([Buffer.from("sanctuary.producer-custody.binding.v1\n"),canonicalBytes(context)]);
        const envelope=encrypt(canonicalBytes(binding),referenceKey,referenceAad);
        await writeFile(file,JSON.stringify(envelope),{mode:0o600});
        expect(decrypt(encryptBinding(binding,master,context),referenceKey,referenceAad)).toEqual(canonicalBytes(binding));
      } finally {referenceKey.fill(0);}
      const reopened=JSON.parse(await readFile(file,"utf8"));expect(decryptBinding(reopened,master,context)).toEqual(binding);
      const wrong=derivePurposeKey(master,"identity-encryption");try{expect(()=>decrypt(reopened,wrong)).toThrow();}finally{wrong.fill(0);}
    }finally{master.fill(0);await unlink(file).catch(()=>{});await rmdir(root);}
  });
  it.each(["tag","iv","encoding","aad-fortress","aad-machine","aad-role","missing-aad"])("refuses independent %s mutation",kind=>{
    const master=randomBytes(32);
    try {
      const encrypted=encryptBinding(binding,master,context);const changed={...encrypted};let ctx={...context};
      if(kind==="tag")changed.ct=Buffer.from(randomBytes(Buffer.from(changed.ct,"base64url").length)).toString("base64url");
      if(kind==="iv") {
        const iv=randomBytes(16); const key=derivePurposeKey(master,"producer-custody-binding-v1");
        try {changed.iv=iv.toString("base64url");changed.ct=Buffer.from(gcm(key,iv,Buffer.concat([Buffer.from(PRODUCER_CUSTODY_BINDING_AAD),canonicalBytes(context)])).encrypt(canonicalBytes(binding))).toString("base64url");}
        finally {key.fill(0);}
      }if(kind==="encoding")changed.iv+="=";
      if(kind==="aad-fortress")ctx.fortress_id="f".repeat(32);if(kind==="aad-machine")ctx.machine_id="f".repeat(32);
      if(kind==="aad-role")ctx={...ctx,role:ROLE_REGISTRY[1].role as typeof context.role};
      if(kind==="missing-aad") {const key=derivePurposeKey(master,"producer-custody-binding-v1");try{expect(()=>decrypt(encrypted,key)).toThrow();}finally{key.fill(0);}}
      else expect(()=>decryptBinding(changed,master,ctx)).toThrow("K1_REFUSED");
      expect(decryptBinding(encrypted,master,context)).toEqual(binding);
    }finally{master.fill(0);}
  });
});
