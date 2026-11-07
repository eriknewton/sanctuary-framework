import {describe,it,expect} from "vitest";
import {randomBytes} from "node:crypto";
import {prepareRoleIdentity} from "../../src/signing/provision.js";
import {EncryptedIdentityProvider} from "../../src/signing/identity-provider.js";
import {prepareRotation,verifyRotation,type RotationBody} from "../../src/signing/rotation.js";
import {ROLE_REGISTRY,CUSTODY_SIGNATURE_SCHEME} from "../../src/signing/contract.js";
describe("dual role rotation candidate",()=>{
  it("requires both epochs over identical lifecycle bytes and retains old pins",()=>{
    const oldKey=randomBytes(32),newKey=randomBytes(32);
    const old=prepareRoleIdentity(ROLE_REGISTRY[0].role,1,"a".repeat(32),oldKey,[],[]);
    const next=prepareRoleIdentity(old.pin.role,2,old.pin.machine_id,newKey,[old.pin],[]);
    const before=JSON.stringify(old.pin);
    const a=new EncryptedIdentityProvider(old.storedIdentity,oldKey,old.pin),b=new EncryptedIdentityProvider(next.storedIdentity,newKey,next.pin);
    try {
      const body:RotationBody={v:1,signature_scheme:CUSTODY_SIGNATURE_SCHEME,role:old.pin.role,machine_id:old.pin.machine_id,old_epoch:1,new_epoch:2,
        old_kid:old.pin.kid,new_kid:next.pin.kid,old_descriptor_digest:"sha256:"+"a".repeat(64),new_descriptor_digest:"sha256:"+"b".repeat(64),
        old_terminal_sequence:9,old_terminal_commitment:"sha256:"+"c".repeat(64),transaction_id:"d".repeat(32),reason:"fixture"};
      const signatures=prepareRotation(body,old.pin,next.pin,a,b);
      expect(verifyRotation(body,old.pin,next.pin,signatures)).toBe(true);
      expect(verifyRotation(body,old.pin,next.pin,{...signatures,old_signature:signatures.new_signature})).toBe(false);
      expect(verifyRotation(body,old.pin,next.pin,{...signatures,new_signature:signatures.old_signature})).toBe(false);
      expect(verifyRotation({...body,old_terminal_sequence:10},old.pin,next.pin,signatures)).toBe(false);
      expect(verifyRotation({...body,new_epoch:3},old.pin,next.pin,signatures)).toBe(false);
      expect(JSON.stringify(old.pin)).toBe(before);
    }finally{a.close();b.close();oldKey.fill(0);newKey.fill(0);}
  });
});

import {roleKid} from "../../src/signing/contract.js";
it.each(["skipped epoch", "reused key"])("refuses rotation with %s", kind => {
  const key = randomBytes(32), nextKey = randomBytes(32);
  const old = prepareRoleIdentity(ROLE_REGISTRY[0].role, 1, "a".repeat(32), key, [], []);
  const next = kind === "reused key" ? {...old, pin: {...old.pin, epoch: 2,
    kid: roleKid(old.pin.role, 2, old.pin.public_key)}} :
    prepareRoleIdentity(old.pin.role, 5, old.pin.machine_id, nextKey, [old.pin], []);
  const a = new EncryptedIdentityProvider(old.storedIdentity, key, old.pin);
  const b = new EncryptedIdentityProvider(next.storedIdentity, kind === "reused key" ? key : nextKey, next.pin);
  try {
    const body: RotationBody = {v: 1, signature_scheme: CUSTODY_SIGNATURE_SCHEME, role: old.pin.role,
      machine_id: old.pin.machine_id, old_epoch: 1, new_epoch: next.pin.epoch, old_kid: old.pin.kid, new_kid: next.pin.kid,
      old_descriptor_digest: "sha256:" + "a".repeat(64), new_descriptor_digest: "sha256:" + "b".repeat(64),
      old_terminal_sequence: 1, old_terminal_commitment: "GENESIS", transaction_id: "c".repeat(32), reason: "fixture"};
    expect(() => prepareRotation(body, old.pin, next.pin, a, b)).toThrow("K1_REFUSED");
  } finally { a.close(); b.close(); key.fill(0); nextKey.fill(0); }
});
