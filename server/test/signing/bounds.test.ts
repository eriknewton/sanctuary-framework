// fail-before-exempt: the STATUS corpus and relay parser are new; existing frame and worker checks are regressions.
import {it,expect} from "vitest";
import {publicFrame,parsePublicFrame,RESPONSE_MAX_BYTES} from "../../src/signing/service.js";
it("public response cap precedes allocation",()=>{expect(()=>publicFrame({op:"x".repeat(RESPONSE_MAX_BYTES)})).toThrow("K1_REFUSED");expect(parsePublicFrame(publicFrame({op:"READY"}))).toEqual({op:"READY"});});
it("truncated, duplicate and noncanonical public responses refuse",()=>{
  for(const body of ['{"op":"READY","op":"READY"}','{ "op":"READY"}']){const b=Buffer.from(body),size=Buffer.alloc(4);size.writeUInt32BE(b.length);expect(()=>parsePublicFrame(Buffer.concat([size,b]))).toThrow();}
  expect(()=>parsePublicFrame(publicFrame({op:"READY"}).subarray(1))).toThrow();
});

import {vi} from "vitest";
import {randomBytes,createHash} from "node:crypto";
import {workerSigner} from "../../src/signing/service.js";
import {prepareRoleIdentity} from "../../src/signing/provision.js";
import {EncryptedIdentityProvider} from "../../src/signing/identity-provider.js";
import {ROLE_REGISTRY,UNLOCK_CHALLENGE_DOMAIN,canonicalBytes} from "../../src/signing/contract.js";
it.skipIf(process.platform!=="linux")("Linux only: worker self-test names the digest of its actual grant",()=>{
  const key=randomBytes(32);const prepared=prepareRoleIdentity(ROLE_REGISTRY[0].role,1,"a".repeat(32),key,[],[]);
  const grant={...prepared.pin,activation_id:"b".repeat(32),lease_id:"c".repeat(32),generation:1};
  const sign=vi.spyOn(EncryptedIdentityProvider.prototype,"sign");let signer:ReturnType<typeof workerSigner>|undefined;
  try{
    signer=workerSigner(prepared.storedIdentity,key,grant,"1");
    const body=JSON.parse(Buffer.from(sign.mock.calls[0][0]).subarray(Buffer.byteLength(UNLOCK_CHALLENGE_DOMAIN)).toString());
    expect(body.grant_digest).toBe("sha256:"+createHash("sha256").update(canonicalBytes(grant)).digest("hex"));expect(body).not.toHaveProperty("descriptor_digest");
  }finally{signer?.close();sign.mockRestore();key.fill(0);}
});

import {parseStatusPacket, statusCorpus} from "../fixtures/k1-relay-client.js";
it.each(statusCorpus.cases)("STATUS packet $id follows the shared runtime schema", row => {
  const parse = () => parseStatusPacket(Buffer.from(row.packet_hex,"hex"));
  if (row.accept) expect(parse).not.toThrow(); else expect(parse).toThrow("K1_REFUSED");
});
it("STATUS corpus runs its complete unique case set", () => {
  const observed = statusCorpus.cases.map(row => {
    let accept = false;
    try { parseStatusPacket(Buffer.from(row.packet_hex,"hex")); accept = true; } catch { /* A refusal is the observed corpus outcome. */ }
    return [row.id, accept];
  });
  expect(new Set(statusCorpus.cases.map(row => row.id)).size).toBe(statusCorpus.cases.length);
  expect(observed).toEqual(statusCorpus.cases.map(row => [row.id,row.accept]));
});
