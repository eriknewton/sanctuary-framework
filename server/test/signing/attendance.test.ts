import { describe,it,expect } from "vitest";
import { serviceFixture,deadline } from "../fixtures/k1-service.js";
import { INERT_COUNTER_SCHEMA,INERT_RECORD_KIND } from "../../src/signing/service.js";
import { verifyRecord } from "../../src/signing/strict-verifier.js";
describe("native attended service",()=>{
  it("PTY unlock signs through K1a and strict verifies, then lock refuses",async()=>{
    const f=await serviceFixture();try{
      expect((await f.client.status()).state).toBe("LOCKED");const code=await f.ceremony();expect(code,JSON.stringify(f.trace)).toBe(0);expect(f.trace.echoed).toBe(false);
      const {g,bytes}=await f.body();const status=await f.client.status();expect(status.state).toBe("UNLOCKED");
      const result=await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline());
      expect(verifyRecord(bytes,result.signature,g,INERT_COUNTER_SCHEMA,INERT_RECORD_KIND)).toBe(true);
      expect(await f.ceremony(true)).toBe(0);
      await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");
    }finally{await f.close();}
  },45_000);
  it("dead native signer fails the caller closed",async()=>{
    const f=await serviceFixture();try{const {g,bytes}=await f.body();await new Promise<void>(resolve=>{f.service.once("exit",()=>resolve());f.service.kill("SIGKILL");});
      await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");
    }finally{await f.close();}
  },15_000);
});

import {readFileSync,existsSync} from "node:fs";
it("crashed secret worker is reaped into WIPE_UNCONFIRMED",async()=>{
  const f=await serviceFixture();try{
    expect(await f.ceremony()).toBe(0);const {g,bytes}=await f.body();
    const children=readFileSync(`/proc/${f.service.pid}/task/${f.service.pid}/children`,"utf8").trim().split(/\s+/).map(Number);
    expect(children).toHaveLength(1);process.kill(children[0],"SIGKILL");
    let state="UNLOCKED";
    for(let i=0;i<50&&state!=="WIPE_UNCONFIRMED";i++){await new Promise(resolve=>setTimeout(resolve,20));state=(await f.client.status()).state;}
    expect(state).toBe("WIPE_UNCONFIRMED");expect(existsSync(`/proc/${children[0]}`)).toBe(false);
    await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");
  }finally{await f.close();}
},45_000);
it.each(["extra","non-tty","foreign"] as const)("ceremony refuses %s descriptors before any factor read",async mode=>{
  const f=await serviceFixture();try{expect(await f.ceremony(mode)).toBe(1);expect(f.trace.promptSeen).toBe(false);expect(f.trace.workerBytes).toBe(0);expect((await f.client.status()).state).toBe("LOCKED");}finally{await f.close();}
},20_000);
it("bridge refuses a stream write from another process",async()=>{
  const f=await serviceFixture();try{const result=await f.foreignWrite();expect(result.responded).toBe(false);expect(result.bridgeExit).toBe(1);}finally{await f.close();}
},20_000);
it("recovery factor unlocks only through the attended terminal",async()=>{
  const f=await serviceFixture();try{expect(await f.ceremonyRecovery()).toBe(0);expect(f.trace.echoed).toBe(false);const {g,bytes}=await f.body();expect((await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).kid).toBe(g.kid);expect(await f.ceremony(true)).toBe(0);}finally{await f.close();}
},20_000);
