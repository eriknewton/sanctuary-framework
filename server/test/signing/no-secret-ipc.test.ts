import { it,expect } from "vitest";
import { serviceFixture,deadline } from "../fixtures/k1-service.js";
it("sentinel keys never occur in any client frame or service log",async()=>{
  const f=await serviceFixture();try{
    const code=await f.ceremony();
    if(code===0){const {g,bytes}=await f.body();await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline());
    await f.ceremony(true);await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");}
    const observed=Buffer.concat([...f.frames,...f.logs,f.privateFrames()]);
    for(const secret of f.secrets){expect(observed.includes(Buffer.from(secret))).toBe(false);for(const repr of [Buffer.from(secret).toString("hex"),Buffer.from(secret).toString("base64"),Buffer.from(secret).toString("base64url"),JSON.stringify([...secret])])expect(observed.includes(Buffer.from(repr))).toBe(false);}
    expect(code).toBe(0);expect(f.logs).toEqual([]);
  }finally{await f.close();}
},45_000);
