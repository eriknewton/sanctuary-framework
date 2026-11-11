// fail-before-exempt: the native client entrypoint is new.
import {it,expect} from "vitest";
import {readFileSync} from "node:fs";
import {serviceFixture} from "../fixtures/k1-service.js";
it.skipIf(process.platform !== "linux")("native client authenticates the real signer and returns its typed STATUS",async()=>{
  const fixture=await serviceFixture();
  try {
    const status=await fixture.probeClient();
    expect(status).toEqual({...await fixture.freshClient(),boot_id:readFileSync("/proc/sys/kernel/random/boot_id","utf8").trim().replaceAll("-","")});
    expect(status).toMatchObject({state:"LOCKED",started_boottime_ns:"0",expires_boottime_ns:"0",anchor_revision:null,anchor_digest:null});
  }finally{await fixture.close();}
});
