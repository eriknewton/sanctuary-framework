// fail-before-exempt: Native process and terminal absence witnesses use separately rebuilt Rust base binaries; the server-only source swap cannot exercise their enforcement sites.
import { describe,it as test,expect } from "vitest";
// Linux native witnesses require kernel credentials and built harness artifacts.
const it = process.platform === "linux" ? test : test.skip;

import { serviceFixture,deadline } from "../fixtures/k1-service.js";
import { INERT_COUNTER_SCHEMA,INERT_RECORD_KIND } from "../../src/signing/service.js";
import { verifyRecord } from "../../src/signing/strict-verifier.js";
describe("native attended service (Linux only: kernel credentials required)",()=>{
  it("Linux only: PTY unlock signs through K1a and strict verifies, then lock refuses",async()=>{
    const f=await serviceFixture();try{
      expect((await f.client.status()).state).toBe("LOCKED");const code=await f.ceremony();expect(code,JSON.stringify(f.trace)).toBe(0);expect(f.trace.echoed).toBe(false);
      const {g,bytes}=await f.body();const status=await f.client.status();expect(status.state).toBe("UNLOCKED");
      for (const field of ["public_key","kid","identity_id","machine_id","role","epoch"] as const) expect(status.grant[field]).toBe(f.grant[field]);
      const result=await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline());
      expect(verifyRecord(bytes,result.signature,g,INERT_COUNTER_SCHEMA,INERT_RECORD_KIND)).toBe(true);
      expect(await f.ceremony(true)).toBe(0);
      await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");
    }finally{await f.close();}
  },45_000);
  it("Linux only: dead native signer fails the caller closed",async()=>{
    const f=await serviceFixture();try{const {g,bytes}=await f.body();await new Promise<void>(resolve=>{f.service.once("exit",()=>resolve());f.service.kill("SIGKILL");});
      await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).rejects.toThrow("K1_REFUSED");
    }finally{await f.close();}
  },15_000);
});

import {readFileSync,existsSync,readdirSync,readlinkSync} from "node:fs";
it("Linux only: crashed secret worker is reaped into WIPE_UNCONFIRMED",async()=>{
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
it.each(["extra","non-tty","foreign"] as const)("Linux only: ceremony refuses %s descriptors before any factor read",async mode=>{
  const f=await serviceFixture();try{expect(await f.ceremony(mode)).toBe(1);expect(f.trace.promptSeen).toBe(false);expect(f.trace.workerBytes).toBe(0);expect((await f.client.status()).state).toBe("LOCKED");}finally{await f.close();}
},20_000);
it("Linux only: bridge refuses a stream write from another process",async()=>{
  const f=await serviceFixture();try{const result=await f.foreignWrite();expect(result.responded).toBe(false);expect(result.bridgeExit).toBe(1);}finally{await f.close();}
},20_000);
it("Linux only: recovery factor unlocks only through the attended terminal",async()=>{
  const f=await serviceFixture();try{expect(await f.ceremonyRecovery()).toBe(0);expect(f.trace.echoed).toBe(false);const {g,bytes}=await f.body();expect((await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline())).kid).toBe(g.kid);expect(await f.ceremony(true)).toBe(0);}finally{await f.close();}
},20_000);

it("Linux only: bad factor cooperatively wipes and permits a corrected attended retry",async()=>{
  const f=await serviceFixture();try{
    const started=Date.now();expect(await f.ceremony(false,"incorrect factor")).toBe(1);expect(Date.now()-started).toBeLessThan(3000);
    for(let i=0;i<100 && (await f.client.status()).state!=="LOCKED";i++) await new Promise(resolve=>setTimeout(resolve,10));
    expect((await f.client.status()).state).toBe("LOCKED");
    const retry=await f.ceremony();expect(retry,JSON.stringify({state:(await f.client.status()).state,trace:f.trace,ops:f.privateFrames().toString().match(/"op":"[A-Z_]+"/g)})).toBe(0); expect(await f.ceremony(true)).toBe(0);
  }finally{await f.close();}
},45_000);

it("Linux only: forced worker loss survives restart as RECOVERY_REQUIRED",async()=>{
  const f=await serviceFixture();try{
    expect(await f.ceremony()).toBe(0);await f.restart();
    expect((await f.client.status()).state).toBe("RECOVERY_REQUIRED");expect(await f.ceremony()).toBe(1);
  }finally{await f.close();}
},45_000);
it("Linux only: reserved LOCK slot kills an UNLOCKING worker before READY",async()=>{
  const f=await serviceFixture();let ceremony:Promise<number|null>|undefined;try{
    ceremony=f.ceremonyHeld();
    for(let i=0;i<500&&!f.trace.promptSeen;i++)await new Promise(resolve=>setTimeout(resolve,10));
    expect(f.trace.promptSeen).toBe(true);expect((await f.client.status()).state).toBe("UNLOCKING");
    const workerPid=f.workerPid();expect(workerPid).toBeGreaterThan(0);
    // Must match signer_watchdog WATCHDOG_TICK_MS: the bound includes launcher startup and one reap tick.
    const tick=Number(readFileSync("../castle-wall-daemon/src/business_profile/signer_watchdog.rs","utf8").match(/WATCHDOG_TICK_MS: i32 = (\d+)/)![1]);
    const launcherAndReapTicks=150;
    const before=performance.now();expect(await f.lockImmediate()).toBe(0);
    while(performance.now()-before < tick*launcherAndReapTicks){
      try{process.kill(workerPid,0);}catch{break;}
      await new Promise(resolve=>setTimeout(resolve,tick));
    }
    expect(()=>process.kill(workerPid,0)).toThrow();
    expect(performance.now()-before).toBeLessThan(tick*launcherAndReapTicks);
    expect(await ceremony).toBe(1);expect((await f.client.status()).state).toBe("WIPE_UNCONFIRMED");
  }finally{await f.close();await ceremony?.catch(()=>undefined);}
},45_000);
it("Linux only: READY closes the supervisor terminal copy before later lock",async()=>{
  const f=await serviceFixture();try{
    expect(await f.ceremony()).toBe(0);
    const descriptors=readdirSync(`/proc/${f.service.pid}/fd`).map(fd=>{try{return readlinkSync(`/proc/${f.service.pid}/fd/${fd}`);}catch{return "";}});
    expect(descriptors.filter(path=>path === "/dev/tty" || path.startsWith("/dev/pts/"))).toEqual([]);expect(await f.ceremony(true)).toBe(0);
  }finally{await f.close();}
},45_000);
it("Linux only: explicit passphrase mode preserves recovery prefix and supports terminal correction",async()=>{
  const f=await serviceFixture("recovery:");try{expect(await f.ceremonyEdited()).toBe(0);expect(await f.ceremony(true)).toBe(0);}finally{await f.close();}
},45_000);

test.skipIf(process.platform !== "linux" || process.env.SANCTUARY_K1_ROOT_UNIT_DRILL !== "1")("root shipped unit denies writes, network and swap then completes ceremony and sign",async()=>{
  const f=await serviceFixture("fixture ",true);try{
    expect(await f.ceremony()).toBe(0);const {g,bytes}=await f.body();
    const signed=await f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,deadline());
    expect(verifyRecord(bytes,signed.signature,f.grant,INERT_COUNTER_SCHEMA,INERT_RECORD_KIND)).toBe(true);
    expect(await f.ceremony(true)).toBe(0);
  }finally{await f.close();}
},45_000);

it("Linux only: LOCK restores terminal after a worker repeatedly switches raw mode",async()=>{
  const source = `const fs=require('node:fs'); const tty=require('node:tty'); const terminal=new tty.ReadStream(3); terminal.setRawMode(true); fs.writeSync(3,'K1 passphrase:'); setInterval(()=>{terminal.setRawMode(false);terminal.setRawMode(true);},1);`;
  const f=await serviceFixture("fixture ",false,source);let ceremony:Promise<number|null>|undefined;
  try{
    ceremony=f.ceremonyHeld();
    for(let i=0;i<500&&!f.trace.promptSeen;i++)await new Promise(resolve=>setTimeout(resolve,10));
    expect(f.trace.promptSeen).toBe(true);
    expect(await f.ceremony(true)).toBe(0);expect(await ceremony).toBe(1);
    expect(f.trace.terminalRestored).toBe(true);
  }finally{await f.close();await ceremony?.catch(()=>undefined);}
},45_000);

it("Linux only: seeded cleanup and fault frames never launder the durable marker",async()=>{
  const seeds=8;
  for(let seed=0;seed<seeds;seed++){
    const fault = seed % 4;
    const source=`const fs=require('node:fs'); const frame=op=>{const b=Buffer.from(JSON.stringify({op}));const n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([n,b]);}; process.stdin.once('data',()=>{setTimeout(()=>{fs.writeSync(1,Buffer.concat([frame('WIPED'),${fault===0?"frame('WIPED')":fault===1?"frame('FAULT')":fault===2?"Buffer.from([0])":"Buffer.alloc(0)"}])); ${fault===3?"fs.writeSync(2,'fault');":""} process.exit(0);},${seed});});`;
    const f=await serviceFixture("fixture ",false,source);
    try{
      expect(await f.ceremony()).toBe(1);
      expect((await f.client.status()).state).toBe("WIPE_UNCONFIRMED");
      await f.restart();expect((await f.client.status()).state).toBe("RECOVERY_REQUIRED");
    }finally{await f.close();}
  }
},180_000);
it("Linux only: reaping replies to an in-flight signer before the bridge deadline",async()=>{
  const source=`const fs=require('node:fs'); let ready=false; process.stdin.on('data',()=>{if(ready)process.exit(0);ready=true;const body=Buffer.from('{"op":"READY"}');const size=Buffer.alloc(4);size.writeUInt32BE(body.length);fs.writeSync(1,Buffer.concat([size,body]));});`;
  const f=await serviceFixture("fixture ",false,source);
  try{
    expect(await f.ceremony()).toBe(0);const workerPid=f.workerPid();const {g,bytes}=await f.body();const end=deadline();
    const reapBudgetMs=250;
    const before=performance.now();
    await expect(f.client.signRecord({role:g.role,epoch:g.epoch,preimage_bytes:bytes},g,end)).rejects.toThrow("K1_REFUSED");
    expect(performance.now()-before).toBeLessThan(reapBudgetMs);
    expect(()=>process.kill(workerPid,0)).toThrow();
  }finally{await f.close();}
},45_000);
