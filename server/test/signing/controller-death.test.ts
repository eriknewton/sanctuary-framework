// fail-before-exempt: controller-death reaping already exists; the relay fixture is new.
import {it,expect} from "vitest";
import {existsSync} from "node:fs";
import {serviceFixture} from "../fixtures/k1-service.js";
import {SIGNER_IDLE_DEADLINE_MS} from "../../src/signing/contract.js";
const CONTROLLER_DEATH_WINDOW_MS=SIGNER_IDLE_DEADLINE_MS/2; // Shorter than idle expiry, so idle cannot explain the reap.
const CONTROLLER_HEARTBEAT_MS=SIGNER_IDLE_DEADLINE_MS/4; // Heartbeats stay within the signer's idle deadline.
const pause=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
it.skipIf(process.platform!=="linux")("controller death reaps an idle worker while a heartbeating controller preserves it",async()=>{
  const fixture=await serviceFixture(); let timer:ReturnType<typeof setInterval>|undefined;
  let heartbeat:Promise<unknown>=Promise.resolve();
  try {
    // This is the existing test-isolation ceremony, not an owner-attended unlock drill.
    expect(await fixture.ceremony()).toBe(0);
    const worker=fixture.workerPid();expect(worker).toBeGreaterThan(0);
    timer=setInterval(()=>{heartbeat=fixture.client.status();},CONTROLLER_HEARTBEAT_MS);
    await pause(CONTROLLER_DEATH_WINDOW_MS);clearInterval(timer);timer=undefined;await heartbeat;
    expect(existsSync(`/proc/${worker}`)).toBe(true);
    await fixture.client.status();await fixture.killController();
    const deadline=Date.now()+CONTROLLER_DEATH_WINDOW_MS;
    while(existsSync(`/proc/${worker}`)&&Date.now()<deadline)await pause(CONTROLLER_HEARTBEAT_MS/10); // Ten observations per heartbeat period.
    expect(existsSync(`/proc/${worker}`)).toBe(false);
    expect((await fixture.freshClient()).state).not.toBe("UNLOCKED");
  }finally{if(timer)clearInterval(timer);await heartbeat.catch(()=>undefined);await fixture.close();}
},30_000);

it.skipIf(process.platform!=="linux")("writer death reaps the worker while the live writer heartbeat preserves it", async () => {
  const fixture = await serviceFixture("writer fixture ", false, undefined, true);
  try {
    expect(fixture.writerNotifications).toContain("READY=1\nSTATUS=writer closed");
    expect(fixture.writerPid).toBeGreaterThan(0);
    expect(await fixture.ceremony()).toBe(0);
    const worker = fixture.workerPid(); expect(worker).toBeGreaterThan(0);
    await pause(CONTROLLER_DEATH_WINDOW_MS);
    expect(existsSync(`/proc/${worker}`)).toBe(true);
    await fixture.killController();
    expect(existsSync(`/proc/${fixture.writerPid}`)).toBe(false);
    const deadline = Date.now() + CONTROLLER_DEATH_WINDOW_MS;
    while (existsSync(`/proc/${worker}`) && Date.now() < deadline) await pause(CONTROLLER_HEARTBEAT_MS / 10);
    expect(existsSync(`/proc/${worker}`)).toBe(false);
  } finally { await fixture.close(); }
}, 30_000);
