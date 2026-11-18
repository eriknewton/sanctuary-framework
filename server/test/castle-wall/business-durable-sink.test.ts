// fail-before-exempt: snapshot replay and post-stat length checks use isolated filesystem handles and the pinned native record corpus.
// W-TS-CONSUMER
import {it, expect, afterEach, vi} from "vitest";
import {mkdtemp, unlink, rmdir, readFile, writeFile} from "node:fs/promises";
import * as files from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createBusinessDurableSink, BUSINESS_SNAPSHOT_MAX_BYTES} from "../../src/castle-wall/runtime/business-durable-sink.js";
import {createBusinessRecordConsumer, type DurableBusinessAcceptance} from "../../src/castle-wall/runtime/business-record-consumer.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {type JoinRecord, type JoinState} from "../../src/signing/record-joins.js";
import type {BusinessPin} from "../../src/linux-business/producer-custody.js";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
const first = (loadCheckedCorpus("record_join_vectors.json") as {cases: {initial:JoinState;records:JoinRecord[]}[]}).cases[0];
const event = () => ({seq:1,captured_at_unix_ms:first.records[0].body.captured_at_unix_ms,prior_sha256_hex:null,event_canonical_json:Buffer.from(canonicalBytes(first.records[0].body)).toString(),critical:true,business_envelope:Buffer.from(canonicalBytes(first.records[0])).toString("base64url"),producer_signature_b64url:null,producer_key_id:null});
const roots: string[] = [];
const sinks: Awaited<ReturnType<typeof createBusinessDurableSink>>[] = [];
const setup = async () => {
  const root = await mkdtemp(join(tmpdir(), "k1c-ts-")); roots.push(root);
  const sink = await createBusinessDurableSink(root); sinks.push(sink);
  return {root,sink};
};
const consumer = (sink: Awaited<ReturnType<typeof createBusinessDurableSink>>) => createBusinessRecordConsumer({kind:"Business",pin:{...first.initial.pin,...first.initial.grant} as unknown as BusinessPin,committed_state:first.initial,durable_sink:sink});
afterEach(async () => {
  for (const sink of sinks.splice(0)) await sink.close().catch(() => {});
  for (const root of roots.splice(0)) {
    for (const name of ["business.accepted.json","business.pending.json","business.lock"]) await unlink(join(root,name)).catch(() => {});
    await rmdir(root);
  }
});
it("persists and reads back the complete acceptance", async () => {
  const {root,sink}=await setup(); const c=await consumer(sink);const ack=await c.accept(event());
  const value=(await sink.load())!;
  expect(value.identity).toEqual(ack?.identity); expect(value.checkpoint).toEqual(c.committedState());
  expect(Buffer.from(value.envelope).toString("base64url")).toBe(event().business_envelope);
  expect((await readFile(join(root,"business.accepted.json"))).length).toBeLessThan(BUSINESS_SNAPSHOT_MAX_BYTES);
});
it("restores exact durable acceptance and replays without a second advance", async () => {
  const {root,sink}=await setup(); const c=await consumer(sink); const ack=await c.accept(event());
  await sink.close();sinks.splice(sinks.indexOf(sink),1);
  const reopened=await createBusinessDurableSink(root);sinks.push(reopened);
  const restored=await consumer(reopened); const before=restored.committedState();
  expect(await restored.accept(event())).toEqual(ack);expect(restored.committedState()).toEqual(before);
});
it("retains exact ownership after a failed atomic publication", async () => {
  const {root,sink}=await setup(); const c=await consumer(sink);
  await writeFile(join(root,"business.pending.json"),"invalid",{mode:0o600});
  await expect(c.accept(event())).rejects.toThrow();expect(c.committedState()).toEqual(first.initial);
  expect(c.pendingDelivery()).not.toBeNull();expect(await sink.load()).toBeNull();
  await unlink(join(root,"business.pending.json"));
  expect(await c.accept(event())).toBeDefined();
});
it("refuses changed bytes at an owned sequence", async () => {
  const {sink}=await setup(); const c=await consumer(sink);await c.accept(event());
  const accepted=(await sink.load())!;const changed=structuredClone(accepted);changed.identity.envelope_sha256="sha256:"+"0".repeat(64);
  await expect(sink.persist(changed)).rejects.toThrow("BUSINESS_REPLAY");expect((await sink.load())!.identity).toEqual(accepted.identity);
  const replay=await sink.persist(accepted).then(value=>({value}),error=>({error:String(error)}));
  expect(replay, "refused replay releases staged ownership").toEqual({value:accepted});
});
it("rejects malformed durable join state on reload", async () => {
  const {root,sink}=await setup();await (await consumer(sink)).accept(event());
  const value=JSON.parse(await readFile(join(root,"business.accepted.json"),"utf8"));value.checkpoint.anchor.sequence++;
  await writeFile(join(root,"business.accepted.json"),canonicalBytes(value));
  await expect(consumer(sink)).rejects.toThrow("BUSINESS_DURABLE_STATE");
});
it("bounds retained snapshots and excludes concurrent owners", async () => {
  const {root,sink}=await setup();await expect(createBusinessDurableSink(root)).rejects.toThrow();
  await expect(sink.persist({envelope:new Uint8Array(BUSINESS_SNAPSHOT_MAX_BYTES),identity:{sequence:1}} as DurableBusinessAcceptance)).rejects.toThrow("BUSINESS_SNAPSHOT_BOUND");
});

it("refuses a snapshot whose read length changed after stat", async () => {
  const {root,sink}=await setup();await (await consumer(sink)).accept(event());
  const probe=await files.open(join(root,"business.accepted.json"),"r");
  const prototype=Object.getPrototypeOf(probe) as typeof probe;
  const originalStat=prototype.stat;
  await probe.close();
  const spy=vi.spyOn(prototype,"stat").mockImplementation(async function(this: typeof probe) {
    const metadata=await originalStat.call(this);
    if(metadata.isFile() && metadata.size>0) metadata.size--;
    return metadata;
  });
  try {
    const outcome=await sink.load().then(()=>null,error=>(error as Error).message);
    expect(outcome, "changed snapshot length refuses before decode").toBe("BUSINESS_SNAPSHOT");
  }
  finally {spy.mockRestore();}
});
