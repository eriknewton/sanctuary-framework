// fail-before-exempt: shared native corpus and append shape parity exercise new pure foundations.
// W-PROVENANCE
// W-ENVELOPE-CAP
// W-JOIN-LIFECYCLE
import {it, expect} from "vitest";
import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
import {APPEND_CONTRACT, appendShape, envelopeSizeAdmitted, parseBusinessEnvelope, parseBusinessEvent, parseBusinessEventBytes, deliveryIdentity} from "../../src/signing/business-append-contract.js";
import {initialLifecycle, lifecycleStep} from "../../src/signing/business-join-lifecycle.js";
import {canonicalBytes} from "../../src/signing/contract.js";
import {validateBusinessRecord} from "../../src/signing/linux-business-records.js";
import type {JoinRecord} from "../../src/signing/record-joins.js";
const corpus = loadCheckedCorpus("record_join_vectors.json") as {cases: Array<{id:string;records:JoinRecord[]}>};
const record = corpus.cases[0].records[0];
const bytes = canonicalBytes(record);
const encoded = Buffer.from(bytes).toString("base64url");
it.each(APPEND_CONTRACT.identity_vectors)("delivery identity $id", row => {
  expect(appendShape("identity", row.value)).toBe(row.accepted);
  expect(appendShape("ack", {version:1,identity:row.value})).toBe(row.accepted);
});
it("exact envelope cap predicates admit 4096 and refuse 4097", () => {
  expect(envelopeSizeAdmitted(4096)).toBe(true);
  expect(envelopeSizeAdmitted(4097)).toBe(false);
  expect(()=>parseBusinessEnvelope(Buffer.alloc(4097,32).toString("base64url"))).toThrow();
});
it("exact canonical envelope and business event preserve every signed byte", () => {
  expect(parseBusinessEnvelope(encoded)).toEqual({bytes:Buffer.from(bytes),record});
  const event = {seq:50,captured_at_unix_ms:record.body.captured_at_unix_ms,prior_sha256_hex:"0".repeat(64),event_canonical_json:Buffer.from(canonicalBytes(record.body)).toString(),critical:true,business_envelope:encoded,producer_signature_b64url:null,producer_key_id:null};
  expect(parseBusinessEvent(event).identity).toEqual(deliveryIdentity(bytes,record));
  for(const changed of [{...event,critical:false},{...event,business_envelope:null},{...event,producer_key_id:"raw"},{...event,captured_at_unix_ms:99},{...event,event_canonical_json:"{}"}]) expect(()=>parseBusinessEvent(changed)).toThrow();
  expect(()=>parseBusinessEnvelope(encoded+"=")).toThrow();
  expect(()=>parseBusinessEnvelope(Buffer.from('{"body":null,"body":null,"outer":{}}').toString("base64url"))).toThrow();
});
it.each(corpus.cases.filter(row=>row.id.startsWith("provenance-")))("schema boundary $id", row => {
  expect(validateBusinessRecord(row.records.at(-1)!.body)).toBe(row.id.endsWith("-equal"));
});
it.each(APPEND_CONTRACT.lifecycle_vectors)("shared lifecycle $id", row => {
  let state=initialLifecycle();
  const events=APPEND_CONTRACT.lifecycle_events as Record<string,Record<string,unknown>>;
  const states=APPEND_CONTRACT.lifecycle_states as Record<string,unknown>;
  for(const [event,accepted,next] of row.steps) {
    const result=lifecycleStep(state,events[String(event)]);
    expect(result.accepted).toBe(accepted);
    expect(result.state).toEqual(states[String(next)]);
    state=result.state;
  }
});

it.each(APPEND_CONTRACT.ack_vectors)("shared ACK $id", row => {
  expect(appendShape("ack",row.value)).toBe(row.accepted);
});
it.each(APPEND_CONTRACT.event_vectors)("shared event $id", row => {
  if(row.accepted) expect(parseBusinessEvent(row.value).identity).toEqual(deliveryIdentity(bytes,record));
  else expect(()=>parseBusinessEvent(row.value)).toThrow();
});

it("serialized business events reject duplicate wrapper keys before normalization", () => {
  const event=APPEND_CONTRACT.event_vectors[0].value;
  const bytes=canonicalBytes(event);
  expect(parseBusinessEventBytes(bytes).identity).toEqual(deliveryIdentity(canonicalBytes(record),record));
  const duplicate=Buffer.from(Buffer.from(bytes).toString().replace('"critical":true','"critical":true,"critical":true'));
  expect(()=>parseBusinessEventBytes(duplicate)).toThrow();
});

it("checkpoint shapes share complete bounded nested tables without granting authority", () => {
  for(const row of APPEND_CONTRACT.checkpoint_vectors) expect(appendShape("checkpoint",row.value),row.id).toBe(row.accepted);
});
