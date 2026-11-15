// Checkpoint ingress preserves the original bounded join-state bytes.
// W-CHECKPOINT
import {expect, it} from "vitest";
import * as append from "../../src/signing/business-append-contract.js";
import {canonicalBytes} from "../../src/signing/contract.js";
// The base's value boundary is the fail-before control for the new raw ingress.
const parse = (bytes: Uint8Array) => {
  const raw = (append as unknown as {parseBusinessCheckpoint?: (b:Uint8Array)=>unknown}).parseBusinessCheckpoint;
  if (raw) return raw(bytes);
  const value: unknown = JSON.parse(Buffer.from(bytes).toString("utf8"));
  if (!append.appendShape("checkpoint", value)) throw Error("BUSINESS_CHECKPOINT");
  return value;
};
const seed = () => structuredClone(append.APPEND_CONTRACT.checkpoint_vectors[0].value);
it("admits the complete canonical checkpoint through the raw join boundary", () => {
  const value=seed(); expect(parse(canonicalBytes(value))).toEqual(value);
});
it("refuses alternate join number spelling before normalization", () => {
  const bytes=Buffer.from(canonicalBytes(seed())).toString("utf8");
  const alternate=bytes.replace('"agent_uids":[1000]', '"agent_uids":[1e3]');
  expect(alternate).not.toEqual(bytes);
  expect(()=>parse(Buffer.from(alternate))).toThrow();
});
it("refuses a duplicated join member on original bytes", () => {
  const bytes=Buffer.from(canonicalBytes(seed())).toString("utf8");
  const alternate=bytes.replace('"agent_uids":[1000]', '"agent_uids":[1000],"agent_uids":[1000]');
  expect(alternate).not.toEqual(bytes);
  expect(()=>parse(Buffer.from(alternate))).toThrow();
});
it("refuses whitespace instead of silently normalizing a checkpoint", () => {
  expect(()=>parse(Buffer.from(JSON.stringify(seed(),null,2)))).toThrow();
});
