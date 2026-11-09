import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { validateBusinessJoin } from "../../src/signing/worker.js";
import { BUSINESS_SCHEMA_DIGEST } from "../../src/signing/linux-business-records.js";
import type { JoinState, JoinRecord } from "../../src/signing/record-joins.js";

// Must match linux_business_schema.rs::shared_join_vectors and the other TS executor: consume every id, result and entire final state.
const corpus = JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/record_join_vectors.json", "utf8")) as {version: number; schema_digest: string; cases: Array<{id: string; initial: JoinState; records: JoinRecord[]; expect: {accepted_prefix: number; refusal_code: string | null; final_state: JoinState}}>};
function execute(row: typeof corpus.cases[number]) {
  let state = structuredClone(row.initial), accepted_prefix = 0, refusal_code: string | null = null;
  for (const record of row.records) {
    const before = structuredClone(state), original = structuredClone(record);
    const result = validateBusinessJoin(state, record);
    expect(state, row.id).toEqual(before);
    expect(record, row.id).toEqual(original);
    state = result.final_state; refusal_code = result.refusal_code;
    if (refusal_code !== null) break;
    accepted_prefix++;
  }
  return {id: row.id, accepted_prefix, refusal_code, final_state: state};
}
it.each(corpus.cases)("worker shared join $id", row => {
  const result = execute(row);
  expect(result.refusal_code, row.id).toBe(row.expect.refusal_code);
  expect(result, row.id).toEqual({id: row.id, ...row.expect});
});
it("worker corpus full id, result and final-state sets have no missing, extra or duplicate member", () => {
  expect(corpus.version).toBe(1); // The initial shared join format is version one.
  expect(corpus.schema_digest).toBe(BUSINESS_SCHEMA_DIGEST);
  const ids = corpus.cases.map(row => row.id);
  expect(new Set(ids).size).toBe(ids.length);
  const actual = corpus.cases.map(execute);
  expect(actual.map(row => row.id)).toEqual(ids);
  expect(actual).toEqual(corpus.cases.map(row => ({id: row.id, ...row.expect})));
});

import { z } from "zod";
import { ed25519 } from "@noble/curves/ed25519";
import { createRecordSigner, type SigningGrant } from "../../src/signing/record-signer.js";
import { canonicalBytes, ROLE_REGISTRY } from "../../src/signing/contract.js";
it("every accepted business join remains unsignable before the counting provider, while inert count signs", () => {
  const first = corpus.cases[0];
  const grant = {...first.initial.pin, ...first.initial.grant} as unknown as SigningGrant;
  let calls = 0;
  const seed = new Uint8Array(32).fill(7); // Deterministic public fixture seed, matching the corpus signatures.
  const signer = createRecordSigner(grant, {sign(message) { calls++; return ed25519.sign(message, seed); }}, z.unknown(), "counter");
  for (const row of corpus.cases) for (const record of row.records) {
    // The malformed-record vector has no body to present.
    if (record === null) continue;
    expect(() => signer.signRecord({role: ROLE_REGISTRY[0].role, epoch: grant.epoch, preimage_bytes: canonicalBytes(record.body)})).toThrow("K1_REFUSED");
  }
  expect(calls).toBe(0);
  const inert = {...first.records[0].body, record_kind: "counter", payload: {count: 1}};
  expect(signer.signRecord({role: grant.role, epoch: grant.epoch, preimage_bytes: canonicalBytes(inert)}).kid).toBe(grant.kid);
  expect(calls).toBe(1);
});

import { createHash } from "node:crypto";
import * as joins from "../../src/signing/record-joins.js";
// Must match vector_manifest.json and every other consumer: the exact corpus bytes and case count are pinned in one place.
it("worker corpus bytes and case count match the shared manifest", () => {
  const manifest = JSON.parse(readFileSync("../castle-wall-daemon/src/business_profile/vector_manifest.json", "utf8")).files["record_join_vectors.json"];
  const bytes = readFileSync("../castle-wall-daemon/src/business_profile/record_join_vectors.json");
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(manifest.sha256);
  expect({cases: corpus.cases.length}).toEqual(manifest.cases);
});
it("worker join state schema is the shared corpus table", () => {
  expect(joins.JOIN_STATE_SCHEMA).toEqual((corpus as unknown as {state_schema: unknown}).state_schema);
});
