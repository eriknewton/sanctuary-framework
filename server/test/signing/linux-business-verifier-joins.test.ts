import {loadCheckedCorpus} from "../fixtures/business-corpus.js";
const checkedRecordJoinVectors = loadCheckedCorpus("record_join_vectors.json") as Record<string, unknown>;
import { it, expect } from "vitest";
import { verifyBusinessJoin } from "../../src/signing/record-joins.js";
import { BUSINESS_SCHEMA_DIGEST } from "../../src/signing/linux-business-records.js";
import type { JoinState, JoinRecord } from "../../src/signing/record-joins.js";

// Must match linux_business_schema.rs::shared_join_vectors and the other TS executor: consume every id, result and entire final state.
const corpus = checkedRecordJoinVectors as {version: number; schema_digest: string; cases: Array<{id: string; initial: JoinState; records: JoinRecord[]; expect: {accepted_prefix: number; refusal_code: string | null; final_state: JoinState}}>};
function execute(row: typeof corpus.cases[number]) {
  let state = structuredClone(row.initial), accepted_prefix = 0, refusal_code: string | null = null;
  for (const record of row.records) {
    const before = structuredClone(state), original = structuredClone(record);
    const result = verifyBusinessJoin(state, record);
    expect(state, row.id).toEqual(before);
    expect(record, row.id).toEqual(original);
    state = result.final_state; refusal_code = result.refusal_code;
    if (refusal_code !== null) break;
    accepted_prefix++;
  }
  return {id: row.id, accepted_prefix, refusal_code, final_state: state};
}
it.each(corpus.cases)("verifier shared join $id", row => {
  const result = execute(row);
  expect(result.refusal_code, row.id).toBe(row.expect.refusal_code);
  expect(result, row.id).toEqual({id: row.id, ...row.expect});
});
it("verifier corpus full id, result and final-state sets have no missing, extra or duplicate member", () => {
  expect(corpus.version).toBe(1); // The initial shared join format is version one.
  expect(corpus.schema_digest).toBe(BUSINESS_SCHEMA_DIGEST);
  const ids = corpus.cases.map(row => row.id);
  expect(new Set(ids).size).toBe(ids.length);
  const actual = corpus.cases.map(execute);
  expect(actual.map(row => row.id)).toEqual(ids);
  expect(actual).toEqual(corpus.cases.map(row => ({id: row.id, ...row.expect})));
});

it("an accepted join still requires its original strict signature", () => {
  const row = corpus.cases[0], original = row.records[0];
  expect(verifyBusinessJoin(row.initial, original).refusal_code).toBe(null);
  const bad = structuredClone(original);
  bad.outer.signature = "A".repeat(86); // Unpadded base64url for sixty-four zero bytes is eighty-six characters.
  expect(verifyBusinessJoin(row.initial, bad)).toEqual({refusal_code: "AUTH", final_state: row.initial});
});

import * as joins from "../../src/signing/record-joins.js";
it("verifier join state schema is the shared corpus table", () => {
  expect(joins.JOIN_STATE_SCHEMA).toEqual((corpus as unknown as {state_schema: unknown}).state_schema);
});
