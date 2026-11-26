/**
 * The statement policy as a pure table over the real 1.8.4 statement: every
 * pinned field missing, every pinned field altered, malformed subjects, and
 * each statement-versus-certificate fact disagreeing.
 */
import { describe, expect, it } from "vitest";
import { mint, type IdentityEvidence } from "../../src/verify-release/evidence.js";
import { STATEMENT_FIELDS, STATEMENT_PINS, state_STATEMENT } from "../../src/verify-release/statement.js";
import { denyAllNetwork, slsaBundle184 } from "./helpers.js";

denyAllNetwork();

const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const REAL_STATEMENT = (): any => JSON.parse(Buffer.from(slsaBundle184().dsseEnvelope.payload, "base64").toString("utf8"));
const bytes = (statement: unknown) => Buffer.from(JSON.stringify(statement), "utf8");

const IDENTITY: IdentityEvidence = mint({
  state: "state_IDENTITY",
  repositoryUri: "https://github.com/eriknewton/sanctuary-framework",
  repositoryId: "1188932575",
  repositoryOwnerId: "38265121",
  ref: "refs/heads/main",
  trigger: "workflow_dispatch",
});

/** JSON paths of each pinned statement field, payloadType excluded (it is not inside the JSON). */
const JSON_PATHS: Record<string, string[]> = Object.fromEntries(
  Object.entries(STATEMENT_FIELDS)
    .filter(([key]) => key !== "payloadType" && key !== "subjects")
    .map(([, field]) => [field, field.split(".")]),
);

function edit(statement: any, path: string[], value: unknown | typeof REMOVE): any {
  let node = statement;
  for (const key of path.slice(0, -1)) node = node[key];
  if (value === REMOVE) delete node[path[path.length - 1]!];
  else node[path[path.length - 1]!] = value;
  return statement;
}
const REMOVE = Symbol("remove");

describe("statement policy", () => {
  it("accepts the real 1.8.4 statement", () => {
    expect(state_STATEMENT(PAYLOAD_TYPE, bytes(REAL_STATEMENT()), IDENTITY)).toMatchObject({ ok: true });
  });

  it("the table below covers every pin", () => {
    const pinned = STATEMENT_PINS.map(([key]) => STATEMENT_FIELDS[key]).filter(field => field !== "payloadType").sort();
    expect(Object.keys(JSON_PATHS).sort()).toEqual(pinned);
  });

  describe.each(Object.entries(JSON_PATHS))("field %s", (field, path) => {
    it("missing refuses provenance-field-absent", () => {
      expect(state_STATEMENT(PAYLOAD_TYPE, bytes(edit(REAL_STATEMENT(), path, REMOVE)), IDENTITY)).toEqual({ ok: false, reason: `provenance-field-absent:${field}` });
    });
    it("of another JSON type refuses provenance-field-absent", () => {
      expect(state_STATEMENT(PAYLOAD_TYPE, bytes(edit(REAL_STATEMENT(), path, 1188932575)), IDENTITY)).toEqual({ ok: false, reason: `provenance-field-absent:${field}` });
    });
    it("altered refuses provenance-pin-mismatch", () => {
      const original = path.reduce((node: any, key) => node[key], REAL_STATEMENT());
      expect(state_STATEMENT(PAYLOAD_TYPE, bytes(edit(REAL_STATEMENT(), path, `${original}x`)), IDENTITY)).toEqual({ ok: false, reason: `provenance-pin-mismatch:${field}` });
    });
  });

  it("another DSSE payloadType refuses provenance-pin-mismatch:payloadType", () => {
    expect(state_STATEMENT("application/json", bytes(REAL_STATEMENT()), IDENTITY)).toEqual({ ok: false, reason: "provenance-pin-mismatch:payloadType" });
  });

  it("a payload that is not UTF-8 JSON refuses provenance-field-absent:payload", () => {
    expect(state_STATEMENT(PAYLOAD_TYPE, Buffer.from([0xff, 0xfe]), IDENTITY)).toEqual({ ok: false, reason: "provenance-field-absent:payload" });
    expect(state_STATEMENT(PAYLOAD_TYPE, Buffer.from("{", "utf8"), IDENTITY)).toEqual({ ok: false, reason: "provenance-field-absent:payload" });
    // Valid JSON only after lossy decoding: an invalid UTF-8 byte inside a JSON string.
    expect(state_STATEMENT(PAYLOAD_TYPE, Buffer.from([0x22, 0xff, 0x22]), IDENTITY)).toEqual({ ok: false, reason: "provenance-field-absent:payload" });
  });

  it.each([
    ["missing", REMOVE],
    ["not an array", { name: "x" }],
    ["an element that is null", [null]],
    ["an element without a name", [{ digest: { sha512: "00" } }]],
    ["an element without a digest", [{ name: "pkg:npm/x@1" }]],
    ["a sha512 that is not a string", [{ name: "pkg:npm/x@1", digest: { sha512: 5 } }]],
  ])("a subject list that is %s refuses provenance-field-absent:subject", (_label, value) => {
    expect(state_STATEMENT(PAYLOAD_TYPE, bytes(edit(REAL_STATEMENT(), ["subject"], value)), IDENTITY)).toEqual({ ok: false, reason: "provenance-field-absent:subject" });
  });
});

describe("statement versus certificate", () => {
  it.each([
    ["repositoryUri", "statement-repository-uri"],
    ["repositoryId", "statement-repository-id"],
    ["repositoryOwnerId", "statement-repository-owner-id"],
    ["ref", "statement-ref"],
    ["trigger", "statement-trigger"],
  ] as const)("a certificate %s that disagrees with the statement refuses identity-mismatch:%s", (key, name) => {
    const identity = mint({ ...IDENTITY, [key]: `${IDENTITY[key]}0` }) as IdentityEvidence;
    expect(state_STATEMENT(PAYLOAD_TYPE, bytes(REAL_STATEMENT()), identity)).toEqual({ ok: false, reason: `identity-mismatch:${name}` });
  });
});
