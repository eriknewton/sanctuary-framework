/**
 * Canonical-digest parity checks for the inert catalog schema assets.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import {
  CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256,
  SPDX_EXPRESSION_ABNF_SHA256,
  canonicalizeJson,
  computeCanonicalSha256,
  parseCatalogBodyV3,
} from "../../src/intelligence/model-catalog-v3.js";
import catalogBody from "../../src/intelligence/catalog-v3/schemas/catalog-body.v3.schema.json";
import catalogIndex from "../../src/intelligence/catalog-v3/schemas/catalog-index.v1.schema.json";
import overlayBody from "../../src/intelligence/catalog-v3/schemas/overlay-body.v1.schema.json";
import signedCatalog from "../../src/intelligence/catalog-v3/schemas/signed-catalog.v3.schema.json";
import signedOverlay from "../../src/intelligence/catalog-v3/schemas/signed-overlay.v1.schema.json";
import digestManifest from "../../src/intelligence/catalog-v3/schemas/schema-digests.json";
import catalogGolden from "../fixtures/catalog-v3/catalog-body-golden.json";
import wireGolden from "../fixtures/catalog-v3/wire-boundaries-golden.json";

type SchemaName = "catalog-body" | "signed-catalog" | "catalog-index" | "overlay-body" | "signed-overlay";
type SchemaCorpusBoundary = {
  name: string;
  domain: string;
  external_fixture?: string;
  body?: unknown;
  signature?: string;
  key_field: "signing_key_id" | "signer_key_id";
  key_id: string;
};
type SchemaCorpusCase = {
  name: string;
  boundary: string;
  operation: "parse_body" | "parse_envelope" | "verify_signature";
  schema?: SchemaName;
  schema_valid?: boolean;
  path?: Array<string | number>;
  value?: unknown;
  delete_path?: Array<string | number>;
  envelope_path?: Array<string | number>;
  envelope_value?: unknown;
  delete_envelope_path?: Array<string | number>;
  mutation?: "append_index_gap" | "append_index_duplicate_release" | "append_index_duplicate_asset" | "append_index_duplicate_envelope" | "append_index_duplicate_body" | "append_index_cross_digest" | "append_duplicate_identity" | "overflow_collection" | "pad_signature" | "noncanonical_signature" | "short_signature" | "zero_signature";
};
const corpus = wireGolden as unknown as {
  boundaries: SchemaCorpusBoundary[];
  contract_cases: SchemaCorpusCase[];
};
const EXPECTED_CONTRACT_CASE_ROW_DIGEST = "953f924e3346ad1dff3eddce1d715f2763acb670a7a0875c261a8019c16113ab";

function setFixturePath(root: unknown, path: readonly (string | number)[], value: unknown): void {
  let cursor = root;
  for (let index = 0; index < path.length - 1; index++) {
    const key = path[index]!;
    if (typeof key === "number") {
      if (!Array.isArray(cursor)) throw new Error("fixture path is not an array");
      cursor = cursor[key];
    } else {
      if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) throw new Error("fixture path is not an object");
      cursor = (cursor as Record<string, unknown>)[key];
    }
  }
  const leaf = path.at(-1)!;
  if (typeof leaf === "number") {
    if (!Array.isArray(cursor)) throw new Error("fixture leaf is not an array");
    cursor[leaf] = structuredClone(value);
  } else {
    if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) throw new Error("fixture leaf is not an object");
    (cursor as Record<string, unknown>)[leaf] = structuredClone(value);
  }
}

function deleteFixturePath(root: unknown, path: readonly (string | number)[]): void {
  let cursor = root;
  for (let index = 0; index < path.length - 1; index++) {
    const key = path[index]!;
    cursor = typeof key === "number"
      ? (cursor as unknown[])[key]
      : (cursor as Record<string, unknown>)[key];
  }
  const leaf = path.at(-1)!;
  if (typeof leaf === "number") (cursor as unknown[]).splice(leaf, 1);
  else delete (cursor as Record<string, unknown>)[leaf];
}

function applyStructuralMutation(body: unknown, boundary: SchemaCorpusBoundary, mutation: SchemaCorpusCase["mutation"]): void {
  if (mutation === "append_index_gap") {
    const indexBody = body as { entries: Array<Record<string, unknown>>; highest_catalog_version: number };
    const gap = structuredClone(indexBody.entries[0]!);
    Object.assign(gap, { catalog_version: 3, catalog_release_id: 1003, catalog_asset_id: 2003 });
    indexBody.entries.push(gap);
    indexBody.highest_catalog_version = 3;
  } else if (mutation?.startsWith("append_index_duplicate_") || mutation === "append_index_cross_digest") {
    const indexBody = body as { entries: Array<Record<string, unknown>>; index_version: number; previous_index_body_sha256: string | null; highest_catalog_version: number };
    const first = indexBody.entries[0]!;
    const second: Record<string, unknown> = {
      ...structuredClone(first), catalog_version: 2, catalog_release_id: 1002,
      catalog_asset_id: 2002, envelope_sha256: "5".repeat(64), body_sha256: "6".repeat(64),
    };
    const duplicateFields: Readonly<Record<string, string>> = {
      append_index_duplicate_release: "catalog_release_id",
      append_index_duplicate_asset: "catalog_asset_id",
      append_index_duplicate_envelope: "envelope_sha256",
      append_index_duplicate_body: "body_sha256",
      append_index_cross_digest: "body_sha256",
    };
    const field = duplicateFields[mutation];
    if (!field) throw new Error(`unknown index duplicate mutation: ${mutation}`);
    second[field] = mutation === "append_index_cross_digest" ? first.envelope_sha256 : first[field];
    indexBody.entries.push(second);
    indexBody.index_version = 2;
    indexBody.highest_catalog_version = 2;
    indexBody.previous_index_body_sha256 = "a".repeat(64);
  } else if (mutation === "append_duplicate_identity") {
    const field = boundary.domain === "sanctuary.model-catalog.v3" ? "models" : "entries";
    const collection = (body as Record<string, Array<Record<string, unknown>>>)[field];
    const duplicate = structuredClone(collection[0]!);
    duplicate.model_id = `${String(collection.at(-1)!.model_id)}z`;
    collection.push(duplicate);
  } else if (mutation === "overflow_collection") {
    if (boundary.domain === "sanctuary.model-catalog-index.v1") {
      const indexBody = body as { entries: Array<Record<string, unknown>>; highest_catalog_version: number };
      const template = indexBody.entries[0]!;
      indexBody.entries = Array.from({ length: 65 }, (_, index) => ({
        ...structuredClone(template), catalog_version: index + 1,
        catalog_release_id: 1001 + index, catalog_asset_id: 2001 + index,
      }));
      indexBody.highest_catalog_version = 65;
    } else {
      const field = boundary.domain === "sanctuary.model-catalog.v3" ? "models" : "entries";
      const limit = field === "models" ? 33 : 65;
      const collection = (body as Record<string, Array<Record<string, unknown>>>)[field];
      const template = collection[0]!;
      (body as Record<string, unknown>)[field] = Array.from({ length: limit }, (_, index) => {
        const item = structuredClone(template);
        item.model_id = `m${index.toString().padStart(2, "0")}`;
        (item.identity as Record<string, unknown>).tag = `t${index.toString().padStart(2, "0")}`;
        return item;
      });
    }
  }
}

describe("catalog v3 companion-schema parity", () => {
  it("uses only bundled URN references and has no resolvable schema fetch surface", () => {
    const schemas = [catalogBody, catalogIndex, overlayBody, signedCatalog, signedOverlay];
    for (const schema of schemas) {
      expect(schema.$id).toMatch(/^urn:sanctuary:schema:/);
      const serialized = JSON.stringify(schema);
      expect(serialized).not.toContain("sanctuary.local");
      expect(serialized).not.toMatch(/"\$ref":"https?:/);
    }
  });

  it("matches every committed JCS schema digest", () => {
    const manifestBytes = readFileSync(fileURLToPath(new URL(
      "../../src/intelligence/catalog-v3/schemas/schema-digests.json",
      import.meta.url,
    )));
    expect(createHash("sha256").update(manifestBytes).digest("hex"))
      .toBe(CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256);
    const schemas: Record<string, unknown> = {
      "catalog-body.v3.schema.json": catalogBody,
      "catalog-index.v1.schema.json": catalogIndex,
      "overlay-body.v1.schema.json": overlayBody,
      "signed-catalog.v3.schema.json": signedCatalog,
      "signed-overlay.v1.schema.json": signedOverlay,
    };
    expect(Object.keys(schemas).sort()).toEqual(Object.keys(digestManifest.jcs_sha256).sort());
    expect(Object.keys(schemas).sort()).toEqual(Object.keys(digestManifest.raw_sha256).sort());
    for (const [name, schema] of Object.entries(schemas)) {
      expect(JSON.parse(canonicalizeJson(schema))).toEqual(schema);
      expect(computeCanonicalSha256(schema)).toBe(digestManifest.jcs_sha256[name as keyof typeof digestManifest.jcs_sha256]);
      const rawBytes = readFileSync(fileURLToPath(new URL(
        `../../src/intelligence/catalog-v3/schemas/${name}`,
        import.meta.url,
      )));
      expect(createHash("sha256").update(rawBytes).digest("hex"))
        .toBe(digestManifest.raw_sha256[name as keyof typeof digestManifest.raw_sha256]);
    }
  });

  it("pins the shipped Sanctuary SPDX profile grammar", () => {
    const asset = (name: string): Buffer => readFileSync(fileURLToPath(new URL(`../../src/intelligence/catalog-v3/spdx/${name}`, import.meta.url)));
    const digest = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");
    expect(digest(asset("spdx-expression-3.0.1.abnf"))).toBe(SPDX_EXPRESSION_ABNF_SHA256);
    expect(digestManifest.source_assets_sha256).toEqual({
      "spdx-expression-3.0.1.abnf": SPDX_EXPRESSION_ABNF_SHA256,
    });
  });

  it("executes every schema-bearing parity-corpus verdict", () => {
    const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
    for (const schema of [catalogBody, catalogIndex, overlayBody, signedCatalog, signedOverlay]) ajv.addSchema(schema);
    const accepts = (id: string, value: unknown): boolean => {
      const validator = ajv.getSchema(id)!;
      return validator(value) === true;
    };
    const schemaIds: Record<SchemaName, string> = {
      "catalog-body": catalogBody.$id,
      "signed-catalog": signedCatalog.$id,
      "catalog-index": catalogIndex.$id,
      "overlay-body": overlayBody.$id,
      "signed-overlay": signedOverlay.$id,
    };
    const consumedRows = new Set<string>();
    expect(createHash("sha256")
      .update(corpus.contract_cases.map((fixture) => fixture.name).join("\n"))
      .digest("hex")).toBe(EXPECTED_CONTRACT_CASE_ROW_DIGEST);
    for (const fixture of corpus.contract_cases) {
      if (!fixture.schema || fixture.schema_valid === undefined) throw new Error(`${fixture.name}: missing schema metadata`);
      consumedRows.add(fixture.name);
      const boundary = corpus.boundaries.find((candidate) => candidate.name === fixture.boundary);
      if (!boundary) throw new Error(`missing corpus boundary: ${fixture.boundary}`);
      const body = structuredClone(boundary.external_fixture === "catalog-body-golden.json" ? catalogGolden.body : boundary.body);
      if (fixture.path) setFixturePath(body, fixture.path, fixture.value);
      if (fixture.delete_path) deleteFixturePath(body, fixture.delete_path);
      applyStructuralMutation(body, boundary, fixture.mutation);
      const signature = boundary.signature ?? catalogGolden.signature;
      const envelope: Record<string, unknown> = boundary.key_field === "signer_key_id"
        ? { body, signature, signer_key_id: boundary.key_id }
        : { body, signature, signing_key_id: boundary.key_id };
      if (fixture.envelope_path) setFixturePath(envelope, fixture.envelope_path, fixture.envelope_value);
      if (fixture.delete_envelope_path) deleteFixturePath(envelope, fixture.delete_envelope_path);
      if (fixture.mutation === "pad_signature") envelope.signature = `${signature}=`;
      if (fixture.mutation === "short_signature") envelope.signature = "AA";
      if (fixture.mutation === "zero_signature") envelope.signature = Buffer.alloc(64).toString("base64url");
      let value: unknown;
      switch (fixture.operation) {
        case "parse_body":
          value = body;
          break;
        case "parse_envelope":
        case "verify_signature":
          value = envelope;
          break;
        default: {
          const exhaustive: never = fixture.operation;
          throw new Error(`unknown schema corpus operation: ${String(exhaustive)}`);
        }
      }
      const schemaId = schemaIds[fixture.schema];
      const accepted = accepts(schemaId, value);
      const validator = ajv.getSchema(schemaId)!;
      expect(accepted, `${fixture.name}: ${JSON.stringify(validator.errors)}`).toBe(fixture.schema_valid);
    }
    expect(consumedRows.size).toBe(corpus.contract_cases.length);

    const validLeapTimestamp = "2024-02-29T23:59:59Z";
    const catalogWithLeapTimestamp = structuredClone(catalogGolden.body);
    catalogWithLeapTimestamp.issued_at = validLeapTimestamp;
    expect(accepts(catalogBody.$id, catalogWithLeapTimestamp)).toBe(true);
    expect(parseCatalogBodyV3(catalogWithLeapTimestamp).ok).toBe(true);
  });
});
