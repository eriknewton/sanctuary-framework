#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const catalogRoot = resolve(serverRoot, "src/intelligence/catalog-v3");
const schemaRoot = resolve(catalogRoot, "schemas");
const spdxRoot = resolve(catalogRoot, "spdx");
const spdxProjectionPath = resolve(spdxRoot, "spdx-id-status-projection.v1.json");
const generatedPath = resolve(spdxRoot, "spdx-tables.generated.ts");
const destinationRoot = resolve(serverRoot, "dist/intelligence/catalog-v3");
// Independent trust root for the exact manifest bytes. The manifest cannot
// authenticate itself: changing an asset and its adjacent digest entry together
// must still fail the normal build unless this reviewed code constant changes.
const EXPECTED_ASSET_DIGEST_MANIFEST_SHA256 = "2260260fdcd5dc5687e8328f2751fffdd38926b130e1ff340833d3ebee5c15b8";
// Independent reviewed source root. This intentionally does not trust the
// digest declared inside the generated file it authenticates.
const EXPECTED_GENERATED_SPDX_SOURCE_SHA256 = "8fea03c8462aeb1514c367eea4a4f1cd3771e48236afee95f23bc068869189fb";
const EXPECTED_SPDX_TABLE_SHA256 = "57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1";
// Integrity root for the committed fact-only SPDX projection. The upstream
// raw JSON is intentionally not redistributed in this repository.
const EXPECTED_SPDX_PROJECTION_SHA256 = "a9517d7e516498a8adec3c07fa95cc6702c80c88e9d7381f1b667bfbf92c1c5e";
const SPDX_RELEASE_TAG = "v3.28.0";
// These git object ids are reviewed provenance attestations. They are not
// derived from, and do not authenticate, the source bytes; the raw/JCS hashes
// below are the integrity roots for externally supplied refresh input.
const SPDX_RELEASE_TAG_OBJECT = "779ef2e5dff6d4af389c53de5e97116ab0bb52e8";
const SPDX_RELEASE_VERSION = "3.28.0";
const SPDX_RELEASE_DATE = "2026-02-20T00:00:00Z";
const SPDX_RELEASE_COMMIT = "c4a7237ec8f4654e867546f9f409749300f1bf4c";
const SPDX_SOURCE_FILES = Object.freeze({
  "licenses.json": Object.freeze({
    collection: "licenses",
    expectedCount: 727,
    expectedDeprecatedCount: 32,
    idKey: "licenseId",
    jcsSha256: "677f3480a6f3c26e7583e0ce41e9f486af91fcd3550de2eb6b8f4827e02589de",
    rawSha256: "f728c534d8bd1044fc515a2ddb2292be99559021d830bfa3281be0bcd36302ee",
    sourceUrl: `https://raw.githubusercontent.com/spdx/license-list-data/${SPDX_RELEASE_TAG}/json/licenses.json`,
  }),
  "exceptions.json": Object.freeze({
    collection: "exceptions",
    expectedCount: 84,
    expectedDeprecatedCount: 1,
    idKey: "licenseExceptionId",
    jcsSha256: "ce36f1adeeaf719982fa9d2ca5134872904febfb09308b3d588456764ce16a12",
    rawSha256: "bd145bb558f44432fcd6f0d7e956ed0124dff72af7641a7cfcb1b557dc390a5b",
    sourceUrl: `https://raw.githubusercontent.com/spdx/license-list-data/${SPDX_RELEASE_TAG}/json/exceptions.json`,
  }),
});

const manifestBytes = await readFile(resolve(schemaRoot, "schema-digests.json"));
const manifestDigest = createHash("sha256").update(manifestBytes).digest("hex");
if (manifestDigest !== EXPECTED_ASSET_DIGEST_MANIFEST_SHA256) {
  throw new Error(`asset digest manifest mismatch: ${manifestDigest}`);
}
const manifest = JSON.parse(manifestBytes.toString("utf8"));
const schemaNames = [
  "catalog-body.v3.schema.json",
  "catalog-index.v1.schema.json",
  "overlay-body.v1.schema.json",
  "signed-catalog.v3.schema.json",
  "signed-overlay.v1.schema.json",
];
const assetNames = ["spdx-expression-3.0.1.abnf"];

function exactKeys(value, expected) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function canonicalizeJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(",")}}`;
  }
  throw new Error("schema contains a non-canonical JSON value");
}

if (!exactKeys(manifest, ["schema", "jcs_sha256", "raw_sha256", "source_assets_sha256"])
  || manifest.schema !== "sanctuary.catalog-schema-digests.v1"
  || !exactKeys(manifest.jcs_sha256, schemaNames)
  || !exactKeys(manifest.raw_sha256, schemaNames)
  || !exactKeys(manifest.source_assets_sha256, assetNames)) {
  throw new Error("schema digest manifest shape mismatch");
}

const schemaBytes = new Map();
for (const name of schemaNames) {
  const bytes = await readFile(resolve(schemaRoot, name));
  const rawDigest = createHash("sha256").update(bytes).digest("hex");
  if (rawDigest !== manifest.raw_sha256[name]) {
    throw new Error(`${name} raw digest mismatch: ${rawDigest}`);
  }
  const parsed = JSON.parse(bytes.toString("utf8"));
  const digest = createHash("sha256").update(canonicalizeJson(parsed)).digest("hex");
  if (digest !== manifest.jcs_sha256[name]) {
    throw new Error(`${name} canonical digest mismatch: ${digest}`);
  }
  schemaBytes.set(name, bytes);
}

const assetBytes = new Map();
for (const name of assetNames) {
  const bytes = await readFile(resolve(spdxRoot, name));
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== manifest.source_assets_sha256[name]) {
    throw new Error(`${name} digest mismatch: ${digest}`);
  }
  assetBytes.set(name, bytes);
}

function spdxOrder(left, right) {
  const foldedLeft = left.toLowerCase();
  const foldedRight = right.toLowerCase();
  return foldedLeft < foldedRight ? -1 : foldedLeft > foldedRight ? 1 : left < right ? -1 : left > right ? 1 : 0;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$/;
const COMMON_ROW_KEYS = [
  "detailsUrl",
  "isDeprecatedLicenseId",
  "name",
  "reference",
  "referenceNumber",
  "seeAlso",
];
const LICENSE_ROW_KEYS = [...COMMON_ROW_KEYS, "isFsfLibre", "isOsiApproved", "licenseId"];
const EXCEPTION_ROW_KEYS = [...COMMON_ROW_KEYS, "licenseExceptionId"];

function validateSummaryRow(row, sourceName, descriptor, referenceNumbers) {
  if (row === null || typeof row !== "object" || Array.isArray(row)) {
    throw new Error(`${sourceName} contains a non-object row`);
  }
  const allowedKeys = descriptor.collection === "licenses" ? LICENSE_ROW_KEYS : EXCEPTION_ROW_KEYS;
  const requiredKeys = descriptor.collection === "licenses"
    ? [...COMMON_ROW_KEYS, "licenseId"]
    : [...COMMON_ROW_KEYS, "licenseExceptionId"];
  if (!requiredKeys.every((key) => Object.hasOwn(row, key))
    || Object.keys(row).some((key) => !allowedKeys.includes(key))) {
    throw new Error(`${sourceName} row shape mismatch`);
  }
  const id = row[descriptor.idKey];
  if (typeof id !== "string" || !ID_PATTERN.test(id)) {
    throw new Error(`${sourceName} contains an invalid SPDX identifier`);
  }
  if (typeof row.name !== "string" || row.name.length === 0
    || typeof row.isDeprecatedLicenseId !== "boolean"
    || !Number.isSafeInteger(row.referenceNumber) || row.referenceNumber < 0
    || referenceNumbers.has(row.referenceNumber)
    || !Array.isArray(row.seeAlso)
    || row.seeAlso.some((url) => typeof url !== "string" || url.length === 0)) {
    throw new Error(`${sourceName} row value mismatch for ${id}`);
  }
  referenceNumbers.add(row.referenceNumber);
  if (row.reference !== `https://spdx.org/licenses/${id}.html`
    || row.detailsUrl !== `https://spdx.org/licenses/${id}.json`) {
    throw new Error(`${sourceName} row URL mismatch for ${id}`);
  }
  for (const optionalBoolean of ["isFsfLibre", "isOsiApproved"]) {
    if (Object.hasOwn(row, optionalBoolean) && typeof row[optionalBoolean] !== "boolean") {
      throw new Error(`${sourceName} ${optionalBoolean} mismatch for ${id}`);
    }
  }
  return [id, row.isDeprecatedLicenseId];
}

async function loadSpdxSummary(sourceName, descriptor) {
  const bytes = await readFile(resolve(refreshSourceRoot, sourceName));
  const rawDigest = createHash("sha256").update(bytes).digest("hex");
  if (rawDigest !== descriptor.rawSha256) {
    throw new Error(`${sourceName} official raw digest mismatch: ${rawDigest}`);
  }
  const summary = JSON.parse(bytes.toString("utf8"));
  if (!exactKeys(summary, ["licenseListVersion", "releaseDate", descriptor.collection])
    || summary.licenseListVersion !== SPDX_RELEASE_VERSION
    || summary.releaseDate !== SPDX_RELEASE_DATE
    || !Array.isArray(summary[descriptor.collection])) {
    throw new Error(`${sourceName} official summary shape/version mismatch`);
  }
  const jcsDigest = createHash("sha256").update(canonicalizeJson(summary)).digest("hex");
  if (jcsDigest !== descriptor.jcsSha256) {
    throw new Error(`${sourceName} official canonical digest mismatch: ${jcsDigest}`);
  }
  const referenceNumbers = new Set();
  const rows = summary[descriptor.collection]
    .map((row) => validateSummaryRow(row, sourceName, descriptor, referenceNumbers));
  if (rows.length !== descriptor.expectedCount) {
    throw new Error(`${sourceName} official row count changed`);
  }
  const identifiers = rows.map(([id]) => id);
  const unique = new Set(identifiers);
  const caseFolded = new Set(identifiers.map((id) => id.toLowerCase()));
  if (unique.size !== rows.length) throw new Error(`${sourceName} contains duplicate IDs`);
  if (caseFolded.size !== rows.length) throw new Error(`${sourceName} contains ASCII-case-equivalent IDs`);
  if (rows.filter(([, deprecated]) => deprecated).length !== descriptor.expectedDeprecatedCount) {
    throw new Error(`${sourceName} deprecated-status count changed`);
  }
  return rows.sort(([left], [right]) => spdxOrder(left, right));
}

function validateProjectionRows(rows, sourceName, descriptor) {
  if (!Array.isArray(rows) || rows.length !== descriptor.expectedCount) {
    throw new Error(`${sourceName} projected row count changed`);
  }
  const identifiers = new Set();
  const caseFolded = new Set();
  let deprecatedCount = 0;
  let prior = null;
  for (const row of rows) {
    if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== "string"
      || !ID_PATTERN.test(row[0]) || typeof row[1] !== "boolean") {
      throw new Error(`${sourceName} contains an invalid projected row`);
    }
    if (prior !== null && spdxOrder(prior, row[0]) >= 0) {
      throw new Error(`${sourceName} projected rows are not uniquely sorted`);
    }
    if (identifiers.has(row[0]) || caseFolded.has(row[0].toLowerCase())) {
      throw new Error(`${sourceName} contains duplicate projected IDs`);
    }
    identifiers.add(row[0]);
    caseFolded.add(row[0].toLowerCase());
    if (row[1]) deprecatedCount++;
    prior = row[0];
  }
  if (deprecatedCount !== descriptor.expectedDeprecatedCount) {
    throw new Error(`${sourceName} projected deprecated-status count changed`);
  }
  return rows;
}

function buildProjection(licenses, exceptions) {
  return {
    schema: "sanctuary.spdx-id-status-projection.v1",
    license_list_version: SPDX_RELEASE_VERSION,
    release_date: SPDX_RELEASE_DATE,
    licenses,
    exceptions,
  };
}

const refreshArgument = process.argv.indexOf("--refresh-source-dir");
const writeMode = process.argv.includes("--write");
const verifyOnly = process.argv.includes("--verify-only");
if (process.argv.filter((argument) => argument === "--refresh-source-dir").length > 1
  || (refreshArgument >= 0 && (!process.argv[refreshArgument + 1]
    || process.argv[refreshArgument + 1].startsWith("--")))) {
  throw new Error("--refresh-source-dir requires exactly one directory path");
}
const allowedArguments = new Set(["--write", "--verify-only", "--refresh-source-dir"]);
for (let index = 2; index < process.argv.length; index++) {
  if (index === refreshArgument + 1) continue;
  if (!allowedArguments.has(process.argv[index])) throw new Error(`unknown argument: ${process.argv[index]}`);
}
if (writeMode !== (refreshArgument >= 0) || (writeMode && verifyOnly)) {
  throw new Error("refresh requires --write --refresh-source-dir <download-directory>");
}
const refreshSourceRoot = refreshArgument >= 0
  ? resolve(process.argv[refreshArgument + 1])
  : null;

let projection;
let projectionBytes;
if (refreshSourceRoot !== null) {
  const licenses = await loadSpdxSummary("licenses.json", SPDX_SOURCE_FILES["licenses.json"]);
  const exceptions = await loadSpdxSummary("exceptions.json", SPDX_SOURCE_FILES["exceptions.json"]);
  projection = buildProjection(licenses, exceptions);
  projectionBytes = Buffer.from(`${JSON.stringify(projection)}\n`, "utf8");
} else {
  projectionBytes = await readFile(spdxProjectionPath);
  const projectionDigest = createHash("sha256").update(projectionBytes).digest("hex");
  if (projectionDigest !== EXPECTED_SPDX_PROJECTION_SHA256) {
    throw new Error(`SPDX fact projection digest mismatch: ${projectionDigest}`);
  }
  projection = JSON.parse(projectionBytes.toString("utf8"));
  if (!exactKeys(projection, ["schema", "license_list_version", "release_date", "licenses", "exceptions"])
    || projection.schema !== "sanctuary.spdx-id-status-projection.v1"
    || projection.license_list_version !== SPDX_RELEASE_VERSION
    || projection.release_date !== SPDX_RELEASE_DATE) {
    throw new Error("SPDX fact projection shape/version mismatch");
  }
}
const licenses = validateProjectionRows(
  projection.licenses, "licenses.json", SPDX_SOURCE_FILES["licenses.json"],
);
const exceptions = validateProjectionRows(
  projection.exceptions, "exceptions.json", SPDX_SOURCE_FILES["exceptions.json"],
);
if (exceptions.filter(([, deprecated]) => deprecated).map(([id]) => id).join(",")
  !== "Nokia-Qt-exception-1.1") {
  throw new Error("SPDX 3.28 deprecated exception changed");
}
const tableJson = JSON.stringify({ exceptions, licenses });
const tableDigest = createHash("sha256").update(tableJson).digest("hex");
if (tableDigest !== EXPECTED_SPDX_TABLE_SHA256) {
  throw new Error(`SPDX 3.28 generated table digest mismatch: ${tableDigest}`);
}
const generated = `/* Generated from Sanctuary's fact-only SPDX ${SPDX_RELEASE_VERSION} projection. Upstream provenance attestation: license-list-data ${SPDX_RELEASE_TAG} tag ${SPDX_RELEASE_TAG_OBJECT} (${SPDX_RELEASE_COMMIT}). Do not edit. */
export const SPDX_GENERATED_LIST_VERSION = "3.28.0";
export const SPDX_GENERATED_TABLE_SHA256 = "${tableDigest}";
const SPDX_GENERATED_LICENSE_ROWS_MUTABLE = ${JSON.stringify(licenses)} as const;
const SPDX_GENERATED_EXCEPTION_ROWS_MUTABLE = ${JSON.stringify(exceptions)} as const;
export const SPDX_GENERATED_LICENSE_ROWS = Object.freeze(SPDX_GENERATED_LICENSE_ROWS_MUTABLE.map((row) => Object.freeze(row)));
export const SPDX_GENERATED_EXCEPTION_ROWS = Object.freeze(SPDX_GENERATED_EXCEPTION_ROWS_MUTABLE.map((row) => Object.freeze(row)));
`;

if (writeMode) {
  const projectionDigest = createHash("sha256").update(projectionBytes).digest("hex");
  if (projectionDigest !== EXPECTED_SPDX_PROJECTION_SHA256) {
    throw new Error(`refreshed SPDX fact projection digest mismatch: ${projectionDigest}`);
  }
  await writeFile(spdxProjectionPath, projectionBytes);
  await writeFile(generatedPath, generated, "utf8");
  process.stdout.write(`wrote ${spdxProjectionPath} and ${generatedPath}\n`);
  process.exit(0);
}

let committedGenerated;
try {
  committedGenerated = await readFile(generatedPath, "utf8");
} catch {
  throw new Error("missing generated SPDX table; refresh it from separately downloaded pinned source");
}
const generatedSourceDigest = createHash("sha256").update(committedGenerated).digest("hex");
if (generatedSourceDigest !== EXPECTED_GENERATED_SPDX_SOURCE_SHA256) {
  throw new Error(`generated SPDX source digest mismatch: ${generatedSourceDigest}`);
}
if (committedGenerated !== generated) {
  throw new Error("generated SPDX table is stale; refresh it from separately downloaded pinned source");
}

if (verifyOnly) {
  process.stdout.write("verified catalog v3 assets\n");
  process.exit(0);
}

await rm(destinationRoot, { recursive: true, force: true });
await mkdir(destinationRoot, { recursive: true });
await mkdir(resolve(destinationRoot, "schemas"), { recursive: true });
for (const name of schemaNames) {
  await writeFile(resolve(destinationRoot, "schemas", name), schemaBytes.get(name));
}
await writeFile(resolve(destinationRoot, "schemas/schema-digests.json"), manifestBytes);
await mkdir(resolve(destinationRoot, "spdx"), { recursive: true });
for (const name of assetNames) {
  await writeFile(resolve(destinationRoot, "spdx", name), assetBytes.get(name));
}
