/** Packed-package gates for the public, inert catalog-v3 contract. */

import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";

const SERVER_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PACKAGE_NAME = "@sanctuary-framework/mcp-server/intelligence";
const REQUIRED_EXPORTS = [
  "CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256",
  "CATALOG_V3_DOMAIN",
  "COMPILED_SPDX_TABLE_SHA256",
  "MAX_CATALOG_WIRE_JSON_BYTES",
  "MAX_SIGNED_VERSION",
  "SIGNATURE_DOMAIN_DELIMITER",
  "deriveCatalogKeyringSha256",
  "parseUntrustedCatalogContinuityObservationV3",
  "parseUntrustedCatalogIndexContinuityObservationV1",
  "verifyAndParseSignedCatalogIndexJsonV1",
  "verifyAndParseSignedCatalogJsonV3",
  "verifyAndParseSignedCatalogV3",
  "verifyAndParseSignedOverlayJsonV1",
].sort();
const INTERNAL_ONLY_HELPERS = [
  "assuranceAtLeast",
  "buildDomainSignaturePreimage",
  "canonicalizeJson",
  "computeCanonicalSha256",
  "effectiveSurfaceFloor",
].sort();
const ASSET_SUBPATHS = [
  "schemas/catalog-body.v3.schema.json",
  "schemas/catalog-index.v1.schema.json",
  "schemas/overlay-body.v1.schema.json",
  "schemas/schema-digests.json",
  "schemas/signed-catalog.v3.schema.json",
  "schemas/signed-overlay.v1.schema.json",
  "spdx/spdx-expression-3.0.1.abnf",
];
const SPDX_OFFICIAL_SOURCES = Object.freeze({
  "licenses.json": Object.freeze({
    count: 727,
    jcsSha256: "677f3480a6f3c26e7583e0ce41e9f486af91fcd3550de2eb6b8f4827e02589de",
    rawSha256: "f728c534d8bd1044fc515a2ddb2292be99559021d830bfa3281be0bcd36302ee",
    url: "https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/licenses.json",
    collection: "licenses",
  }),
  "exceptions.json": Object.freeze({
    count: 84,
    jcsSha256: "ce36f1adeeaf719982fa9d2ca5134872904febfb09308b3d588456764ce16a12",
    rawSha256: "bd145bb558f44432fcd6f0d7e956ed0124dff72af7641a7cfcb1b557dc390a5b",
    url: "https://raw.githubusercontent.com/spdx/license-list-data/v3.28.0/json/exceptions.json",
    collection: "exceptions",
  }),
});
const SPDX_PROJECTION_SHA256 = "a9517d7e516498a8adec3c07fa95cc6702c80c88e9d7381f1b667bfbf92c1c5e";
const SYNTHETIC_REFRESH_PINS = Object.freeze({
  licenseRaw: "09c86f6716699cbc013b95c52f176459ee22d56544289bd65f17af6b9c00dcdc",
  licenseJcs: "a8f9c2837435198412eebb781c6af5f18409414e1afeb0b51eacbcb487f79692",
  exceptionRaw: "0281cf3a852c76cd8a0feb00767a73132e50f10d22445eb705d46813729b0482",
  exceptionJcs: "017ed0634c9cda0e704912cf647a9f598c3b36cd97803391eb55e7b8b530a180",
  projectionRaw: "ac175482835c6b2cea0ed22dcf24bd60906214adb4414309978eef74af8d606a",
  table: "6e9e306c20e63e20be069cd72b454ac4fce21a16c8ddbbefe74a70914955a868",
  generated: "65b4d9ea226606e9e1c17488dea412290137bd9cc318d5e814e2ca6d54fcaf55",
});

function runNode(cwd: string, mode: "import" | "require") {
  const expression = mode === "import"
    ? `const m=await import(${JSON.stringify(PACKAGE_NAME)}); console.log(JSON.stringify(Object.keys(m).filter(k=>${JSON.stringify(REQUIRED_EXPORTS)}.includes(k)).sort()))`
    : `const m=require(${JSON.stringify(PACKAGE_NAME)}); console.log(JSON.stringify(Object.keys(m).filter(k=>${JSON.stringify(REQUIRED_EXPORTS)}.includes(k)).sort()))`;
  return spawnSync("node", mode === "import" ? ["--input-type=module", "-e", expression] : ["-e", expression], {
    cwd,
    encoding: "utf8",
    timeout: 15_000,
  });
}

function runCrossFormatBrandCheck(cwd: string) {
  const expression = `
    const { createRequire } = await import("node:module");
    const { readFileSync } = await import("node:fs");
    const require = createRequire(import.meta.url);
    const esm = await import(${JSON.stringify(PACKAGE_NAME)});
    const cjs = require(${JSON.stringify(PACKAGE_NAME)});
    const golden = JSON.parse(readFileSync("test/fixtures/catalog-v3/catalog-body-golden.json", "utf8"));
    const corpus = JSON.parse(readFileSync("test/fixtures/catalog-v3/wire-boundaries-golden.json", "utf8"));
    const envelope = { body: golden.body, signature: golden.signature, signing_key_id: "cat-epoch-1" };
    const overlayFixture = corpus.boundaries.find((candidate) => candidate.name === "overlay-body-and-envelope");
    if (!overlayFixture) throw new Error("overlay fixture missing");
    const overlayEnvelope = {
      body: overlayFixture.body,
      signature: overlayFixture.signature,
      signer_key_id: overlayFixture.key_id,
    };
    const operatorPublicKey = Buffer.from(corpus.test_public_key, "base64url");
    const esmVerified = esm.verifyAndParseSignedCatalogV3(envelope, corpus.test_catalog_keyring);
    const cjsVerified = cjs.verifyAndParseSignedCatalogV3(envelope, corpus.test_catalog_keyring);
    const esmOverlay = esm.verifyAndParseSignedOverlayV1(overlayEnvelope, operatorPublicKey);
    const cjsOverlay = cjs.verifyAndParseSignedOverlayV1(overlayEnvelope, operatorPublicKey);
    const trustRoot = esm.deriveCatalogKeyringSha256(corpus.test_catalog_keyring);
    if (!esmVerified.ok || !cjsVerified.ok || !esmOverlay.ok || !cjsOverlay.ok || !trustRoot.ok) {
      throw new Error("fixture verification failed");
    }
    const args = [
      overlayFixture.body.overlay_binding_id,
      0,
      trustRoot.value,
      overlayFixture.key_id,
    ];
    console.log(JSON.stringify([
      cjs.validateCatalogOverlayCombination(esmVerified.value, cjsOverlay.value, ...args),
      esm.validateCatalogOverlayCombination(cjsVerified.value, esmOverlay.value, ...args),
      cjs.validateCatalogOverlayCombination(cjsVerified.value, esmOverlay.value, ...args),
      esm.validateCatalogOverlayCombination(esmVerified.value, cjsOverlay.value, ...args),
    ]));
  `;
  return spawnSync("node", ["--input-type=module", "-e", expression], {
    cwd,
    encoding: "utf8",
    timeout: 15_000,
  });
}

function readPublishedManifestRoot(cwd: string, mode: "import" | "require") {
  const expression = mode === "import"
    ? `const m=await import(${JSON.stringify(PACKAGE_NAME)}); console.log(m.CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256)`
    : `const m=require(${JSON.stringify(PACKAGE_NAME)}); console.log(m.CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256)`;
  return spawnSync("node", mode === "import" ? ["--input-type=module", "-e", expression] : ["-e", expression], {
    cwd,
    encoding: "utf8",
    timeout: 15_000,
  });
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("non-canonical JSON value");
}

function canonicalSha256(path: string): string {
  return createHash("sha256").update(canonicalJson(JSON.parse(readFileSync(path, "utf8")))).digest("hex");
}

function repinProjection(serverRoot: string) {
  const projectionPath = join(
    serverRoot,
    "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json",
  );
  const scriptPath = join(serverRoot, "scripts/copy-catalog-v3-assets.mjs");
  const script = readFileSync(scriptPath, "utf8");
  const repinned = script.replace(SPDX_PROJECTION_SHA256, sha256(projectionPath));
  expect(repinned).not.toBe(script);
  writeFileSync(scriptPath, repinned);
}

function assetVerifierFixture(mutate: (serverRoot: string) => void, args: string[] = []) {
  const temporary = mkdtempSync(join(tmpdir(), "sanctuary-catalog-v3-build-"));
  const serverRoot = join(temporary, "server");
  try {
    mkdirSync(join(serverRoot, "scripts"), { recursive: true });
    mkdirSync(join(serverRoot, "src/intelligence"), { recursive: true });
    cpSync(
      resolve(SERVER_ROOT, "scripts/copy-catalog-v3-assets.mjs"),
      join(serverRoot, "scripts/copy-catalog-v3-assets.mjs"),
    );
    cpSync(
      resolve(SERVER_ROOT, "src/intelligence/catalog-v3"),
      join(serverRoot, "src/intelligence/catalog-v3"),
      { recursive: true },
    );
    mutate(serverRoot);
    return spawnSync("node", ["scripts/copy-catalog-v3-assets.mjs", ...args], {
      cwd: serverRoot,
      encoding: "utf8",
      timeout: 15_000,
    });
  } finally {
    rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

function syntheticSpdxSummaryRow(
  idKey: "licenseId" | "licenseExceptionId",
  id: string,
  deprecated: boolean,
  referenceNumber: number,
) {
  return {
    reference: `https://spdx.org/licenses/${id}.html`,
    isDeprecatedLicenseId: deprecated,
    detailsUrl: `https://spdx.org/licenses/${id}.json`,
    referenceNumber,
    name: `Synthetic ${id}`,
    [idKey]: id,
    seeAlso: [`https://example.com/${id}`],
  };
}

function replaceExactOnce(source: string, needle: string, replacement: string): string {
  expect(source.split(needle)).toHaveLength(2);
  return source.replace(needle, replacement);
}

function syntheticRefreshFixture() {
  const temporary = mkdtempSync(join(tmpdir(), "sanctuary-catalog-v3-refresh-"));
  const serverRoot = join(temporary, "server");
  const sourceRoot = join(temporary, "downloaded-source");
  try {
    mkdirSync(join(serverRoot, "scripts"), { recursive: true });
    mkdirSync(join(serverRoot, "src/intelligence"), { recursive: true });
    mkdirSync(sourceRoot, { recursive: true });
    cpSync(
      resolve(SERVER_ROOT, "scripts/copy-catalog-v3-assets.mjs"),
      join(serverRoot, "scripts/copy-catalog-v3-assets.mjs"),
    );
    cpSync(
      resolve(SERVER_ROOT, "src/intelligence/catalog-v3"),
      join(serverRoot, "src/intelligence/catalog-v3"),
      { recursive: true },
    );

    const licenseRows = [
      syntheticSpdxSummaryRow("licenseId", "Synthetic-License-A", false, 1),
      syntheticSpdxSummaryRow("licenseId", "Synthetic-License-B", true, 2),
    ];
    const exceptionRows = [
      syntheticSpdxSummaryRow("licenseExceptionId", "Nokia-Qt-exception-1.1", true, 1),
      syntheticSpdxSummaryRow("licenseExceptionId", "Synthetic-exception", false, 2),
    ];
    const licenseSummary = {
      licenseListVersion: "3.28.0",
      releaseDate: "2026-02-20T00:00:00Z",
      licenses: licenseRows,
    };
    const exceptionSummary = {
      licenseListVersion: "3.28.0",
      releaseDate: "2026-02-20T00:00:00Z",
      exceptions: exceptionRows,
    };
    const licenseBytes = Buffer.from(`${JSON.stringify(licenseSummary)}\n`, "utf8");
    const exceptionBytes = Buffer.from(`${JSON.stringify(exceptionSummary)}\n`, "utf8");
    writeFileSync(join(sourceRoot, "licenses.json"), licenseBytes);
    writeFileSync(join(sourceRoot, "exceptions.json"), exceptionBytes);

    const licenses: Array<[string, boolean]> = licenseRows.map((row) => [
      row.licenseId as string,
      row.isDeprecatedLicenseId,
    ]);
    const exceptions: Array<[string, boolean]> = exceptionRows.map((row) => [
      row.licenseExceptionId as string,
      row.isDeprecatedLicenseId,
    ]);
    const projection = {
      schema: "sanctuary.spdx-id-status-projection.v1",
      license_list_version: "3.28.0",
      release_date: "2026-02-20T00:00:00Z",
      licenses,
      exceptions,
    };
    const projectionBytes = Buffer.from(`${JSON.stringify(projection)}\n`, "utf8");
    const tableDigest = createHash("sha256")
      .update(JSON.stringify({ exceptions, licenses }))
      .digest("hex");
    const generated = `/* Generated from Sanctuary's fact-only SPDX 3.28.0 projection. Upstream provenance attestation: license-list-data v3.28.0 tag 779ef2e5dff6d4af389c53de5e97116ab0bb52e8 (c4a7237ec8f4654e867546f9f409749300f1bf4c). Do not edit. */
export const SPDX_GENERATED_LIST_VERSION = "3.28.0";
export const SPDX_GENERATED_TABLE_SHA256 = "${tableDigest}";
const SPDX_GENERATED_LICENSE_ROWS_MUTABLE = ${JSON.stringify(licenses)} as const;
const SPDX_GENERATED_EXCEPTION_ROWS_MUTABLE = ${JSON.stringify(exceptions)} as const;
export const SPDX_GENERATED_LICENSE_ROWS = Object.freeze(SPDX_GENERATED_LICENSE_ROWS_MUTABLE.map((row) => Object.freeze(row)));
export const SPDX_GENERATED_EXCEPTION_ROWS = Object.freeze(SPDX_GENERATED_EXCEPTION_ROWS_MUTABLE.map((row) => Object.freeze(row)));
`;
    const digestBytes = (bytes: Uint8Array | string): string => createHash("sha256")
      .update(bytes)
      .digest("hex");
    const canonicalDigest = (value: unknown): string => digestBytes(canonicalJson(value));
    expect({
      licenseRaw: digestBytes(licenseBytes),
      licenseJcs: canonicalDigest(licenseSummary),
      exceptionRaw: digestBytes(exceptionBytes),
      exceptionJcs: canonicalDigest(exceptionSummary),
      projectionRaw: digestBytes(projectionBytes),
      table: tableDigest,
      generated: digestBytes(generated),
    }).toEqual(SYNTHETIC_REFRESH_PINS);
    const scriptPath = join(serverRoot, "scripts/copy-catalog-v3-assets.mjs");
    let script = readFileSync(scriptPath, "utf8");
    for (const [needle, replacement] of [
      [SPDX_OFFICIAL_SOURCES["licenses.json"].rawSha256, SYNTHETIC_REFRESH_PINS.licenseRaw],
      [SPDX_OFFICIAL_SOURCES["licenses.json"].jcsSha256, SYNTHETIC_REFRESH_PINS.licenseJcs],
      [SPDX_OFFICIAL_SOURCES["exceptions.json"].rawSha256, SYNTHETIC_REFRESH_PINS.exceptionRaw],
      [SPDX_OFFICIAL_SOURCES["exceptions.json"].jcsSha256, SYNTHETIC_REFRESH_PINS.exceptionJcs],
      [SPDX_PROJECTION_SHA256, SYNTHETIC_REFRESH_PINS.projectionRaw],
      ["57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1", SYNTHETIC_REFRESH_PINS.table],
      ["8fea03c8462aeb1514c367eea4a4f1cd3771e48236afee95f23bc068869189fb", SYNTHETIC_REFRESH_PINS.generated],
      ["expectedCount: 727", "expectedCount: 2"],
      ["expectedDeprecatedCount: 32", "expectedDeprecatedCount: 1"],
      ["expectedCount: 84", "expectedCount: 2"],
    ]) {
      script = replaceExactOnce(script, needle, replacement);
    }
    writeFileSync(scriptPath, script);

    const refresh = spawnSync(
      "node",
      ["scripts/copy-catalog-v3-assets.mjs", "--write", "--refresh-source-dir", sourceRoot],
      { cwd: serverRoot, encoding: "utf8", timeout: 15_000 },
    );
    const projectionPath = join(
      serverRoot,
      "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json",
    );
    const generatedPath = join(
      serverRoot,
      "src/intelligence/catalog-v3/spdx/spdx-tables.generated.ts",
    );
    expect(refresh.status, refresh.stderr).toBe(0);
    expect(readFileSync(projectionPath)).toEqual(projectionBytes);
    expect(readFileSync(generatedPath, "utf8")).toBe(generated);

    rmSync(sourceRoot, { recursive: true, force: true });
    const offline = spawnSync(
      "node",
      ["scripts/copy-catalog-v3-assets.mjs", "--verify-only"],
      { cwd: serverRoot, encoding: "utf8", timeout: 15_000 },
    );
    return { refresh, offline };
  } finally {
    rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

function resolvePackedAssets(cwd: string, mode: "import" | "require") {
  const specifiers = ASSET_SUBPATHS.map((path) => `${PACKAGE_NAME}/catalog-v3/${path}`);
  const expression = mode === "import"
    ? `console.log(JSON.stringify(${JSON.stringify(specifiers)}.map(s=>import.meta.resolve(s))))`
    : `console.log(JSON.stringify(${JSON.stringify(specifiers)}.map(s=>require.resolve(s))))`;
  return spawnSync("node", mode === "import" ? ["--input-type=module", "-e", expression] : ["-e", expression], {
    cwd,
    encoding: "utf8",
    timeout: 15_000,
  });
}

describe("catalog-v3 built and packed consumers", () => {
  it("keeps the documented module and barrel counts mechanically honest", () => {
    const sourceRoot = resolve(SERVER_ROOT, "src");
    const modules = readdirSync(sourceRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    const moduleMap = readFileSync(join(sourceRoot, "README.md"), "utf8");
    const table = moduleMap.slice(
      moduleMap.indexOf("## MODULE INDEX TABLE"),
      moduleMap.indexOf("## Confusable clusters"),
    );
    const documented = [...table.matchAll(/^\| ([a-z0-9-]+) \|/gm)]
      .map((match) => match[1]!)
      .sort();
    const barrels = modules.filter((name) => existsSync(join(sourceRoot, name, "index.ts")));
    const contributing = readFileSync(resolve(SERVER_ROOT, "..", "CONTRIBUTING.md"), "utf8");
    expect(documented).toEqual(modules);
    expect(moduleMap).toContain(`MODULE INDEX TABLE (${modules.length} modules)`);
    expect(moduleMap).toContain(`Status today: ${barrels.length} of ${modules.length} modules have a barrel`);
    expect(contributing).toContain(`the ${modules.length}-module index`);
    expect(contributing).toContain(`${barrels.length} of ${modules.length} modules have a barrel`);
  });

  it("loads the built intelligence entrypoint through both module systems", () => {
    const packageJson = JSON.parse(readFileSync(resolve(SERVER_ROOT, "package.json"), "utf8")) as {
      exports: Record<string, unknown>;
      files: string[];
      scripts: Record<string, string>;
    };
    expect(packageJson.files).toEqual(["dist", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]);
    expect(packageJson.scripts.pretest).toBe("npm run build");
    expect(packageJson.scripts.build.indexOf("node scripts/copy-catalog-v3-assets.mjs --verify-only"))
      .toBeLessThan(packageJson.scripts.build.indexOf("tsup"));
    expect(Object.keys(packageJson.exports).sort()).toEqual([
      ".",
      "./intelligence",
      ...ASSET_SUBPATHS.map((path) => `./intelligence/catalog-v3/${path}`),
    ].sort());
    for (const mode of ["import", "require"] as const) {
      const result = runNode(SERVER_ROOT, mode);
      expect(result.status, `${mode}: ${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout.trim())).toEqual(REQUIRED_EXPORTS);
      const helpersExpression = mode === "import"
        ? `const m=await import(${JSON.stringify(PACKAGE_NAME)}); console.log(JSON.stringify(${JSON.stringify(INTERNAL_ONLY_HELPERS)}.filter(k=>k in m)))`
        : `const m=require(${JSON.stringify(PACKAGE_NAME)}); console.log(JSON.stringify(${JSON.stringify(INTERNAL_ONLY_HELPERS)}.filter(k=>k in m)))`;
      const helpers = spawnSync("node", mode === "import"
        ? ["--input-type=module", "-e", helpersExpression]
        : ["-e", helpersExpression], { cwd: SERVER_ROOT, encoding: "utf8", timeout: 15_000 });
      expect(helpers.status, `${mode} internal helpers: ${helpers.stderr}`).toBe(0);
      expect(JSON.parse(helpers.stdout.trim())).toEqual([]);
    }
    const crossFormat = runCrossFormatBrandCheck(SERVER_ROOT);
    expect(crossFormat.status, crossFormat.stderr).toBe(0);
    expect(JSON.parse(crossFormat.stdout.trim())).toEqual([
      { ok: false, reason: "unauthenticated_input" },
      { ok: false, reason: "unauthenticated_input" },
      { ok: false, reason: "unauthenticated_input" },
      { ok: false, reason: "unauthenticated_input" },
    ]);
  });

  it("pins a fact-only SPDX v3.28.0 projection and needs no executable dependency", () => {
    const packageJson = JSON.parse(readFileSync(resolve(SERVER_ROOT, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    const lockfile = JSON.parse(readFileSync(resolve(SERVER_ROOT, "package-lock.json"), "utf8")) as {
      packages: Record<string, { version?: string; integrity?: string }>;
    };
    for (const name of ["spdx-license-ids", "spdx-exceptions", "spdx-vir"]) {
      expect(packageJson.dependencies[name]).toBeUndefined();
      expect(packageJson.devDependencies[name]).toBeUndefined();
      expect(lockfile.packages[`node_modules/${name}`]).toBeUndefined();
    }
    const script = readFileSync(resolve(SERVER_ROOT, "scripts/copy-catalog-v3-assets.mjs"), "utf8");
    const projectionPath = resolve(
      SERVER_ROOT,
      "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json",
    );
    const projection = JSON.parse(readFileSync(projectionPath, "utf8")) as {
      schema: string;
      license_list_version: string;
      release_date: string;
      licenses: Array<[string, boolean]>;
      exceptions: Array<[string, boolean]>;
    };
    expect(sha256(projectionPath)).toBe(SPDX_PROJECTION_SHA256);
    expect(projection).toMatchObject({
      schema: "sanctuary.spdx-id-status-projection.v1",
      license_list_version: "3.28.0",
      release_date: "2026-02-20T00:00:00Z",
    });
    expect(projection.licenses).toHaveLength(727);
    expect(projection.exceptions).toHaveLength(84);
    expect(readdirSync(resolve(SERVER_ROOT, "src/intelligence/catalog-v3/spdx")))
      .not.toContain("source");
    expect(script).toContain('const SPDX_RELEASE_TAG = "v3.28.0"');
    expect(script).toContain('779ef2e5dff6d4af389c53de5e97116ab0bb52e8');
    expect(script).toContain('const SPDX_RELEASE_COMMIT = "c4a7237ec8f4654e867546f9f409749300f1bf4c"');
    for (const [name, expected] of Object.entries(SPDX_OFFICIAL_SOURCES)) {
      const sourceUrlTemplate = `https://raw.githubusercontent.com/spdx/license-list-data/\${SPDX_RELEASE_TAG}/json/${name}`;
      expect(sourceUrlTemplate.replace("${SPDX_RELEASE_TAG}", "v3.28.0")).toBe(expected.url);
      expect(script).toContain(`sourceUrl: \`${sourceUrlTemplate}\``);
      expect(script).toContain(expected.rawSha256);
      expect(script).toContain(expected.jcsSha256);
    }
    for (const prosePath of [
      resolve(SERVER_ROOT, "README.md"),
      resolve(SERVER_ROOT, "reorg-surface-manifest.md"),
    ]) {
      const prose = readFileSync(prosePath, "utf8");
      const normalizedProse = prose.replace(/\s+/g, " ");
      expect(normalizedProse, prosePath).toContain("fact-only");
      expect(normalizedProse, prosePath).toContain("no executable SPDX dependency");
      expect(normalizedProse, prosePath).toContain("provenance attestations");
      expect(normalizedProse, prosePath).not.toContain("lockfile-integrity-pinned");
      expect(normalizedProse, prosePath).not.toContain("pinned build packages");
    }
  });

  it("ships exact assets and fails closed if either built table is tampered", () => {
    const temporary = mkdtempSync(join(tmpdir(), "sanctuary-catalog-v3-package-"));
    try {
      const packed = JSON.parse(execFileSync(
        "npm",
        ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
        {
          cwd: SERVER_ROOT,
          encoding: "utf8",
          env: { ...process.env, npm_config_cache: join(temporary, ".npm-cache") },
          timeout: 60_000,
        },
      )) as Array<{ filename: string }>;
      expect(packed).toHaveLength(1);
      execFileSync("tar", ["-xzf", join(temporary, packed[0]!.filename), "-C", temporary]);
      const packageRoot = join(temporary, "package");
      symlinkSync(resolve(SERVER_ROOT, "node_modules"), join(packageRoot, "node_modules"), "junction");
      const notices = readFileSync(join(packageRoot, "THIRD_PARTY_NOTICES.md"), "utf8");
      expect(notices).not.toContain("spdx-vir");
      expect(notices).not.toContain("spdx-license-ids@3.0.23");
      expect(notices).not.toContain("spdx-exceptions@2.5.0");
      expect(notices).toContain("SPDX License List data 3.28.0");
      expect(notices).toContain("c4a7237ec8f4654e867546f9f409749300f1bf4c");
      expect(notices).toContain(SPDX_OFFICIAL_SOURCES["licenses.json"].rawSha256);
      expect(notices).toContain(SPDX_OFFICIAL_SOURCES["exceptions.json"].rawSha256);
      expect(existsSync(join(packageRoot, "third_party_licenses"))).toBe(false);
      expect(readdirSync(join(packageRoot, "dist/intelligence")).sort()).toEqual([
        "catalog-v3",
        "index.cjs",
        "index.cjs.map",
        "index.d.cts",
        "index.d.ts",
        "index.js",
        "index.js.map",
      ]);

      for (const mode of ["import", "require"] as const) {
        const result = runNode(packageRoot, mode);
        expect(result.status, `${mode}: ${result.stderr}`).toBe(0);
        expect(JSON.parse(result.stdout.trim())).toEqual(REQUIRED_EXPORTS);
        const assetResolution = resolvePackedAssets(packageRoot, mode);
        expect(assetResolution.status, `${mode} asset exports: ${assetResolution.stderr}`).toBe(0);
        expect(JSON.parse(assetResolution.stdout.trim())).toHaveLength(ASSET_SUBPATHS.length);
      }

      const schemas = resolve(packageRoot, "dist/intelligence/catalog-v3/schemas");
      const spdx = resolve(packageRoot, "dist/intelligence/catalog-v3/spdx");
      expect(readdirSync(schemas).sort()).toEqual([
        "catalog-body.v3.schema.json",
        "catalog-index.v1.schema.json",
        "overlay-body.v1.schema.json",
        "schema-digests.json",
        "signed-catalog.v3.schema.json",
        "signed-overlay.v1.schema.json",
      ]);
      expect(readdirSync(spdx).sort()).toEqual([
        "spdx-expression-3.0.1.abnf",
      ]);
      expect(existsSync(join(packageRoot, "dist/intelligence/catalog-v3/spdx/source"))).toBe(false);
      const digestManifestPath = join(schemas, "schema-digests.json");
      const digestManifestOriginal = readFileSync(digestManifestPath, "utf8");
      const digestManifest = JSON.parse(digestManifestOriginal) as {
        jcs_sha256: Record<string, string>;
        raw_sha256: Record<string, string>;
        source_assets_sha256: Record<string, string>;
      };
      const publishedManifestRoots = new Map<"import" | "require", string>();
      for (const mode of ["import", "require"] as const) {
        const publishedRoot = readPublishedManifestRoot(packageRoot, mode);
        expect(publishedRoot.status, `${mode} manifest root: ${publishedRoot.stderr}`).toBe(0);
        const root = publishedRoot.stdout.trim();
        publishedManifestRoots.set(mode, root);
        expect(sha256(digestManifestPath), `${mode} manifest root`).toBe(root);
      }
      for (const [name, expected] of Object.entries(digestManifest.jcs_sha256)) {
        expect(canonicalSha256(join(schemas, name)), name).toBe(expected);
      }
      for (const [name, expected] of Object.entries(digestManifest.raw_sha256)) {
        expect(sha256(join(schemas, name)), `${name} raw bytes`).toBe(expected);
      }
      for (const [name, expected] of Object.entries(digestManifest.source_assets_sha256)) {
        expect(sha256(join(spdx, name)), name).toBe(expected);
      }

      const packedSchemas = Object.fromEntries(readdirSync(schemas)
        .filter((name) => name.endsWith(".schema.json"))
        .map((name) => [name, JSON.parse(readFileSync(join(schemas, name), "utf8"))]));
      for (const bodyName of [
        "catalog-body.v3.schema.json",
        "catalog-index.v1.schema.json",
        "overlay-body.v1.schema.json",
      ]) {
        expect(() => new Ajv2020({ strict: true }).compile(packedSchemas[bodyName])).not.toThrow();
      }
      const registered = new Ajv2020({ strict: true });
      registered.addSchema(packedSchemas["catalog-body.v3.schema.json"]);
      registered.addSchema(packedSchemas["overlay-body.v1.schema.json"]);
      expect(() => registered.compile(packedSchemas["signed-catalog.v3.schema.json"])).not.toThrow();
      expect(() => registered.compile(packedSchemas["signed-overlay.v1.schema.json"])).not.toThrow();

      const packedSchema = join(schemas, "catalog-body.v3.schema.json");
      const packedSchemaOriginal = readFileSync(packedSchema, "utf8");
      const packedSchemaTampered = JSON.parse(packedSchemaOriginal) as Record<string, unknown>;
      packedSchemaTampered.title = "tampered";
      writeFileSync(packedSchema, JSON.stringify(packedSchemaTampered));
      expect(canonicalSha256(packedSchema)).not.toBe(digestManifest.jcs_sha256["catalog-body.v3.schema.json"]);
      writeFileSync(packedSchema, packedSchemaOriginal);

      const coordinatedSchema = JSON.parse(packedSchemaOriginal) as Record<string, unknown>;
      coordinatedSchema.title = "coordinated schema tamper";
      writeFileSync(packedSchema, JSON.stringify(coordinatedSchema));
      const coordinatedSchemaManifest = JSON.parse(digestManifestOriginal) as typeof digestManifest;
      coordinatedSchemaManifest.jcs_sha256["catalog-body.v3.schema.json"] = canonicalSha256(packedSchema);
      coordinatedSchemaManifest.raw_sha256["catalog-body.v3.schema.json"] = sha256(packedSchema);
      writeFileSync(digestManifestPath, JSON.stringify(coordinatedSchemaManifest));
      expect(canonicalSha256(packedSchema)).toBe(
        coordinatedSchemaManifest.jcs_sha256["catalog-body.v3.schema.json"],
      );
      for (const [mode, root] of publishedManifestRoots) {
        expect(sha256(digestManifestPath), `${mode} coordinated schema tamper`).not.toBe(root);
      }
      writeFileSync(packedSchema, packedSchemaOriginal);
      writeFileSync(digestManifestPath, digestManifestOriginal);

      const packedSpdx = join(spdx, "spdx-expression-3.0.1.abnf");
      const packedSpdxOriginal = readFileSync(packedSpdx, "utf8");
      writeFileSync(packedSpdx, `${packedSpdxOriginal}\n; coordinated SPDX tamper\n`);
      const coordinatedSpdxManifest = JSON.parse(digestManifestOriginal) as typeof digestManifest;
      coordinatedSpdxManifest.source_assets_sha256["spdx-expression-3.0.1.abnf"] = sha256(packedSpdx);
      writeFileSync(digestManifestPath, JSON.stringify(coordinatedSpdxManifest));
      expect(sha256(packedSpdx)).toBe(
        coordinatedSpdxManifest.source_assets_sha256["spdx-expression-3.0.1.abnf"],
      );
      for (const [mode, root] of publishedManifestRoots) {
        expect(sha256(digestManifestPath), `${mode} coordinated SPDX tamper`).not.toBe(root);
      }
      writeFileSync(packedSpdx, packedSpdxOriginal);
      writeFileSync(digestManifestPath, digestManifestOriginal);

      for (const [mode, relative] of [
        ["import", "dist/intelligence/index.js"],
        ["require", "dist/intelligence/index.cjs"],
      ] as const) {
        const path = resolve(packageRoot, relative);
        const original = readFileSync(path, "utf8");
        const tampered = original.replace('["0BSD", false]', '["0BSX", false]');
        expect(tampered, `${mode} tamper marker`).not.toBe(original);
        writeFileSync(path, tampered);
        const result = runNode(packageRoot, mode);
        expect(result.status, `${mode} unexpectedly accepted tampered SPDX table`).not.toBe(0);
        expect(result.stderr).toContain("SPDX runtime table integrity mismatch");
        writeFileSync(path, original);
      }

    } finally {
      rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }, 90_000);

  it("rejects projection drift and coordinated manifest/generated-table tampering", () => {
    const reproducible = assetVerifierFixture(() => undefined);
    expect(reproducible.status, reproducible.stderr).toBe(0);
    const projectionRawFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json");
      writeFileSync(path, `${readFileSync(path, "utf8")}\n`);
    });
    expect(projectionRawFailure.status).not.toBe(0);
    expect(projectionRawFailure.stderr).toContain("SPDX fact projection digest mismatch");

    const projectionVersionFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json");
      const projection = JSON.parse(readFileSync(path, "utf8")) as { license_list_version: string };
      projection.license_list_version = "3.28.1";
      writeFileSync(path, `${JSON.stringify(projection)}\n`);
      repinProjection(serverRoot);
    });
    expect(projectionVersionFailure.status).not.toBe(0);
    expect(projectionVersionFailure.stderr).toContain("SPDX fact projection shape/version mismatch");

    const caseFoldFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json");
      const projection = JSON.parse(readFileSync(path, "utf8")) as {
        licenses: Array<[string, boolean]>;
      };
      projection.licenses[1]![0] = projection.licenses[0]![0].toLowerCase();
      writeFileSync(path, `${JSON.stringify(projection)}\n`);
      repinProjection(serverRoot);
    });
    expect(caseFoldFailure.status).not.toBe(0);
    expect(caseFoldFailure.stderr).toContain("contains duplicate projected IDs");

    const deprecatedStatusFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-id-status-projection.v1.json");
      const projection = JSON.parse(readFileSync(path, "utf8")) as {
        exceptions: Array<[string, boolean]>;
      };
      const deprecated = projection.exceptions.find((row) => row[1]);
      expect(deprecated).toBeDefined();
      deprecated![1] = false;
      writeFileSync(path, `${JSON.stringify(projection)}\n`);
      repinProjection(serverRoot);
    });
    expect(deprecatedStatusFailure.status).not.toBe(0);
    expect(deprecatedStatusFailure.stderr).toContain("projected deprecated-status count changed");

    const unsafeStandaloneWrite = assetVerifierFixture(() => undefined, ["--write"]);
    expect(unsafeStandaloneWrite.status).not.toBe(0);
    expect(unsafeStandaloneWrite.stderr)
      .toContain("refresh requires --write --refresh-source-dir <download-directory>");
    const schemaFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/schemas/catalog-body.v3.schema.json");
      const schema = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      schema.title = "tampered";
      writeFileSync(path, JSON.stringify(schema));
    });
    expect(schemaFailure.status).not.toBe(0);
    expect(schemaFailure.stderr).toContain("catalog-body.v3.schema.json raw digest mismatch");

    const duplicateSchemaKeyFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/schemas/catalog-body.v3.schema.json");
      const source = readFileSync(path, "utf8");
      expect(source.startsWith("{")).toBe(true);
      // JSON.parse keeps the later original title, so JCS alone would miss
      // this duplicate-key raw wire mutation. The raw schema root must refuse.
      // Anchored `^{`: inject exactly once, right after the root opening brace
      // (asserted above to be char 0). Not sanitization; a single deliberate
      // mutation, so a global replace would be wrong here.
      writeFileSync(
        path,
        source.replace(/^\{/, '{"title":"shadowed duplicate",'),
      );
    });
    expect(duplicateSchemaKeyFailure.status).not.toBe(0);
    expect(duplicateSchemaKeyFailure.stderr)
      .toContain("catalog-body.v3.schema.json raw digest mismatch");

    const coordinatedSchemaFailure = assetVerifierFixture((serverRoot) => {
      const schemaPath = join(serverRoot, "src/intelligence/catalog-v3/schemas/catalog-body.v3.schema.json");
      const manifestPath = join(serverRoot, "src/intelligence/catalog-v3/schemas/schema-digests.json");
      const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as Record<string, unknown>;
      schema.title = "coordinated schema tamper";
      writeFileSync(schemaPath, JSON.stringify(schema));
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        jcs_sha256: Record<string, string>;
        raw_sha256: Record<string, string>;
      };
      manifest.jcs_sha256["catalog-body.v3.schema.json"] = canonicalSha256(schemaPath);
      manifest.raw_sha256["catalog-body.v3.schema.json"] = sha256(schemaPath);
      writeFileSync(manifestPath, JSON.stringify(manifest));
    });
    expect(coordinatedSchemaFailure.status).not.toBe(0);
    expect(coordinatedSchemaFailure.stderr).toContain("asset digest manifest mismatch");

    const coordinatedSpdxFailure = assetVerifierFixture((serverRoot) => {
      const spdxPath = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-expression-3.0.1.abnf");
      const manifestPath = join(serverRoot, "src/intelligence/catalog-v3/schemas/schema-digests.json");
      writeFileSync(spdxPath, `${readFileSync(spdxPath, "utf8")}\n; coordinated SPDX tamper\n`);
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        source_assets_sha256: Record<string, string>;
      };
      manifest.source_assets_sha256["spdx-expression-3.0.1.abnf"] = sha256(spdxPath);
      writeFileSync(manifestPath, JSON.stringify(manifest));
    });
    expect(coordinatedSpdxFailure.status).not.toBe(0);
    expect(coordinatedSpdxFailure.stderr).toContain("asset digest manifest mismatch");

    const generatedFailure = assetVerifierFixture((serverRoot) => {
      const path = join(serverRoot, "src/intelligence/catalog-v3/spdx/spdx-tables.generated.ts");
      let generated = readFileSync(path, "utf8");
      const licenses = JSON.parse(generated.match(/SPDX_GENERATED_LICENSE_ROWS_MUTABLE = (.+) as const;/)?.[1] ?? "null") as Array<[string, boolean]>;
      const exceptions = JSON.parse(generated.match(/SPDX_GENERATED_EXCEPTION_ROWS_MUTABLE = (.+) as const;/)?.[1] ?? "null") as Array<[string, boolean]>;
      licenses[0]![0] = "0BSX";
      const recomputed = createHash("sha256").update(JSON.stringify({ exceptions, licenses })).digest("hex");
      generated = generated
        .replace(/SPDX_GENERATED_TABLE_SHA256 = "[0-9a-f]{64}";/, `SPDX_GENERATED_TABLE_SHA256 = "${recomputed}";`)
        .replace('SPDX_GENERATED_LICENSE_ROWS_MUTABLE = [["0BSD",false]', 'SPDX_GENERATED_LICENSE_ROWS_MUTABLE = [["0BSX",false]');
      writeFileSync(path, generated);
    });
    expect(generatedFailure.status).not.toBe(0);
    expect(generatedFailure.stderr).toContain("generated SPDX source digest mismatch");
  });

  it("refreshes from pinned synthetic source and verifies the result offline", () => {
    const { refresh, offline } = syntheticRefreshFixture();
    expect(refresh.stdout).toContain("spdx-id-status-projection.v1.json");
    expect(offline.status, offline.stderr).toBe(0);
    expect(offline.stdout).toBe("verified catalog v3 assets\n");
  });
});
