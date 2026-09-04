#!/usr/bin/env node
/*
 * Sanctuary MCP Server: verify and copy the packaged signed V2 model manifest.
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Build step for the one signed `sanctuary.model-manifest.v2` envelope that
 * ships inside the npm package. Runs twice in `npm run build`: `--verify-only`
 * before tsup, and the copy after it. Both modes refuse the build when the
 * committed asset does not hash to the reviewed pin below, so a tampered or
 * re-signed-but-not-repinned asset can never reach `dist/`.
 *
 * This script checks bytes and shape only. Signature verification is the
 * runtime loader's job (`src/intelligence/packaged-model-manifest.ts`), which
 * uses the shared V2 parser and the compiled catalog root pin; duplicating that
 * here would be a second verifier to keep in lockstep.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Must match PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH in
// src/intelligence/packaged-model-manifest.ts and the matching `exports` entry
// in package.json (asserted below).
const ASSET_RELATIVE_PATH = "intelligence/model-manifest/model-manifest.v2.json";

// Independent trust root for the exact asset bytes. Must match
// PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256 in
// src/intelligence/packaged-model-manifest.ts; both constants are rewritten
// only by scripts/sign-model-manifest-v2.mjs when a new asset is produced.
const EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256 = "edc2091d555ee61a3ba760ef33c9bca4ba3dad5d83c44878cba2e0ba774d6b90";

// Must match MAX_CATALOG_WIRE_JSON_BYTES in src/intelligence/model-catalog-v3.ts
// (65,536 = 64 KiB), the cap the runtime loader applies before parsing.
const MAX_ASSET_BYTES = 65_536;

const sourcePath = resolve(serverRoot, "src", ASSET_RELATIVE_PATH);
const destinationPath = resolve(serverRoot, "dist", ASSET_RELATIVE_PATH);

const verifyOnly = process.argv.includes("--verify-only");
for (const argument of process.argv.slice(2)) {
  if (argument !== "--verify-only") throw new Error(`unknown argument: ${argument}`);
}

const bytes = await readFile(sourcePath);
if (bytes.length > MAX_ASSET_BYTES) {
  throw new Error(`model manifest asset exceeds ${MAX_ASSET_BYTES} bytes: ${bytes.length}`);
}
const digest = createHash("sha256").update(bytes).digest("hex");
if (digest !== EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256) {
  throw new Error(
    `model manifest asset digest mismatch: ${digest} (expected ${EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256}); `
      + "re-run scripts/sign-model-manifest-v2.mjs to produce and repin a new asset",
  );
}

// Shape-only check: exact envelope keys. A body the runtime schema rejects is
// still refused at load; this just stops a non-envelope file from shipping.
const envelope = JSON.parse(bytes.toString("utf8"));
const keys = envelope !== null && typeof envelope === "object" && !Array.isArray(envelope)
  ? Object.keys(envelope).sort()
  : [];
if (keys.join(",") !== "body,signature" || typeof envelope.signature !== "string") {
  throw new Error("model manifest asset is not a {body, signature} envelope");
}

// The asset is useless to a consumer that cannot resolve it: assert the
// package export entry so the loader path, this script, and package.json agree.
const packageJson = JSON.parse(await readFile(resolve(serverRoot, "package.json"), "utf8"));
const exportKey = `./${ASSET_RELATIVE_PATH}`;
if (packageJson.exports?.[exportKey] !== `./dist/${ASSET_RELATIVE_PATH}`) {
  throw new Error(`package.json exports is missing "${exportKey}" -> "./dist/${ASSET_RELATIVE_PATH}"`);
}

if (verifyOnly) {
  process.stdout.write(`verified model manifest asset ${digest}\n`);
  process.exit(0);
}

await mkdir(dirname(destinationPath), { recursive: true });
await writeFile(destinationPath, bytes);
const copied = createHash("sha256").update(await readFile(destinationPath)).digest("hex");
if (copied !== digest) {
  throw new Error(`copied model manifest asset digest mismatch: ${copied}`);
}
process.stdout.write(`copied model manifest asset -> dist/${ASSET_RELATIVE_PATH}\n`);
