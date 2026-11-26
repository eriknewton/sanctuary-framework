#!/usr/bin/env node
/*
 * Sanctuary MCP Server: copy the committed Sigstore trusted root into dist/.
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * `sanctuary verify-release` checks npm provenance against this one committed
 * root and never fetches one. tsup bundles the verifier into dist/cli.js, so
 * the root is copied beside it at dist/verify-release/trusted_root.json, the
 * path the runtime loader derives from its own module URL. The build refuses
 * when the committed bytes do not hash to the reviewed pin below, so an edited
 * root cannot ship without a matching, reviewed pin change.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const serverRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Must match TRUSTED_ROOT_RELATIVE_PATH in src/verify-release/trust-root.ts.
const TRUSTED_ROOT_RELATIVE_PATH = "verify-release/trusted_root.json";

// Must match TRUSTED_ROOT_SHA256 in test/verify-release/trust-root.test.ts and
// the sha256 recorded in src/verify-release/README.md.
const EXPECTED_TRUSTED_ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

const sourcePath = resolve(serverRoot, "src", TRUSTED_ROOT_RELATIVE_PATH);
const destinationPath = resolve(serverRoot, "dist", TRUSTED_ROOT_RELATIVE_PATH);

const verifyOnly = process.argv.includes("--verify-only");
for (const argument of process.argv.slice(2)) {
  if (argument !== "--verify-only") throw new Error(`unknown argument: ${argument}`);
}

const bytes = await readFile(sourcePath);
const digest = createHash("sha256").update(bytes).digest("hex");
if (digest !== EXPECTED_TRUSTED_ROOT_SHA256) {
  throw new Error(`verify-release trusted root digest mismatch: ${digest} (expected ${EXPECTED_TRUSTED_ROOT_SHA256})`);
}

if (verifyOnly) {
  process.stdout.write(`verified verify-release trusted root ${digest}\n`);
  process.exit(0);
}

await mkdir(dirname(destinationPath), { recursive: true });
await writeFile(destinationPath, bytes);
const copied = createHash("sha256").update(await readFile(destinationPath)).digest("hex");
if (copied !== digest) throw new Error(`copied verify-release trusted root digest mismatch: ${copied}`);
process.stdout.write(`copied verify-release trusted root -> dist/${TRUSTED_ROOT_RELATIVE_PATH}\n`);
