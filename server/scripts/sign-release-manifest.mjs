#!/usr/bin/env tsx
/*
 * Sanctuary MCP Server: sign a release manifest for the signed-update path.
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * What this does (Seam 2 of the signed self-update wiring):
 *   1. Runs `npm pack` on the current build to produce the EXACT publishable
 *      tarball (the same bytes `npm publish` would upload).
 *   2. Computes the tarball's SHA-256.
 *   3. Builds the ReleaseManifestBody { version, artifact_hashes: { <name>: <hex> } }.
 *   4. Signs the domain-separated canonical message using the SAME primitives
 *      the runtime verifier uses (buildReleaseManifestMessage from
 *      release-manifest.ts + the project's core Ed25519 signing surface).
 *   5. Writes release-manifest.json (signed body + detached base64url signature).
 *
 * The private signing key is read ONLY from the env var
 * SANCTUARY_RELEASE_SIGNING_KEY_B64URL (base64url of the 32-byte Ed25519 seed).
 * It is never hardcoded and never logged. If the env var is absent the script
 * fails loudly (non-zero exit) so a release never silently produces an unsigned
 * or misfiled manifest.
 *
 * Invoke via: npm run sign-release -- <version> [--out <path>]
 *   <version>  must match server/package.json version (guard below).
 *   --out      output path for release-manifest.json (default: cwd).
 *
 * This script is invoked from the Publish workflow AFTER npm publish, with the
 * private key sourced from the GitHub Actions secret RELEASE_SIGNING_KEY. The
 * key was ACTIVATED 2026-07-01; the workflow fails closed BEFORE publishing if
 * the secret is empty or absent (step "Require release signing key"), and this
 * script's own missing-env failure is the second, unconditional layer of that
 * gate. There is no skip path: a publish without a signed manifest is a defect.
 *
 * Crypto is NOT hand-rolled: canonicalization + the signed-message construction
 * come from release-manifest.ts; the Ed25519 sign primitive comes from
 * @noble/curves, the same library core/identity.ts wraps for verification.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { buildReleaseManifestMessage } from "../src/release-manifest.js";
import { fromBase64url, toBase64url } from "../src/core/encoding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_DIR = resolve(__dirname, "..");
const PRIVATE_KEY_ENV = "SANCTUARY_RELEASE_SIGNING_KEY_B64URL";
const ED25519_SEED_LENGTH = 32;

/** Print an error and exit non-zero. Never prints key material. */
function die(message) {
  // SAFETY: build/release script; stderr is the only operator-facing channel and there is no logger in a standalone .mjs build script.
  console.error(`[sign-release] ERROR: ${message}`);
  process.exit(1);
}

/** Parse argv: first positional is the version; --out <path> is optional. */
function parseArgs(argv) {
  const args = argv.slice(2);
  let version;
  let out = process.cwd();
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--out") {
      out = args[i + 1];
      i++;
    } else if (!a.startsWith("--") && version === undefined) {
      version = a;
    }
  }
  return { version, out };
}

function main() {
  const { version, out } = parseArgs(process.argv);

  if (!version) {
    die("missing <version> argument. Usage: npm run sign-release -- <version> [--out <path>]");
  }

  // Fail loudly if the signing key is absent. This is the pre-activation guard
  // at the script layer (the workflow layer skips before reaching here, but a
  // manual/local invocation must also refuse rather than emit an unsigned file).
  const keyB64 = process.env[PRIVATE_KEY_ENV];
  if (!keyB64 || keyB64.trim().length === 0) {
    die(
      `${PRIVATE_KEY_ENV} is not set. Refusing to produce a manifest without a signing key. ` +
        "This env var must hold the base64url Ed25519 signing seed (32 bytes).",
    );
  }

  // Verify the on-disk package version matches the requested version, so a
  // manifest can never attest a different version than what is packed.
  const pkg = JSON.parse(readFileSync(join(SERVER_DIR, "package.json"), "utf8"));
  if (pkg.version !== version) {
    die(
      `requested version (${version}) does not match server/package.json version (${pkg.version}). ` +
        "Refusing to sign a mismatched manifest.",
    );
  }

  // Decode the signing seed. Never log the decoded bytes or the raw env value.
  let seed;
  try {
    seed = fromBase64url(keyB64.trim());
  } catch {
    die(`${PRIVATE_KEY_ENV} is not valid base64url.`);
  }
  if (seed.length !== ED25519_SEED_LENGTH) {
    die(
      `${PRIVATE_KEY_ENV} decodes to ${seed.length} bytes; expected ${ED25519_SEED_LENGTH}. ` +
        "It must be the base64url of the 32-byte Ed25519 seed.",
    );
  }

  // Produce the EXACT publishable tarball via `npm pack` into an mkdtemp dir
  // (CodeQL js/insecure-temporary-file: never a static /tmp path).
  const packDir = mkdtempSync(join(tmpdir(), "sanctuary-release-"));
  let packOut;
  try {
    packOut = execFileSync(
      "npm",
      ["pack", "--json", "--pack-destination", packDir],
      { cwd: SERVER_DIR, encoding: "utf8" },
    );
  } catch (err) {
    // Do not surface arbitrary stdout that could echo env; report a bounded message.
    die(`npm pack failed: ${err && err.message ? err.message : "unknown error"}`);
  }

  let packInfo;
  try {
    packInfo = JSON.parse(packOut);
  } catch {
    die("could not parse `npm pack --json` output.");
  }
  const entry = Array.isArray(packInfo) ? packInfo[0] : packInfo;
  const tarballName = entry && entry.filename;
  if (typeof tarballName !== "string" || tarballName.length === 0) {
    die("`npm pack --json` did not report a tarball filename.");
  }

  // npm pack reports `filename` with the scope slash replaced by a dash in some
  // npm versions but writes the file under that same reported name to
  // --pack-destination. Resolve the actual written file.
  const tarballPath = join(packDir, tarballName);
  let tarballBytes;
  try {
    tarballBytes = readFileSync(tarballPath);
  } catch {
    die(`packed tarball not found at ${tarballPath}.`);
  }

  const sha256Hex = createHash("sha256").update(tarballBytes).digest("hex");

  const body = {
    version,
    artifact_hashes: {
      [tarballName]: sha256Hex,
    },
  };

  // Sign the domain-separated canonical message using the verifier's own
  // message construction, so the signed bytes are byte-identical to what
  // verifyReleaseManifest reconstructs at runtime.
  const message = buildReleaseManifestMessage(body);
  const signatureBytes = ed25519.sign(message, seed);
  // Zero the seed from memory as soon as signing is done.
  seed.fill(0);

  const manifest = {
    body,
    signature: toBase64url(signatureBytes),
  };

  const outPath = resolve(out.endsWith(".json") ? out : join(out, "release-manifest.json"));
  writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  // SAFETY: build/release script; stderr is the operator-facing progress channel and there is no logger in a standalone .mjs build script. No key material is printed.
  console.error(`[sign-release] wrote ${outPath}`);
  // SAFETY: build/release script; stderr is the operator-facing progress channel and there is no logger in a standalone .mjs build script.
  console.error(`[sign-release] version=${version} tarball=${tarballName} sha256=${sha256Hex}`);
}

main();
