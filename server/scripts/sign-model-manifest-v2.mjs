#!/usr/bin/env tsx
/*
 * Sanctuary MCP Server: build and sign the packaged V2 model manifest.
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * LOCAL SIGNING CEREMONY (operator-run; not invoked by any workflow).
 *
 * What this does:
 *   1. Reads the reviewed source list of models at
 *      server/model-catalog/model-manifest-v2.source.json (identities, license
 *      metadata, tier bands, surface defaults; no digests).
 *   2. Fetches each model's exact Ollama manifest from the pinned registry and
 *      records SHA-256 over the manifest bytes as `ollama_manifest_sha256`.
 *      That digest is what `/api/tags` reports and what the on-disk manifest
 *      hashes to, so the signed root and the runtime evidence are the same
 *      object. The fetch is bounded (timeout, byte cap, no redirects).
 *   3. Builds the `sanctuary.model-manifest.v2` body and validates it with the
 *      SHARED runtime parser (`parseModelManifestV2Json`); there is no second
 *      schema here.
 *   4. Refuses a non-monotonic `manifest_version` against the asset already at
 *      the output path.
 *   5. Signs domain + "\n" + canonical JSON of the body with Ed25519, using the
 *      seed read ONLY from SANCTUARY_MODEL_CATALOG_ROOT_SEED_B64URL, after
 *      checking that the seed derives the compiled model-catalog root pin.
 *   6. Self-verifies the envelope with the SAME verifier the runtime uses and
 *      refuses to write on any mismatch; then writes the asset atomically and
 *      rewrites the two build-pin constants (loader module + copy script) to
 *      the new asset digest.
 *
 * `--placeholder` produces the same body with an all-zero signature and no
 * seed: the tree then carries an asset that every consumer REFUSES
 * (`zero_signature`) instead of no asset, so it is never silently unverified.
 *
 * Usage:
 *   SANCTUARY_MODEL_CATALOG_ROOT_SEED_B64URL=... npm run sign-model-manifest
 *   npm run sign-model-manifest -- --placeholder
 *   Options: [--source <path>] [--out <path>] [--repin-root <dir>] [--no-repin]
 *            [--registry-origin <origin>] [--test-trust-root-b64url <key>]
 *
 * `--registry-origin` and `--test-trust-root-b64url` exist for the round-trip
 * test with an ephemeral key against a loopback registry. An asset signed
 * under a test root cannot load at runtime: the loader only accepts the
 * compiled pin, so a misuse fails closed there.
 *
 * Crypto is NOT hand-rolled: the message construction, the parser, and the
 * verifier are the runtime's own modules; Ed25519 signing is @noble/curves,
 * the library core/identity.ts wraps for verification.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64urlStrict, toBase64url } from "../src/core/encoding.js";
import { IMMUNE_OCI_MANIFEST_MAX_BYTES } from "../src/intelligence/immune-disk-verifier.js";
import { loadPinnedModelManifestKey } from "../src/intelligence/model-manifest.js";
import {
  MODEL_MANIFEST_V2_REGISTRY,
  MODEL_MANIFEST_V2_SCHEMA_VERSION,
  buildModelManifestV2Message,
  computeModelManifestV2BodyDigest,
  deriveOllamaRuntimeTag,
  parseModelManifestV2Json,
  verifyModelManifestV2WithKey,
} from "../src/intelligence/model-manifest-v2.js";
import { PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH } from "../src/intelligence/packaged-model-manifest.js";
import { parseStrictJson } from "../src/substrate/strict-json.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_DIR = resolve(__dirname, "..");
const SEED_ENV = "SANCTUARY_MODEL_CATALOG_ROOT_SEED_B64URL";
const ED25519_SEED_LENGTH = 32;
// 86 = unpadded base64url length of a 64-byte Ed25519 signature; all "A" is all-zero bytes.
const ALL_ZERO_SIGNATURE_B64URL = "A".repeat(86);
const DEFAULT_REGISTRY_ORIGIN = `https://${MODEL_MANIFEST_V2_REGISTRY}`;
const REGISTRY_FETCH_TIMEOUT_MS = 20_000;
const DOCKER_MANIFEST_V2_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json";
const DEFAULT_SOURCE = join(SERVER_DIR, "model-catalog", "model-manifest-v2.source.json");
const DEFAULT_OUT = join(SERVER_DIR, "src", PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH);
// Both pins are rewritten together; the loader and the copy script each carry
// a "must match" comment naming the other.
const PIN_TARGETS = [
  { file: join("src", "intelligence", "packaged-model-manifest.ts"), name: "PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256" },
  { file: join("scripts", "copy-model-manifest-v2-asset.mjs"), name: "EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256" },
];

/** Print an error and exit non-zero. Never prints key material. */
function die(message) {
  // SAFETY: operator-run signing script; stderr is the only operator-facing channel and there is no logger in a standalone .mjs script.
  console.error(`[sign-model-manifest] ERROR: ${message}`);
  process.exit(1);
}

function note(message) {
  // SAFETY: operator-run signing script; stderr is the operator-facing progress channel and there is no logger in a standalone .mjs script. No key material is printed.
  console.error(`[sign-model-manifest] ${message}`);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    source: DEFAULT_SOURCE,
    out: DEFAULT_OUT,
    placeholder: false,
    repin: true,
    repinRoot: SERVER_DIR,
    registryOrigin: DEFAULT_REGISTRY_ORIGIN,
    testTrustRoot: null,
  };
  const takeValue = (flag, index) => {
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) die(`${flag} requires a value`);
    return value;
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    switch (argument) {
      case "--source": options.source = resolve(takeValue(argument, index)); index += 1; break;
      case "--out": options.out = resolve(takeValue(argument, index)); index += 1; break;
      case "--repin-root": options.repinRoot = resolve(takeValue(argument, index)); index += 1; break;
      case "--registry-origin": options.registryOrigin = takeValue(argument, index); index += 1; break;
      case "--test-trust-root-b64url": options.testTrustRoot = takeValue(argument, index); index += 1; break;
      case "--placeholder": options.placeholder = true; break;
      case "--no-repin": options.repin = false; break;
      default: die(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value, expected) {
  return isRecord(value) && Object.keys(value).sort().join(",") === [...expected].sort().join(",");
}

/** Only the production registry over TLS, or a loopback test registry. */
function validateRegistryOrigin(origin) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    die(`--registry-origin is not a URL: ${origin}`);
  }
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "" || url.username || url.password) {
    die("--registry-origin must be a bare origin");
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "[::1]";
  if (url.protocol === "https:" && url.host === MODEL_MANIFEST_V2_REGISTRY) return url.origin;
  if (url.protocol === "http:" && loopback) {
    note(`NON-PRODUCTION registry origin ${url.origin}; digests are for a test round-trip only`);
    return url.origin;
  }
  die(`--registry-origin must be ${DEFAULT_REGISTRY_ORIGIN} or a loopback http origin`);
}

/**
 * Fetch one Ollama manifest and return SHA-256 over its exact bytes. The body
 * is read as a stream and the request is aborted the moment the running total
 * passes the cap, so a missing or lying Content-Length cannot make the tool
 * buffer more than the cap plus one chunk. The cap equals the immune
 * verifier's cap for the same on-disk object.
 */
async function fetchManifestDigest(origin, identity) {
  const url = `${origin}/v2/${identity.namespace}/${identity.model}/manifests/${identity.tag}`;
  const abort = new AbortController();
  let response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { accept: DOCKER_MANIFEST_V2_MEDIA_TYPE },
      redirect: "error",
      signal: AbortSignal.any([AbortSignal.timeout(REGISTRY_FETCH_TIMEOUT_MS), abort.signal]),
    });
  } catch (error) {
    die(`fetch failed for ${url}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  if (response.status !== 200) die(`registry returned HTTP ${response.status} for ${url}`);
  // Early refusal on an honest header; the streaming cap below is the guard.
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > IMMUNE_OCI_MANIFEST_MAX_BYTES) {
    abort.abort();
    die(`manifest for ${url} declares ${declared} bytes; cap is ${IMMUNE_OCI_MANIFEST_MAX_BYTES}`);
  }
  if (response.body === null) die(`registry returned no body for ${url}`);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > IMMUNE_OCI_MANIFEST_MAX_BYTES) {
        abort.abort();
        await reader.cancel().catch(() => undefined);
        die(`manifest for ${url} exceeded the ${IMMUNE_OCI_MANIFEST_MAX_BYTES}-byte cap while streaming; request aborted`);
      }
      chunks.push(value);
    }
  } catch (error) {
    die(`stream failed for ${url}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  const bytes = new Uint8Array(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
  if (bytes.length === 0) die(`manifest for ${url} is empty`);
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    die(`manifest for ${url} is not UTF-8 JSON`);
  }
  if (
    !isRecord(manifest) || manifest.schemaVersion !== 2
    || manifest.mediaType !== DOCKER_MANIFEST_V2_MEDIA_TYPE
    || !isRecord(manifest.config) || typeof manifest.config.digest !== "string"
    || !/^sha256:[0-9a-f]{64}$/.test(manifest.config.digest)
    || !Array.isArray(manifest.layers) || manifest.layers.length === 0
  ) {
    die(`manifest for ${url} is not a schemaVersion-2 Docker distribution manifest`);
  }
  return {
    digest: createHash("sha256").update(bytes).digest("hex"),
    fetchedAt: new Date().toISOString(),
    bytes: bytes.length,
  };
}

function readSource(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    die(`cannot read source ${path}`);
  }
  let source;
  try {
    source = parseStrictJson(text);
  } catch (error) {
    die(`source is not strict JSON: ${error instanceof Error ? error.message : "parse error"}`);
  }
  if (!exactKeys(source, ["manifest_version", "models", "tiers", "surface_defaults"])) {
    die("source must have exactly the keys manifest_version, models, tiers, surface_defaults");
  }
  if (!isRecord(source.models) || Object.keys(source.models).length === 0) die("source.models must be a non-empty object");
  for (const [modelId, entry] of Object.entries(source.models)) {
    if (!exactKeys(entry, [
      "model_name", "model_version", "provider", "ollama_identity", "params_b", "license", "open_weights", "open_source",
    ])) {
      die(`source model ${modelId} has unexpected keys (the tool fills model_id, runtime, registry, and the digest)`);
    }
    if (!exactKeys(entry.ollama_identity, ["namespace", "model", "tag"])) {
      die(`source model ${modelId} ollama_identity must have exactly namespace, model, tag`);
    }
    for (const part of ["namespace", "model", "tag"]) {
      if (typeof entry.ollama_identity[part] !== "string") die(`source model ${modelId} ${part} must be a string`);
    }
  }
  return source;
}

async function buildBody(source, registryOrigin) {
  const models = {};
  const fetched = [];
  for (const [modelId, entry] of Object.entries(source.models)) {
    const identity = entry.ollama_identity;
    const evidence = await fetchManifestDigest(registryOrigin, identity);
    models[modelId] = {
      model_id: modelId,
      model_name: entry.model_name,
      model_version: entry.model_version,
      provider: entry.provider,
      runtime: "ollama",
      ollama_identity: {
        registry: MODEL_MANIFEST_V2_REGISTRY,
        namespace: identity.namespace,
        model: identity.model,
        tag: identity.tag,
        ollama_manifest_sha256: evidence.digest,
      },
      params_b: entry.params_b,
      license: entry.license,
      open_weights: entry.open_weights,
      open_source: entry.open_source,
    };
    fetched.push({ modelId, ...evidence });
  }
  const body = {
    schema_version: MODEL_MANIFEST_V2_SCHEMA_VERSION,
    manifest_version: source.manifest_version,
    models,
    tiers: source.tiers,
    surface_defaults: source.surface_defaults,
  };
  // Shared-parser validation (rule 11): the signature placeholder is a
  // non-empty string so the parser walks the body; nothing is verified here.
  const parsed = parseModelManifestV2Json(JSON.stringify({ body, signature: ALL_ZERO_SIGNATURE_B64URL }));
  if (!parsed.ok) die(`body rejected by the shared V2 parser: ${parsed.reason}`);
  return { body, fetched };
}

/** Enforce monotonic manifest_version against whatever already sits at `out`. */
function checkMonotonic(outPath, newVersion, trustRoot) {
  if (!existsSync(outPath)) return "no existing asset";
  const existingText = readFileSync(outPath, "utf8");
  const parsed = parseModelManifestV2Json(existingText);
  if (!parsed.ok) {
    die(`existing asset at ${outPath} is not a parseable V2 envelope (${parsed.reason}); remove it deliberately before re-signing`);
  }
  const existingVersion = parsed.value.body.manifest_version;
  const verified = verifyModelManifestV2WithKey(existingText, trustRoot).ok;
  if (verified && newVersion <= existingVersion) {
    die(`manifest_version ${newVersion} is not greater than the verified existing asset version ${existingVersion}`);
  }
  if (!verified && newVersion < existingVersion) {
    die(`manifest_version ${newVersion} is below the existing (unverified placeholder) asset version ${existingVersion}`);
  }
  return `existing asset version ${existingVersion} (${verified ? "verified" : "unverified placeholder"})`;
}

function resolveTrustRoot(testTrustRoot) {
  if (testTrustRoot !== null) {
    let key;
    try {
      key = fromBase64urlStrict(testTrustRoot);
    } catch {
      die("--test-trust-root-b64url is not canonical base64url");
    }
    if (key.length !== ED25519_SEED_LENGTH) die("--test-trust-root-b64url must decode to 32 bytes");
    note("NON-PRODUCTION trust root override in effect; the runtime loader will REFUSE this asset");
    return key;
  }
  const pinned = loadPinnedModelManifestKey();
  if (pinned === null) die("the compiled model-catalog root pin is unavailable; refusing to sign");
  return pinned;
}

/**
 * Read and check the seed BEFORE any fetch or file read, so a wrong or missing
 * seed fails fast and a foreign key never gets as far as a signature. The
 * returned bytes are zeroed by `signWith` or on any later refusal.
 */
function loadSeed(trustRoot) {
  const seedB64 = process.env[SEED_ENV];
  if (!seedB64 || seedB64.trim().length === 0) {
    die(`${SEED_ENV} is not set. Refusing to produce a signed manifest without the catalog root seed (use --placeholder for an unsigned tree state).`);
  }
  let seed;
  try {
    seed = fromBase64urlStrict(seedB64.trim());
  } catch {
    die(`${SEED_ENV} is not canonical base64url.`);
  }
  if (seed.length !== ED25519_SEED_LENGTH) {
    seed.fill(0);
    die(`${SEED_ENV} decodes to the wrong length; expected the 32-byte Ed25519 seed.`);
  }
  const derived = ed25519.getPublicKey(seed);
  if (toBase64url(derived) !== toBase64url(trustRoot)) {
    seed.fill(0);
    die("the seed does not derive the compiled model-catalog root public key; refusing to sign under a foreign key");
  }
  return seed;
}

function signWith(seed, body) {
  const signature = ed25519.sign(buildModelManifestV2Message(body), seed);
  seed.fill(0);
  return toBase64url(signature);
}

function repin(repinRoot, digest) {
  const touched = [];
  for (const target of PIN_TARGETS) {
    const path = join(repinRoot, target.file);
    let text;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      die(`cannot read pin target ${path}`);
    }
    const pattern = new RegExp(`(${target.name}\\s*=\\s*\\n?\\s*")([0-9a-f]{64})(")`, "g");
    const matches = [...text.matchAll(pattern)];
    if (matches.length !== 1) die(`expected exactly one ${target.name} pin in ${path}; found ${matches.length}`);
    const previous = matches[0][2];
    const updated = text.replace(pattern, `$1${digest}$3`);
    writeFileSync(path, updated, "utf8");
    touched.push({ path, previous });
  }
  return touched;
}

async function main() {
  const options = parseArgs(process.argv);
  const registryOrigin = validateRegistryOrigin(options.registryOrigin);
  if (options.testTrustRoot !== null) {
    // A test root must never touch the compiled pins or the packaged asset:
    // repinning to a test-key asset would make the build accept bytes the
    // runtime pin can never verify. Test runs write and repin only in a
    // staging root outside this checkout, or not at all.
    if (options.repin && options.repinRoot === SERVER_DIR) {
      die("--test-trust-root-b64url refuses to repin the compiled constants; pass --no-repin or a --repin-root outside the server checkout");
    }
    const packagedDir = join(SERVER_DIR, "src", "intelligence", "model-manifest");
    if (options.out === DEFAULT_OUT || options.out.startsWith(`${packagedDir}${sep}`) || options.out.startsWith(`${join(SERVER_DIR, "src")}${sep}`)) {
      die("--test-trust-root-b64url refuses to write under the packaged asset path; pass an --out outside the server checkout");
    }
  }
  const trustRoot = resolveTrustRoot(options.testTrustRoot);
  const seed = options.placeholder ? null : loadSeed(trustRoot);
  const source = readSource(options.source);
  const { body, fetched } = await buildBody(source, registryOrigin);
  const monotonic = checkMonotonic(options.out, body.manifest_version, trustRoot);

  const signature = seed === null ? ALL_ZERO_SIGNATURE_B64URL : signWith(seed, body);
  const text = `${JSON.stringify({ body, signature }, null, 2)}\n`;

  // Self-verify with the runtime verifier before anything is written.
  const verified = verifyModelManifestV2WithKey(text, trustRoot);
  if (options.placeholder) {
    if (verified.ok || verified.reason !== "zero_signature") {
      die(`placeholder self-check expected zero_signature refusal, got ${verified.ok ? "ok" : verified.reason}`);
    }
  } else if (!verified.ok) {
    die(`self-verification failed (${verified.reason}); nothing written`);
  }

  const temporary = `${options.out}.tmp-${process.pid}`;
  writeFileSync(temporary, text, "utf8");
  renameSync(temporary, options.out);
  const assetDigest = createHash("sha256").update(readFileSync(options.out)).digest("hex");
  const touched = options.repin ? repin(options.repinRoot, assetDigest) : [];

  note(`mode=${options.placeholder ? "PLACEHOLDER (all-zero signature; every consumer refuses it)" : "SIGNED"}`);
  note(`trust root (b64url)=${toBase64url(trustRoot)} hex=${Buffer.from(trustRoot).toString("hex")}`);
  note(`manifest_version=${body.manifest_version}; ${monotonic}`);
  for (const entry of fetched) {
    const model = body.models[entry.modelId];
    note(`model ${entry.modelId} -> ${deriveOllamaRuntimeTag(model.ollama_identity)} ollama_manifest_sha256=${entry.digest} (${entry.bytes} manifest bytes, fetched ${entry.fetchedAt})`);
  }
  note(`body sha256=${computeModelManifestV2BodyDigest(body)}`);
  note(`asset sha256=${assetDigest} written to ${options.out}`);
  if (touched.length === 0) {
    note("pins NOT rewritten (--no-repin); the build will refuse until both pin constants equal the asset sha256");
  }
  for (const entry of touched) note(`repinned ${entry.path} (${entry.previous} -> ${assetDigest})`);
}

await main();
