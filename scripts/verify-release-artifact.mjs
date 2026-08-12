#!/usr/bin/env node
import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { basename, resolve } from "node:path";
import {
  canonicalJson,
  MAX_RELEASE_TARBALL_BYTES,
  readBoundedRegularFile,
  RELEASE_MANIFEST_DOMAIN,
  RELEASE_VERSION_SHAPE,
  validatePackageIdentity,
} from "./release-artifact-lib.mjs";

const SPKI_ED25519_PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HASH_SHAPE = /^[0-9a-f]{64}$/;
const B64URL_SHAPE = /^[A-Za-z0-9_-]+$/;
const MAX_MANIFEST_BYTES = 64 * 1024;

function fail(message) {
  console.error(`Release verification refused: ${message}`);
  process.exit(1);
}

function argsOf(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith("--") || value === undefined) fail("invalid arguments");
    result[key.slice(2)] = value;
  }
  return result;
}

function decodeBase64urlStrict(value, expectedBytes, label) {
  if (typeof value !== "string" || !B64URL_SHAPE.test(value) || value.includes("=")) {
    fail(`${label} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) {
    fail(`${label} must encode exactly ${expectedBytes} bytes`);
  }
  return decoded;
}

const args = argsOf(process.argv.slice(2));
if (!args.tarball || !args.manifest || !args.version || !args["expected-public-key"]) {
  fail("required: --tarball --manifest --version --expected-public-key");
}
if (!RELEASE_VERSION_SHAPE.test(args.version)) fail("version is not canonical semver");

const manifestPath = resolve(args.manifest);
let manifestBytes;
try {
  manifestBytes = readBoundedRegularFile(manifestPath, MAX_MANIFEST_BYTES, "manifest").toString("utf8");
} catch {
  fail("manifest is not readable");
}
let manifest;
try {
  manifest = JSON.parse(manifestBytes);
} catch {
  fail("manifest is invalid JSON");
}
if (
  manifest === null ||
  typeof manifest !== "object" ||
  Array.isArray(manifest) ||
  Object.keys(manifest).sort().join(",") !== "body,signature" ||
  manifest.body === null ||
  typeof manifest.body !== "object" ||
  Array.isArray(manifest.body) ||
  Object.keys(manifest.body).sort().join(",") !== "artifact_hashes,version" ||
  manifest.body.version !== args.version
) {
  fail("manifest shape or version is invalid");
}

const tarballPath = resolve(args.tarball);
const tarballName = basename(tarballPath);
let tarball;
try {
  tarball = readBoundedRegularFile(tarballPath, MAX_RELEASE_TARBALL_BYTES, "tarball");
} catch (error) {
  fail(error instanceof Error ? error.message : "tarball is not readable");
}
try {
  validatePackageIdentity(tarball, tarballName, args.version);
} catch (error) {
  fail(error instanceof Error ? error.message : "tarball package identity validation failed");
}
const hashes = manifest.body.artifact_hashes;
if (
  hashes === null ||
  typeof hashes !== "object" ||
  Array.isArray(hashes) ||
  Object.keys(hashes).length !== 1 ||
  !Object.hasOwn(hashes, tarballName) ||
  !HASH_SHAPE.test(hashes[tarballName])
) {
  fail("manifest must hash exactly the supplied tarball");
}

const actualHash = createHash("sha256").update(tarball).digest();
const expectedHash = Buffer.from(hashes[tarballName], "hex");
if (!timingSafeEqual(actualHash, expectedHash)) fail("tarball hash mismatch");

const publicKey = decodeBase64urlStrict(args["expected-public-key"], 32, "expected public key");
const signature = decodeBase64urlStrict(manifest.signature, 64, "signature");
if (publicKey.every((byte) => byte === 0)) fail("expected public key is the forbidden all-zero value");
if (signature.every((byte) => byte === 0)) fail("signature is the forbidden all-zero value");
const publicKeyObject = createPublicKey({
  key: Buffer.concat([SPKI_ED25519_PUBLIC_PREFIX, publicKey]),
  format: "der",
  type: "spki",
});
const message = Buffer.concat([Buffer.from(RELEASE_MANIFEST_DOMAIN, "utf8"), Buffer.from(canonicalJson(manifest.body), "utf8")]);
if (!verify(null, message, publicKeyObject, signature)) fail("signature is invalid");

console.log(`Verified ${tarballName} for release ${args.version}.`);
