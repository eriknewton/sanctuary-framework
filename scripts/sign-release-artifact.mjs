#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
} from "node:crypto";
import { basename, resolve } from "node:path";
import { writeFileSync } from "node:fs";
import {
  canonicalJson,
  MAX_RELEASE_TARBALL_BYTES,
  readBoundedRegularFile,
  RELEASE_MANIFEST_DOMAIN,
  RELEASE_VERSION_SHAPE,
  validatePackageIdentity,
} from "./release-artifact-lib.mjs";

const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const B64URL_SHAPE = /^[A-Za-z0-9_-]+$/;

function fail(message) {
  console.error(`Release signing refused: ${message}`);
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
  if (!B64URL_SHAPE.test(value) || value.includes("=")) fail(`${label} is not canonical base64url`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) {
    fail(`${label} must encode exactly ${expectedBytes} bytes`);
  }
  return decoded;
}

const args = argsOf(process.argv.slice(2));
if (!args.tarball || !args.version || !args.out || !args["expected-public-key"]) {
  fail("required: --tarball --version --out --expected-public-key");
}
if (!RELEASE_VERSION_SHAPE.test(args.version)) fail("version is not canonical semver");

const seedText = process.env.RELEASE_SIGNING_KEY;
if (!seedText) fail("RELEASE_SIGNING_KEY is empty or missing");
const seed = decodeBase64urlStrict(seedText, 32, "RELEASE_SIGNING_KEY");
const expectedPublicKey = decodeBase64urlStrict(args["expected-public-key"], 32, "expected public key");
if (expectedPublicKey.every((byte) => byte === 0)) fail("expected public key is the forbidden all-zero value");

try {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const derivedPublicKey = publicDer.subarray(SPKI_ED25519_PUBLIC_PREFIX.length);
  if (
    derivedPublicKey.length !== expectedPublicKey.length ||
    !timingSafeEqual(derivedPublicKey, expectedPublicKey)
  ) {
    fail("signing seed does not match the public key pinned by shipped clients");
  }

  const tarballPath = resolve(args.tarball);
  let tarball;
  try {
    tarball = readBoundedRegularFile(tarballPath, MAX_RELEASE_TARBALL_BYTES, "tarball");
  } catch (error) {
    fail(error instanceof Error ? error.message : "tarball is not readable");
  }
  try {
    validatePackageIdentity(tarball, basename(tarballPath), args.version);
  } catch (error) {
    fail(error instanceof Error ? error.message : "tarball package identity validation failed");
  }
  const body = {
    artifact_hashes: {
      [basename(tarballPath)]: createHash("sha256").update(tarball).digest("hex"),
    },
    version: args.version,
  };
  const message = Buffer.concat([Buffer.from(RELEASE_MANIFEST_DOMAIN, "utf8"), Buffer.from(canonicalJson(body), "utf8")]);
  const signature = sign(null, message, privateKey).toString("base64url");
  writeFileSync(resolve(args.out), `${JSON.stringify({ body, signature }, null, 2)}\n`, { mode: 0o644 });
  console.log(`Signed ${basename(tarballPath)} for release ${args.version}.`);
} finally {
  seed.fill(0);
}
