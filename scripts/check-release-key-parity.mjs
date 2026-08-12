#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const repoRoot = new URL("..", import.meta.url).pathname;
let workflowPath = join(repoRoot, ".github", "workflows", "publish-on-tag.yml");
let sourcePath = join(repoRoot, "server", "src", "release-manifest.ts");

if (process.argv.length > 2) {
  if (process.argv.length !== 6 || process.argv[2] !== "--workflow" || process.argv[4] !== "--source") {
    console.error("Usage: check-release-key-parity.mjs [--workflow <path> --source <path>]");
    process.exit(2);
  }
  workflowPath = resolve(process.argv[3]);
  sourcePath = resolve(process.argv[5]);
}

function oneMatch(source, pattern, label) {
  const values = [...source.matchAll(pattern)].map((match) => match[1]);
  if (values.length !== 1) {
    console.error(`Release key parity check failed: expected exactly one ${label}, found ${values.length}.`);
    process.exit(1);
  }
  return values[0];
}

function decodeKey(value, label) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) {
    console.error(`Release key parity check failed: ${label} is not canonical unpadded base64url.`);
    process.exit(1);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== value || decoded.every((byte) => byte === 0)) {
    console.error(`Release key parity check failed: ${label} must encode one nonzero 32-byte Ed25519 public key.`);
    process.exit(1);
  }
  return decoded;
}

const workflow = readFileSync(workflowPath, "utf8");
const source = readFileSync(sourcePath, "utf8");
const workflowKey = oneMatch(workflow, /^\s{2}RELEASE_PUBLIC_KEY_B64URL:\s*([A-Za-z0-9_-]+)\s*$/gm, "workflow release public key");
const productKey = oneMatch(source, /^export const PINNED_RELEASE_SIGNING_PUBLIC_KEY_B64URL\s*=\s*\n\s*"([A-Za-z0-9_-]+)";\s*$/gm, "product pinned release public key");
const workflowBytes = decodeKey(workflowKey, "workflow release public key");
const productBytes = decodeKey(productKey, "product pinned release public key");

if (!workflowBytes.equals(productBytes)) {
  console.error("Release key parity check failed: workflow signer/verifier key differs from the key pinned by shipped clients.");
  process.exit(1);
}

console.log("Release key parity check passed: workflow and shipped-client public keys match.");
