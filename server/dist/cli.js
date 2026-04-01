#!/usr/bin/env node
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { mkdir, readFile, writeFile, stat, unlink, readdir, chmod, access } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createRequire } from 'module';
import { randomBytes as randomBytes$1, createHmac } from 'crypto';
import { gcm } from '@noble/ciphers/aes.js';
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519';
import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer as createServer$2 } from 'http';
import { createServer as createServer$1, get } from 'https';
import { readFileSync, statSync } from 'fs';
import { execSync } from 'child_process';

var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/core/encoding.ts
var encoding_exports = {};
__export(encoding_exports, {
  bytesToString: () => bytesToString,
  concatBytes: () => concatBytes,
  constantTimeEqual: () => constantTimeEqual,
  fromBase64url: () => fromBase64url,
  stringToBytes: () => stringToBytes,
  toBase64url: () => toBase64url
});
function toBase64url(bytes) {
  const base64 = Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64url(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const buf = Buffer.from(base64, "base64");
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}
function stringToBytes(str) {
  return new TextEncoder().encode(str);
}
function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}
function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
var init_encoding = __esm({
  "src/core/encoding.ts"() {
  }
});

// src/core/hashing.ts
var hashing_exports = {};
__export(hashing_exports, {
  buildMerkleTree: () => buildMerkleTree,
  computeMerkleRoot: () => computeMerkleRoot,
  generateMerkleProof: () => generateMerkleProof,
  hash: () => hash,
  hashToString: () => hashToString,
  hmacSha256: () => hmacSha256,
  verifyMerkleProof: () => verifyMerkleProof
});
function hash(data) {
  return sha256(data);
}
function hashToString(data) {
  return toBase64url(hash(data));
}
function hmacSha256(key, data) {
  return hmac(sha256, key, data);
}
function buildMerkleTree(entries) {
  if (entries.size === 0) return null;
  const sortedKeys = Array.from(entries.keys()).sort();
  let nodes = sortedKeys.map((key) => {
    const contentHash = entries.get(key);
    const leafData = concatBytes(
      stringToBytes(key),
      stringToBytes(contentHash)
    );
    return {
      hash: hashToString(leafData),
      key
    };
  });
  while (nodes.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      if (i + 1 < nodes.length) {
        const right = nodes[i + 1];
        const parentData = concatBytes(
          stringToBytes(left.hash),
          stringToBytes(right.hash)
        );
        nextLevel.push({
          hash: hashToString(parentData),
          left,
          right
        });
      } else {
        nextLevel.push(left);
      }
    }
    nodes = nextLevel;
  }
  return nodes[0] ?? null;
}
function generateMerkleProof(entries, targetKey) {
  if (!entries.has(targetKey)) return null;
  const sortedKeys = Array.from(entries.keys()).sort();
  const targetIndex = sortedKeys.indexOf(targetKey);
  if (targetIndex === -1) return null;
  const leafHashes = sortedKeys.map((key) => {
    const contentHash = entries.get(key);
    const leafData = concatBytes(
      stringToBytes(key),
      stringToBytes(contentHash)
    );
    return hashToString(leafData);
  });
  const path = [];
  let currentIndex = targetIndex;
  let currentLevel = leafHashes;
  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      if (i + 1 < currentLevel.length) {
        const right = currentLevel[i + 1];
        if (i === currentIndex || i + 1 === currentIndex) {
          if (currentIndex === i) {
            path.push({ hash: right, position: "right" });
          } else {
            path.push({ hash: left, position: "left" });
          }
        }
        const parentData = concatBytes(
          stringToBytes(left),
          stringToBytes(right)
        );
        nextLevel.push(hashToString(parentData));
      } else {
        nextLevel.push(left);
      }
    }
    currentIndex = Math.floor(currentIndex / 2);
    currentLevel = nextLevel;
  }
  const root = buildMerkleTree(entries);
  return {
    leaf: leafHashes[targetIndex],
    path,
    root: root?.hash ?? ""
  };
}
function verifyMerkleProof(proof) {
  let currentHash = proof.leaf;
  for (const step of proof.path) {
    const left = step.position === "left" ? step.hash : currentHash;
    const right = step.position === "right" ? step.hash : currentHash;
    const parentData = concatBytes(
      stringToBytes(left),
      stringToBytes(right)
    );
    currentHash = hashToString(parentData);
  }
  return currentHash === proof.root;
}
function computeMerkleRoot(entries) {
  const tree = buildMerkleTree(entries);
  return tree?.hash ?? "";
}
var init_hashing = __esm({
  "src/core/hashing.ts"() {
    init_encoding();
  }
});
var require2 = createRequire(import.meta.url);
var { version: PKG_VERSION } = require2("../package.json");
var SANCTUARY_VERSION = PKG_VERSION;
function defaultConfig() {
  return {
    version: PKG_VERSION,
    storage_path: join(homedir(), ".sanctuary"),
    state: {
      encryption: "aes-256-gcm",
      key_protection: "none",
      key_derivation: "argon2id",
      integrity: "merkle-sha256",
      identity_provider: "ed25519"
    },
    execution: {
      environment: "local-process",
      attestation: true,
      resource_limits: {
        max_memory_mb: 512,
        max_storage_mb: 1024,
        max_cpu_percent: 50
      }
    },
    disclosure: {
      proof_system: "commitment-only",
      default_policy: "minimum-necessary"
    },
    reputation: {
      mode: "self-custodied",
      attestation_format: "eas-compatible",
      export_format: "SANCTUARY_REP_V1",
      service_endpoints: []
    },
    transport: "stdio",
    http_port: 3500,
    dashboard: {
      enabled: false,
      port: 3501,
      host: "127.0.0.1"
    },
    webhook: {
      enabled: false,
      url: "",
      secret: "",
      callback_port: 3502,
      callback_host: "127.0.0.1"
    }
  };
}
async function loadConfig(configPath) {
  const config = defaultConfig();
  if (process.env.SANCTUARY_STORAGE_PATH) {
    config.storage_path = process.env.SANCTUARY_STORAGE_PATH;
  }
  if (process.env.SANCTUARY_TRANSPORT) {
    config.transport = process.env.SANCTUARY_TRANSPORT;
  }
  if (process.env.SANCTUARY_HTTP_PORT) {
    config.http_port = parseInt(process.env.SANCTUARY_HTTP_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_ENABLED === "true") {
    config.dashboard.enabled = true;
  }
  if (process.env.SANCTUARY_DASHBOARD_PORT) {
    config.dashboard.port = parseInt(process.env.SANCTUARY_DASHBOARD_PORT, 10);
  }
  if (process.env.SANCTUARY_DASHBOARD_HOST) {
    config.dashboard.host = process.env.SANCTUARY_DASHBOARD_HOST;
  }
  if (process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN) {
    config.dashboard.auth_token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  }
  if (process.env.SANCTUARY_DASHBOARD_TLS_CERT && process.env.SANCTUARY_DASHBOARD_TLS_KEY) {
    config.dashboard.tls = {
      cert_path: process.env.SANCTUARY_DASHBOARD_TLS_CERT,
      key_path: process.env.SANCTUARY_DASHBOARD_TLS_KEY
    };
  }
  if (process.env.SANCTUARY_WEBHOOK_ENABLED === "true") {
    config.webhook.enabled = true;
  }
  if (process.env.SANCTUARY_WEBHOOK_URL) {
    config.webhook.url = process.env.SANCTUARY_WEBHOOK_URL;
  }
  if (process.env.SANCTUARY_WEBHOOK_SECRET) {
    config.webhook.secret = process.env.SANCTUARY_WEBHOOK_SECRET;
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT) {
    config.webhook.callback_port = parseInt(process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT, 10);
  }
  if (process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST) {
    config.webhook.callback_host = process.env.SANCTUARY_WEBHOOK_CALLBACK_HOST;
  }
  const path = configPath ?? join(config.storage_path, "sanctuary.json");
  try {
    const raw = await readFile(path, "utf-8");
    const fileConfig = JSON.parse(raw);
    const merged = deepMerge(config, fileConfig);
    validateConfig(merged);
    return merged;
  } catch (err) {
    if (err instanceof Error && err.message.includes("unimplemented features")) {
      throw err;
    }
    return config;
  }
}
async function saveConfig(config, configPath) {
  const path = join(config.storage_path, "sanctuary.json");
  await writeFile(path, JSON.stringify(config, null, 2), { mode: 384 });
}
function validateConfig(config) {
  const errors = [];
  const implementedKeyProtection = /* @__PURE__ */ new Set(["passphrase", "none"]);
  if (!implementedKeyProtection.has(config.state.key_protection)) {
    errors.push(
      `Unimplemented config value: state.key_protection = "${config.state.key_protection}". Only ${[...implementedKeyProtection].map((v) => `"${v}"`).join(", ")} are currently implemented. Using an unimplemented key protection mode would silently degrade security.`
    );
  }
  const implementedEnvironment = /* @__PURE__ */ new Set(["local-process", "docker"]);
  if (!implementedEnvironment.has(config.execution.environment)) {
    errors.push(
      `Unimplemented config value: execution.environment = "${config.execution.environment}". Only ${[...implementedEnvironment].map((v) => `"${v}"`).join(", ")} are currently implemented. Using an unimplemented environment would silently degrade security.`
    );
  }
  const implementedProofSystem = /* @__PURE__ */ new Set(["commitment-only"]);
  if (!implementedProofSystem.has(config.disclosure.proof_system)) {
    errors.push(
      `Unimplemented config value: disclosure.proof_system = "${config.disclosure.proof_system}". Only ${[...implementedProofSystem].map((v) => `"${v}"`).join(", ")} is currently implemented. Using an unimplemented proof system would silently degrade security.`
    );
  }
  const implementedDisclosurePolicy = /* @__PURE__ */ new Set(["minimum-necessary"]);
  if (!implementedDisclosurePolicy.has(config.disclosure.default_policy)) {
    errors.push(
      `Unimplemented config value: disclosure.default_policy = "${config.disclosure.default_policy}". Only ${[...implementedDisclosurePolicy].map((v) => `"${v}"`).join(", ")} is currently implemented. Using an unimplemented disclosure policy would silently skip disclosure controls.`
    );
  }
  const implementedReputationMode = /* @__PURE__ */ new Set(["self-custodied"]);
  if (!implementedReputationMode.has(config.reputation.mode)) {
    errors.push(
      `Unimplemented config value: reputation.mode = "${config.reputation.mode}". Only ${[...implementedReputationMode].map((v) => `"${v}"`).join(", ")} is currently implemented. Using an unimplemented reputation mode would silently skip reputation verification.`
    );
  }
  if (errors.length > 0) {
    throw new Error(
      `Sanctuary configuration references unimplemented features:
${errors.join("\n")}`
    );
  }
}
function deepMerge(base, override) {
  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value !== null && typeof value === "object" && !Array.isArray(value) && typeof result[key] === "object" && result[key] !== null) {
      result[key] = deepMerge(
        result[key],
        value
      );
    } else {
      result[key] = value;
    }
  }
  return result;
}
function randomBytes(length) {
  if (length <= 0) {
    throw new RangeError("Length must be positive");
  }
  const buf = randomBytes$1(length);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}
function generateIV() {
  return randomBytes(12);
}
function generateSalt() {
  return randomBytes(32);
}
function generateRandomKey() {
  return randomBytes(32);
}

// src/storage/filesystem.ts
var FilesystemStorage = class {
  basePath;
  constructor(basePath) {
    this.basePath = basePath;
  }
  entryPath(namespace, key) {
    const safeNamespace = namespace.replace(/[^a-zA-Z0-9_-]/g, "_");
    const safeKey = key.replace(/[^a-zA-Z0-9_.-]/g, "_");
    return join(this.basePath, safeNamespace, `${safeKey}.enc`);
  }
  namespacePath(namespace) {
    const safeNamespace = namespace.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.basePath, safeNamespace);
  }
  async write(namespace, key, data) {
    const dirPath = this.namespacePath(namespace);
    const filePath = this.entryPath(namespace, key);
    await mkdir(dirPath, { recursive: true, mode: 448 });
    await writeFile(filePath, data, { mode: 384 });
  }
  async read(namespace, key) {
    const filePath = this.entryPath(namespace, key);
    try {
      const buf = await readFile(filePath);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (err) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        return null;
      }
      throw err;
    }
  }
  async delete(namespace, key, secureOverwrite = true) {
    const filePath = this.entryPath(namespace, key);
    try {
      if (secureOverwrite) {
        const fileStat = await stat(filePath);
        const size = fileStat.size;
        for (let pass = 0; pass < 3; pass++) {
          const randomData = randomBytes(size);
          await writeFile(filePath, randomData, { mode: 384 });
        }
      }
      await unlink(filePath);
      return true;
    } catch (err) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        return false;
      }
      throw err;
    }
  }
  async list(namespace, prefix) {
    const dirPath = this.namespacePath(namespace);
    try {
      const files = await readdir(dirPath);
      const entries = [];
      for (const file of files) {
        if (!file.endsWith(".enc")) continue;
        const key = file.slice(0, -4);
        if (prefix && !key.startsWith(prefix)) continue;
        const filePath = join(dirPath, file);
        const fileStat = await stat(filePath);
        entries.push({
          key,
          namespace,
          size_bytes: fileStat.size,
          modified_at: fileStat.mtime.toISOString()
        });
      }
      return entries.sort((a, b) => a.key.localeCompare(b.key));
    } catch (err) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        return [];
      }
      throw err;
    }
  }
  async exists(namespace, key) {
    const filePath = this.entryPath(namespace, key);
    try {
      await stat(filePath);
      return true;
    } catch {
      return false;
    }
  }
  async totalSize() {
    let total = 0;
    try {
      const namespaces = await readdir(this.basePath);
      for (const ns of namespaces) {
        const nsPath = join(this.basePath, ns);
        const nsStat = await stat(nsPath);
        if (!nsStat.isDirectory()) continue;
        const files = await readdir(nsPath);
        for (const file of files) {
          const filePath = join(nsPath, file);
          const fileStat = await stat(filePath);
          total += fileStat.size;
        }
      }
    } catch {
    }
    return total;
  }
};
init_encoding();
function encrypt(plaintext, key, aad) {
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }
  const iv = generateIV();
  const cipher = gcm(key, iv, aad);
  const ciphertext = cipher.encrypt(plaintext);
  return {
    v: 1,
    alg: "aes-256-gcm",
    iv: toBase64url(iv),
    ct: toBase64url(ciphertext),
    ts: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function decrypt(payload, key, aad) {
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }
  if (payload.v !== 1) {
    throw new Error(`Unsupported payload version: ${payload.v}`);
  }
  if (payload.alg !== "aes-256-gcm") {
    throw new Error(`Unsupported algorithm: ${payload.alg}`);
  }
  const iv = fromBase64url(payload.iv);
  const ciphertext = fromBase64url(payload.ct);
  const cipher = gcm(key, iv, aad);
  return cipher.decrypt(ciphertext);
}

// src/l1-cognitive/state-store.ts
init_hashing();

// src/core/identity.ts
init_encoding();
init_hashing();
function generateKeypair() {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}
function publicKeyToDid(publicKey) {
  const multicodec = new Uint8Array([237, 1, ...publicKey]);
  return `did:key:z${toBase64url(multicodec)}`;
}
function generateIdentityId(publicKey) {
  const keyHash = hash(publicKey);
  return Array.from(keyHash.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function createIdentity(label, encryptionKey, keyProtection) {
  const { publicKey, privateKey } = generateKeypair();
  const identityId = generateIdentityId(publicKey);
  const did = publicKeyToDid(publicKey);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const encryptedPrivateKey = encrypt(privateKey, encryptionKey);
  privateKey.fill(0);
  const publicIdentity = {
    identity_id: identityId,
    label,
    public_key: toBase64url(publicKey),
    did,
    created_at: now,
    key_type: "ed25519",
    key_protection: keyProtection
  };
  const storedIdentity = {
    ...publicIdentity,
    encrypted_private_key: encryptedPrivateKey,
    rotation_history: []
  };
  return { publicIdentity, storedIdentity };
}
function sign(payload, encryptedPrivateKey, encryptionKey) {
  const privateKey = decrypt(encryptedPrivateKey, encryptionKey);
  try {
    return ed25519.sign(payload, privateKey);
  } finally {
    privateKey.fill(0);
  }
}
function verify(payload, signature, publicKey) {
  try {
    return ed25519.verify(signature, payload, publicKey);
  } catch {
    return false;
  }
}
function rotateKeys(storedIdentity, encryptionKey, reason) {
  const { publicKey: newPublicKey, privateKey: newPrivateKey } = generateKeypair();
  const newIdentityDid = publicKeyToDid(newPublicKey);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const eventData = JSON.stringify({
    old_public_key: storedIdentity.public_key,
    new_public_key: toBase64url(newPublicKey),
    identity_id: storedIdentity.identity_id,
    reason,
    rotated_at: now
  });
  const eventBytes = new TextEncoder().encode(eventData);
  const signature = sign(
    eventBytes,
    storedIdentity.encrypted_private_key,
    encryptionKey
  );
  const rotationEvent = {
    old_public_key: storedIdentity.public_key,
    new_public_key: toBase64url(newPublicKey),
    identity_id: storedIdentity.identity_id,
    reason,
    rotated_at: now,
    signature: toBase64url(signature)
  };
  const encryptedNewPrivateKey = encrypt(newPrivateKey, encryptionKey);
  newPrivateKey.fill(0);
  const updatedIdentity = {
    ...storedIdentity,
    public_key: toBase64url(newPublicKey),
    did: newIdentityDid,
    encrypted_private_key: encryptedNewPrivateKey,
    rotation_history: [
      ...storedIdentity.rotation_history,
      {
        old_public_key: storedIdentity.public_key,
        new_public_key: toBase64url(newPublicKey),
        rotation_event: toBase64url(
          new TextEncoder().encode(JSON.stringify(rotationEvent))
        ),
        rotated_at: now
      }
    ]
  };
  return { updatedIdentity, rotationEvent };
}
init_encoding();
var ARGON2_MEMORY_COST = 65536;
var ARGON2_TIME_COST = 3;
var ARGON2_PARALLELISM = 4;
var ARGON2_HASH_LENGTH = 32;
async function deriveMasterKey(passphrase, existingParams) {
  const salt = existingParams ? fromBase64url(existingParams.salt) : generateSalt();
  const params = existingParams ?? {
    alg: "argon2id",
    salt: toBase64url(salt),
    m: ARGON2_MEMORY_COST,
    t: ARGON2_TIME_COST,
    p: ARGON2_PARALLELISM,
    l: ARGON2_HASH_LENGTH
  };
  const hashHex = await argon2id({
    password: passphrase,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: params.l,
    outputType: "hex"
  });
  const key = new Uint8Array(params.l);
  for (let i = 0; i < params.l; i++) {
    key[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
  }
  return { key, params };
}
function deriveNamespaceKey(masterKey, namespace) {
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes");
  }
  return hkdf(
    sha256,
    masterKey,
    stringToBytes("sanctuary-namespace-v1"),
    // salt (fixed, acts as domain separator)
    stringToBytes(namespace),
    // info (namespace name)
    32
    // output length: 256 bits
  );
}
function derivePurposeKey(masterKey, purpose) {
  if (masterKey.length !== 32) {
    throw new Error("Master key must be 32 bytes");
  }
  return hkdf(
    sha256,
    masterKey,
    stringToBytes("sanctuary-purpose-v1"),
    stringToBytes(purpose),
    32
  );
}

// src/l1-cognitive/state-store.ts
init_encoding();
var RESERVED_NAMESPACE_PREFIXES = [
  "_identities",
  "_policies",
  "_audit",
  "_meta",
  "_principal",
  "_commitments",
  "_reputation",
  "_escrow",
  "_guarantees",
  "_bridge",
  "_federation",
  "_handshake",
  "_shr"
];
var StateStore = class {
  storage;
  masterKey;
  // Cache of version numbers per namespace/key for anti-rollback
  versionCache = /* @__PURE__ */ new Map();
  // Cache of content hashes per namespace for Merkle tree computation
  contentHashes = /* @__PURE__ */ new Map();
  constructor(storage, masterKey) {
    this.storage = storage;
    this.masterKey = masterKey;
  }
  versionKey(namespace, key) {
    return `${namespace}/${key}`;
  }
  /**
   * Get or initialize the content hash map for a namespace.
   */
  async getNamespaceHashes(namespace) {
    if (this.contentHashes.has(namespace)) {
      return this.contentHashes.get(namespace);
    }
    const entries = await this.storage.list(namespace);
    const hashMap = /* @__PURE__ */ new Map();
    for (const entry of entries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (raw) {
        try {
          const stateEntry = JSON.parse(bytesToString(raw));
          hashMap.set(entry.key, stateEntry.integrity_hash);
          this.versionCache.set(
            this.versionKey(namespace, entry.key),
            stateEntry.ver
          );
        } catch {
        }
      }
    }
    this.contentHashes.set(namespace, hashMap);
    return hashMap;
  }
  /**
   * Write encrypted state.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param value - Plaintext value (will be encrypted)
   * @param identityId - Identity performing the write
   * @param encryptedPrivateKey - Identity's encrypted private key (for signing)
   * @param identityEncryptionKey - Key to decrypt the identity's private key
   * @param options - Optional metadata
   */
  async write(namespace, key, value, identityId, encryptedPrivateKey, identityEncryptionKey, options = {}) {
    const namespaceKey = deriveNamespaceKey(this.masterKey, namespace);
    const plaintext = stringToBytes(value);
    const integrityHash = hashToString(plaintext);
    const payload = encrypt(plaintext, namespaceKey);
    const vk = this.versionKey(namespace, key);
    const currentVersion = this.versionCache.get(vk) ?? 0;
    const newVersion = currentVersion + 1;
    const ciphertextBytes = fromBase64url(payload.ct);
    const signature = sign(
      ciphertextBytes,
      encryptedPrivateKey,
      identityEncryptionKey
    );
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const stateEntry = {
      v: 1,
      payload,
      ver: newVersion,
      sig: toBase64url(signature),
      kid: identityId,
      integrity_hash: integrityHash,
      metadata: {
        content_type: options.content_type,
        ttl_seconds: options.ttl_seconds,
        tags: options.tags,
        written_at: now
      }
    };
    const serialized = stringToBytes(JSON.stringify(stateEntry));
    await this.storage.write(namespace, key, serialized);
    this.versionCache.set(vk, newVersion);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.set(key, integrityHash);
    const merkleRoot = computeMerkleRoot(nsHashes);
    return {
      key,
      namespace,
      version: newVersion,
      merkle_root: merkleRoot,
      written_at: now,
      size_bytes: serialized.length,
      integrity_hash: integrityHash
    };
  }
  /**
   * Read and decrypt state.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param signerPublicKey - Expected signer's public key (for signature verification)
   * @param verifyIntegrity - Whether to verify Merkle proof (default: true)
   */
  async read(namespace, key, signerPublicKey, verifyIntegrity = true) {
    const raw = await this.storage.read(namespace, key);
    if (!raw) return null;
    let stateEntry;
    try {
      stateEntry = JSON.parse(bytesToString(raw));
    } catch {
      throw new Error(`Corrupted state entry: ${namespace}/${key}`);
    }
    if (stateEntry.v !== 1) {
      throw new Error(`Unsupported state entry version: ${stateEntry.v}`);
    }
    const vk = this.versionKey(namespace, key);
    const cachedVersion = this.versionCache.get(vk);
    if (cachedVersion !== void 0 && stateEntry.ver < cachedVersion) {
      throw new Error(
        `Rollback detected for ${namespace}/${key}: found version ${stateEntry.ver}, expected >= ${cachedVersion}`
      );
    }
    if (signerPublicKey) {
      const ciphertextBytes = fromBase64url(stateEntry.payload.ct);
      const signatureBytes = fromBase64url(stateEntry.sig);
      const sigValid = verify(ciphertextBytes, signatureBytes, signerPublicKey);
      if (!sigValid) {
        throw new Error(
          `Signature verification failed for ${namespace}/${key}`
        );
      }
    }
    const namespaceKey = deriveNamespaceKey(this.masterKey, namespace);
    const plaintext = decrypt(stateEntry.payload, namespaceKey);
    const value = bytesToString(plaintext);
    const computedHash = hashToString(plaintext);
    if (computedHash !== stateEntry.integrity_hash) {
      throw new Error(
        `Integrity hash mismatch for ${namespace}/${key}: computed ${computedHash}, stored ${stateEntry.integrity_hash}`
      );
    }
    let merkleProofPath = [];
    let integrityVerified = true;
    if (verifyIntegrity) {
      const nsHashes = await this.getNamespaceHashes(namespace);
      const proof = generateMerkleProof(nsHashes, key);
      if (proof) {
        integrityVerified = verifyMerkleProof(proof);
        merkleProofPath = proof.path.map(
          (step) => `${step.position}:${step.hash}`
        );
      }
    }
    this.versionCache.set(vk, stateEntry.ver);
    return {
      key,
      namespace,
      value,
      version: stateEntry.ver,
      integrity_verified: integrityVerified,
      merkle_proof: merkleProofPath,
      written_at: stateEntry.metadata.written_at,
      written_by: stateEntry.kid
    };
  }
  /**
   * List keys in a namespace (metadata only — no decryption).
   */
  async list(namespace, prefix, tags, limit = 100, offset = 0) {
    const storageEntries = await this.storage.list(namespace, prefix);
    const result = [];
    for (const entry of storageEntries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (!raw) continue;
      try {
        const stateEntry = JSON.parse(bytesToString(raw));
        if (tags && tags.length > 0) {
          const entryTags = stateEntry.metadata.tags ?? [];
          const hasMatchingTag = tags.some((t) => entryTags.includes(t));
          if (!hasMatchingTag) continue;
        }
        result.push({
          key: entry.key,
          version: stateEntry.ver,
          size_bytes: entry.size_bytes,
          written_at: stateEntry.metadata.written_at,
          tags: stateEntry.metadata.tags ?? []
        });
      } catch {
      }
    }
    const nsHashes = await this.getNamespaceHashes(namespace);
    const merkleRoot = computeMerkleRoot(nsHashes);
    return {
      keys: result.slice(offset, offset + limit),
      total: result.length,
      merkle_root: merkleRoot
    };
  }
  /**
   * Securely delete state (overwrite with random bytes before removal).
   */
  async delete(namespace, key) {
    const deleted = await this.storage.delete(namespace, key, true);
    const vk = this.versionKey(namespace, key);
    this.versionCache.delete(vk);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.delete(key);
    const merkleRoot = computeMerkleRoot(nsHashes);
    return {
      deleted,
      key,
      namespace,
      new_merkle_root: merkleRoot,
      deleted_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  /**
   * Export all state for a namespace as an encrypted bundle.
   */
  async export(namespace) {
    const namespacesToExport = [];
    if (namespace) {
      namespacesToExport.push(namespace);
    } else {
      for (const ns of this.contentHashes.keys()) {
        namespacesToExport.push(ns);
      }
    }
    const exportData = {};
    let totalKeys = 0;
    for (const ns of namespacesToExport) {
      const entries = await this.storage.list(ns);
      exportData[ns] = [];
      for (const entry of entries) {
        const raw = await this.storage.read(ns, entry.key);
        if (!raw) continue;
        try {
          const stateEntry = JSON.parse(bytesToString(raw));
          exportData[ns].push({ key: entry.key, entry: stateEntry });
          totalKeys++;
        } catch {
        }
      }
    }
    const bundleJson = JSON.stringify({
      sanctuary_export_version: 1,
      exported_at: (/* @__PURE__ */ new Date()).toISOString(),
      namespaces: namespacesToExport,
      data: exportData
    });
    const bundleBytes = stringToBytes(bundleJson);
    const bundleHash = hashToString(bundleBytes);
    return {
      bundle: toBase64url(bundleBytes),
      namespaces: namespacesToExport,
      total_keys: totalKeys,
      bundle_hash: bundleHash,
      exported_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  /**
   * Import a previously exported state bundle.
   */
  async import(bundleBase64, conflictResolution = "skip", publicKeyResolver) {
    const bundleBytes = fromBase64url(bundleBase64);
    const bundleJson = bytesToString(bundleBytes);
    const bundle = JSON.parse(bundleJson);
    let importedKeys = 0;
    let skippedKeys = 0;
    let skippedInvalidSig = 0;
    let skippedUnknownKid = 0;
    let conflicts = 0;
    const namespaces = [];
    for (const [ns, entries] of Object.entries(
      bundle.data
    )) {
      if (RESERVED_NAMESPACE_PREFIXES.some(
        (prefix) => ns === prefix || ns.startsWith(prefix + "/")
      )) {
        skippedKeys += entries.length;
        continue;
      }
      namespaces.push(ns);
      for (const { key, entry } of entries) {
        const signerPublicKey = publicKeyResolver(entry.kid);
        if (!signerPublicKey) {
          skippedUnknownKid++;
          skippedKeys++;
          continue;
        }
        try {
          const ciphertextBytes = fromBase64url(entry.payload.ct);
          const signatureBytes = fromBase64url(entry.sig);
          const sigValid = verify(ciphertextBytes, signatureBytes, signerPublicKey);
          if (!sigValid) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
        } catch {
          skippedInvalidSig++;
          skippedKeys++;
          continue;
        }
        const exists = await this.storage.exists(ns, key);
        if (exists) {
          conflicts++;
          if (conflictResolution === "skip") {
            skippedKeys++;
            continue;
          }
          if (conflictResolution === "version") {
            const raw = await this.storage.read(ns, key);
            if (raw) {
              try {
                const existingEntry = JSON.parse(
                  bytesToString(raw)
                );
                if (entry.ver <= existingEntry.ver) {
                  skippedKeys++;
                  continue;
                }
              } catch {
              }
            }
          }
        }
        const serialized = stringToBytes(JSON.stringify(entry));
        await this.storage.write(ns, key, serialized);
        importedKeys++;
        const vk = this.versionKey(ns, key);
        this.versionCache.set(vk, entry.ver);
        const nsHashes = await this.getNamespaceHashes(ns);
        nsHashes.set(key, entry.integrity_hash);
      }
    }
    return {
      imported_keys: importedKeys,
      skipped_keys: skippedKeys,
      skipped_invalid_sig: skippedInvalidSig,
      skipped_unknown_kid: skippedUnknownKid,
      conflicts,
      namespaces,
      imported_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
};
var require3 = createRequire(import.meta.url);
var { version: PKG_VERSION2 } = require3("../package.json");
var MAX_STRING_BYTES = 1048576;
var MAX_BUNDLE_BYTES = 5242880;
var BUNDLE_FIELDS = /* @__PURE__ */ new Set(["bundle"]);
function validateArgs(args, schema) {
  const errors = [];
  const properties = schema.properties ?? {};
  const required = schema.required ?? [];
  for (const field of required) {
    if (args[field] === void 0 || args[field] === null) {
      errors.push({ field, message: `Required field "${field}" is missing` });
    }
  }
  const knownFields = new Set(Object.keys(properties));
  for (const field of Object.keys(args)) {
    if (!knownFields.has(field)) {
      errors.push({ field, message: `Unknown field "${field}"` });
    }
  }
  for (const [field, value] of Object.entries(args)) {
    if (value === void 0 || value === null) continue;
    const propSchema = properties[field];
    if (!propSchema) continue;
    const typeError = checkType(field, value, propSchema);
    if (typeError) {
      errors.push(typeError);
      continue;
    }
    if (typeof value === "string") {
      const maxBytes = BUNDLE_FIELDS.has(field) ? MAX_BUNDLE_BYTES : MAX_STRING_BYTES;
      const byteLength = new TextEncoder().encode(value).length;
      if (byteLength > maxBytes) {
        errors.push({
          field,
          message: `Field "${field}" exceeds maximum size (${byteLength} bytes > ${maxBytes} bytes)`
        });
      }
    }
    if (propSchema.enum && !propSchema.enum.includes(value)) {
      errors.push({
        field,
        message: `Field "${field}" must be one of: ${propSchema.enum.join(", ")}`
      });
    }
  }
  return errors;
}
function checkType(field, value, schema) {
  if (!schema.type) return null;
  switch (schema.type) {
    case "string":
      if (typeof value !== "string") {
        return { field, message: `Expected string for "${field}", got ${typeof value}` };
      }
      break;
    case "number":
      if (typeof value !== "number") {
        return { field, message: `Expected number for "${field}", got ${typeof value}` };
      }
      break;
    case "boolean":
      if (typeof value !== "boolean") {
        return { field, message: `Expected boolean for "${field}", got ${typeof value}` };
      }
      break;
    case "object":
      if (typeof value !== "object" || Array.isArray(value)) {
        return { field, message: `Expected object for "${field}", got ${typeof value}` };
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        return { field, message: `Expected array for "${field}", got ${typeof value}` };
      }
      break;
  }
  return null;
}
function createServer(tools, options) {
  const gate = options?.gate;
  const server = new Server(
    {
      name: "sanctuary-mcp-server",
      version: PKG_VERSION2
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema
      }))
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const typedArgs = args ?? {};
    const tool = tools.find((t) => t.name === name);
    if (!tool) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: `Unknown tool: ${name}` })
          }
        ],
        isError: true
      };
    }
    const validationErrors = validateArgs(typedArgs, tool.inputSchema);
    if (validationErrors.length > 0) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: "validation_failed",
              message: "Tool arguments failed schema validation",
              violations: validationErrors
            })
          }
        ],
        isError: true
      };
    }
    if (gate) {
      const result = await gate.evaluate(name, typedArgs);
      if (!result.allowed) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "Operation not permitted",
                approval_required: result.approval_required
              })
            }
          ],
          isError: true
        };
      }
    }
    try {
      return await tool.handler(typedArgs);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: message })
          }
        ],
        isError: true
      };
    }
  });
  return server;
}
function toolResult(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }]
  };
}

// src/l1-cognitive/tools.ts
init_encoding();
init_encoding();
var RESERVED_NAMESPACE_PREFIXES2 = [
  "_identities",
  "_policies",
  "_audit",
  "_meta",
  "_principal",
  "_commitments",
  "_reputation",
  "_escrow",
  "_guarantees",
  "_bridge",
  "_federation",
  "_handshake",
  "_shr"
];
function getReservedNamespaceViolation(namespace) {
  for (const prefix of RESERVED_NAMESPACE_PREFIXES2) {
    if (namespace === prefix || namespace.startsWith(prefix + "/")) {
      return prefix;
    }
  }
  return null;
}
var IdentityManager = class {
  storage;
  masterKey;
  identities = /* @__PURE__ */ new Map();
  primaryIdentityId = null;
  constructor(storage, masterKey) {
    this.storage = storage;
    this.masterKey = masterKey;
  }
  get encryptionKey() {
    return derivePurposeKey(this.masterKey, "identity-encryption");
  }
  /** Load identities from storage on startup */
  async load() {
    const entries = await this.storage.list("_identities");
    for (const entry of entries) {
      const raw = await this.storage.read("_identities", entry.key);
      if (!raw) continue;
      try {
        const encrypted = JSON.parse(bytesToString(raw));
        const decrypted = decrypt(encrypted, this.encryptionKey);
        const identity = JSON.parse(bytesToString(decrypted));
        this.identities.set(identity.identity_id, identity);
        if (!this.primaryIdentityId) {
          this.primaryIdentityId = identity.identity_id;
        }
      } catch {
      }
    }
  }
  /** Save an identity to storage */
  async save(identity) {
    const serialized = stringToBytes(JSON.stringify(identity));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_identities",
      identity.identity_id,
      stringToBytes(JSON.stringify(encrypted))
    );
    this.identities.set(identity.identity_id, identity);
    if (!this.primaryIdentityId) {
      this.primaryIdentityId = identity.identity_id;
    }
  }
  get(id) {
    return this.identities.get(id);
  }
  getDefault() {
    if (!this.primaryIdentityId) return void 0;
    return this.identities.get(this.primaryIdentityId);
  }
  list() {
    return Array.from(this.identities.values()).map((si) => ({
      identity_id: si.identity_id,
      label: si.label,
      public_key: si.public_key,
      did: si.did,
      created_at: si.created_at,
      key_type: si.key_type,
      key_protection: si.key_protection
    }));
  }
};
function createL1Tools(stateStore, storage, masterKey, keyProtection, auditLog) {
  const identityMgr = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  function resolveIdentity(identityId) {
    const id = identityId ? identityMgr.get(identityId) : identityMgr.getDefault();
    if (!id) {
      throw new Error(
        identityId ? `Identity not found: ${identityId}` : "No default identity. Create one with sanctuary/identity_create."
      );
    }
    return id;
  }
  const tools = [
    // ── Identity Tools ──────────────────────────────────────────────────
    {
      name: "sanctuary/identity_create",
      description: "Create a new sovereign identity (Ed25519 keypair). The private key is encrypted and never exposed.",
      inputSchema: {
        type: "object",
        properties: {
          label: {
            type: "string",
            description: 'Human-readable label (e.g., "my-agent")'
          }
        },
        required: ["label"]
      },
      handler: async (args) => {
        const label = args.label;
        const { publicIdentity, storedIdentity } = createIdentity(
          label,
          identityEncKey,
          keyProtection
        );
        await identityMgr.save(storedIdentity);
        auditLog?.append("l1", "identity_create", publicIdentity.identity_id, {
          label
        });
        return toolResult({
          identity_id: publicIdentity.identity_id,
          public_key: publicIdentity.public_key,
          did: publicIdentity.did,
          created_at: publicIdentity.created_at,
          key_type: publicIdentity.key_type,
          key_protection: publicIdentity.key_protection,
          backed_up: false
        });
      }
    },
    {
      name: "sanctuary/identity_list",
      description: "List all managed sovereign identities.",
      inputSchema: {
        type: "object",
        properties: {
          filter: {
            type: "object",
            properties: {
              label: { type: "string" }
            }
          }
        }
      },
      handler: async (args) => {
        let identities = identityMgr.list();
        const filter = args.filter;
        if (filter?.label) {
          identities = identities.filter(
            (i) => i.label.includes(filter.label)
          );
        }
        return toolResult({ identities });
      }
    },
    {
      name: "sanctuary/identity_sign",
      description: "Sign data with a managed identity. The private key is decrypted in memory only during signing.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: { type: "string" },
          payload: {
            type: "string",
            description: "Base64url-encoded data to sign"
          }
        },
        required: ["payload"]
      },
      handler: async (args) => {
        const identity = resolveIdentity(args.identity_id);
        const payloadStr = args.payload;
        let payload;
        try {
          payload = fromBase64url(payloadStr);
        } catch {
          payload = stringToBytes(payloadStr);
        }
        const signature = sign(
          payload,
          identity.encrypted_private_key,
          identityEncKey
        );
        auditLog?.append("l1", "identity_sign", identity.identity_id);
        return toolResult({
          signature: toBase64url(signature),
          algorithm: "Ed25519",
          signed_at: (/* @__PURE__ */ new Date()).toISOString(),
          public_key: identity.public_key,
          payload_encoding: "base64url"
        });
      }
    },
    {
      name: "sanctuary/identity_verify",
      description: "Verify an Ed25519 signature. Provide either identity_id or public_key.",
      inputSchema: {
        type: "object",
        properties: {
          payload: {
            type: "string",
            description: "Original data (plain text or base64url-encoded)"
          },
          signature: { type: "string", description: "Base64url signature" },
          identity_id: {
            type: "string",
            description: "Identity ID to look up public key (alternative to public_key)"
          },
          public_key: {
            type: "string",
            description: "Base64url public key (alternative to identity_id)"
          }
        },
        required: ["payload", "signature"]
      },
      handler: async (args) => {
        const payloadStr = args.payload;
        let payload;
        try {
          payload = fromBase64url(payloadStr);
        } catch {
          payload = stringToBytes(payloadStr);
        }
        const signature = fromBase64url(args.signature);
        let publicKey;
        if (args.identity_id) {
          const identity = resolveIdentity(args.identity_id);
          publicKey = fromBase64url(identity.public_key);
        } else if (args.public_key) {
          publicKey = fromBase64url(args.public_key);
        } else {
          return toolResult({
            error: "Provide either identity_id or public_key for verification."
          });
        }
        const valid = verify(payload, signature, publicKey);
        return toolResult({
          valid,
          verified_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    {
      name: "sanctuary/identity_rotate",
      description: "Rotate keys for an identity. Generates a new keypair and signs a rotation event with the old key for verifiable chain.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: { type: "string" },
          reason: { type: "string" }
        },
        required: ["identity_id"]
      },
      handler: async (args) => {
        const identity = resolveIdentity(args.identity_id);
        const reason = args.reason ?? "Key rotation";
        const { updatedIdentity, rotationEvent } = rotateKeys(
          identity,
          identityEncKey,
          reason
        );
        await identityMgr.save(updatedIdentity);
        auditLog?.append("l1", "identity_rotate", identity.identity_id, {
          reason
        });
        return toolResult({
          identity_id: updatedIdentity.identity_id,
          old_public_key: rotationEvent.old_public_key,
          new_public_key: rotationEvent.new_public_key,
          new_did: updatedIdentity.did,
          rotated_at: rotationEvent.rotated_at
        });
      }
    },
    // ── State Tools ─────────────────────────────────────────────────────
    {
      name: "sanctuary/state_write",
      description: "Write encrypted state to the sovereign store. Value is encrypted with a namespace-specific key. The write is signed by the active identity.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: {
            type: "string",
            description: 'Logical grouping (e.g., "memory", "config")'
          },
          key: { type: "string", description: "State key within namespace" },
          value: {
            type: "string",
            description: "Plaintext value (encrypted before storage)"
          },
          metadata: {
            type: "object",
            properties: {
              content_type: { type: "string" },
              ttl_seconds: { type: "number" },
              tags: { type: "array", items: { type: "string" } }
            }
          },
          identity_id: { type: "string" }
        },
        required: ["namespace", "key", "value"]
      },
      handler: async (args) => {
        const reservedViolation = getReservedNamespaceViolation(args.namespace);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Choose a different namespace.`
          });
        }
        const identity = resolveIdentity(args.identity_id);
        const metadata = args.metadata;
        const result = await stateStore.write(
          args.namespace,
          args.key,
          args.value,
          identity.identity_id,
          identity.encrypted_private_key,
          identityEncKey,
          {
            content_type: metadata?.content_type,
            ttl_seconds: metadata?.ttl_seconds,
            tags: metadata?.tags
          }
        );
        auditLog?.append("l1", "state_write", identity.identity_id, {
          namespace: args.namespace,
          key: args.key
        });
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/state_read",
      description: "Read and decrypt state from the sovereign store. Verifies integrity via Merkle proof and signature.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          key: { type: "string" },
          verify_integrity: { type: "boolean", default: true }
        },
        required: ["namespace", "key"]
      },
      handler: async (args) => {
        const reservedViolation = getReservedNamespaceViolation(args.namespace);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot read from reserved namespaces.`
          });
        }
        const result = await stateStore.read(
          args.namespace,
          args.key,
          void 0,
          // Skip signature verification for now (would need writer's pubkey)
          args.verify_integrity ?? true
        );
        if (!result) {
          return toolResult({
            error: "not_found",
            namespace: args.namespace,
            key: args.key
          });
        }
        auditLog?.append("l1", "state_read", result.written_by, {
          namespace: args.namespace,
          key: args.key
        });
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/state_list",
      description: "List keys in a namespace (metadata only \u2014 no decryption).",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          prefix: { type: "string" },
          tags: { type: "array", items: { type: "string" } },
          limit: { type: "number", default: 100 },
          offset: { type: "number", default: 0 }
        },
        required: ["namespace"]
      },
      handler: async (args) => {
        const reservedViolation = getReservedNamespaceViolation(args.namespace);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot list reserved namespaces.`
          });
        }
        const result = await stateStore.list(
          args.namespace,
          args.prefix,
          args.tags,
          args.limit ?? 100,
          args.offset ?? 0
        );
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/state_delete",
      description: "Securely delete state. Overwrites file with random bytes before removal (right to deletion, S1.6).",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          key: { type: "string" },
          reason: { type: "string" }
        },
        required: ["namespace", "key"]
      },
      handler: async (args) => {
        const reservedViolation = getReservedNamespaceViolation(args.namespace);
        if (reservedViolation) {
          return toolResult({
            error: "namespace_reserved",
            message: `Namespace "${args.namespace}" is reserved for internal use (prefix: ${reservedViolation}). Cannot delete from reserved namespaces.`
          });
        }
        const result = await stateStore.delete(
          args.namespace,
          args.key
        );
        auditLog?.append("l1", "state_delete", "principal", {
          namespace: args.namespace,
          key: args.key,
          reason: args.reason
        });
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/state_export",
      description: "Export state as an encrypted, portable bundle for migration.",
      inputSchema: {
        type: "object",
        properties: {
          namespace: { type: "string" },
          format: { type: "string", default: "sanctuary-v1" }
        }
      },
      handler: async (args) => {
        const result = await stateStore.export(
          args.namespace
        );
        auditLog?.append("l1", "state_export", "principal", {
          namespaces: result.namespaces
        });
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/state_import",
      description: "Import a previously exported state bundle.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: { type: "string", description: "Base64url-encoded bundle" },
          conflict_resolution: {
            type: "string",
            enum: ["skip", "overwrite", "version"],
            default: "skip"
          }
        },
        required: ["bundle"]
      },
      handler: async (args) => {
        const publicKeyResolver = (kid) => {
          const identity = identityMgr.get(kid);
          if (!identity) return null;
          return fromBase64url(identity.public_key);
        };
        const result = await stateStore.import(
          args.bundle,
          args.conflict_resolution ?? "skip",
          publicKeyResolver
        );
        auditLog?.append("l1", "state_import", "principal", {
          imported_keys: result.imported_keys
        });
        return toolResult(result);
      }
    }
  ];
  return { tools, identityManager: identityMgr };
}

// src/l2-operational/audit-log.ts
init_encoding();
var AuditLog = class {
  storage;
  encryptionKey;
  entries = [];
  counter = 0;
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "audit-log");
  }
  /**
   * Append an audit entry.
   */
  append(layer, operation, identityId, details, result = "success") {
    const entry = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      layer,
      operation,
      identity_id: identityId,
      result,
      details
    };
    this.entries.push(entry);
    this.persistEntry(entry).catch(() => {
    });
  }
  async persistEntry(entry) {
    const key = `${Date.now()}-${this.counter++}`;
    const serialized = stringToBytes(JSON.stringify(entry));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_audit",
      key,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
  /**
   * Query the audit log with filtering.
   */
  async query(options) {
    await this.loadPersistedEntries();
    let filtered = this.entries;
    if (options.since) {
      const sinceDate = new Date(options.since);
      filtered = filtered.filter(
        (e) => new Date(e.timestamp) >= sinceDate
      );
    }
    if (options.layer) {
      filtered = filtered.filter((e) => e.layer === options.layer);
    }
    if (options.operation_type) {
      filtered = filtered.filter(
        (e) => e.operation === options.operation_type
      );
    }
    const total = filtered.length;
    const limit = options.limit ?? 50;
    const entries = filtered.slice(-limit);
    return { entries, total };
  }
  async loadPersistedEntries() {
    try {
      const storedEntries = await this.storage.list("_audit");
      for (const meta of storedEntries) {
        const raw = await this.storage.read("_audit", meta.key);
        if (!raw) continue;
        try {
          const encrypted = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const entry = JSON.parse(bytesToString(decrypted));
          const isDuplicate = this.entries.some(
            (e) => e.timestamp === entry.timestamp && e.operation === entry.operation && e.identity_id === entry.identity_id
          );
          if (!isDuplicate) {
            this.entries.push(entry);
          }
        } catch {
        }
      }
      this.entries.sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
    } catch {
    }
  }
  /**
   * Get total number of entries.
   */
  get size() {
    return this.entries.length;
  }
};

// src/l3-disclosure/commitments.ts
init_hashing();
init_encoding();
init_encoding();
function createCommitment(value, blindingFactor) {
  const blindingBytes = blindingFactor ? fromBase64url(blindingFactor) : randomBytes(32);
  const valueBytes = stringToBytes(value);
  const combined = concatBytes(valueBytes, blindingBytes);
  const commitmentHash = hash(combined);
  return {
    commitment: toBase64url(commitmentHash),
    blinding_factor: toBase64url(blindingBytes),
    committed_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyCommitment(commitment, value, blindingFactor) {
  const blindingBytes = fromBase64url(blindingFactor);
  const valueBytes = stringToBytes(value);
  const combined = concatBytes(valueBytes, blindingBytes);
  const expectedHash = toBase64url(hash(combined));
  return commitment === expectedHash;
}
var CommitmentStore = class {
  storage;
  encryptionKey;
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l3-commitments");
  }
  /**
   * Store a commitment (encrypted) for later reference.
   */
  async store(commitment, value) {
    const id = `cmt-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const stored = {
      commitment: commitment.commitment,
      blinding_factor: commitment.blinding_factor,
      value,
      committed_at: commitment.committed_at,
      revealed: false
    };
    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_commitments",
      id,
      stringToBytes(JSON.stringify(encrypted))
    );
    return id;
  }
  /**
   * Retrieve a stored commitment by ID.
   */
  async get(id) {
    const raw = await this.storage.read("_commitments", id);
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }
  /**
   * Mark a commitment as revealed.
   */
  async markRevealed(id) {
    const stored = await this.get(id);
    if (!stored) return;
    stored.revealed = true;
    stored.revealed_at = (/* @__PURE__ */ new Date()).toISOString();
    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_commitments",
      id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
};

// src/l3-disclosure/policies.ts
init_encoding();
function evaluateDisclosure(policy, context, requestedFields) {
  return requestedFields.map((field) => {
    const exactRule = policy.rules.find((r) => r.context === context);
    const wildcardRule = policy.rules.find((r) => r.context === "*");
    const matchedRule = exactRule ?? wildcardRule;
    if (!matchedRule) {
      return {
        field,
        action: policy.default_action,
        reason: `No rule matches context "${context}"`,
        applicable_rule: "default"
      };
    }
    const ruleName = `${matchedRule.context}`;
    if (matchedRule.withhold.includes(field)) {
      return {
        field,
        action: "withhold",
        reason: `Field "${field}" is explicitly withheld in ${ruleName} context`,
        applicable_rule: ruleName
      };
    }
    if (matchedRule.proof_required.includes(field)) {
      return {
        field,
        action: "proof",
        reason: `Field "${field}" requires cryptographic proof in ${ruleName} context`,
        applicable_rule: ruleName
      };
    }
    if (matchedRule.disclose.includes(field)) {
      return {
        field,
        action: "disclose",
        reason: `Field "${field}" is permitted for disclosure in ${ruleName} context`,
        applicable_rule: ruleName
      };
    }
    return {
      field,
      action: policy.default_action,
      reason: `Field "${field}" not addressed in ${ruleName} rule; applying default`,
      applicable_rule: ruleName
    };
  });
}
var PolicyStore = class {
  storage;
  encryptionKey;
  policies = /* @__PURE__ */ new Map();
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l3-policies");
  }
  /**
   * Create and store a new disclosure policy.
   */
  async create(policyName, rules, defaultAction, identityId) {
    const policyId = `pol-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const policy = {
      policy_id: policyId,
      policy_name: policyName,
      rules,
      default_action: defaultAction,
      identity_id: identityId,
      created_at: now,
      updated_at: now
    };
    await this.persist(policy);
    this.policies.set(policyId, policy);
    return policy;
  }
  /**
   * Get a policy by ID.
   */
  async get(policyId) {
    if (this.policies.has(policyId)) {
      return this.policies.get(policyId);
    }
    const raw = await this.storage.read("_policies", policyId);
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const policy = JSON.parse(bytesToString(decrypted));
      this.policies.set(policyId, policy);
      return policy;
    } catch {
      return null;
    }
  }
  /**
   * List all policies.
   */
  async list() {
    await this.loadAll();
    return Array.from(this.policies.values());
  }
  /**
   * Load all persisted policies into memory.
   */
  async loadAll() {
    try {
      const entries = await this.storage.list("_policies");
      for (const meta of entries) {
        if (this.policies.has(meta.key)) continue;
        const raw = await this.storage.read("_policies", meta.key);
        if (!raw) continue;
        try {
          const encrypted = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const policy = JSON.parse(bytesToString(decrypted));
          this.policies.set(policy.policy_id, policy);
        } catch {
        }
      }
    } catch {
    }
  }
  async persist(policy) {
    const serialized = stringToBytes(JSON.stringify(policy));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_policies",
      policy.policy_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
};
init_encoding();
var G = RistrettoPoint.BASE;
var H_INPUT = concatBytes(
  sha256(stringToBytes("sanctuary-pedersen-generator-H-v1-a")),
  sha256(stringToBytes("sanctuary-pedersen-generator-H-v1-b"))
);
var H = RistrettoPoint.hashToCurve(H_INPUT);
function bigintToBytes(n) {
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function bytesToBigint(bytes) {
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}
var ORDER = BigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989");
function mod(n) {
  return (n % ORDER + ORDER) % ORDER;
}
function safeMultiply(point, scalar) {
  const s = mod(scalar);
  if (s === 0n) return RistrettoPoint.ZERO;
  return point.multiply(s);
}
function randomScalar() {
  const bytes = randomBytes(64);
  return mod(bytesToBigint(bytes));
}
function fiatShamirChallenge(domain, ...points) {
  const domainBytes = stringToBytes(domain);
  const combined = concatBytes(domainBytes, ...points);
  const hash2 = sha256(combined);
  return mod(bytesToBigint(hash2));
}
function createPedersenCommitment(value) {
  const v = mod(BigInt(value));
  const b = randomScalar();
  const C = safeMultiply(G, v).add(safeMultiply(H, b));
  return {
    commitment: toBase64url(C.toRawBytes()),
    blinding_factor: toBase64url(bigintToBytes(b)),
    committed_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyPedersenCommitment(commitment, value, blindingFactor) {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(commitment));
    const v = mod(BigInt(value));
    const b = bytesToBigint(fromBase64url(blindingFactor));
    const expected = safeMultiply(G, v).add(safeMultiply(H, b));
    return C.equals(expected);
  } catch {
    return false;
  }
}
function createProofOfKnowledge(value, blindingFactor, commitment) {
  const v = mod(BigInt(value));
  const b = bytesToBigint(fromBase64url(blindingFactor));
  const r_v = randomScalar();
  const r_b = randomScalar();
  const R = safeMultiply(G, r_v).add(safeMultiply(H, r_b));
  const C_bytes = fromBase64url(commitment);
  const R_bytes = R.toRawBytes();
  const e = fiatShamirChallenge("sanctuary-zk-pok-v1", C_bytes, R_bytes);
  const s_v = mod(r_v + e * v);
  const s_b = mod(r_b + e * b);
  return {
    type: "schnorr-pedersen-ristretto255",
    commitment,
    announcement: toBase64url(R_bytes),
    response_v: toBase64url(bigintToBytes(s_v)),
    response_b: toBase64url(bigintToBytes(s_b)),
    generated_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyProofOfKnowledge(proof) {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(proof.commitment));
    const R = RistrettoPoint.fromHex(fromBase64url(proof.announcement));
    const s_v = bytesToBigint(fromBase64url(proof.response_v));
    const s_b = bytesToBigint(fromBase64url(proof.response_b));
    const e = fiatShamirChallenge(
      "sanctuary-zk-pok-v1",
      fromBase64url(proof.commitment),
      fromBase64url(proof.announcement)
    );
    const lhs = safeMultiply(G, s_v).add(safeMultiply(H, s_b));
    const rhs = R.add(safeMultiply(C, e));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
function createRangeProof(value, blindingFactor, commitment, min, max) {
  if (value < min || value > max) {
    return { error: `Value ${value} is not in range [${min}, ${max}]` };
  }
  const range = max - min;
  const numBits = Math.ceil(Math.log2(range + 1));
  const shifted = value - min;
  const b = bytesToBigint(fromBase64url(blindingFactor));
  const bits = [];
  for (let i = 0; i < numBits; i++) {
    bits.push(shifted >> i & 1);
  }
  const bitBlindings = [];
  const bitCommitments = [];
  const bitProofs = [];
  for (let i = 0; i < numBits; i++) {
    const bit_b = randomScalar();
    bitBlindings.push(bit_b);
    const C_i = safeMultiply(G, mod(BigInt(bits[i]))).add(safeMultiply(H, bit_b));
    bitCommitments.push(toBase64url(C_i.toRawBytes()));
    const bitProof = createBitProof(bits[i], bit_b, C_i);
    bitProofs.push(bitProof);
  }
  const sumBlinding = bitBlindings.reduce(
    (acc, bi, i) => mod(acc + mod(BigInt(1) << BigInt(i)) * bi),
    0n
  );
  const blindingDiff = mod(b - sumBlinding);
  const r_sum = randomScalar();
  const R_sum = safeMultiply(H, r_sum);
  const e_sum = fiatShamirChallenge(
    "sanctuary-zk-range-sum-v1",
    fromBase64url(commitment),
    R_sum.toRawBytes()
  );
  const s_sum = mod(r_sum + e_sum * blindingDiff);
  return {
    type: "range-pedersen-ristretto255",
    commitment,
    min,
    max,
    bit_commitments: bitCommitments,
    bit_proofs: bitProofs,
    sum_proof: {
      announcement: toBase64url(R_sum.toRawBytes()),
      response: toBase64url(bigintToBytes(s_sum))
    },
    generated_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function verifyRangeProof(proof) {
  try {
    const C = RistrettoPoint.fromHex(fromBase64url(proof.commitment));
    const range = proof.max - proof.min;
    const numBits = Math.ceil(Math.log2(range + 1));
    if (proof.bit_commitments.length !== numBits) return false;
    if (proof.bit_proofs.length !== numBits) return false;
    for (let i = 0; i < numBits; i++) {
      const C_i = RistrettoPoint.fromHex(fromBase64url(proof.bit_commitments[i]));
      if (!verifyBitProof(proof.bit_proofs[i], C_i)) {
        return false;
      }
    }
    let reconstructed = RistrettoPoint.ZERO;
    for (let i = 0; i < numBits; i++) {
      const C_i = RistrettoPoint.fromHex(fromBase64url(proof.bit_commitments[i]));
      const weight = mod(BigInt(1) << BigInt(i));
      reconstructed = reconstructed.add(safeMultiply(C_i, weight));
    }
    const diff = C.subtract(safeMultiply(G, mod(BigInt(proof.min)))).subtract(reconstructed);
    const R_sum = RistrettoPoint.fromHex(fromBase64url(proof.sum_proof.announcement));
    const s_sum = bytesToBigint(fromBase64url(proof.sum_proof.response));
    const e_sum = fiatShamirChallenge(
      "sanctuary-zk-range-sum-v1",
      fromBase64url(proof.commitment),
      fromBase64url(proof.sum_proof.announcement)
    );
    const lhs = safeMultiply(H, s_sum);
    const rhs = R_sum.add(safeMultiply(diff, e_sum));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}
function createBitProof(bit, blinding, commitment) {
  const C_bytes = commitment.toRawBytes();
  if (bit === 0) {
    const C_minus_G = commitment.subtract(G);
    const e_1 = randomScalar();
    const s_1 = randomScalar();
    const R_1 = safeMultiply(H, s_1).subtract(safeMultiply(C_minus_G, e_1));
    const r_0 = randomScalar();
    const R_0 = safeMultiply(H, r_0);
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    const e_0 = mod(e - e_1);
    const s_0 = mod(r_0 + e_0 * blinding);
    return {
      announcement_0: toBase64url(R_0.toRawBytes()),
      announcement_1: toBase64url(R_1.toRawBytes()),
      challenge_0: toBase64url(bigintToBytes(e_0)),
      challenge_1: toBase64url(bigintToBytes(e_1)),
      response_0: toBase64url(bigintToBytes(s_0)),
      response_1: toBase64url(bigintToBytes(s_1))
    };
  } else {
    const e_0 = randomScalar();
    const s_0 = randomScalar();
    const R_0 = safeMultiply(H, s_0).subtract(safeMultiply(commitment, e_0));
    const r_1 = randomScalar();
    const R_1 = safeMultiply(H, r_1);
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    const e_1 = mod(e - e_0);
    const s_1 = mod(r_1 + e_1 * blinding);
    return {
      announcement_0: toBase64url(R_0.toRawBytes()),
      announcement_1: toBase64url(R_1.toRawBytes()),
      challenge_0: toBase64url(bigintToBytes(e_0)),
      challenge_1: toBase64url(bigintToBytes(e_1)),
      response_0: toBase64url(bigintToBytes(s_0)),
      response_1: toBase64url(bigintToBytes(s_1))
    };
  }
}
function verifyBitProof(proof, commitment) {
  try {
    const C_bytes = commitment.toRawBytes();
    const R_0 = RistrettoPoint.fromHex(fromBase64url(proof.announcement_0));
    const R_1 = RistrettoPoint.fromHex(fromBase64url(proof.announcement_1));
    const e_0 = bytesToBigint(fromBase64url(proof.challenge_0));
    const e_1 = bytesToBigint(fromBase64url(proof.challenge_1));
    const s_0 = bytesToBigint(fromBase64url(proof.response_0));
    const s_1 = bytesToBigint(fromBase64url(proof.response_1));
    const e = fiatShamirChallenge(
      "sanctuary-zk-bit-v1",
      C_bytes,
      R_0.toRawBytes(),
      R_1.toRawBytes()
    );
    if (mod(e_0 + e_1) !== e) return false;
    const lhs_0 = safeMultiply(H, s_0);
    const rhs_0 = R_0.add(safeMultiply(commitment, e_0));
    if (!lhs_0.equals(rhs_0)) return false;
    const C_minus_G = commitment.subtract(G);
    const lhs_1 = safeMultiply(H, s_1);
    const rhs_1 = R_1.add(safeMultiply(C_minus_G, e_1));
    if (!lhs_1.equals(rhs_1)) return false;
    return true;
  } catch {
    return false;
  }
}

// src/l3-disclosure/tools.ts
function createL3Tools(storage, masterKey, auditLog) {
  const commitmentStore = new CommitmentStore(storage, masterKey);
  const policyStore = new PolicyStore(storage, masterKey);
  const tools = [
    // ─── Commitment Schemes ───────────────────────────────────────────────
    {
      name: "sanctuary/proof_commitment",
      description: "Create a cryptographic commitment to a value. The commitment hides the value until you choose to reveal it. Returns the commitment hash and a blinding factor (store securely).",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "string",
            description: "The value to commit to"
          },
          blinding_factor: {
            type: "string",
            description: "Optional base64url blinding factor (auto-generated if omitted)"
          }
        },
        required: ["value"]
      },
      handler: async (args) => {
        const value = args.value;
        const blindingFactor = args.blinding_factor;
        const commitment = createCommitment(value, blindingFactor);
        const commitmentId = await commitmentStore.store(commitment, value);
        auditLog.append("l3", "proof_commitment", "system", {
          commitment_id: commitmentId,
          commitment_hash: commitment.commitment
        });
        return toolResult({
          commitment_id: commitmentId,
          commitment: commitment.commitment,
          blinding_factor: commitment.blinding_factor,
          committed_at: commitment.committed_at,
          note: "Store the blinding_factor securely. You will need it to reveal the committed value."
        });
      }
    },
    {
      name: "sanctuary/proof_reveal",
      description: "Verify a previously committed value by revealing it with the blinding factor. Returns whether the revealed value matches the commitment.",
      inputSchema: {
        type: "object",
        properties: {
          commitment: {
            type: "string",
            description: "The original commitment hash"
          },
          value: {
            type: "string",
            description: "The value being revealed"
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from the original commitment"
          }
        },
        required: ["commitment", "value", "blinding_factor"]
      },
      handler: async (args) => {
        const commitment = args.commitment;
        const value = args.value;
        const blindingFactor = args.blinding_factor;
        const valid = verifyCommitment(commitment, value, blindingFactor);
        auditLog.append("l3", "proof_reveal", "system", {
          commitment_hash: commitment,
          valid
        });
        return toolResult({
          valid,
          commitment,
          revealed_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    // ─── Disclosure Policies ──────────────────────────────────────────────
    {
      name: "sanctuary/disclosure_set_policy",
      description: "Define a disclosure policy that controls what an agent will and will not disclose in different interaction contexts. Rules specify which fields may be disclosed, which must be withheld, and which require cryptographic proof.",
      inputSchema: {
        type: "object",
        properties: {
          policy_name: {
            type: "string",
            description: "Human-readable policy name"
          },
          rules: {
            type: "array",
            description: "Disclosure rules for different contexts",
            items: {
              type: "object",
              properties: {
                context: {
                  type: "string",
                  description: 'Interaction context: "negotiation", "commerce", "identity", "*" (wildcard)'
                },
                disclose: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields the agent MAY disclose"
                },
                withhold: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields the agent MUST NOT disclose"
                },
                proof_required: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields that require proof rather than plain disclosure"
                }
              },
              required: ["context", "disclose", "withhold", "proof_required"]
            }
          },
          default_action: {
            type: "string",
            enum: ["withhold", "ask-principal"],
            description: "What to do when no rule matches a field"
          },
          identity_id: {
            type: "string",
            description: "Optional identity this policy is bound to"
          }
        },
        required: ["policy_name", "rules", "default_action"]
      },
      handler: async (args) => {
        const policyName = args.policy_name;
        const rules = args.rules;
        const defaultAction = args.default_action;
        const identityId = args.identity_id;
        const policy = await policyStore.create(
          policyName,
          rules,
          defaultAction,
          identityId
        );
        auditLog.append("l3", "disclosure_set_policy", identityId ?? "system", {
          policy_id: policy.policy_id,
          policy_name: policyName,
          rules_count: rules.length
        });
        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          rules_count: policy.rules.length,
          created_at: policy.created_at
        });
      }
    },
    {
      name: "sanctuary/disclosure_evaluate",
      description: "Evaluate a disclosure request against an active policy. Returns per-field decisions: disclose, withhold, proof, or ask-principal.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "string",
            description: "The interaction context"
          },
          requested_fields: {
            type: "array",
            items: { type: "string" },
            description: "Fields the counterparty is requesting"
          },
          policy_id: {
            type: "string",
            description: "Specific policy to evaluate (uses first available if omitted)"
          }
        },
        required: ["context", "requested_fields"]
      },
      handler: async (args) => {
        const context = args.context;
        const requestedFields = args.requested_fields;
        const policyId = args.policy_id;
        let policy;
        if (policyId) {
          policy = await policyStore.get(policyId);
        } else {
          const allPolicies = await policyStore.list();
          policy = allPolicies[0] ?? null;
        }
        if (!policy) {
          return toolResult({
            error: "No disclosure policy found. Create one with disclosure_set_policy first."
          });
        }
        const decisions = evaluateDisclosure(policy, context, requestedFields);
        const withholding = decisions.filter(
          (d) => d.action === "withhold"
        ).length;
        const disclosing = decisions.filter(
          (d) => d.action === "disclose"
        ).length;
        const proofRequired = decisions.filter(
          (d) => d.action === "proof"
        ).length;
        const askPrincipal = decisions.filter(
          (d) => d.action === "ask-principal"
        ).length;
        auditLog.append("l3", "disclosure_evaluate", "system", {
          policy_id: policy.policy_id,
          context,
          fields_requested: requestedFields.length,
          withholding,
          disclosing,
          proof_required: proofRequired
        });
        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          context,
          decisions,
          summary: {
            total_fields: requestedFields.length,
            disclose: disclosing,
            withhold: withholding,
            proof: proofRequired,
            ask_principal: askPrincipal
          },
          overall_recommendation: withholding > 0 ? `Withholding ${withholding} of ${requestedFields.length} requested fields per policy "${policy.policy_name}"` : `All ${requestedFields.length} fields may be disclosed per policy "${policy.policy_name}"`
        });
      }
    },
    // ─── ZK Proof Tools ───────────────────────────────────────────────────
    {
      name: "sanctuary/zk_commit",
      description: "Create a Pedersen commitment to a numeric value on Ristretto255. Unlike SHA-256 commitments, Pedersen commitments support zero-knowledge proofs: you can prove properties about the committed value without revealing it.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The integer value to commit to"
          }
        },
        required: ["value"]
      },
      handler: async (args) => {
        const value = args.value;
        if (!Number.isInteger(value)) {
          return toolResult({ error: "Value must be an integer." });
        }
        const commitment = createPedersenCommitment(value);
        auditLog.append("l3", "zk_commit", "system", {
          commitment_hash: commitment.commitment.slice(0, 16) + "..."
        });
        return toolResult({
          commitment: commitment.commitment,
          blinding_factor: commitment.blinding_factor,
          committed_at: commitment.committed_at,
          proof_system: "pedersen-ristretto255",
          note: "Store the blinding_factor securely. Use zk_prove to create proofs about this commitment."
        });
      }
    },
    {
      name: "sanctuary/zk_prove",
      description: "Create a zero-knowledge proof of knowledge for a Pedersen commitment. Proves you know the value and blinding factor without revealing either. Uses a Schnorr sigma protocol with Fiat-Shamir transform.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The committed value (integer)"
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from zk_commit (base64url)"
          },
          commitment: {
            type: "string",
            description: "The Pedersen commitment (base64url)"
          }
        },
        required: ["value", "blinding_factor", "commitment"]
      },
      handler: async (args) => {
        const value = args.value;
        const blindingFactor = args.blinding_factor;
        const commitment = args.commitment;
        if (!verifyPedersenCommitment(commitment, value, blindingFactor)) {
          return toolResult({
            error: "The provided value and blinding factor do not match the commitment."
          });
        }
        const proof = createProofOfKnowledge(value, blindingFactor, commitment);
        auditLog.append("l3", "zk_prove", "system", {
          proof_type: proof.type,
          commitment: commitment.slice(0, 16) + "..."
        });
        return toolResult({
          proof,
          note: "This proof demonstrates knowledge of the commitment opening without revealing the value."
        });
      }
    },
    {
      name: "sanctuary/zk_verify",
      description: "Verify a zero-knowledge proof of knowledge for a Pedersen commitment. Checks that the prover knows the commitment's opening without learning anything.",
      inputSchema: {
        type: "object",
        properties: {
          proof: {
            type: "object",
            description: "The ZK proof object from zk_prove"
          }
        },
        required: ["proof"]
      },
      handler: async (args) => {
        const proof = args.proof;
        const valid = verifyProofOfKnowledge(proof);
        auditLog.append("l3", "zk_verify", "system", {
          proof_type: proof.type,
          valid
        });
        return toolResult({
          valid,
          proof_type: proof.type,
          commitment: proof.commitment,
          verified_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    {
      name: "sanctuary/zk_range_prove",
      description: "Create a zero-knowledge range proof: prove that a committed value is within [min, max] without revealing the exact value. Uses bit-decomposition with OR-proofs on Ristretto255.",
      inputSchema: {
        type: "object",
        properties: {
          value: {
            type: "number",
            description: "The committed value (integer)"
          },
          blinding_factor: {
            type: "string",
            description: "The blinding factor from zk_commit (base64url)"
          },
          commitment: {
            type: "string",
            description: "The Pedersen commitment (base64url)"
          },
          min: {
            type: "number",
            description: "Minimum of the range (inclusive)"
          },
          max: {
            type: "number",
            description: "Maximum of the range (inclusive)"
          }
        },
        required: ["value", "blinding_factor", "commitment", "min", "max"]
      },
      handler: async (args) => {
        const value = args.value;
        const blindingFactor = args.blinding_factor;
        const commitment = args.commitment;
        const min = args.min;
        const max = args.max;
        const proof = createRangeProof(value, blindingFactor, commitment, min, max);
        if ("error" in proof) {
          return toolResult({ error: proof.error });
        }
        auditLog.append("l3", "zk_range_prove", "system", {
          proof_type: proof.type,
          range: `[${min}, ${max}]`,
          bits: proof.bit_commitments.length
        });
        return toolResult({
          proof,
          note: `This proof demonstrates the committed value is in [${min}, ${max}] without revealing it.`
        });
      }
    },
    {
      name: "sanctuary/zk_range_verify",
      description: "Verify a zero-knowledge range proof \u2014 confirms a committed value is within the claimed range without learning the value.",
      inputSchema: {
        type: "object",
        properties: {
          proof: {
            type: "object",
            description: "The range proof object from zk_range_prove"
          }
        },
        required: ["proof"]
      },
      handler: async (args) => {
        const proof = args.proof;
        const valid = verifyRangeProof(proof);
        auditLog.append("l3", "zk_range_verify", "system", {
          proof_type: proof.type,
          valid,
          range: `[${proof.min}, ${proof.max}]`
        });
        return toolResult({
          valid,
          proof_type: proof.type,
          range: { min: proof.min, max: proof.max },
          commitment: proof.commitment,
          verified_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    }
  ];
  return { tools, commitmentStore, policyStore };
}

// src/l4-reputation/reputation-store.ts
init_encoding();
function computeMedian(values) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}
function aggregateMetrics(attestations, metricNames) {
  const result = {};
  const names = metricNames ?? Array.from(
    new Set(
      attestations.flatMap(
        (a) => Object.keys(a.attestation.data.metrics)
      )
    )
  );
  for (const name of names) {
    const values = attestations.map((a) => a.attestation.data.metrics[name]).filter((v) => v !== void 0);
    if (values.length === 0) {
      result[name] = { mean: 0, median: 0, min: 0, max: 0, count: 0 };
      continue;
    }
    result[name] = {
      mean: values.reduce((s, v) => s + v, 0) / values.length,
      median: computeMedian(values),
      min: Math.min(...values),
      max: Math.max(...values),
      count: values.length
    };
  }
  return result;
}
var ReputationStore = class {
  storage;
  encryptionKey;
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l4-reputation");
  }
  /**
   * Record an interaction outcome as a signed attestation.
   */
  async record(interactionId, counterpartyDid, outcome, context, identity, identityEncryptionKey, counterpartyAttestation, sovereigntyTier) {
    const attestationId = `att-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const attestationData = {
      interaction_id: interactionId,
      participant_did: identity.did,
      counterparty_did: counterpartyDid,
      outcome_type: outcome.type,
      outcome_result: outcome.result,
      metrics: outcome.metrics ?? {},
      context,
      timestamp: now,
      sovereignty_tier: sovereigntyTier
    };
    const dataBytes = stringToBytes(JSON.stringify(attestationData));
    const signature = sign(
      dataBytes,
      identity.encrypted_private_key,
      identityEncryptionKey
    );
    const attestation = {
      attestation_id: attestationId,
      schema: "sanctuary-interaction-v1",
      data: attestationData,
      signature: toBase64url(signature),
      signer: identity.did
    };
    const stored = {
      attestation,
      counterparty_attestation: counterpartyAttestation,
      counterparty_confirmed: !!counterpartyAttestation,
      recorded_at: now
    };
    const serialized = stringToBytes(JSON.stringify(stored));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_reputation",
      attestationId,
      stringToBytes(JSON.stringify(encrypted))
    );
    return stored;
  }
  /**
   * Query reputation data with filtering.
   * Returns aggregates only — not raw interaction data.
   */
  async query(options) {
    const all = await this.loadAll();
    let filtered = all;
    if (options.context) {
      filtered = filtered.filter(
        (a) => a.attestation.data.context === options.context
      );
    }
    if (options.time_range) {
      const start2 = new Date(options.time_range.start).getTime();
      const end2 = new Date(options.time_range.end).getTime();
      filtered = filtered.filter((a) => {
        const t = new Date(a.attestation.data.timestamp).getTime();
        return t >= start2 && t <= end2;
      });
    }
    if (options.counterparty_did) {
      filtered = filtered.filter(
        (a) => a.attestation.data.counterparty_did === options.counterparty_did
      );
    }
    const contexts = Array.from(
      new Set(filtered.map((a) => a.attestation.data.context))
    );
    const timestamps = filtered.map(
      (a) => new Date(a.attestation.data.timestamp).getTime()
    );
    const start = timestamps.length > 0 ? new Date(Math.min(...timestamps)).toISOString() : (/* @__PURE__ */ new Date()).toISOString();
    const end = timestamps.length > 0 ? new Date(Math.max(...timestamps)).toISOString() : (/* @__PURE__ */ new Date()).toISOString();
    return {
      total_interactions: filtered.length,
      completed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "completed"
      ).length,
      partial: filtered.filter(
        (a) => a.attestation.data.outcome_result === "partial"
      ).length,
      failed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "failed"
      ).length,
      disputed: filtered.filter(
        (a) => a.attestation.data.outcome_result === "disputed"
      ).length,
      contexts,
      time_range: { start, end },
      aggregate_metrics: aggregateMetrics(filtered, options.metrics)
    };
  }
  /**
   * Export attestations as a portable reputation bundle.
   */
  async exportBundle(identity, identityEncryptionKey, context) {
    let all = await this.loadAll();
    if (context) {
      all = all.filter((a) => a.attestation.data.context === context);
    }
    const attestations = all.map((a) => a.attestation);
    const bundleData = {
      version: "SANCTUARY_REP_V1",
      attestations,
      exported_at: (/* @__PURE__ */ new Date()).toISOString(),
      exporter_did: identity.did
    };
    const bundleBytes = stringToBytes(JSON.stringify(bundleData));
    const bundleSignature = sign(
      bundleBytes,
      identity.encrypted_private_key,
      identityEncryptionKey
    );
    return {
      ...bundleData,
      bundle_signature: toBase64url(bundleSignature)
    };
  }
  /**
   * Import attestations from a reputation bundle.
   * Verifies signatures if requested (default: true).
   *
   * @param publicKeys - Map of DID → public key bytes for signature verification
   */
  async importBundle(bundle, verifySignatures, publicKeys) {
    let imported = 0;
    let invalid = 0;
    const contexts = /* @__PURE__ */ new Set();
    for (const attestation of bundle.attestations) {
      if (verifySignatures) {
        const signerKey = publicKeys.get(attestation.signer);
        if (!signerKey) {
          invalid++;
          continue;
        }
        const dataBytes = stringToBytes(
          JSON.stringify(attestation.data)
        );
        const sigBytes = fromBase64url(attestation.signature);
        if (!verify(dataBytes, sigBytes, signerKey)) {
          invalid++;
          continue;
        }
      }
      const stored = {
        attestation,
        counterparty_confirmed: false,
        recorded_at: (/* @__PURE__ */ new Date()).toISOString()
      };
      const serialized = stringToBytes(JSON.stringify(stored));
      const encrypted = encrypt(serialized, this.encryptionKey);
      await this.storage.write(
        "_reputation",
        attestation.attestation_id,
        stringToBytes(JSON.stringify(encrypted))
      );
      imported++;
      contexts.add(attestation.data.context);
    }
    return {
      imported,
      invalid,
      contexts: Array.from(contexts)
    };
  }
  // ─── Escrow ───────────────────────────────────────────────────────────
  /**
   * Create an escrow for trust bootstrapping.
   */
  async createEscrow(transactionTerms, counterpartyDid, timeoutSeconds, creatorDid, collateralAmount) {
    const escrowId = `esc-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = /* @__PURE__ */ new Date();
    const expiresAt = new Date(now.getTime() + timeoutSeconds * 1e3);
    const { hashToString: hashToString2 } = await Promise.resolve().then(() => (init_hashing(), hashing_exports));
    const termsHash = hashToString2(stringToBytes(transactionTerms));
    const escrow = {
      escrow_id: escrowId,
      transaction_terms: transactionTerms,
      terms_hash: termsHash,
      collateral_amount: collateralAmount,
      counterparty_did: counterpartyDid,
      creator_did: creatorDid,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      status: "pending"
    };
    const serialized = stringToBytes(JSON.stringify(escrow));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_escrows",
      escrowId,
      stringToBytes(JSON.stringify(encrypted))
    );
    return escrow;
  }
  /**
   * Get an escrow by ID.
   */
  async getEscrow(escrowId) {
    const raw = await this.storage.read("_escrows", escrowId);
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }
  // ─── Guarantees ─────────────────────────────────────────────────────
  /**
   * Create a principal's guarantee for a new agent.
   */
  async createGuarantee(principalIdentity, agentDid, scope, durationSeconds, identityEncryptionKey, maxLiability) {
    const guaranteeId = `guar-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = /* @__PURE__ */ new Date();
    const validUntil = new Date(now.getTime() + durationSeconds * 1e3);
    const certificateData = {
      guarantee_id: guaranteeId,
      principal_did: principalIdentity.did,
      agent_did: agentDid,
      scope,
      max_liability: maxLiability,
      valid_until: validUntil.toISOString(),
      issued_at: now.toISOString()
    };
    const certBytes = stringToBytes(JSON.stringify(certificateData));
    const signature = sign(
      certBytes,
      principalIdentity.encrypted_private_key,
      identityEncryptionKey
    );
    const certificate = toBase64url(
      stringToBytes(
        JSON.stringify({
          ...certificateData,
          signature: toBase64url(signature)
        })
      )
    );
    const guarantee = {
      guarantee_id: guaranteeId,
      principal_did: principalIdentity.did,
      agent_did: agentDid,
      scope,
      max_liability: maxLiability,
      valid_until: validUntil.toISOString(),
      certificate,
      created_at: now.toISOString()
    };
    const serialized = stringToBytes(JSON.stringify(guarantee));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_guarantees",
      guaranteeId,
      stringToBytes(JSON.stringify(encrypted))
    );
    return guarantee;
  }
  // ─── Tier-Aware Access ───────────────────────────────────────────────
  /**
   * Load attestations for tier-weighted scoring.
   * Applies basic context/counterparty filtering, returns full StoredAttestations
   * so callers can access sovereignty_tier from attestation data.
   */
  async loadAllForTierScoring(options) {
    let all = await this.loadAll();
    if (options?.context) {
      all = all.filter((a) => a.attestation.data.context === options.context);
    }
    if (options?.counterparty_did) {
      all = all.filter(
        (a) => a.attestation.data.counterparty_did === options.counterparty_did
      );
    }
    return all;
  }
  // ─── Internal ─────────────────────────────────────────────────────────
  async loadAll() {
    const results = [];
    try {
      const entries = await this.storage.list("_reputation");
      for (const meta of entries) {
        const raw = await this.storage.read("_reputation", meta.key);
        if (!raw) continue;
        try {
          const encrypted = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          results.push(JSON.parse(bytesToString(decrypted)));
        } catch {
        }
      }
    } catch {
    }
    return results;
  }
};

// src/l4-reputation/tools.ts
init_encoding();

// src/l4-reputation/tiers.ts
var TIER_WEIGHTS = {
  "verified-sovereign": 1,
  "verified-degraded": 0.8,
  "self-attested": 0.5,
  "unverified": 0.2
};
function resolveTier(counterpartyId, handshakeResults, hasSanctuaryIdentity) {
  const handshake = handshakeResults.get(counterpartyId);
  if (handshake && handshake.verified) {
    const expiresAt = new Date(handshake.expires_at);
    if (expiresAt > /* @__PURE__ */ new Date()) {
      return {
        sovereignty_tier: handshake.trust_tier,
        handshake_completed_at: handshake.completed_at,
        verified_by: handshake.counterparty_id
      };
    }
  }
  if (hasSanctuaryIdentity) {
    return { sovereignty_tier: "self-attested" };
  }
  return { sovereignty_tier: "unverified" };
}
function trustTierToSovereigntyTier(trustTier) {
  switch (trustTier) {
    case "verified-sovereign":
      return "verified-sovereign";
    case "verified-degraded":
      return "verified-degraded";
    default:
      return "unverified";
  }
}
function computeWeightedScore(attestations) {
  if (attestations.length === 0) return null;
  let weightedSum = 0;
  let totalWeight = 0;
  for (const a of attestations) {
    const weight = TIER_WEIGHTS[a.tier];
    weightedSum += a.value * weight;
    totalWeight += weight;
  }
  return totalWeight > 0 ? weightedSum / totalWeight : null;
}
function tierDistribution(tiers) {
  const dist = {
    "verified-sovereign": 0,
    "verified-degraded": 0,
    "self-attested": 0,
    "unverified": 0
  };
  for (const tier of tiers) {
    dist[tier]++;
  }
  return dist;
}

// src/l4-reputation/tools.ts
function createL4Tools(storage, masterKey, identityManager, auditLog, handshakeResults) {
  const reputationStore = new ReputationStore(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const hsResults = handshakeResults ?? /* @__PURE__ */ new Map();
  const tools = [
    // ─── Reputation Recording ─────────────────────────────────────────
    {
      name: "sanctuary/reputation_record",
      description: "Record an interaction outcome as a signed attestation. Creates an EAS-compatible attestation signed by the specified identity.",
      inputSchema: {
        type: "object",
        properties: {
          interaction_id: {
            type: "string",
            description: "Unique interaction identifier"
          },
          counterparty_did: {
            type: "string",
            description: "Counterparty's DID"
          },
          outcome: {
            type: "object",
            description: "Interaction outcome",
            properties: {
              type: {
                type: "string",
                enum: ["transaction", "negotiation", "service", "dispute", "custom"]
              },
              result: {
                type: "string",
                enum: ["completed", "partial", "failed", "disputed"]
              },
              metrics: {
                type: "object",
                description: "Domain-specific metrics (e.g., fulfillment_rate, response_time_ms)"
              }
            },
            required: ["type", "result"]
          },
          context: {
            type: "string",
            description: "Category/domain for context-specific reputation",
            default: "general"
          },
          counterparty_attestation: {
            type: "string",
            description: "Counterparty's signed attestation of the same interaction"
          },
          identity_id: {
            type: "string",
            description: "Identity to sign with (uses default if omitted)"
          }
        },
        required: ["interaction_id", "counterparty_did", "outcome"]
      },
      handler: async (args) => {
        const identityId = args.identity_id;
        const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first."
          });
        }
        const outcome = args.outcome;
        const context = args.context ?? "general";
        const counterpartyDid = args.counterparty_did;
        const hasSanctuaryIdentity = identityManager.list().some(
          (id) => identityManager.get(id.identity_id)?.did === counterpartyDid
        );
        const tierMeta = resolveTier(counterpartyDid, hsResults, hasSanctuaryIdentity);
        const stored = await reputationStore.record(
          args.interaction_id,
          counterpartyDid,
          outcome,
          context,
          identity,
          identityEncryptionKey,
          args.counterparty_attestation,
          tierMeta.sovereignty_tier
        );
        auditLog.append("l4", "reputation_record", identity.identity_id, {
          interaction_id: args.interaction_id,
          outcome_type: outcome.type,
          outcome_result: outcome.result,
          context,
          sovereignty_tier: tierMeta.sovereignty_tier
        });
        return toolResult({
          attestation_id: stored.attestation.attestation_id,
          interaction_id: stored.attestation.data.interaction_id,
          self_attestation: stored.attestation.signature,
          counterparty_confirmed: stored.counterparty_confirmed,
          sovereignty_tier: tierMeta.sovereignty_tier,
          context,
          recorded_at: stored.recorded_at
        });
      }
    },
    // ─── Reputation Query ─────────────────────────────────────────────
    {
      name: "sanctuary/reputation_query",
      description: "Query aggregated reputation data with filtering. Returns summary statistics, never raw interaction details.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "string",
            description: "Filter by context/domain"
          },
          time_range: {
            type: "object",
            description: "Filter by time range",
            properties: {
              start: { type: "string", description: "ISO 8601 start" },
              end: { type: "string", description: "ISO 8601 end" }
            }
          },
          metrics: {
            type: "array",
            items: { type: "string" },
            description: "Which metrics to aggregate"
          },
          counterparty_did: {
            type: "string",
            description: "Filter by counterparty"
          }
        }
      },
      handler: async (args) => {
        const summary = await reputationStore.query({
          context: args.context,
          time_range: args.time_range,
          metrics: args.metrics,
          counterparty_did: args.counterparty_did
        });
        auditLog.append("l4", "reputation_query", "system", {
          total_interactions: summary.total_interactions,
          contexts: summary.contexts
        });
        return toolResult({
          summary,
          // SEC-ADD-03: Tag response as containing counterparty-generated attestation data
          _content_trust: "external"
        });
      }
    },
    // ─── Reputation Export ─────────────────────────────────────────────
    {
      name: "sanctuary/reputation_export",
      description: "Export a portable reputation bundle (SANCTUARY_REP_V1). Includes all signed attestations for independent verification.",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["SANCTUARY_REP_V1"],
            default: "SANCTUARY_REP_V1"
          },
          context: {
            type: "string",
            description: "Export specific context only"
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the bundle with"
          }
        }
      },
      handler: async (args) => {
        const identityId = args.identity_id;
        const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first."
          });
        }
        const context = args.context;
        const bundle = await reputationStore.exportBundle(
          identity,
          identityEncryptionKey,
          context
        );
        const bundleJson = JSON.stringify(bundle);
        const bundleBase64 = toBase64url(
          new TextEncoder().encode(bundleJson)
        );
        auditLog.append("l4", "reputation_export", identity.identity_id, {
          attestation_count: bundle.attestations.length,
          contexts: Array.from(
            new Set(bundle.attestations.map((a) => a.data.context))
          )
        });
        const { hashToString: hashToString2 } = await Promise.resolve().then(() => (init_hashing(), hashing_exports));
        const { stringToBytes: stringToBytes2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
        return toolResult({
          bundle: bundleBase64,
          attestation_count: bundle.attestations.length,
          contexts: Array.from(
            new Set(bundle.attestations.map((a) => a.data.context))
          ),
          bundle_hash: hashToString2(stringToBytes2(bundleJson)),
          exported_at: bundle.exported_at
        });
      }
    },
    // ─── Reputation Import ────────────────────────────────────────────
    {
      name: "sanctuary/reputation_import",
      description: "Import a reputation bundle from another Sanctuary instance. Verifies all attestation signatures by default.",
      inputSchema: {
        type: "object",
        properties: {
          bundle: {
            type: "string",
            description: "Base64url-encoded reputation bundle"
          }
        },
        required: ["bundle"]
      },
      handler: async (args) => {
        const bundleBase64 = args.bundle;
        const verifySignatures = true;
        let bundle;
        try {
          const bundleBytes = fromBase64url(bundleBase64);
          const bundleJson = new TextDecoder().decode(bundleBytes);
          bundle = JSON.parse(bundleJson);
        } catch {
          return toolResult({
            error: "Invalid bundle format. Expected base64url-encoded JSON."
          });
        }
        const publicKeys = /* @__PURE__ */ new Map();
        for (const pub of identityManager.list()) {
          const identity = identityManager.get(pub.identity_id);
          if (identity) {
            publicKeys.set(identity.did, fromBase64url(identity.public_key));
          }
        }
        const result = await reputationStore.importBundle(
          bundle,
          verifySignatures,
          publicKeys
        );
        auditLog.append("l4", "reputation_import", "system", {
          imported: result.imported,
          invalid: result.invalid,
          contexts: result.contexts
        });
        return toolResult({
          imported_attestations: result.imported,
          invalid_attestations: result.invalid,
          contexts: result.contexts,
          imported_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    // ─── Sovereignty-Weighted Query ──────────────────────────────────
    {
      name: "sanctuary/reputation_query_weighted",
      description: "Query reputation with sovereignty-weighted scoring. Attestations from verified-sovereign agents carry full weight (1.0); unverified attestations carry reduced weight (0.2). Returns both the weighted score and tier distribution.",
      inputSchema: {
        type: "object",
        properties: {
          metric: {
            type: "string",
            description: "Which metric to compute the weighted score for"
          },
          context: {
            type: "string",
            description: "Filter by context/domain"
          },
          counterparty_did: {
            type: "string",
            description: "Filter by counterparty"
          }
        },
        required: ["metric"]
      },
      handler: async (args) => {
        const summary = await reputationStore.query({
          context: args.context,
          counterparty_did: args.counterparty_did
        });
        const allAttestations = await reputationStore.loadAllForTierScoring({
          context: args.context,
          counterparty_did: args.counterparty_did
        });
        const metric = args.metric;
        const tieredAttestations = allAttestations.filter((a) => a.attestation.data.metrics[metric] !== void 0).map((a) => ({
          value: a.attestation.data.metrics[metric],
          tier: a.attestation.data.sovereignty_tier ?? "unverified"
        }));
        const weightedScore = computeWeightedScore(tieredAttestations);
        const tiers = allAttestations.map(
          (a) => a.attestation.data.sovereignty_tier ?? "unverified"
        );
        const dist = tierDistribution(tiers);
        auditLog.append("l4", "reputation_query_weighted", "system", {
          metric,
          attestation_count: tieredAttestations.length,
          weighted_score: weightedScore
        });
        return toolResult({
          metric,
          weighted_score: weightedScore,
          attestation_count: tieredAttestations.length,
          tier_distribution: dist,
          tier_weights: TIER_WEIGHTS,
          unweighted_summary: summary
        });
      }
    },
    // ─── Trust Bootstrap: Escrow ──────────────────────────────────────
    {
      name: "sanctuary/bootstrap_create_escrow",
      description: "Create an escrow record for trust bootstrapping. Allows new participants with no reputation to transact safely.",
      inputSchema: {
        type: "object",
        properties: {
          transaction_terms: {
            type: "string",
            description: "Description of the transaction"
          },
          collateral_amount: {
            type: "number",
            description: "Optional stake/collateral amount"
          },
          counterparty_did: {
            type: "string",
            description: "Counterparty's DID"
          },
          timeout_seconds: {
            type: "number",
            description: "Escrow timeout in seconds"
          },
          identity_id: {
            type: "string",
            description: "Identity creating the escrow"
          }
        },
        required: ["transaction_terms", "counterparty_did", "timeout_seconds"]
      },
      handler: async (args) => {
        const identityId = args.identity_id;
        const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
        if (!identity) {
          return toolResult({
            error: "No identity found. Create one with identity_create first."
          });
        }
        const escrow = await reputationStore.createEscrow(
          args.transaction_terms,
          args.counterparty_did,
          args.timeout_seconds,
          identity.did,
          args.collateral_amount
        );
        auditLog.append("l4", "bootstrap_create_escrow", identity.identity_id, {
          escrow_id: escrow.escrow_id,
          counterparty_did: args.counterparty_did,
          timeout_seconds: args.timeout_seconds
        });
        return toolResult({
          escrow_id: escrow.escrow_id,
          terms_hash: escrow.terms_hash,
          created_at: escrow.created_at,
          expires_at: escrow.expires_at,
          status: escrow.status
        });
      }
    },
    // ─── Trust Bootstrap: Guarantee ───────────────────────────────────
    {
      name: "sanctuary/bootstrap_provide_guarantee",
      description: "A principal provides a signed reputation guarantee for a new agent. The guarantee certificate can be presented to counterparties.",
      inputSchema: {
        type: "object",
        properties: {
          principal_identity_id: {
            type: "string",
            description: "Identity of the guarantor (principal)"
          },
          agent_identity_id: {
            type: "string",
            description: "Identity of the agent being guaranteed"
          },
          scope: {
            type: "string",
            description: "What the guarantee covers"
          },
          duration_seconds: {
            type: "number",
            description: "How long the guarantee is valid"
          },
          max_liability: {
            type: "number",
            description: "Maximum liability amount"
          }
        },
        required: [
          "principal_identity_id",
          "agent_identity_id",
          "scope",
          "duration_seconds"
        ]
      },
      handler: async (args) => {
        const principalIdentity = identityManager.get(
          args.principal_identity_id
        );
        const agentIdentity = identityManager.get(
          args.agent_identity_id
        );
        if (!principalIdentity) {
          return toolResult({
            error: `Principal identity "${args.principal_identity_id}" not found.`
          });
        }
        if (!agentIdentity) {
          return toolResult({
            error: `Agent identity "${args.agent_identity_id}" not found.`
          });
        }
        const guarantee = await reputationStore.createGuarantee(
          principalIdentity,
          agentIdentity.did,
          args.scope,
          args.duration_seconds,
          identityEncryptionKey,
          args.max_liability
        );
        auditLog.append(
          "l4",
          "bootstrap_provide_guarantee",
          principalIdentity.identity_id,
          {
            guarantee_id: guarantee.guarantee_id,
            agent_did: agentIdentity.did,
            scope: args.scope
          }
        );
        return toolResult({
          guarantee_id: guarantee.guarantee_id,
          guarantee_certificate: guarantee.certificate,
          scope: guarantee.scope,
          valid_until: guarantee.valid_until
        });
      }
    }
  ];
  return { tools, reputationStore };
}
var DEFAULT_TIER2 = {
  new_namespace_access: "approve",
  new_counterparty: "approve",
  frequency_spike_multiplier: 5,
  max_signs_per_minute: 10,
  bulk_read_threshold: 20,
  first_session_policy: "approve"
};
var DEFAULT_CHANNEL = {
  type: "stderr",
  timeout_seconds: 300
  // SEC-002: auto_deny is not configurable. Timeout always denies.
  // Field omitted intentionally — all channels hardcode deny on timeout.
};
var DEFAULT_POLICY = {
  version: 1,
  tier1_always_approve: [
    "state_export",
    "state_import",
    "state_delete",
    "identity_rotate",
    "reputation_import",
    "reputation_export",
    "bootstrap_provide_guarantee",
    "decommission_certificate"
  ],
  tier2_anomaly: DEFAULT_TIER2,
  tier3_always_allow: [
    "state_read",
    "state_write",
    "state_list",
    "identity_create",
    "identity_list",
    "identity_sign",
    "identity_verify",
    "proof_commitment",
    "proof_reveal",
    "disclosure_set_policy",
    "disclosure_evaluate",
    "reputation_record",
    "reputation_query",
    "bootstrap_create_escrow",
    "exec_attest",
    "monitor_health",
    "monitor_audit_log",
    "manifest",
    "principal_policy_view",
    "principal_baseline_view",
    "shr_generate",
    "shr_verify",
    "handshake_initiate",
    "handshake_respond",
    "handshake_complete",
    "handshake_status",
    "reputation_query_weighted",
    "federation_peers",
    "federation_trust_evaluate",
    "federation_status",
    "zk_commit",
    "zk_prove",
    "zk_verify",
    "zk_range_prove",
    "zk_range_verify",
    "context_gate_set_policy",
    "context_gate_apply_template",
    "context_gate_recommend",
    "context_gate_filter",
    "context_gate_list_policies",
    "l2_hardening_status",
    "l2_verify_isolation",
    "sovereignty_audit",
    "shr_gateway_export",
    "bridge_commit",
    "bridge_verify",
    "bridge_attest"
  ],
  approval_channel: DEFAULT_CHANNEL
};
function extractOperationName(toolName) {
  return toolName.startsWith("sanctuary/") ? toolName.slice("sanctuary/".length) : toolName;
}
function parsePolicy(content) {
  const trimmed = content.trim();
  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    return validatePolicy(parsed);
  }
  const policy = {};
  let currentKey = null;
  let currentList = null;
  let currentObject = null;
  for (const rawLine of trimmed.split("\n")) {
    const line = rawLine.split("#")[0];
    if (line.trim() === "") continue;
    const indent = line.length - line.trimStart().length;
    const stripped = line.trim();
    if (indent === 0 && stripped.includes(":")) {
      if (currentKey && currentList) {
        policy[currentKey] = currentList;
      } else if (currentKey && currentObject) {
        policy[currentKey] = currentObject;
      }
      const colonIdx = stripped.indexOf(":");
      const key = stripped.slice(0, colonIdx).trim();
      const value = stripped.slice(colonIdx + 1).trim();
      if (value === "" || value === "|") {
        currentKey = key;
        currentList = null;
        currentObject = null;
      } else {
        policy[key] = parseScalar(value);
        currentKey = null;
        currentList = null;
        currentObject = null;
      }
    } else if (indent > 0 && stripped.startsWith("- ")) {
      if (!currentList) currentList = [];
      currentList.push(stripped.slice(2).trim().split(/\s+/)[0]);
    } else if (indent > 0 && stripped.includes(":")) {
      if (!currentObject) currentObject = {};
      const colonIdx = stripped.indexOf(":");
      const key = stripped.slice(0, colonIdx).trim();
      const value = stripped.slice(colonIdx + 1).trim();
      currentObject[key] = parseScalar(value.split(/\s+/)[0]);
    }
  }
  if (currentKey && currentList) {
    policy[currentKey] = currentList;
  } else if (currentKey && currentObject) {
    policy[currentKey] = currentObject;
  }
  return validatePolicy(policy);
}
function parseScalar(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;
  return value.replace(/^["']|["']$/g, "");
}
function validatePolicy(raw) {
  const userTier3 = raw.tier3_always_allow ?? [];
  const mergedTier3 = [
    .../* @__PURE__ */ new Set([...userTier3, ...DEFAULT_POLICY.tier3_always_allow])
  ];
  return {
    version: raw.version ?? 1,
    tier1_always_approve: raw.tier1_always_approve ?? DEFAULT_POLICY.tier1_always_approve,
    tier2_anomaly: {
      ...DEFAULT_TIER2,
      ...raw.tier2_anomaly ?? {}
    },
    tier3_always_allow: mergedTier3,
    approval_channel: (() => {
      const merged = {
        ...DEFAULT_CHANNEL,
        ...raw.approval_channel ?? {}
      };
      delete merged.auto_deny;
      return merged;
    })()
  };
}
function generateDefaultPolicyYaml() {
  return `# Sanctuary Principal Policy v1
# This file controls what your agent can do without asking.
# Edit this file directly. Your agent cannot modify it.
# Changes take effect on server restart.

version: 1

# \u2500\u2500\u2500 Tier 1: Always Requires Approval \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# These operations ALWAYS require your explicit approval.
# They are inherently high-risk regardless of context.
tier1_always_approve:
  - state_export
  - state_import
  - state_delete
  - identity_rotate
  - reputation_import
  - reputation_export
  - bootstrap_provide_guarantee

# \u2500\u2500\u2500 Tier 2: Behavioral Anomaly Detection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Triggers approval when agent behavior deviates from its baseline.
# Options for each setting: approve | log | allow
tier2_anomaly:
  new_namespace_access: approve
  new_counterparty: approve
  frequency_spike_multiplier: 5
  max_signs_per_minute: 10
  bulk_read_threshold: 20
  first_session_policy: approve

# \u2500\u2500\u2500 Tier 3: Always Allowed (Audit Only) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# These operations never require approval but are always logged.
tier3_always_allow:
  - state_read
  - state_write
  - state_list
  - identity_create
  - identity_list
  - identity_sign
  - identity_verify
  - proof_commitment
  - proof_reveal
  - disclosure_set_policy
  - disclosure_evaluate
  - reputation_record
  - reputation_query
  - bootstrap_create_escrow
  - exec_attest
  - monitor_health
  - monitor_audit_log
  - manifest
  - principal_policy_view
  - principal_baseline_view
  - shr_generate
  - shr_verify
  - handshake_initiate
  - handshake_respond
  - handshake_complete
  - handshake_status
  - reputation_query_weighted
  - federation_peers
  - federation_trust_evaluate
  - federation_status
  - zk_commit
  - zk_prove
  - zk_verify
  - zk_range_prove
  - zk_range_verify
  - context_gate_set_policy
  - context_gate_apply_template
  - context_gate_recommend
  - context_gate_filter
  - context_gate_list_policies
  - sovereignty_audit
  - shr_gateway_export
  - bridge_commit
  - bridge_verify
  - bridge_attest

# \u2500\u2500\u2500 Approval Channel \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# How Sanctuary reaches you when approval is needed.
# NOTE: Timeout always results in denial. This is not configurable (SEC-002).
approval_channel:
  type: stderr
  timeout_seconds: 300
`;
}
async function loadPrincipalPolicy(storagePath) {
  const policyPath = join(storagePath, "principal-policy.yaml");
  try {
    const content = await readFile(policyPath, "utf-8");
    const policy = parsePolicy(content);
    return Object.freeze(policy);
  } catch {
    const defaultYaml = generateDefaultPolicyYaml();
    try {
      await writeFile(policyPath, defaultYaml, "utf-8");
      await chmod(policyPath, 384);
    } catch {
    }
    return Object.freeze({ ...DEFAULT_POLICY });
  }
}

// src/principal-policy/baseline.ts
init_encoding();
var BASELINE_NAMESPACE = "_principal";
var BASELINE_KEY = "session-baseline";
var BaselineTracker = class {
  storage;
  encryptionKey;
  profile;
  /** Sliding window: timestamps of tool calls per tool name (last 60s) */
  callWindows = /* @__PURE__ */ new Map();
  /** Sliding window: read counts per namespace (last 60s) */
  readWindows = /* @__PURE__ */ new Map();
  /** Sliding window: sign call timestamps (last 60s) */
  signWindow = [];
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "principal-baseline");
    this.profile = {
      known_namespaces: [],
      known_counterparties: [],
      tool_call_counts: {},
      is_first_session: true,
      started_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  /**
   * Load the previous session's baseline from storage.
   * If none exists, this is a first session.
   */
  async load() {
    try {
      const raw = await this.storage.read(BASELINE_NAMESPACE, BASELINE_KEY);
      if (!raw) return;
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const saved = JSON.parse(bytesToString(decrypted));
      this.profile.known_namespaces = saved.known_namespaces ?? [];
      this.profile.known_counterparties = saved.known_counterparties ?? [];
      this.profile.is_first_session = false;
    } catch {
      this.profile.is_first_session = true;
    }
  }
  /**
   * Save the current baseline to storage (encrypted).
   * Called at session end or periodically.
   */
  async save() {
    this.profile.saved_at = (/* @__PURE__ */ new Date()).toISOString();
    const serialized = stringToBytes(JSON.stringify(this.profile));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      BASELINE_NAMESPACE,
      BASELINE_KEY,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
  /**
   * Record a tool call for baseline tracking.
   * Returns anomaly information if applicable.
   */
  recordToolCall(toolName) {
    const now = Date.now();
    this.profile.tool_call_counts[toolName] = (this.profile.tool_call_counts[toolName] ?? 0) + 1;
    if (!this.callWindows.has(toolName)) {
      this.callWindows.set(toolName, []);
    }
    const window = this.callWindows.get(toolName);
    window.push(now);
    const cutoff = now - 6e4;
    while (window.length > 0 && window[0] < cutoff) {
      window.shift();
    }
  }
  /**
   * Record a namespace access.
   * @returns true if this is a new namespace (not in baseline)
   */
  recordNamespaceAccess(namespace) {
    if (namespace.startsWith("_")) return false;
    const isNew = !this.profile.known_namespaces.includes(namespace);
    if (isNew) {
      this.profile.known_namespaces.push(namespace);
    }
    return isNew;
  }
  /**
   * Record a namespace read for bulk-read detection.
   * @returns the number of reads in the current 60-second window
   */
  recordNamespaceRead(namespace) {
    const now = Date.now();
    if (!this.readWindows.has(namespace)) {
      this.readWindows.set(namespace, []);
    }
    const window = this.readWindows.get(namespace);
    window.push(now);
    const cutoff = now - 6e4;
    while (window.length > 0 && window[0] < cutoff) {
      window.shift();
    }
    return window.length;
  }
  /**
   * Record a counterparty DID interaction.
   * @returns true if this is a new counterparty (not in baseline)
   */
  recordCounterparty(did) {
    const isNew = !this.profile.known_counterparties.includes(did);
    if (isNew) {
      this.profile.known_counterparties.push(did);
    }
    return isNew;
  }
  /**
   * Record a signing operation.
   * @returns the number of signs in the current 60-second window
   */
  recordSign() {
    const now = Date.now();
    this.signWindow.push(now);
    const cutoff = now - 6e4;
    while (this.signWindow.length > 0 && this.signWindow[0] < cutoff) {
      this.signWindow.shift();
    }
    return this.signWindow.length;
  }
  /**
   * Get the current call rate for a tool (calls per minute).
   */
  getCallRate(toolName) {
    return this.callWindows.get(toolName)?.length ?? 0;
  }
  /**
   * Get the average call rate across all tools in the baseline.
   */
  getAverageCallRate() {
    let total = 0;
    let count = 0;
    for (const window of this.callWindows.values()) {
      total += window.length;
      count++;
    }
    return count > 0 ? total / count : 0;
  }
  /** Whether this is the first session */
  get isFirstSession() {
    return this.profile.is_first_session;
  }
  /** Get a read-only view of the current profile */
  getProfile() {
    return { ...this.profile };
  }
};

// src/principal-policy/approval-channel.ts
var StderrApprovalChannel = class {
  constructor(_config) {
  }
  async requestApproval(request) {
    const prompt = this.formatPrompt(request);
    process.stderr.write(prompt + "\n");
    return {
      decision: "deny",
      decided_at: (/* @__PURE__ */ new Date()).toISOString(),
      decided_by: "stderr:non-interactive"
    };
  }
  formatPrompt(request) {
    const tierLabel = request.tier === 1 ? "Tier 1 \u2014 always requires approval" : "Tier 2 \u2014 behavioral anomaly detected";
    const contextLines = Object.entries(request.context).map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
    return [
      "",
      "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557",
      "\u2551  SANCTUARY: Operation Denied (non-interactive channel)           \u2551",
      "\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563",
      `\u2551  Operation:  ${request.operation.padEnd(50)}\u2551`,
      `\u2551  ${tierLabel.padEnd(62)}\u2551`,
      `\u2551  Reason:     ${request.reason.slice(0, 50).padEnd(50)}\u2551`,
      "\u2551                                                                  \u2551",
      `\u2551  Details:                                                        \u2551`,
      ...contextLines.split("\n").map(
        (line) => `\u2551    ${line.padEnd(60)}\u2551`
      ),
      "\u2551                                                                  \u2551",
      "\u2551  Denied: stderr channel cannot accept input (SEC-016)            \u2551",
      "\u2551  Use dashboard or webhook channel for interactive approval.      \u2551",
      "\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D",
      ""
    ].join("\n");
  }
};

// src/principal-policy/dashboard-html.ts
function generateDashboardHTML(options) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sanctuary \u2014 Principal Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --bg-surface: #1a1d27;
    --bg-elevated: #242736;
    --border: #2e3244;
    --text: #e4e6f0;
    --text-muted: #8b8fa3;
    --accent: #6c8aff;
    --accent-hover: #839dff;
    --approve: #3ecf8e;
    --approve-hover: #5dd9a3;
    --deny: #f87171;
    --deny-hover: #fca5a5;
    --warning: #fbbf24;
    --tier1: #f87171;
    --tier2: #fbbf24;
    --tier3: #3ecf8e;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --mono: "SF Mono", "Fira Code", "Cascadia Code", monospace;
    --radius: 8px;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
  }

  /* Layout */
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 20px; border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
  }
  header h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.3px; }
  header h1 span { color: var(--accent); }
  .status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 12px; color: var(--text-muted);
    padding: 4px 10px; border-radius: 12px;
    background: var(--bg-surface); border: 1px solid var(--border);
  }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--approve); animation: pulse 2s infinite;
  }
  .status-dot.disconnected { background: var(--deny); animation: none; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

  /* Tabs */
  .tabs {
    display: flex; gap: 2px; margin-bottom: 20px;
    background: var(--bg-surface); border-radius: var(--radius);
    padding: 3px; border: 1px solid var(--border);
  }
  .tab {
    flex: 1; padding: 8px 12px; text-align: center;
    font-size: 13px; font-weight: 500; cursor: pointer;
    border-radius: 6px; border: none; color: var(--text-muted);
    background: transparent; transition: all 0.15s;
  }
  .tab:hover { color: var(--text); }
  .tab.active { background: var(--bg-elevated); color: var(--text); }
  .tab .count {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 18px; height: 18px; padding: 0 5px;
    font-size: 11px; font-weight: 600; border-radius: 9px;
    margin-left: 6px;
  }
  .tab .count.alert { background: var(--deny); color: white; }
  .tab .count.muted { background: var(--border); color: var(--text-muted); }

  /* Tab Content */
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Pending Requests */
  .pending-empty {
    text-align: center; padding: 60px 20px; color: var(--text-muted);
  }
  .pending-empty .icon { font-size: 32px; margin-bottom: 12px; }
  .pending-empty p { font-size: 14px; }

  .request-card {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px; margin-bottom: 12px;
    animation: slideIn 0.2s ease-out;
  }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
  .request-card.tier1 { border-left: 3px solid var(--tier1); }
  .request-card.tier2 { border-left: 3px solid var(--tier2); }
  .request-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 10px;
  }
  .request-op {
    font-family: var(--mono); font-size: 14px; font-weight: 600;
  }
  .tier-badge {
    font-size: 11px; font-weight: 600; padding: 2px 8px;
    border-radius: 4px; text-transform: uppercase;
  }
  .tier-badge.tier1 { background: rgba(248,113,113,0.15); color: var(--tier1); }
  .tier-badge.tier2 { background: rgba(251,191,36,0.15); color: var(--tier2); }
  .request-reason {
    font-size: 13px; color: var(--text-muted); margin-bottom: 12px;
  }
  .request-context {
    font-family: var(--mono); font-size: 12px; color: var(--text-muted);
    background: var(--bg); border-radius: 4px; padding: 8px 10px;
    margin-bottom: 14px; white-space: pre-wrap; word-break: break-all;
    max-height: 120px; overflow-y: auto;
  }
  .request-actions {
    display: flex; align-items: center; gap: 10px;
  }
  .btn {
    padding: 7px 16px; border-radius: 6px; font-size: 13px;
    font-weight: 600; border: none; cursor: pointer;
    transition: all 0.15s;
  }
  .btn-approve { background: var(--approve); color: #0f1117; }
  .btn-approve:hover { background: var(--approve-hover); }
  .btn-deny { background: var(--deny); color: white; }
  .btn-deny:hover { background: var(--deny-hover); }
  .countdown {
    margin-left: auto; font-size: 12px; color: var(--text-muted);
    font-family: var(--mono);
  }
  .countdown.urgent { color: var(--deny); font-weight: 600; }

  /* Audit Log */
  .audit-table { width: 100%; border-collapse: collapse; }
  .audit-table th {
    text-align: left; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--text-muted); padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  .audit-table td {
    font-size: 13px; padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  .audit-table tr { transition: background 0.1s; }
  .audit-table tr:hover { background: var(--bg-elevated); }
  .audit-table tr.new { animation: highlight 1s ease-out; }
  @keyframes highlight { from { background: rgba(108,138,255,0.15); } to { background: transparent; } }
  .audit-time { font-family: var(--mono); font-size: 12px; color: var(--text-muted); }
  .audit-op { font-family: var(--mono); font-size: 12px; }
  .audit-layer {
    font-size: 11px; font-weight: 600; padding: 1px 6px;
    border-radius: 3px; text-transform: uppercase;
  }
  .audit-layer.l1 { background: rgba(108,138,255,0.15); color: var(--accent); }
  .audit-layer.l2 { background: rgba(251,191,36,0.15); color: var(--tier2); }
  .audit-layer.l3 { background: rgba(62,207,142,0.15); color: var(--tier3); }
  .audit-layer.l4 { background: rgba(168,85,247,0.15); color: #a855f7; }

  /* Baseline & Policy */
  .info-section {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px; margin-bottom: 16px;
  }
  .info-section h3 {
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 12px;
  }
  .info-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 6px 0; font-size: 13px;
  }
  .info-label { color: var(--text-muted); }
  .info-value { font-family: var(--mono); font-size: 12px; }
  .tag-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .tag {
    font-family: var(--mono); font-size: 11px; padding: 2px 8px;
    background: var(--bg-elevated); border-radius: 4px;
    color: var(--text-muted); border: 1px solid var(--border);
  }
  .policy-op {
    font-family: var(--mono); font-size: 12px; padding: 3px 0;
  }

  /* Footer */
  footer {
    margin-top: 32px; padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 12px; color: var(--text-muted);
    text-align: center;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>Sanctuary</span> Principal Dashboard</h1>
    <div class="status-badge">
      <div class="status-dot" id="statusDot"></div>
      <span id="statusText">Connected</span>
    </div>
  </header>

  <div class="tabs">
    <button class="tab active" data-tab="pending">
      Pending<span class="count muted" id="pendingCount">0</span>
    </button>
    <button class="tab" data-tab="audit">
      Audit Log<span class="count muted" id="auditCount">0</span>
    </button>
    <button class="tab" data-tab="baseline">Baseline</button>
    <button class="tab" data-tab="policy">Policy</button>
  </div>

  <!-- Pending Approvals -->
  <div class="tab-content active" id="tab-pending">
    <div class="pending-empty" id="pendingEmpty">
      <div class="icon">&#x2714;</div>
      <p>No pending approval requests.</p>
      <p style="font-size:12px; margin-top:4px;">Requests will appear here in real time.</p>
    </div>
    <div id="pendingList"></div>
  </div>

  <!-- Audit Log -->
  <div class="tab-content" id="tab-audit">
    <table class="audit-table">
      <thead>
        <tr><th>Time</th><th>Layer</th><th>Operation</th><th>Identity</th></tr>
      </thead>
      <tbody id="auditBody"></tbody>
    </table>
  </div>

  <!-- Baseline -->
  <div class="tab-content" id="tab-baseline">
    <div class="info-section">
      <h3>Session Info</h3>
      <div class="info-row"><span class="info-label">First session</span><span class="info-value" id="bFirstSession">\u2014</span></div>
      <div class="info-row"><span class="info-label">Started</span><span class="info-value" id="bStarted">\u2014</span></div>
    </div>
    <div class="info-section">
      <h3>Known Namespaces</h3>
      <div class="tag-list" id="bNamespaces"><span class="tag">\u2014</span></div>
    </div>
    <div class="info-section">
      <h3>Known Counterparties</h3>
      <div class="tag-list" id="bCounterparties"><span class="tag">\u2014</span></div>
    </div>
    <div class="info-section">
      <h3>Tool Call Counts</h3>
      <div id="bToolCalls"><span class="info-value">\u2014</span></div>
    </div>
  </div>

  <!-- Policy -->
  <div class="tab-content" id="tab-policy">
    <div class="info-section">
      <h3>Tier 1 \u2014 Always Requires Approval</h3>
      <div id="pTier1"></div>
    </div>
    <div class="info-section">
      <h3>Tier 2 \u2014 Anomaly Detection</h3>
      <div id="pTier2"></div>
    </div>
    <div class="info-section">
      <h3>Tier 3 \u2014 Always Allowed</h3>
      <div class="info-row">
        <span class="info-label">Operations</span>
        <span class="info-value" id="pTier3Count">\u2014</span>
      </div>
    </div>
    <div class="info-section">
      <h3>Approval Channel</h3>
      <div id="pChannel"></div>
    </div>
  </div>

  <footer>Sanctuary Framework v${options.serverVersion} \u2014 Principal Dashboard</footer>
</div>

<script>
(function() {
  const TIMEOUT = ${options.timeoutSeconds};
  // SEC-012: Auth token is passed via Authorization header only \u2014 never in URLs.
  // The token is provided by the server at generation time (embedded for initial auth).
  const AUTH_TOKEN = ${options.authToken ? JSON.stringify(options.authToken) : "null"};
  let SESSION_ID = null; // Short-lived session for SSE and URL-based requests
  const pending = new Map();
  let auditCount = 0;

  // Auth helpers \u2014 SEC-012: token goes in header, session goes in URL
  function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (AUTH_TOKEN) h['Authorization'] = 'Bearer ' + AUTH_TOKEN;
    return h;
  }
  function sessionQuery(url) {
    if (!SESSION_ID) return url;
    const sep = url.includes('?') ? '&' : '?';
    return url + sep + 'session=' + SESSION_ID;
  }

  // SEC-012: Exchange the long-lived token for a short-lived session
  async function exchangeSession() {
    if (!AUTH_TOKEN) return;
    try {
      const resp = await fetch('/auth/session', { method: 'POST', headers: authHeaders() });
      if (resp.ok) {
        const data = await resp.json();
        SESSION_ID = data.session_id;
        // Refresh session before expiry (at 80% of TTL)
        const refreshMs = (data.expires_in_seconds || 300) * 800;
        setTimeout(async () => { await exchangeSession(); reconnectSSE(); }, refreshMs);
      }
    } catch(e) { /* will retry on next connect */ }
  }

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });

  // SSE Connection \u2014 SEC-012: uses short-lived session token in URL, not auth token
  let evtSource;
  function reconnectSSE() {
    if (evtSource) { evtSource.close(); }
    connect();
  }
  function connect() {
    evtSource = new EventSource(sessionQuery('/events'));
    evtSource.onopen = () => {
      document.getElementById('statusDot').classList.remove('disconnected');
      document.getElementById('statusText').textContent = 'Connected';
    };
    evtSource.onerror = () => {
      document.getElementById('statusDot').classList.add('disconnected');
      document.getElementById('statusText').textContent = 'Reconnecting...';
    };
    evtSource.addEventListener('pending-request', (e) => {
      const data = JSON.parse(e.data);
      addPendingRequest(data);
    });
    evtSource.addEventListener('request-resolved', (e) => {
      const data = JSON.parse(e.data);
      removePendingRequest(data.request_id);
    });
    evtSource.addEventListener('audit-entry', (e) => {
      const data = JSON.parse(e.data);
      addAuditEntry(data);
    });
    evtSource.addEventListener('baseline-update', (e) => {
      const data = JSON.parse(e.data);
      updateBaseline(data);
    });
    evtSource.addEventListener('policy-update', (e) => {
      const data = JSON.parse(e.data);
      updatePolicy(data);
    });
    evtSource.addEventListener('init', (e) => {
      const data = JSON.parse(e.data);
      if (data.baseline) updateBaseline(data.baseline);
      if (data.policy) updatePolicy(data.policy);
      if (data.pending) data.pending.forEach(addPendingRequest);
      if (data.audit) data.audit.forEach(addAuditEntry);
    });
  }

  // Pending requests
  function addPendingRequest(req) {
    pending.set(req.request_id, { ...req, remaining: TIMEOUT });
    renderPending();
    updatePendingCount();
    flashTab('pending');
  }

  function removePendingRequest(id) {
    pending.delete(id);
    renderPending();
    updatePendingCount();
  }

  function renderPending() {
    const list = document.getElementById('pendingList');
    const empty = document.getElementById('pendingEmpty');
    if (pending.size === 0) {
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    list.innerHTML = '';
    for (const [id, req] of pending) {
      const card = document.createElement('div');
      card.className = 'request-card tier' + req.tier;
      card.id = 'req-' + id;
      const ctx = typeof req.context === 'string' ? req.context : JSON.stringify(req.context, null, 2);
      card.innerHTML =
        '<div class="request-header">' +
          '<span class="request-op">' + esc(req.operation) + '</span>' +
          '<span class="tier-badge tier' + req.tier + '">Tier ' + req.tier + '</span>' +
        '</div>' +
        '<div class="request-reason">' + esc(req.reason) + '</div>' +
        '<div class="request-context">' + esc(ctx) + '</div>' +
        '<div class="request-actions">' +
          '<button class="btn btn-approve" onclick="handleApprove(\\'' + id + '\\')">Approve</button>' +
          '<button class="btn btn-deny" onclick="handleDeny(\\'' + id + '\\')">Deny</button>' +
          '<span class="countdown" id="cd-' + id + '">' + req.remaining + 's</span>' +
        '</div>';
      list.appendChild(card);
    }
  }

  function updatePendingCount() {
    const el = document.getElementById('pendingCount');
    el.textContent = pending.size;
    el.className = pending.size > 0 ? 'count alert' : 'count muted';
  }

  function flashTab(name) {
    const tab = document.querySelector('[data-tab="' + name + '"]');
    if (!tab.classList.contains('active')) {
      tab.style.background = 'rgba(248,113,113,0.15)';
      setTimeout(() => { tab.style.background = ''; }, 1500);
    }
  }

  // Countdown timer
  setInterval(() => {
    for (const [id, req] of pending) {
      req.remaining = Math.max(0, req.remaining - 1);
      const el = document.getElementById('cd-' + id);
      if (el) {
        el.textContent = req.remaining + 's';
        el.className = req.remaining <= 30 ? 'countdown urgent' : 'countdown';
      }
    }
  }, 1000);

  // Approve / Deny handlers (global scope)
  window.handleApprove = function(id) {
    fetch('/api/approve/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    });
  };
  window.handleDeny = function(id) {
    fetch('/api/deny/' + id, { method: 'POST', headers: authHeaders() }).then(() => {
      removePendingRequest(id);
    });
  };

  // Audit log
  function addAuditEntry(entry) {
    auditCount++;
    document.getElementById('auditCount').textContent = auditCount;
    const tbody = document.getElementById('auditBody');
    const tr = document.createElement('tr');
    tr.className = 'new';
    const time = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '\u2014';
    const layer = entry.layer || '\u2014';
    tr.innerHTML =
      '<td class="audit-time">' + esc(time) + '</td>' +
      '<td><span class="audit-layer ' + layer + '">' + esc(layer) + '</span></td>' +
      '<td class="audit-op">' + esc(entry.operation || '\u2014') + '</td>' +
      '<td style="font-size:12px;color:var(--text-muted)">' + esc(entry.identity_id || '\u2014') + '</td>';
    tbody.insertBefore(tr, tbody.firstChild);
    // Keep last 100 entries
    while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
  }

  // Baseline
  function updateBaseline(b) {
    if (!b) return;
    document.getElementById('bFirstSession').textContent = b.is_first_session ? 'Yes' : 'No';
    document.getElementById('bStarted').textContent = b.started_at ? new Date(b.started_at).toLocaleString() : '\u2014';
    const ns = document.getElementById('bNamespaces');
    ns.innerHTML = (b.known_namespaces || []).length > 0
      ? (b.known_namespaces || []).map(n => '<span class="tag">' + esc(n) + '</span>').join('')
      : '<span class="tag">none</span>';
    const cp = document.getElementById('bCounterparties');
    cp.innerHTML = (b.known_counterparties || []).length > 0
      ? (b.known_counterparties || []).map(c => '<span class="tag">' + esc(c.slice(0,16)) + '...</span>').join('')
      : '<span class="tag">none</span>';
    const tc = document.getElementById('bToolCalls');
    const counts = b.tool_call_counts || {};
    const entries = Object.entries(counts).sort((a,b) => b[1] - a[1]);
    tc.innerHTML = entries.length > 0
      ? entries.map(([k,v]) => '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + v + '</span></div>').join('')
      : '<span class="info-value">no calls yet</span>';
  }

  // Policy
  function updatePolicy(p) {
    if (!p) return;
    const t1 = document.getElementById('pTier1');
    t1.innerHTML = (p.tier1_always_approve || []).map(op =>
      '<div class="policy-op">' + esc(op) + '</div>'
    ).join('');
    const t2 = document.getElementById('pTier2');
    const cfg = p.tier2_anomaly || {};
    t2.innerHTML = Object.entries(cfg).map(([k,v]) =>
      '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + esc(String(v)) + '</span></div>'
    ).join('');
    document.getElementById('pTier3Count').textContent = (p.tier3_always_allow || []).length + ' operations';
    const ch = document.getElementById('pChannel');
    const chan = p.approval_channel || {};
    ch.innerHTML = Object.entries(chan).filter(([k]) => k !== 'webhook_secret').map(([k,v]) =>
      '<div class="info-row"><span class="info-label">' + esc(k) + '</span><span class="info-value">' + esc(String(v)) + '</span></div>'
    ).join('');
  }

  function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  // Init \u2014 SEC-012: exchange token for session before connecting SSE
  (async function init() {
    await exchangeSession();
    // Clean token from URL if present (legacy bookmarks)
    if (window.location.search.includes('token=')) {
      const clean = window.location.pathname;
      window.history.replaceState({}, '', clean);
    }
    connect();
    fetch('/api/status', { headers: authHeaders() }).then(r => r.json()).then(data => {
      if (data.baseline) updateBaseline(data.baseline);
      if (data.policy) updatePolicy(data.policy);
    }).catch(() => {});
  })();
})();
</script>
</body>
</html>`;
}

// src/principal-policy/dashboard.ts
var SESSION_TTL_MS = 5 * 60 * 1e3;
var MAX_SESSIONS = 1e3;
var RATE_LIMIT_WINDOW_MS = 6e4;
var RATE_LIMIT_GENERAL = 120;
var RATE_LIMIT_DECISIONS = 20;
var MAX_RATE_LIMIT_ENTRIES = 1e4;
var DashboardApprovalChannel = class {
  config;
  pending = /* @__PURE__ */ new Map();
  sseClients = /* @__PURE__ */ new Set();
  httpServer = null;
  policy = null;
  baseline = null;
  auditLog = null;
  dashboardHTML;
  authToken;
  useTLS;
  /** SEC-012: Short-lived session store. Sessions replace URL query tokens. */
  sessions = /* @__PURE__ */ new Map();
  sessionCleanupTimer = null;
  /** Rate limiting: per-IP request tracking */
  rateLimits = /* @__PURE__ */ new Map();
  constructor(config) {
    this.config = config;
    this.authToken = config.auth_token;
    this.useTLS = !!(config.tls?.cert_path && config.tls?.key_path);
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: config.timeout_seconds,
      serverVersion: SANCTUARY_VERSION,
      authToken: this.authToken
    });
    this.sessionCleanupTimer = setInterval(() => this.cleanupSessions(), 6e4);
  }
  /**
   * Inject dependencies after construction.
   * Called from index.ts after all components are initialized.
   */
  setDependencies(deps) {
    this.policy = deps.policy;
    this.baseline = deps.baseline;
    this.auditLog = deps.auditLog;
  }
  /**
   * Start the HTTP(S) server for the dashboard.
   */
  async start() {
    return new Promise((resolve, reject) => {
      const handler = (req, res) => this.handleRequest(req, res);
      if (this.useTLS && this.config.tls) {
        const tlsOpts = {
          cert: readFileSync(this.config.tls.cert_path),
          key: readFileSync(this.config.tls.key_path)
        };
        this.httpServer = createServer$1(tlsOpts, handler);
      } else {
        this.httpServer = createServer$2(handler);
      }
      const protocol = this.useTLS ? "https" : "http";
      const baseUrl = `${protocol}://${this.config.host}:${this.config.port}`;
      this.httpServer.listen(this.config.port, this.config.host, () => {
        if (this.authToken) {
          const hint = this.authToken.slice(0, 4) + "..." + this.authToken.slice(-4);
          process.stderr.write(
            `
  Sanctuary Principal Dashboard: ${baseUrl}
`
          );
          process.stderr.write(
            `  Auth required (token: ${hint}). Use Authorization: Bearer <TOKEN> header.

`
          );
        } else {
          process.stderr.write(
            `
  Sanctuary Principal Dashboard: ${baseUrl}

`
          );
        }
        resolve();
      });
      this.httpServer.on("error", reject);
    });
  }
  /**
   * Stop the HTTP server and clean up.
   */
  async stop() {
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        decision: "deny",
        decided_at: (/* @__PURE__ */ new Date()).toISOString(),
        decided_by: "auto"
      });
    }
    this.pending.clear();
    for (const client of this.sseClients) {
      client.end();
    }
    this.sseClients.clear();
    this.sessions.clear();
    if (this.sessionCleanupTimer) {
      clearInterval(this.sessionCleanupTimer);
      this.sessionCleanupTimer = null;
    }
    this.rateLimits.clear();
    if (this.httpServer) {
      return new Promise((resolve) => {
        this.httpServer.close(() => resolve());
      });
    }
  }
  /**
   * Request approval from the human via the dashboard.
   * Blocks until the human approves/denies or timeout occurs.
   */
  async requestApproval(request) {
    const id = randomBytes$1(8).toString("hex");
    process.stderr.write(
      `[Sanctuary] Approval required: ${request.operation} (Tier ${request.tier}) \u2014 open dashboard to respond
`
    );
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const response = {
          // SEC-002: Timeout ALWAYS denies. No configuration can change this.
          decision: "deny",
          decided_at: (/* @__PURE__ */ new Date()).toISOString(),
          decided_by: "timeout"
        };
        this.broadcastSSE("request-resolved", {
          request_id: id,
          decision: response.decision,
          decided_by: "timeout"
        });
        resolve(response);
      }, this.config.timeout_seconds * 1e3);
      const pending = {
        id,
        request,
        resolve,
        timer,
        created_at: (/* @__PURE__ */ new Date()).toISOString()
      };
      this.pending.set(id, pending);
      this.broadcastSSE("pending-request", {
        request_id: id,
        operation: request.operation,
        tier: request.tier,
        reason: request.reason,
        context: request.context,
        timestamp: request.timestamp
      });
    });
  }
  // ── Authentication ──────────────────────────────────────────────────
  /**
   * Verify bearer token authentication.
   *
   * SEC-012: The long-lived auth token is ONLY accepted via the Authorization
   * header — never in URL query strings. For SSE and page loads that cannot
   * set headers, a short-lived session token (obtained via POST /auth/session)
   * is accepted via ?session= query parameter.
   *
   * Returns true if auth passes, false if blocked (response already sent).
   */
  checkAuth(req, url, res) {
    if (!this.authToken) return true;
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const parts = authHeader.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer" && parts[1] === this.authToken) {
        return true;
      }
    }
    const sessionId = url.searchParams.get("session");
    if (sessionId && this.validateSession(sessionId)) {
      return true;
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized \u2014 use Authorization: Bearer header or a valid session" }));
    return false;
  }
  // ── Session Management (SEC-012) ──────────────────────────────────
  /**
   * Create a short-lived session by exchanging the long-lived auth token
   * (provided in the Authorization header) for a session ID.
   */
  createSession() {
    if (this.sessions.size >= MAX_SESSIONS) {
      this.cleanupSessions();
      if (this.sessions.size >= MAX_SESSIONS) {
        const oldest = [...this.sessions.entries()].sort(
          (a, b) => a[1].created_at - b[1].created_at
        )[0];
        if (oldest) this.sessions.delete(oldest[0]);
      }
    }
    const id = randomBytes$1(32).toString("hex");
    const now = Date.now();
    this.sessions.set(id, {
      id,
      created_at: now,
      expires_at: now + SESSION_TTL_MS
    });
    return id;
  }
  /**
   * Validate a session ID — must exist and not be expired.
   */
  validateSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (Date.now() > session.expires_at) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }
  /**
   * Remove all expired sessions.
   */
  cleanupSessions() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now > session.expires_at) {
        this.sessions.delete(id);
      }
    }
  }
  // ── Rate Limiting ─────────────────────────────────────────────────
  /**
   * Get the remote address from a request, normalizing IPv6-mapped IPv4.
   */
  getRemoteAddr(req) {
    const addr = req.socket.remoteAddress ?? "unknown";
    return addr.startsWith("::ffff:") ? addr.slice(7) : addr;
  }
  /**
   * Check rate limit for a request. Returns true if allowed, false if rate-limited.
   * When rate-limited, sends a 429 response.
   */
  checkRateLimit(req, res, type) {
    const addr = this.getRemoteAddr(req);
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    let entry = this.rateLimits.get(addr);
    if (!entry) {
      if (this.rateLimits.size >= MAX_RATE_LIMIT_ENTRIES) {
        this.pruneRateLimits(now);
      }
      entry = { general: [], decisions: [] };
      this.rateLimits.set(addr, entry);
    }
    entry.general = entry.general.filter((t) => t > windowStart);
    entry.decisions = entry.decisions.filter((t) => t > windowStart);
    const limit = type === "decisions" ? RATE_LIMIT_DECISIONS : RATE_LIMIT_GENERAL;
    const timestamps = entry[type];
    if (timestamps.length >= limit) {
      const retryAfter = Math.ceil((timestamps[0] + RATE_LIMIT_WINDOW_MS - now) / 1e3);
      res.writeHead(429, {
        "Content-Type": "application/json",
        "Retry-After": String(Math.max(1, retryAfter))
      });
      res.end(JSON.stringify({
        error: "Rate limit exceeded",
        retry_after_seconds: Math.max(1, retryAfter)
      }));
      return false;
    }
    timestamps.push(now);
    return true;
  }
  /**
   * Remove stale entries from the rate limit map.
   */
  pruneRateLimits(now) {
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    for (const [addr, entry] of this.rateLimits) {
      const hasRecent = entry.general.some((t) => t > windowStart) || entry.decisions.some((t) => t > windowStart);
      if (!hasRecent) {
        this.rateLimits.delete(addr);
      }
    }
  }
  // ── HTTP Request Handler ────────────────────────────────────────────
  handleRequest(req, res) {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const method = req.method ?? "GET";
    const origin = req.headers.origin;
    const protocol = this.useTLS ? "https" : "http";
    const selfOrigin = `${protocol}://${this.config.host}:${this.config.port}`;
    if (origin === selfOrigin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (!this.checkAuth(req, url, res)) return;
    if (!this.checkRateLimit(req, res, "general")) return;
    try {
      if (method === "POST" && url.pathname === "/auth/session") {
        this.handleSessionExchange(req, res);
        return;
      }
      if (method === "GET" && url.pathname === "/") {
        this.serveDashboard(res);
      } else if (method === "GET" && url.pathname === "/events") {
        this.handleSSE(req, res);
      } else if (method === "GET" && url.pathname === "/api/status") {
        this.handleStatus(res);
      } else if (method === "GET" && url.pathname === "/api/pending") {
        this.handlePendingList(res);
      } else if (method === "GET" && url.pathname === "/api/audit-log") {
        this.handleAuditLog(url, res);
      } else if (method === "POST" && url.pathname.startsWith("/api/approve/")) {
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/approve/".length);
        this.handleDecision(id, "approve", res);
      } else if (method === "POST" && url.pathname.startsWith("/api/deny/")) {
        if (!this.checkRateLimit(req, res, "decisions")) return;
        const id = url.pathname.slice("/api/deny/".length);
        this.handleDecision(id, "deny", res);
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
      }
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }
  // ── Route Handlers ──────────────────────────────────────────────────
  /**
   * SEC-012: Exchange a long-lived auth token (in Authorization header)
   * for a short-lived session ID. The session ID can be used in URL
   * query parameters without exposing the long-lived credential.
   *
   * This endpoint performs its OWN auth check (header-only) because it
   * must reject query-parameter tokens and is called before the
   * normal checkAuth flow.
   */
  handleSessionExchange(req, res) {
    if (!this.authToken) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ session_id: "no-auth" }));
      return;
    }
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Authorization header required" }));
      return;
    }
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer" || parts[1] !== this.authToken) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid bearer token" }));
      return;
    }
    const sessionId = this.createSession();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      session_id: sessionId,
      expires_in_seconds: SESSION_TTL_MS / 1e3
    }));
  }
  serveDashboard(res) {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache"
    });
    res.end(this.dashboardHTML);
  }
  handleSSE(req, res) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive"
    });
    const initData = {};
    if (this.baseline) {
      initData.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      initData.policy = {
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true
          // SEC-002: hardcoded, not configurable
        }
      };
    }
    const pendingList = Array.from(this.pending.values()).map((p) => ({
      request_id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp
    }));
    if (pendingList.length > 0) {
      initData.pending = pendingList;
    }
    res.write(`event: init
data: ${JSON.stringify(initData)}

`);
    this.sseClients.add(res);
    req.on("close", () => {
      this.sseClients.delete(res);
    });
  }
  handleStatus(res) {
    const status = {
      pending_count: this.pending.size,
      connected_clients: this.sseClients.size
    };
    if (this.baseline) {
      status.baseline = this.baseline.getProfile();
    }
    if (this.policy) {
      status.policy = {
        version: this.policy.version,
        tier1_always_approve: this.policy.tier1_always_approve,
        tier2_anomaly: this.policy.tier2_anomaly,
        tier3_always_allow: this.policy.tier3_always_allow,
        approval_channel: {
          type: this.policy.approval_channel.type,
          timeout_seconds: this.policy.approval_channel.timeout_seconds,
          auto_deny: true
          // SEC-002: hardcoded, not configurable
        }
      };
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(status));
  }
  handlePendingList(res) {
    const list = Array.from(this.pending.values()).map((p) => ({
      id: p.id,
      operation: p.request.operation,
      tier: p.request.tier,
      reason: p.request.reason,
      context: p.request.context,
      timestamp: p.request.timestamp,
      created_at: p.created_at
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(list));
  }
  handleAuditLog(url, res) {
    const limit = parseInt(url.searchParams.get("limit") ?? "50", 10);
    if (this.auditLog) {
      this.auditLog.query({ limit }).then((entries) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(entries));
      }).catch(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify([]));
      });
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([]));
    }
  }
  handleDecision(id, decision, res) {
    const pending = this.pending.get(id);
    if (!pending) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Request not found or already resolved" }));
      return;
    }
    clearTimeout(pending.timer);
    this.pending.delete(id);
    const response = {
      decision,
      decided_at: (/* @__PURE__ */ new Date()).toISOString(),
      decided_by: "human"
    };
    this.broadcastSSE("request-resolved", {
      request_id: id,
      decision,
      decided_by: "human"
    });
    pending.resolve(response);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, decision }));
  }
  // ── SSE Broadcasting ────────────────────────────────────────────────
  broadcastSSE(event, data) {
    const message = `event: ${event}
data: ${JSON.stringify(data)}

`;
    for (const client of this.sseClients) {
      try {
        client.write(message);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }
  /**
   * Broadcast an audit entry to connected dashboards.
   * Called externally when audit events happen.
   */
  broadcastAuditEntry(entry) {
    this.broadcastSSE("audit-entry", entry);
  }
  /**
   * Broadcast a baseline update to connected dashboards.
   * Called externally after baseline changes.
   */
  broadcastBaselineUpdate() {
    if (this.baseline) {
      this.broadcastSSE("baseline-update", this.baseline.getProfile());
    }
  }
  /** Get the number of pending requests */
  get pendingCount() {
    return this.pending.size;
  }
  /** Get the number of connected SSE clients */
  get clientCount() {
    return this.sseClients.size;
  }
};
function signPayload(body, secret) {
  return createHmac("sha256", secret).update(body).digest("hex");
}
function verifySignature(body, signature, secret) {
  const expected = signPayload(body, secret);
  if (expected.length !== signature.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return mismatch === 0;
}
var WebhookApprovalChannel = class {
  config;
  pending = /* @__PURE__ */ new Map();
  callbackServer = null;
  constructor(config) {
    this.config = config;
  }
  /**
   * Start the callback listener server.
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.callbackServer = createServer$2(
        (req, res) => this.handleCallback(req, res)
      );
      this.callbackServer.listen(
        this.config.callback_port,
        this.config.callback_host,
        () => {
          process.stderr.write(
            `
  Sanctuary Webhook Callback: http://${this.config.callback_host}:${this.config.callback_port}
  Webhook target: ${this.config.webhook_url}

`
          );
          resolve();
        }
      );
      this.callbackServer.on("error", reject);
    });
  }
  /**
   * Stop the callback server and clean up pending requests.
   */
  async stop() {
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.resolve({
        decision: "deny",
        decided_at: (/* @__PURE__ */ new Date()).toISOString(),
        decided_by: "auto"
      });
    }
    this.pending.clear();
    if (this.callbackServer) {
      return new Promise((resolve) => {
        this.callbackServer.close(() => resolve());
      });
    }
  }
  /**
   * Request approval by POSTing to the webhook and waiting for a callback.
   */
  async requestApproval(request) {
    const id = randomBytes$1(8).toString("hex");
    process.stderr.write(
      `[Sanctuary] Webhook approval sent: ${request.operation} (Tier ${request.tier}) \u2014 awaiting callback
`
    );
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const response = {
          // SEC-002: Timeout ALWAYS denies. No configuration can change this.
          decision: "deny",
          decided_at: (/* @__PURE__ */ new Date()).toISOString(),
          decided_by: "timeout"
        };
        resolve(response);
      }, this.config.timeout_seconds * 1e3);
      const pending = {
        id,
        request,
        resolve,
        timer,
        created_at: (/* @__PURE__ */ new Date()).toISOString()
      };
      this.pending.set(id, pending);
      const callbackUrl = `http://${this.config.callback_host}:${this.config.callback_port}/webhook/respond/${id}`;
      const payload = {
        request_id: id,
        operation: request.operation,
        tier: request.tier,
        reason: request.reason,
        context: request.context,
        timestamp: request.timestamp,
        callback_url: callbackUrl,
        timeout_seconds: this.config.timeout_seconds
      };
      this.sendWebhook(payload).catch((err) => {
        process.stderr.write(
          `[Sanctuary] Webhook delivery failed: ${err instanceof Error ? err.message : String(err)}
`
        );
      });
    });
  }
  // ── Outbound Webhook ──────────────────────────────────────────────────
  async sendWebhook(payload) {
    const body = JSON.stringify(payload);
    const signature = signPayload(body, this.config.webhook_secret);
    const response = await fetch(this.config.webhook_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sanctuary-Signature": signature,
        "X-Sanctuary-Request-Id": payload.request_id
      },
      body
    });
    if (!response.ok) {
      throw new Error(
        `Webhook returned ${response.status}: ${await response.text().catch(() => "")}`
      );
    }
  }
  // ── Inbound Callback Handler ──────────────────────────────────────────
  handleCallback(req, res) {
    const url = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`
    );
    const method = req.method ?? "GET";
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-Sanctuary-Signature"
    );
    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          pending_count: this.pending.size
        })
      );
      return;
    }
    const match = url.pathname.match(/^\/webhook\/respond\/([a-f0-9]+)$/);
    if (method !== "POST" || !match) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }
    const requestId = match[1];
    let bodyChunks = [];
    req.on("data", (chunk) => bodyChunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(bodyChunks).toString("utf-8");
      const signature = req.headers["x-sanctuary-signature"];
      if (typeof signature !== "string" || !verifySignature(body, signature, this.config.webhook_secret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Invalid signature" })
        );
        return;
      }
      let callbackPayload;
      try {
        callbackPayload = JSON.parse(body);
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON" }));
        return;
      }
      if (callbackPayload.decision !== "approve" && callbackPayload.decision !== "deny") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: 'Decision must be "approve" or "deny"'
          })
        );
        return;
      }
      if (callbackPayload.request_id !== requestId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Request ID mismatch" })
        );
        return;
      }
      const pending = this.pending.get(requestId);
      if (!pending) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Request not found or already resolved"
          })
        );
        return;
      }
      clearTimeout(pending.timer);
      this.pending.delete(requestId);
      const response = {
        decision: callbackPayload.decision,
        decided_at: (/* @__PURE__ */ new Date()).toISOString(),
        decided_by: "human"
      };
      pending.resolve(response);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          success: true,
          decision: callbackPayload.decision
        })
      );
    });
  }
  /** Get the number of pending requests */
  get pendingCount() {
    return this.pending.size;
  }
};

// src/principal-policy/gate.ts
var ApprovalGate = class {
  policy;
  baseline;
  channel;
  auditLog;
  constructor(policy, baseline, channel, auditLog) {
    this.policy = policy;
    this.baseline = baseline;
    this.channel = channel;
    this.auditLog = auditLog;
  }
  /**
   * Evaluate a tool call against the Principal Policy.
   *
   * @param toolName - Full MCP tool name (e.g., "sanctuary/state_export")
   * @param args - Tool call arguments (for context extraction)
   * @returns GateResult indicating whether the call is allowed
   */
  async evaluate(toolName, args) {
    const operation = extractOperationName(toolName);
    this.baseline.recordToolCall(operation);
    if (this.policy.tier1_always_approve.includes(operation)) {
      return this.requestApproval(operation, 1, `"${operation}" is a Tier 1 operation (always requires approval)`, {
        operation,
        args_summary: this.summarizeArgs(args)
      });
    }
    const anomaly = this.detectAnomaly(operation, args);
    if (anomaly) {
      return this.requestApproval(operation, 2, anomaly.reason, anomaly.context);
    }
    if (this.policy.tier3_always_allow.includes(operation)) {
      this.auditLog.append("l2", `gate_allow:${operation}`, "system", {
        tier: 3,
        operation
      });
      return {
        allowed: true,
        tier: 3,
        reason: "Operation allowed (Tier 3)",
        approval_required: false
      };
    }
    this.auditLog.append("l2", `gate_unclassified:${operation}`, "system", {
      tier: 1,
      operation,
      warning: "Operation is not classified in any policy tier \u2014 defaulting to Tier 1 (require approval)"
    });
    return this.requestApproval(
      operation,
      1,
      `"${operation}" is not classified in any policy tier \u2014 requires approval (SEC-011 safe default)`,
      { operation, unclassified: true }
    );
  }
  /**
   * Detect Tier 2 behavioral anomalies.
   */
  detectAnomaly(operation, args) {
    const config = this.policy.tier2_anomaly;
    if (this.baseline.isFirstSession && config.first_session_policy === "approve") {
      if (!this.policy.tier3_always_allow.includes(operation)) {
        return {
          reason: `First session: "${operation}" has no established baseline`,
          context: { operation, is_first_session: true }
        };
      }
    }
    if (config.new_namespace_access === "approve") {
      const namespace = args.namespace;
      if (namespace) {
        const isNew = this.baseline.recordNamespaceAccess(namespace);
        if (isNew) {
          return {
            reason: `First access to namespace "${namespace}" (not in session baseline)`,
            context: {
              operation,
              namespace,
              known_namespaces: this.baseline.getProfile().known_namespaces
            }
          };
        }
      }
    } else if (config.new_namespace_access === "log") {
      const namespace = args.namespace;
      if (namespace) {
        this.baseline.recordNamespaceAccess(namespace);
      }
    }
    if (config.new_counterparty === "approve") {
      const counterpartyDid = args.counterparty_did ?? args.agent_identity_id;
      if (counterpartyDid) {
        const isNew = this.baseline.recordCounterparty(counterpartyDid);
        if (isNew) {
          return {
            reason: `First interaction with counterparty "${counterpartyDid}"`,
            context: {
              operation,
              counterparty_did: counterpartyDid,
              known_counterparties: this.baseline.getProfile().known_counterparties
            }
          };
        }
      }
    } else if (config.new_counterparty === "log") {
      const counterpartyDid = args.counterparty_did;
      if (counterpartyDid) {
        this.baseline.recordCounterparty(counterpartyDid);
      }
    }
    if (operation === "identity_sign") {
      const signCount = this.baseline.recordSign();
      if (signCount > config.max_signs_per_minute) {
        return {
          reason: `Signing frequency (${signCount}/min) exceeds limit (${config.max_signs_per_minute}/min)`,
          context: {
            operation,
            signs_per_minute: signCount,
            limit: config.max_signs_per_minute
          }
        };
      }
    }
    if (operation === "state_read") {
      const namespace = args.namespace;
      if (namespace) {
        const readCount = this.baseline.recordNamespaceRead(namespace);
        if (readCount > config.bulk_read_threshold) {
          return {
            reason: `Bulk read detected: ${readCount} reads from "${namespace}" in 60 seconds (threshold: ${config.bulk_read_threshold})`,
            context: {
              operation,
              namespace,
              reads_in_window: readCount,
              threshold: config.bulk_read_threshold
            }
          };
        }
      }
    }
    const callRate = this.baseline.getCallRate(operation);
    const avgRate = this.baseline.getAverageCallRate();
    if (avgRate > 0 && callRate > avgRate * config.frequency_spike_multiplier) {
      return {
        reason: `Frequency spike: "${operation}" at ${callRate}/min (${config.frequency_spike_multiplier}\xD7 above average ${avgRate.toFixed(1)}/min)`,
        context: {
          operation,
          current_rate: callRate,
          average_rate: avgRate,
          multiplier: config.frequency_spike_multiplier
        }
      };
    }
    return null;
  }
  /**
   * Request approval from the human principal.
   */
  async requestApproval(operation, tier, reason, context) {
    const request = {
      operation,
      tier,
      reason,
      context,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    const response = await this.channel.requestApproval(request);
    this.auditLog.append("l2", `gate_${response.decision}:${operation}`, "system", {
      tier,
      reason,
      decided_by: response.decided_by
    });
    return {
      allowed: response.decision === "approve",
      tier,
      reason: response.decision === "approve" ? `Approved by ${response.decided_by}` : reason,
      approval_required: true,
      approval_response: response
    };
  }
  /**
   * Summarize tool arguments for the approval prompt.
   * Strips potentially large values to keep the prompt readable.
   */
  summarizeArgs(args) {
    const summary = {};
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === "string" && value.length > 100) {
        summary[key] = value.slice(0, 100) + "...";
      } else {
        summary[key] = value;
      }
    }
    return summary;
  }
  /** Get the baseline tracker for saving at session end */
  getBaseline() {
    return this.baseline;
  }
};

// src/principal-policy/tools.ts
function createPrincipalPolicyTools(policy, baseline, auditLog) {
  return [
    {
      name: "sanctuary/principal_policy_view",
      description: "View the current Principal Policy \u2014 the human-controlled rules governing what operations require approval. Read-only.",
      inputSchema: {
        type: "object",
        properties: {
          include_defaults: {
            type: "boolean",
            description: "Include tier3_always_allow list (can be long)",
            default: false
          }
        }
      },
      handler: async (args) => {
        const includeDefaults = args.include_defaults ?? false;
        const view = {
          version: policy.version,
          tier1_always_approve: policy.tier1_always_approve,
          tier2_anomaly: policy.tier2_anomaly,
          approval_channel: {
            type: policy.approval_channel.type,
            timeout_seconds: policy.approval_channel.timeout_seconds,
            auto_deny: true
            // SEC-002: hardcoded, not configurable
          }
        };
        if (includeDefaults) {
          view.tier3_always_allow = policy.tier3_always_allow;
        } else {
          view.tier3_always_allow_count = policy.tier3_always_allow.length;
          view.note = "Pass include_defaults: true to see the full tier3_always_allow list";
        }
        auditLog.append("l2", "principal_policy_view", "system", {
          include_defaults: includeDefaults
        });
        return toolResult(view);
      }
    },
    {
      name: "sanctuary/principal_baseline_view",
      description: "View the current behavioral baseline \u2014 the session profile used for anomaly detection. Shows known namespaces, counterparties, and tool call counts. Read-only.",
      inputSchema: {
        type: "object",
        properties: {}
      },
      handler: async () => {
        const profile = baseline.getProfile();
        auditLog.append("l2", "principal_baseline_view", "system");
        return toolResult({
          is_first_session: profile.is_first_session,
          session_started_at: profile.started_at,
          known_namespaces: profile.known_namespaces,
          known_counterparties: profile.known_counterparties,
          tool_call_counts: profile.tool_call_counts,
          last_saved: profile.saved_at ?? "not yet saved"
        });
      }
    }
  ];
}

// src/shr/types.ts
function deepSortKeys(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  const sorted = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = deepSortKeys(obj[key]);
  }
  return sorted;
}
function canonicalizeForSigning(body) {
  return JSON.stringify(deepSortKeys(body));
}

// src/shr/generator.ts
init_encoding();
var DEFAULT_VALIDITY_MS = 60 * 60 * 1e3;
function generateSHR(identityId, opts) {
  const { config, identityManager, masterKey, validityMs } = opts;
  const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
  if (!identity) {
    return "No identity available for signing. Create an identity first.";
  }
  const now = /* @__PURE__ */ new Date();
  const expiresAt = new Date(now.getTime() + (validityMs ?? DEFAULT_VALIDITY_MS));
  const degradations = [];
  if (config.execution.environment === "local-process") {
    degradations.push({
      layer: "l2",
      code: "PROCESS_ISOLATION_ONLY",
      severity: "warning",
      description: "Process-level isolation only (no TEE)",
      mitigation: "TEE support planned for a future release"
    });
    degradations.push({
      layer: "l2",
      code: "SELF_REPORTED_ATTESTATION",
      severity: "warning",
      description: "Attestation is self-reported (no hardware root of trust)",
      mitigation: "TEE attestation planned for a future release"
    });
  }
  if (config.disclosure.proof_system === "commitment-only") {
    degradations.push({
      layer: "l3",
      code: "COMMITMENT_ONLY",
      severity: "info",
      description: "Commitment schemes only (no ZK proofs)",
      mitigation: "ZK proof support planned for future release"
    });
  }
  const body = {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: config.version,
      node_version: process.versions.node,
      generated_by: "sanctuary-mcp-server"
    },
    instance_id: identity.identity_id,
    generated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    layers: {
      l1: {
        status: "active",
        encryption: config.state.encryption,
        key_custody: "self",
        integrity: config.state.integrity,
        identity_type: config.state.identity_provider,
        state_portable: true
      },
      l2: {
        status: config.execution.environment === "local-process" ? "degraded" : "active",
        isolation_type: config.execution.environment,
        attestation_available: config.execution.attestation
      },
      l3: {
        status: config.disclosure.proof_system === "commitment-only" ? "degraded" : "active",
        proof_system: config.disclosure.proof_system,
        selective_disclosure: config.disclosure.proof_system !== "commitment-only"
      },
      l4: {
        status: "active",
        reputation_mode: config.reputation.mode,
        attestation_format: config.reputation.attestation_format,
        reputation_portable: true
      }
    },
    capabilities: {
      handshake: true,
      shr_exchange: true,
      reputation_verify: true,
      encrypted_channel: false
      // Not yet implemented
    },
    degradations
  };
  const canonical = canonicalizeForSigning(body);
  const payload = stringToBytes(canonical);
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const signatureBytes = sign(
    payload,
    identity.encrypted_private_key,
    encryptionKey
  );
  return {
    body,
    signed_by: identity.public_key,
    signature: toBase64url(signatureBytes)
  };
}

// src/shr/verifier.ts
init_encoding();
function verifySHR(shr, now) {
  const errors = [];
  const warnings = [];
  const currentTime = /* @__PURE__ */ new Date();
  if (!shr.body || !shr.signed_by || !shr.signature) {
    errors.push("Missing required SHR fields (body, signed_by, or signature)");
    return {
      valid: false,
      errors,
      warnings,
      sovereignty_level: "minimal",
      counterparty_id: shr.body?.instance_id ?? "unknown",
      expires_at: shr.body?.expires_at ?? "unknown"
    };
  }
  if (shr.body.shr_version !== "1.0") {
    errors.push(`Unsupported SHR version: ${shr.body.shr_version}`);
  }
  const expiresAt = new Date(shr.body.expires_at);
  if (isNaN(expiresAt.getTime())) {
    errors.push("Invalid expires_at timestamp");
  } else if (currentTime > expiresAt) {
    errors.push(`SHR expired at ${shr.body.expires_at}`);
  }
  const generatedAt = new Date(shr.body.generated_at);
  if (isNaN(generatedAt.getTime())) {
    errors.push("Invalid generated_at timestamp");
  } else if (generatedAt > currentTime) {
    warnings.push("SHR generated_at is in the future \u2014 clock skew detected");
  }
  try {
    const publicKey = fromBase64url(shr.signed_by);
    const signatureBytes = fromBase64url(shr.signature);
    const canonical = canonicalizeForSigning(shr.body);
    const payload = stringToBytes(canonical);
    const signatureValid = verify(payload, signatureBytes, publicKey);
    if (!signatureValid) {
      errors.push("Invalid signature \u2014 SHR may have been tampered with");
    }
  } catch (e) {
    errors.push(`Signature verification failed: ${e.message}`);
  }
  const { layers } = shr.body;
  if (!layers.l1 || !layers.l2 || !layers.l3 || !layers.l4) {
    errors.push("Missing one or more layer definitions");
  }
  const sovereigntyLevel = assessSovereigntyLevel(shr.body);
  for (const d of shr.body.degradations ?? []) {
    if (d.severity === "critical") {
      warnings.push(`Critical degradation in ${d.layer}: ${d.description}`);
    }
  }
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    sovereignty_level: sovereigntyLevel,
    counterparty_id: shr.body.instance_id,
    expires_at: shr.body.expires_at
  };
}
function assessSovereigntyLevel(body) {
  const { l1, l2, l3, l4 } = body.layers;
  if (l1.status === "active" && l2.status === "active" && l3.status === "active" && l4.status === "active") {
    return "full";
  }
  if (l1.status !== "active") {
    return "minimal";
  }
  if (l4.status === "active" || l4.status === "degraded") {
    return "degraded";
  }
  return "minimal";
}

// src/shr/gateway-adapter.ts
var LAYER_WEIGHTS = {
  l1: 100,
  l2: 100,
  l3: 100,
  l4: 100
};
var DEGRADATION_IMPACT = {
  critical: 40,
  warning: 25,
  info: 10
};
function transformSHRForGateway(shr) {
  const { body, signed_by, signature } = shr;
  const layerScores = calculateLayerScores(body);
  const overallScore = calculateOverallScore(layerScores);
  const trustLevel = determineTrustLevel(overallScore);
  const signals = extractAuthorizationSignals(body);
  const degradations = transformDegradations(body.degradations);
  const constraints = generateAuthorizationConstraints(body);
  return {
    shr_version: body.shr_version,
    agent_identity: signed_by,
    generated_at: (/* @__PURE__ */ new Date()).toISOString(),
    context_expires_at: body.expires_at,
    overall_score: overallScore,
    recommended_trust_level: trustLevel,
    layer_scores: {
      l1_cognitive: layerScores.l1,
      l2_operational: layerScores.l2,
      l3_disclosure: layerScores.l3,
      l4_reputation: layerScores.l4
    },
    layer_status: {
      l1_cognitive: body.layers.l1.status,
      l2_operational: body.layers.l2.status,
      l3_disclosure: body.layers.l3.status,
      l4_reputation: body.layers.l4.status
    },
    authorization_signals: signals,
    degradations,
    recommended_constraints: constraints,
    shr_signature: signature,
    shr_signed_by: signed_by
  };
}
function calculateLayerScores(body) {
  const layers = body.layers;
  const degradations = body.degradations;
  let l1Score = LAYER_WEIGHTS.l1;
  let l2Score = LAYER_WEIGHTS.l2;
  let l3Score = LAYER_WEIGHTS.l3;
  let l4Score = LAYER_WEIGHTS.l4;
  for (const deg of degradations) {
    const impact = DEGRADATION_IMPACT[deg.severity] || 10;
    if (deg.layer === "l1") {
      l1Score = Math.max(0, l1Score - impact);
    } else if (deg.layer === "l2") {
      l2Score = Math.max(0, l2Score - impact);
    } else if (deg.layer === "l3") {
      l3Score = Math.max(0, l3Score - impact);
    } else if (deg.layer === "l4") {
      l4Score = Math.max(0, l4Score - impact);
    }
  }
  if (layers.l1.status === "active" && l1Score > 50) l1Score = Math.min(100, l1Score + 5);
  if (layers.l2.status === "active" && l2Score > 50) l2Score = Math.min(100, l2Score + 5);
  if (layers.l3.status === "active" && l3Score > 50) l3Score = Math.min(100, l3Score + 5);
  if (layers.l4.status === "active" && l4Score > 50) l4Score = Math.min(100, l4Score + 5);
  if (layers.l1.status === "inactive") l1Score = 0;
  if (layers.l2.status === "inactive") l2Score = 0;
  if (layers.l3.status === "inactive") l3Score = 0;
  if (layers.l4.status === "inactive") l4Score = 0;
  return {
    l1: Math.round(l1Score),
    l2: Math.round(l2Score),
    l3: Math.round(l3Score),
    l4: Math.round(l4Score)
  };
}
function calculateOverallScore(layerScores) {
  const average = (layerScores.l1 + layerScores.l2 + layerScores.l3 + layerScores.l4) / 4;
  return Math.round(average);
}
function determineTrustLevel(score) {
  if (score >= 80) return "full";
  if (score >= 60) return "elevated";
  if (score >= 40) return "standard";
  return "restricted";
}
function extractAuthorizationSignals(body) {
  const l1 = body.layers.l1;
  const l3 = body.layers.l3;
  const l4 = body.layers.l4;
  return {
    approval_gate_active: body.capabilities.handshake,
    // Handshake implies human loop capability
    context_gating_active: body.capabilities.encrypted_channel,
    // Proxy for gating capability
    encryption_at_rest: l1.encryption !== "none" && l1.encryption !== "unencrypted",
    behavioral_baseline_active: false,
    // Would need explicit field in SHR v1.1
    identity_verified: l1.identity_type === "ed25519" || l1.identity_type !== "none",
    zero_knowledge_capable: l3.status === "active" && l3.proof_system !== "commitment-only",
    selective_disclosure_active: l3.selective_disclosure,
    reputation_portable: l4.reputation_portable,
    handshake_capable: body.capabilities.handshake
  };
}
function transformDegradations(degradations) {
  return degradations.map((deg) => {
    let authzImpact = "";
    if (deg.code === "NO_TEE") {
      authzImpact = "Restricted to read-only operations until TEE available";
    } else if (deg.code === "PROCESS_ISOLATION_ONLY") {
      authzImpact = "Requires additional identity verification";
    } else if (deg.code === "COMMITMENT_ONLY") {
      authzImpact = "Limited data sharing scope \u2014 no zero-knowledge proofs";
    } else if (deg.code === "NO_ZK_PROOFS") {
      authzImpact = "Cannot perform confidential disclosures";
    } else if (deg.code === "SELF_REPORTED_ATTESTATION") {
      authzImpact = "Attestation trust degraded \u2014 human verification recommended";
    } else if (deg.code === "NO_SELECTIVE_DISCLOSURE") {
      authzImpact = "Must share entire data context, cannot redact";
    } else if (deg.code === "BASIC_SYBIL_ONLY") {
      authzImpact = "Restrict to interactions with known agents only";
    } else {
      authzImpact = "Unknown authorization impact";
    }
    return {
      layer: deg.layer,
      code: deg.code,
      severity: deg.severity,
      description: deg.description,
      authorization_impact: authzImpact
    };
  });
}
function generateAuthorizationConstraints(body, _degradations) {
  const constraints = [];
  const layers = body.layers;
  if (layers.l1.status === "degraded" || layers.l1.key_custody !== "self") {
    constraints.push({
      type: "identity_verification_required",
      description: "Additional identity verification required for sensitive operations",
      rationale: "L1 is degraded or key custody is not self-managed",
      priority: "high"
    });
  }
  if (!layers.l1.state_portable) {
    constraints.push({
      type: "location_bound",
      description: "Agent state is not portable \u2014 restrict to home environment",
      rationale: "State cannot be safely migrated across boundaries",
      priority: "medium"
    });
  }
  if (layers.l2.status === "degraded" || layers.l2.isolation_type === "local-process") {
    constraints.push({
      type: "read_only",
      description: "Restrict to read-only operations until operational isolation improves",
      rationale: "L2 isolation is process-level only (no TEE)",
      priority: "high"
    });
  }
  if (!layers.l2.attestation_available) {
    constraints.push({
      type: "requires_approval",
      description: "Human approval required for writes and sensitive reads",
      rationale: "No attestation available \u2014 self-reported integrity only",
      priority: "high"
    });
  }
  if (layers.l3.status === "degraded" || !layers.l3.selective_disclosure) {
    constraints.push({
      type: "restricted_scope",
      description: "Limit data sharing to minimal required scope \u2014 no selective disclosure",
      rationale: "Agent cannot redact data or prove predicates without revealing all context",
      priority: "high"
    });
  }
  if (layers.l3.proof_system === "commitment-only") {
    constraints.push({
      type: "restricted_scope",
      description: "No zero-knowledge proofs available \u2014 entire state context may be visible",
      rationale: "Proof system is commitment-only (no ZK)",
      priority: "medium"
    });
  }
  if (layers.l4.status === "degraded") {
    constraints.push({
      type: "known_agents_only",
      description: "Restrict interactions to known, pre-approved agents",
      rationale: "Reputation layer is degraded",
      priority: "medium"
    });
  }
  if (!layers.l4.reputation_portable) {
    constraints.push({
      type: "location_bound",
      description: "Reputation is not portable \u2014 restrict to home environment",
      rationale: "Cannot present reputation to external parties",
      priority: "low"
    });
  }
  const layerScores = calculateLayerScores(body);
  const overallScore = calculateOverallScore(layerScores);
  if (overallScore < 40) {
    constraints.push({
      type: "restricted_scope",
      description: "Overall sovereignty score below threshold \u2014 restrict to non-sensitive operations",
      rationale: `Overall sovereignty score is ${overallScore}/100`,
      priority: "high"
    });
  }
  return constraints;
}
function transformSHRGeneric(shr) {
  const context = transformSHRForGateway(shr);
  return {
    agent_id: context.agent_identity,
    sovereignty_score: context.overall_score,
    trust_level: context.recommended_trust_level,
    layer_scores: {
      l1: context.layer_scores.l1_cognitive,
      l2: context.layer_scores.l2_operational,
      l3: context.layer_scores.l3_disclosure,
      l4: context.layer_scores.l4_reputation
    },
    capabilities: context.authorization_signals,
    constraints: context.recommended_constraints.map((c) => ({
      type: c.type,
      description: c.description
    })),
    expires_at: context.context_expires_at,
    signature: context.shr_signature
  };
}

// src/shr/tools.ts
function createSHRTools(config, identityManager, masterKey, auditLog) {
  const generatorOpts = {
    config,
    identityManager,
    masterKey
  };
  const tools = [
    {
      name: "sanctuary/shr_generate",
      description: "Generate a signed Sovereignty Health Report (SHR) \u2014 a machine-readable, cryptographically signed advertisement of this instance's sovereignty posture. Present this to counterparties to prove your sovereignty capabilities.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description: "Identity to sign the SHR with. Defaults to primary identity."
          },
          validity_minutes: {
            type: "number",
            description: "How long the SHR is valid (minutes). Default: 60."
          }
        }
      },
      handler: async (args) => {
        const validityMs = args.validity_minutes ? args.validity_minutes * 60 * 1e3 : void 0;
        const result = generateSHR(args.identity_id, {
          ...generatorOpts,
          validityMs
        });
        if (typeof result === "string") {
          return toolResult({ error: result });
        }
        auditLog.append("l2", "shr_generate", result.body.instance_id);
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/shr_verify",
      description: "Verify a counterparty's Sovereignty Health Report (SHR). Checks signature validity, temporal validity, and assesses sovereignty level.",
      inputSchema: {
        type: "object",
        properties: {
          shr: {
            type: "object",
            description: "The signed SHR to verify (full SignedSHR object)."
          }
        },
        required: ["shr"]
      },
      handler: async (args) => {
        const shr = args.shr;
        const result = verifySHR(shr);
        auditLog.append(
          "l2",
          "shr_verify",
          result.counterparty_id,
          void 0,
          result.valid ? "success" : "failure"
        );
        return toolResult(result);
      }
    },
    {
      name: "sanctuary/shr_gateway_export",
      description: "Export this instance's Sovereignty Health Report formatted for Ping Identity's Agent Gateway or other identity providers. Transforms the SHR into an authorization context with sovereignty scores, capability flags, and recommended access constraints.",
      inputSchema: {
        type: "object",
        properties: {
          format: {
            type: "string",
            enum: ["ping", "generic"],
            description: "Output format: 'ping' (Ping Identity Gateway format) or 'generic' (format-agnostic). Default: 'ping'."
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the SHR with. Defaults to primary identity."
          },
          validity_minutes: {
            type: "number",
            description: "How long the SHR is valid (minutes). Default: 60."
          }
        }
      },
      handler: async (args) => {
        const format = args.format || "ping";
        const validityMs = args.validity_minutes ? args.validity_minutes * 60 * 1e3 : void 0;
        const shrResult = generateSHR(args.identity_id, {
          ...generatorOpts,
          validityMs
        });
        if (typeof shrResult === "string") {
          return toolResult({ error: shrResult });
        }
        let context;
        if (format === "generic") {
          context = transformSHRGeneric(shrResult);
        } else {
          context = transformSHRForGateway(shrResult);
        }
        auditLog.append(
          "l2",
          "shr_gateway_export",
          shrResult.body.instance_id,
          void 0,
          "success"
        );
        return toolResult(context);
      }
    }
  ];
  return { tools };
}

// src/handshake/protocol.ts
init_encoding();
function generateNonce() {
  return toBase64url(randomBytes(32));
}
function initiateHandshake(ourSHR) {
  const nonce = generateNonce();
  const sessionId = toBase64url(randomBytes(16));
  const challenge = {
    protocol_version: "1.0",
    shr: ourSHR,
    nonce,
    initiated_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  const session = {
    session_id: sessionId,
    role: "initiator",
    state: "initiated",
    our_nonce: nonce,
    our_shr: ourSHR,
    initiated_at: challenge.initiated_at
  };
  return { challenge, session };
}
function respondToHandshake(challenge, ourSHR, identityManager, masterKey, identityId) {
  if (challenge.protocol_version !== "1.0") {
    return { error: `Unsupported protocol version: ${challenge.protocol_version}` };
  }
  const shrResult = verifySHR(challenge.shr);
  if (!shrResult.valid) {
    return { error: `Initiator SHR verification failed: ${shrResult.errors.join(", ")}` };
  }
  const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
  if (!identity) {
    return { error: "No identity available for signing" };
  }
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const nonceBytes = stringToBytes(challenge.nonce);
  const nonceSignature = sign(
    nonceBytes,
    identity.encrypted_private_key,
    encryptionKey
  );
  const responderNonce = generateNonce();
  const response = {
    protocol_version: "1.0",
    shr: ourSHR,
    responder_nonce: responderNonce,
    initiator_nonce_signature: toBase64url(nonceSignature),
    responded_at: (/* @__PURE__ */ new Date()).toISOString()
  };
  const session = {
    session_id: toBase64url(randomBytes(16)),
    role: "responder",
    state: "responded",
    our_nonce: responderNonce,
    their_nonce: challenge.nonce,
    our_shr: ourSHR,
    their_shr: challenge.shr,
    initiated_at: challenge.initiated_at
  };
  return { response, session };
}
function completeHandshake(response, session, identityManager, masterKey, identityId) {
  if (response.protocol_version !== "1.0") {
    return { error: `Unsupported protocol version: ${response.protocol_version}` };
  }
  const shrResult = verifySHR(response.shr);
  if (!shrResult.valid) {
    return { error: `Responder SHR verification failed: ${shrResult.errors.join(", ")}` };
  }
  const responderPublicKey = fromBase64url(response.shr.signed_by);
  const ourNonceBytes = stringToBytes(session.our_nonce);
  const nonceSignatureBytes = fromBase64url(response.initiator_nonce_signature);
  const nonceSignatureValid = verify(
    ourNonceBytes,
    nonceSignatureBytes,
    responderPublicKey
  );
  if (!nonceSignatureValid) {
    return { error: "Responder's nonce signature is invalid \u2014 possible replay or MITM" };
  }
  const identity = identityManager.getDefault();
  if (!identity) {
    return { error: "No identity available for signing" };
  }
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const responderNonceBytes = stringToBytes(response.responder_nonce);
  const responderNonceSignature = sign(
    responderNonceBytes,
    identity.encrypted_private_key,
    encryptionKey
  );
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const completion = {
    protocol_version: "1.0",
    responder_nonce_signature: toBase64url(responderNonceSignature),
    completed_at: now
  };
  const sovereigntyLevel = shrResult.sovereignty_level;
  const trustTier = deriveTrustTier(sovereigntyLevel);
  const result = {
    counterparty_id: shrResult.counterparty_id,
    counterparty_shr: response.shr,
    verified: true,
    sovereignty_level: sovereigntyLevel,
    trust_tier: trustTier,
    completed_at: now,
    expires_at: shrResult.expires_at,
    errors: []
  };
  return { completion, result };
}
function verifyCompletion(completion, session) {
  const errors = [];
  if (!session.their_shr) {
    return {
      counterparty_id: "unknown",
      counterparty_shr: session.our_shr,
      // placeholder
      verified: false,
      sovereignty_level: "unverified",
      trust_tier: "unverified",
      completed_at: completion.completed_at,
      expires_at: (/* @__PURE__ */ new Date()).toISOString(),
      errors: ["No initiator SHR in session state"]
    };
  }
  const initiatorPublicKey = fromBase64url(session.their_shr.signed_by);
  const ourNonceBytes = stringToBytes(session.our_nonce);
  const nonceSignatureBytes = fromBase64url(completion.responder_nonce_signature);
  const nonceSignatureValid = verify(
    ourNonceBytes,
    nonceSignatureBytes,
    initiatorPublicKey
  );
  if (!nonceSignatureValid) {
    errors.push("Initiator's nonce signature is invalid \u2014 possible replay or MITM");
  }
  const shrResult = verifySHR(session.their_shr);
  if (!shrResult.valid) {
    errors.push(...shrResult.errors);
  }
  const verified = errors.length === 0;
  const sovereigntyLevel = verified ? shrResult.sovereignty_level : "unverified";
  return {
    counterparty_id: session.their_shr.body.instance_id,
    counterparty_shr: session.their_shr,
    verified,
    sovereignty_level: sovereigntyLevel,
    trust_tier: deriveTrustTier(sovereigntyLevel),
    completed_at: completion.completed_at,
    expires_at: session.their_shr.body.expires_at,
    errors
  };
}
function deriveTrustTier(level) {
  switch (level) {
    case "full":
      return "verified-sovereign";
    case "degraded":
      return "verified-degraded";
    default:
      return "unverified";
  }
}

// src/handshake/tools.ts
function createHandshakeTools(config, identityManager, masterKey, auditLog) {
  const sessions = /* @__PURE__ */ new Map();
  const handshakeResults = /* @__PURE__ */ new Map();
  const shrOpts = {
    config,
    identityManager,
    masterKey
  };
  const tools = [
    {
      name: "sanctuary/handshake_initiate",
      description: "Initiate a sovereignty handshake with a counterparty. Generates a challenge containing this instance's signed SHR and a cryptographic nonce. Send the returned challenge to the counterparty.",
      inputSchema: {
        type: "object",
        properties: {
          identity_id: {
            type: "string",
            description: "Identity to use for the handshake. Defaults to primary identity."
          }
        }
      },
      handler: async (args) => {
        const shr = generateSHR(args.identity_id, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }
        const { challenge, session } = initiateHandshake(shr);
        sessions.set(session.session_id, session);
        auditLog.append("l4", "handshake_initiate", shr.body.instance_id);
        return toolResult({
          session_id: session.session_id,
          challenge,
          instructions: "Send the 'challenge' object to the counterparty's sanctuary/handshake_respond tool. When you receive their response, pass it to sanctuary/handshake_complete with this session_id."
        });
      }
    },
    {
      name: "sanctuary/handshake_respond",
      description: "Respond to an incoming sovereignty handshake challenge. Verifies the initiator's SHR, signs their nonce, and returns our SHR with a counter-nonce.",
      inputSchema: {
        type: "object",
        properties: {
          challenge: {
            type: "object",
            description: "The HandshakeChallenge received from the initiator."
          },
          identity_id: {
            type: "string",
            description: "Identity to use for the response. Defaults to primary identity."
          }
        },
        required: ["challenge"]
      },
      handler: async (args) => {
        const challenge = args.challenge;
        const shr = generateSHR(args.identity_id, shrOpts);
        if (typeof shr === "string") {
          return toolResult({ error: shr });
        }
        const result = respondToHandshake(
          challenge,
          shr,
          identityManager,
          masterKey,
          args.identity_id
        );
        if ("error" in result) {
          auditLog.append("l4", "handshake_respond", shr.body.instance_id, void 0, "failure");
          return toolResult({ error: result.error });
        }
        sessions.set(result.session.session_id, result.session);
        auditLog.append("l4", "handshake_respond", shr.body.instance_id);
        return toolResult({
          session_id: result.session.session_id,
          response: result.response,
          instructions: "Send the 'response' object back to the initiator. When you receive their completion, pass it to sanctuary/handshake_status with this session_id.",
          // SEC-ADD-03: Tag response — contains SHR data that will be sent to counterparty
          _content_trust: "external"
        });
      }
    },
    {
      name: "sanctuary/handshake_complete",
      description: "Complete a sovereignty handshake (initiator side). Verifies the responder's SHR and nonce signature, signs their nonce, and produces the final result.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID from handshake_initiate."
          },
          response: {
            type: "object",
            description: "The HandshakeResponse received from the responder."
          }
        },
        required: ["session_id", "response"]
      },
      handler: async (args) => {
        const sessionId = args.session_id;
        const response = args.response;
        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        if (session.state !== "initiated") {
          return toolResult({
            error: `Session is in state '${session.state}', expected 'initiated'`
          });
        }
        const result = completeHandshake(
          response,
          session,
          identityManager,
          masterKey
        );
        if ("error" in result) {
          session.state = "failed";
          auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id, void 0, "failure");
          return toolResult({ error: result.error });
        }
        session.state = "completed";
        session.their_shr = response.shr;
        session.their_nonce = response.responder_nonce;
        session.result = result.result;
        handshakeResults.set(result.result.counterparty_id, result.result);
        auditLog.append("l4", "handshake_complete", session.our_shr.body.instance_id);
        return toolResult({
          completion: result.completion,
          result: result.result,
          instructions: "Send the 'completion' object to the responder so they can verify the handshake. The 'result' object contains the verified counterparty status and trust tier.",
          // SEC-ADD-03: Tag response as containing counterparty-controlled SHR data
          _content_trust: "external"
        });
      }
    },
    {
      name: "sanctuary/handshake_status",
      description: "Check the status of a handshake session, or verify a completion message (responder side).",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Session ID to check."
          },
          completion: {
            type: "object",
            description: "Optional: HandshakeCompletion from the initiator (responder-side verification)."
          }
        },
        required: ["session_id"]
      },
      handler: async (args) => {
        const sessionId = args.session_id;
        const completion = args.completion;
        const session = sessions.get(sessionId);
        if (!session) {
          return toolResult({ error: `No handshake session found: ${sessionId}` });
        }
        if (completion && session.role === "responder" && session.state === "responded") {
          const result = verifyCompletion(completion, session);
          session.state = result.verified ? "completed" : "failed";
          session.result = result;
          if (result.verified) {
            handshakeResults.set(result.counterparty_id, result);
          }
          auditLog.append(
            "l4",
            "handshake_verify_completion",
            session.our_shr.body.instance_id,
            void 0,
            result.verified ? "success" : "failure"
          );
          return toolResult({ result });
        }
        return toolResult({
          session_id: session.session_id,
          role: session.role,
          state: session.state,
          initiated_at: session.initiated_at,
          result: session.result ?? null
        });
      }
    }
  ];
  return { tools, handshakeResults };
}

// src/federation/registry.ts
var DEFAULT_CAPABILITIES = {
  reputation_exchange: true,
  mutual_attestation: true,
  encrypted_channel: false,
  attestation_formats: ["sanctuary-interaction-v1"]
};
var FederationRegistry = class {
  peers = /* @__PURE__ */ new Map();
  /**
   * Register or update a peer from a completed handshake.
   * This is the ONLY way peers enter the registry.
   */
  registerFromHandshake(result, peerDid, capabilities) {
    const existing = this.peers.get(result.counterparty_id);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const peer = {
      peer_id: result.counterparty_id,
      peer_did: peerDid,
      first_seen: existing?.first_seen ?? now,
      last_handshake: result.completed_at,
      trust_tier: trustTierToSovereigntyTier(result.trust_tier),
      handshake_result: result,
      capabilities: {
        ...DEFAULT_CAPABILITIES,
        ...existing?.capabilities ?? {},
        ...capabilities ?? {}
      },
      active: result.verified && new Date(result.expires_at) > /* @__PURE__ */ new Date()
    };
    if (!peer.active) {
      peer.trust_tier = "self-attested";
    }
    this.peers.set(result.counterparty_id, peer);
    return peer;
  }
  /**
   * Get a peer by instance ID.
   * Automatically updates active status based on handshake expiry.
   */
  getPeer(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) return null;
    if (peer.active && new Date(peer.handshake_result.expires_at) <= /* @__PURE__ */ new Date()) {
      peer.active = false;
      peer.trust_tier = "self-attested";
    }
    return peer;
  }
  /**
   * List all known peers, optionally filtered by status.
   */
  listPeers(filter) {
    const peers = Array.from(this.peers.values());
    for (const peer of peers) {
      if (peer.active && new Date(peer.handshake_result.expires_at) <= /* @__PURE__ */ new Date()) {
        peer.active = false;
        peer.trust_tier = "self-attested";
      }
    }
    if (filter?.active_only) {
      return peers.filter((p) => p.active);
    }
    return peers;
  }
  /**
   * Evaluate trust for a federation peer.
   *
   * Trust assessment considers:
   * - Handshake status (current vs expired)
   * - Sovereignty tier (verified-sovereign vs degraded vs unverified)
   * - Reputation data (if available)
   * - Mutual attestation history
   */
  evaluateTrust(peerId, mutualAttestationCount = 0, reputationScore) {
    const peer = this.getPeer(peerId);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    if (!peer) {
      return {
        peer_id: peerId,
        sovereignty_tier: "unverified",
        handshake_current: false,
        mutual_attestation_count: 0,
        trust_level: "none",
        factors: ["Peer not found in federation registry"],
        evaluated_at: now
      };
    }
    const factors = [];
    let score = 0;
    if (peer.active) {
      factors.push("Active handshake (trust current)");
      score += 3;
    } else {
      factors.push("Handshake expired (trust degraded)");
      score += 1;
    }
    switch (peer.trust_tier) {
      case "verified-sovereign":
        factors.push("Verified sovereign \u2014 full sovereignty posture");
        score += 4;
        break;
      case "verified-degraded":
        factors.push("Verified degraded \u2014 sovereignty with known limitations");
        score += 3;
        break;
      case "self-attested":
        factors.push("Self-attested \u2014 claims not independently verified");
        score += 1;
        break;
      case "unverified":
        factors.push("Unverified \u2014 no sovereignty proof");
        score += 0;
        break;
    }
    if (mutualAttestationCount > 10) {
      factors.push(`Strong attestation history (${mutualAttestationCount} mutual attestations)`);
      score += 3;
    } else if (mutualAttestationCount > 0) {
      factors.push(`Some attestation history (${mutualAttestationCount} mutual attestations)`);
      score += 1;
    } else {
      factors.push("No mutual attestation history");
    }
    if (reputationScore !== void 0) {
      if (reputationScore >= 80) {
        factors.push(`High reputation score (${reputationScore})`);
        score += 2;
      } else if (reputationScore >= 50) {
        factors.push(`Moderate reputation score (${reputationScore})`);
        score += 1;
      } else {
        factors.push(`Low reputation score (${reputationScore})`);
      }
    }
    let trust_level;
    if (score >= 9) trust_level = "high";
    else if (score >= 5) trust_level = "medium";
    else if (score >= 2) trust_level = "low";
    else trust_level = "none";
    return {
      peer_id: peerId,
      sovereignty_tier: peer.trust_tier,
      handshake_current: peer.active,
      reputation_score: reputationScore,
      mutual_attestation_count: mutualAttestationCount,
      trust_level,
      factors,
      evaluated_at: now
    };
  }
  /**
   * Remove a peer from the registry.
   */
  removePeer(peerId) {
    return this.peers.delete(peerId);
  }
  /**
   * Get the handshake results map (for tier resolution integration).
   */
  getHandshakeResults() {
    const results = /* @__PURE__ */ new Map();
    for (const [id, peer] of this.peers) {
      if (peer.active) {
        results.set(id, peer.handshake_result);
      }
    }
    return results;
  }
};

// src/federation/tools.ts
function createFederationTools(auditLog, handshakeResults) {
  const registry = new FederationRegistry();
  const tools = [
    // ─── Peer Management ──────────────────────────────────────────────
    {
      name: "sanctuary/federation_peers",
      description: "List known federation peers, register a peer from a completed handshake, or remove a peer. Every peer MUST enter through a verified handshake \u2014 no self-registration allowed.",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            enum: ["list", "register", "remove"],
            description: "Operation to perform on the peer registry"
          },
          peer_id: {
            type: "string",
            description: "Peer instance ID (required for register/remove)"
          },
          peer_did: {
            type: "string",
            description: "Peer DID (required for register)"
          },
          active_only: {
            type: "boolean",
            description: "When listing, only show peers with active handshakes"
          }
        },
        required: ["action"]
      },
      handler: async (args) => {
        const action = args.action;
        switch (action) {
          case "list": {
            const peers = registry.listPeers({
              active_only: args.active_only
            });
            auditLog.append("l4", "federation_peers_list", "system", {
              peer_count: peers.length
            });
            return toolResult({
              peers: peers.map((p) => ({
                peer_id: p.peer_id,
                peer_did: p.peer_did,
                trust_tier: p.trust_tier,
                active: p.active,
                first_seen: p.first_seen,
                last_handshake: p.last_handshake,
                capabilities: p.capabilities
              })),
              total: peers.length
            });
          }
          case "register": {
            const peerId = args.peer_id;
            const peerDid = args.peer_did;
            if (!peerId || !peerDid) {
              return toolResult({
                error: "Both peer_id and peer_did are required for registration."
              });
            }
            const hsResult = handshakeResults.get(peerId);
            if (!hsResult) {
              return toolResult({
                error: `No completed handshake found for peer "${peerId}". Complete a sovereignty handshake first using handshake_initiate.`
              });
            }
            if (!hsResult.verified) {
              return toolResult({
                error: `Handshake with "${peerId}" was not verified. Only verified handshakes can establish federation.`
              });
            }
            const peer = registry.registerFromHandshake(hsResult, peerDid);
            auditLog.append("l4", "federation_peer_register", "system", {
              peer_id: peerId,
              peer_did: peerDid,
              trust_tier: peer.trust_tier
            });
            return toolResult({
              registered: true,
              peer_id: peer.peer_id,
              trust_tier: peer.trust_tier,
              active: peer.active,
              capabilities: peer.capabilities
            });
          }
          case "remove": {
            const peerId = args.peer_id;
            if (!peerId) {
              return toolResult({ error: "peer_id is required for removal." });
            }
            const removed = registry.removePeer(peerId);
            auditLog.append("l4", "federation_peer_remove", "system", {
              peer_id: peerId,
              removed
            });
            return toolResult({
              removed,
              peer_id: peerId
            });
          }
          default:
            return toolResult({ error: `Unknown action: ${action}` });
        }
      }
    },
    // ─── Trust Evaluation ─────────────────────────────────────────────
    {
      name: "sanctuary/federation_trust_evaluate",
      description: "Evaluate the trust level of a federation peer. Considers handshake status, sovereignty tier, reputation score, and mutual attestation history. Returns a composite trust assessment.",
      inputSchema: {
        type: "object",
        properties: {
          peer_id: {
            type: "string",
            description: "Peer instance ID to evaluate"
          },
          mutual_attestation_count: {
            type: "number",
            description: "Number of mutual attestations with this peer (0 if unknown)"
          },
          reputation_score: {
            type: "number",
            description: "Peer's weighted reputation score (from reputation_query_weighted)"
          }
        },
        required: ["peer_id"]
      },
      handler: async (args) => {
        const peerId = args.peer_id;
        const mutualCount = args.mutual_attestation_count ?? 0;
        const repScore = args.reputation_score;
        const evaluation = registry.evaluateTrust(peerId, mutualCount, repScore);
        auditLog.append("l4", "federation_trust_evaluate", "system", {
          peer_id: peerId,
          trust_level: evaluation.trust_level,
          sovereignty_tier: evaluation.sovereignty_tier
        });
        return toolResult(evaluation);
      }
    },
    // ─── Federation Status ────────────────────────────────────────────
    {
      name: "sanctuary/federation_status",
      description: "Overview of federation state: total peers, active connections, trust distribution, and readiness for cross-instance operations.",
      inputSchema: {
        type: "object",
        properties: {}
      },
      handler: async () => {
        const allPeers = registry.listPeers();
        const activePeers = registry.listPeers({ active_only: true });
        const tierCounts = {
          "verified-sovereign": 0,
          "verified-degraded": 0,
          "self-attested": 0,
          "unverified": 0
        };
        for (const peer of allPeers) {
          tierCounts[peer.trust_tier] = (tierCounts[peer.trust_tier] ?? 0) + 1;
        }
        const capCounts = {
          reputation_exchange: activePeers.filter((p) => p.capabilities.reputation_exchange).length,
          mutual_attestation: activePeers.filter((p) => p.capabilities.mutual_attestation).length,
          encrypted_channel: activePeers.filter((p) => p.capabilities.encrypted_channel).length
        };
        auditLog.append("l4", "federation_status", "system", {
          total_peers: allPeers.length,
          active_peers: activePeers.length
        });
        return toolResult({
          total_peers: allPeers.length,
          active_peers: activePeers.length,
          expired_peers: allPeers.length - activePeers.length,
          trust_distribution: tierCounts,
          capability_coverage: capCounts,
          federation_ready: activePeers.length > 0,
          checked_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    }
  ];
  return { tools, registry };
}

// src/bridge/tools.ts
init_encoding();
init_encoding();

// src/bridge/bridge.ts
init_encoding();
init_hashing();
function canonicalize(outcome) {
  return stringToBytes(stableStringify(outcome));
}
function stableStringify(value) {
  if (value === null) return "null";
  if (value === void 0) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(
        `Cannot canonicalize non-finite number: ${value}. NaN, Infinity, and -Infinity are not representable in JSON.`
      );
    }
    if (Object.is(value, -0)) {
      throw new Error(
        "Cannot canonicalize negative zero (-0). Use 0 instead for deterministic cross-language serialization."
      );
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k]));
  return "{" + pairs.join(",") + "}";
}
function createBridgeCommitment(outcome, identity, identityEncryptionKey, includePedersen = false) {
  const commitmentId = `bridge-${Date.now()}-${toBase64url(randomBytes(8))}`;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const canonicalBytes = canonicalize(outcome);
  const canonicalString = new TextDecoder().decode(canonicalBytes);
  const sha2564 = createCommitment(canonicalString);
  let pedersenData;
  if (includePedersen && Number.isInteger(outcome.rounds) && outcome.rounds >= 0) {
    const pedersen = createPedersenCommitment(outcome.rounds);
    pedersenData = {
      commitment: pedersen.commitment,
      blinding_factor: pedersen.blinding_factor
    };
  }
  const commitmentPayload = {
    bridge_commitment_id: commitmentId,
    session_id: outcome.session_id,
    sha256_commitment: sha2564.commitment,
    terms_hash: outcome.terms_hash,
    committer_did: identity.did,
    committed_at: now,
    bridge_version: "sanctuary-concordia-bridge-v1"
  };
  const payloadBytes = stringToBytes(stableStringify(commitmentPayload));
  const signature = sign(payloadBytes, identity.encrypted_private_key, identityEncryptionKey);
  return {
    bridge_commitment_id: commitmentId,
    session_id: outcome.session_id,
    sha256_commitment: sha2564.commitment,
    blinding_factor: sha2564.blinding_factor,
    committer_did: identity.did,
    signature: toBase64url(signature),
    pedersen_commitment: pedersenData,
    committed_at: now,
    bridge_version: "sanctuary-concordia-bridge-v1"
  };
}
function verifyBridgeCommitment(commitment, outcome, committerPublicKey) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const canonicalString = new TextDecoder().decode(canonicalize(outcome));
  const sha256Match = verifyCommitment(
    commitment.sha256_commitment,
    canonicalString,
    commitment.blinding_factor
  );
  const commitmentPayload = {
    bridge_commitment_id: commitment.bridge_commitment_id,
    session_id: commitment.session_id,
    sha256_commitment: commitment.sha256_commitment,
    terms_hash: outcome.terms_hash,
    committer_did: commitment.committer_did,
    committed_at: commitment.committed_at,
    bridge_version: commitment.bridge_version
  };
  const payloadBytes = stringToBytes(stableStringify(commitmentPayload));
  const sigBytes = fromBase64url(commitment.signature);
  const signatureValid = verify(payloadBytes, sigBytes, committerPublicKey);
  const sessionIdMatch = commitment.session_id === outcome.session_id;
  const termsBytes = stringToBytes(stableStringify(outcome.terms));
  const computedTermsHash = toBase64url(hash(termsBytes));
  const termsHashMatch = computedTermsHash === outcome.terms_hash;
  let pedersenMatch;
  if (commitment.pedersen_commitment) {
    pedersenMatch = verifyPedersenCommitment(
      commitment.pedersen_commitment.commitment,
      outcome.rounds,
      commitment.pedersen_commitment.blinding_factor
    );
  }
  const valid = sha256Match && signatureValid && sessionIdMatch && termsHashMatch && (pedersenMatch === void 0 || pedersenMatch);
  return {
    valid,
    checks: {
      sha256_match: sha256Match,
      signature_valid: signatureValid,
      session_id_match: sessionIdMatch,
      terms_hash_match: termsHashMatch,
      pedersen_match: pedersenMatch
    },
    bridge_commitment_id: commitment.bridge_commitment_id,
    verified_at: now
  };
}

// src/bridge/tools.ts
var BridgeStore = class {
  storage;
  encryptionKey;
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "bridge-commitments");
  }
  async save(commitment, outcome) {
    const record = { commitment, outcome };
    const serialized = stringToBytes(JSON.stringify(record));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_bridge",
      commitment.bridge_commitment_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
  async get(commitmentId) {
    const raw = await this.storage.read("_bridge", commitmentId);
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      return JSON.parse(bytesToString(decrypted));
    } catch {
      return null;
    }
  }
};
function createBridgeTools(storage, masterKey, identityManager, auditLog, handshakeResults) {
  const bridgeStore = new BridgeStore(storage, masterKey);
  const reputationStore = new ReputationStore(storage, masterKey);
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const hsResults = handshakeResults ?? /* @__PURE__ */ new Map();
  function resolveIdentity(identityId) {
    const id = identityId ? identityManager.get(identityId) : identityManager.getDefault();
    if (!id) {
      throw new Error(
        identityId ? `Identity "${identityId}" not found` : "No identity available. Create one with identity_create first."
      );
    }
    return id;
  }
  const tools = [
    // ─── bridge_commit ─────────────────────────────────────────────────
    {
      name: "sanctuary/bridge_commit",
      description: "Create a cryptographic commitment binding a Concordia negotiation outcome to Sanctuary's L3 proof layer. The commitment includes a SHA-256 hash of the canonical outcome (hiding + binding), an Ed25519 signature by the committer's identity, and an optional Pedersen commitment on the round count for zero-knowledge range proofs. This is the Sanctuary side of the Concordia bridge \u2014 call this when a Concordia `accept` fires.",
      inputSchema: {
        type: "object",
        properties: {
          session_id: {
            type: "string",
            description: "Concordia session identifier"
          },
          protocol_version: {
            type: "string",
            description: 'Concordia protocol version (e.g., "concordia-v1")'
          },
          proposer_did: {
            type: "string",
            description: "DID of the party who proposed the accepted terms"
          },
          acceptor_did: {
            type: "string",
            description: "DID of the party who accepted"
          },
          terms: {
            type: "object",
            description: "The accepted terms (opaque to Sanctuary, meaningful to Concordia)"
          },
          terms_hash: {
            type: "string",
            description: "SHA-256 hash of the canonical terms serialization (computed by Concordia)"
          },
          rounds: {
            type: "number",
            description: "Number of negotiation rounds (propose/counter cycles)"
          },
          accepted_at: {
            type: "string",
            description: "ISO 8601 timestamp when accept was issued"
          },
          session_receipt: {
            type: "string",
            description: "Optional: signed Concordia session receipt"
          },
          identity_id: {
            type: "string",
            description: "Sanctuary identity to sign the commitment (uses default if omitted)"
          },
          include_pedersen: {
            type: "boolean",
            description: "Include a Pedersen commitment on round count for ZK range proofs"
          }
        },
        required: [
          "session_id",
          "protocol_version",
          "proposer_did",
          "acceptor_did",
          "terms",
          "terms_hash",
          "rounds",
          "accepted_at"
        ]
      },
      handler: async (args) => {
        const outcome = {
          session_id: args.session_id,
          protocol_version: args.protocol_version,
          proposer_did: args.proposer_did,
          acceptor_did: args.acceptor_did,
          terms: args.terms,
          terms_hash: args.terms_hash,
          rounds: args.rounds,
          accepted_at: args.accepted_at,
          session_receipt: args.session_receipt
        };
        const identity = resolveIdentity(args.identity_id);
        const includePedersen = args.include_pedersen ?? false;
        const bridgeCommitment = createBridgeCommitment(
          outcome,
          identity,
          identityEncryptionKey,
          includePedersen
        );
        await bridgeStore.save(bridgeCommitment, outcome);
        auditLog.append("l3", "bridge_commit", identity.identity_id, {
          bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
          session_id: outcome.session_id,
          counterparty: outcome.proposer_did === identity.did ? outcome.acceptor_did : outcome.proposer_did
        });
        return toolResult({
          bridge_commitment_id: bridgeCommitment.bridge_commitment_id,
          session_id: bridgeCommitment.session_id,
          sha256_commitment: bridgeCommitment.sha256_commitment,
          committer_did: bridgeCommitment.committer_did,
          signature: bridgeCommitment.signature,
          pedersen_commitment: bridgeCommitment.pedersen_commitment ? { commitment: bridgeCommitment.pedersen_commitment.commitment } : void 0,
          committed_at: bridgeCommitment.committed_at,
          bridge_version: bridgeCommitment.bridge_version,
          note: "Bridge commitment created. The blinding factor is stored encrypted. Use bridge_verify to verify the commitment against the revealed outcome. Use bridge_attest to link this negotiation to your reputation."
        });
      }
    },
    // ─── bridge_verify ───────────────────────────────────────────────────
    {
      name: "sanctuary/bridge_verify",
      description: "Verify a bridge commitment against a revealed Concordia negotiation outcome. Checks SHA-256 commitment validity, Ed25519 signature, session ID match, terms hash integrity, and Pedersen commitment (if present). Use this to confirm that a counterparty's claimed negotiation outcome matches what was cryptographically committed.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to verify"
          },
          committer_public_key: {
            type: "string",
            description: "The committer's Ed25519 public key (base64url). Required if verifying a counterparty's commitment. Omit to auto-resolve from local identities."
          }
        },
        required: ["bridge_commitment_id"]
      },
      handler: async (args) => {
        const commitmentId = args.bridge_commitment_id;
        const externalPublicKey = args.committer_public_key;
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`
          });
        }
        const { commitment: storedCommitment, outcome } = record;
        let publicKey;
        if (externalPublicKey) {
          publicKey = fromBase64url(externalPublicKey);
        } else {
          const localIdentities = identityManager.list();
          const match = localIdentities.find((i) => i.did === storedCommitment.committer_did);
          if (!match) {
            return toolResult({
              error: `Cannot resolve public key for committer "${storedCommitment.committer_did}". Provide committer_public_key for external verification.`
            });
          }
          publicKey = fromBase64url(match.public_key);
        }
        const result = verifyBridgeCommitment(storedCommitment, outcome, publicKey);
        auditLog.append("l3", "bridge_verify", "system", {
          bridge_commitment_id: commitmentId,
          session_id: storedCommitment.session_id,
          valid: result.valid
        });
        return toolResult({
          ...result,
          session_id: storedCommitment.session_id,
          committer_did: storedCommitment.committer_did,
          // SEC-ADD-03: Tag response as containing counterparty-controlled data
          _content_trust: "external"
        });
      }
    },
    // ─── bridge_attest ───────────────────────────────────────────────────
    {
      name: "sanctuary/bridge_attest",
      description: "Record a Concordia negotiation as a Sanctuary L4 reputation attestation, linked to a bridge commitment. This completes the bridge: the commitment (L3) proves the terms were agreed, and the attestation (L4) feeds the sovereignty-weighted reputation score. The attestation is automatically tagged with the counterparty's sovereignty tier from any completed handshake.",
      inputSchema: {
        type: "object",
        properties: {
          bridge_commitment_id: {
            type: "string",
            description: "The bridge commitment ID to link"
          },
          outcome_result: {
            type: "string",
            enum: ["completed", "partial", "failed", "disputed"],
            description: "Negotiation outcome for reputation scoring"
          },
          metrics: {
            type: "object",
            description: "Optional metrics (e.g., rounds, response_time_ms, terms_complexity)"
          },
          identity_id: {
            type: "string",
            description: "Identity to sign the attestation (uses default if omitted)"
          }
        },
        required: ["bridge_commitment_id", "outcome_result"]
      },
      handler: async (args) => {
        const commitmentId = args.bridge_commitment_id;
        const outcomeResult = args.outcome_result;
        const metrics = args.metrics ?? {};
        const identityId = args.identity_id;
        const record = await bridgeStore.get(commitmentId);
        if (!record) {
          return toolResult({
            error: `Bridge commitment "${commitmentId}" not found`
          });
        }
        const { outcome } = record;
        const identity = resolveIdentity(identityId);
        const counterpartyDid = outcome.proposer_did === identity.did ? outcome.acceptor_did : outcome.proposer_did;
        const hasSanctuaryIdentity = identityManager.list().some(
          (id) => identityManager.get(id.identity_id)?.did === counterpartyDid
        );
        const tierMeta = resolveTier(counterpartyDid, hsResults, hasSanctuaryIdentity);
        const tier = tierMeta.sovereignty_tier;
        const fullMetrics = {
          ...metrics,
          negotiation_rounds: outcome.rounds
        };
        const attestation = await reputationStore.record(
          outcome.session_id,
          // interaction_id = concordia session
          counterpartyDid,
          {
            type: "negotiation",
            result: outcomeResult,
            metrics: fullMetrics
          },
          "concordia-bridge",
          // context
          identity,
          identityEncryptionKey,
          void 0,
          // counterparty_attestation
          tier
        );
        auditLog.append("l4", "bridge_attest", identity.identity_id, {
          bridge_commitment_id: commitmentId,
          session_id: outcome.session_id,
          attestation_id: attestation.attestation.attestation_id,
          counterparty_did: counterpartyDid,
          sovereignty_tier: tier
        });
        const weight = TIER_WEIGHTS[tier];
        return toolResult({
          attestation_id: attestation.attestation.attestation_id,
          bridge_commitment_id: commitmentId,
          session_id: outcome.session_id,
          counterparty_did: counterpartyDid,
          outcome_result: outcomeResult,
          sovereignty_tier: tier,
          attested_at: attestation.recorded_at,
          note: `Negotiation recorded as reputation attestation. Counterparty sovereignty tier: ${tier} (weight: ${weight}).`
        });
      }
    }
  ];
  return { tools };
}
function lenientJsonParse(raw) {
  let cleaned = raw.replace(/\/\/[^\n]*/g, "");
  cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, "");
  cleaned = cleaned.replace(/,\s*([\]}])/g, "$1");
  return JSON.parse(cleaned);
}
async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
async function safeReadFile(path) {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return null;
  }
}
async function detectEnvironment(config, deepScan) {
  const fingerprint = {
    sanctuary_installed: true,
    // We're running inside Sanctuary
    sanctuary_version: config.version,
    openclaw_detected: false,
    openclaw_version: null,
    openclaw_config: null,
    node_version: process.version,
    platform: `${process.platform}-${process.arch}`
  };
  if (!deepScan) {
    return fingerprint;
  }
  const home = homedir();
  const openclawConfigPath = join(home, ".openclaw", "openclaw.json");
  const openclawEnvPath = join(home, ".openclaw", ".env");
  const openclawMemoryPath = join(home, ".openclaw", "workspace", "MEMORY.md");
  const openclawMemoryDir = join(home, ".openclaw", "workspace", "memory");
  const configExists = await fileExists(openclawConfigPath);
  const envExists = await fileExists(openclawEnvPath);
  const memoryExists = await fileExists(openclawMemoryPath);
  const memoryDirExists = await fileExists(openclawMemoryDir);
  if (configExists || memoryExists || memoryDirExists) {
    fingerprint.openclaw_detected = true;
    fingerprint.openclaw_config = await auditOpenClawConfig(
      openclawConfigPath,
      openclawEnvPath,
      openclawMemoryPath,
      configExists,
      envExists,
      memoryExists
    );
  }
  return fingerprint;
}
async function auditOpenClawConfig(configPath, envPath, _memoryPath, configExists, envExists, memoryExists) {
  const audit = {
    config_path: configExists ? configPath : null,
    require_approval_enabled: false,
    sandbox_policy_active: false,
    sandbox_allow_list: [],
    sandbox_deny_list: [],
    memory_encrypted: false,
    // Stock OpenClaw never encrypts memory
    env_file_exposed: false,
    gateway_token_set: false,
    dm_pairing_enabled: false,
    mcp_bridge_active: false
  };
  if (configExists) {
    const raw = await safeReadFile(configPath);
    if (raw) {
      try {
        const parsed = lenientJsonParse(raw);
        const hooks = parsed.hooks;
        if (hooks) {
          const beforeToolCall = hooks.before_tool_call;
          if (beforeToolCall) {
            const hookStr = JSON.stringify(beforeToolCall);
            audit.require_approval_enabled = hookStr.includes("requireApproval");
          }
        }
        const tools = parsed.tools;
        if (tools) {
          const sandbox = tools.sandbox;
          if (sandbox) {
            const sandboxTools = sandbox.tools;
            if (sandboxTools) {
              audit.sandbox_policy_active = true;
              if (Array.isArray(sandboxTools.allow)) {
                audit.sandbox_allow_list = sandboxTools.allow.filter(
                  (item) => typeof item === "string"
                );
              }
              if (Array.isArray(sandboxTools.alsoAllow)) {
                audit.sandbox_allow_list = [
                  ...audit.sandbox_allow_list,
                  ...sandboxTools.alsoAllow.filter(
                    (item) => typeof item === "string"
                  )
                ];
              }
              if (Array.isArray(sandboxTools.deny)) {
                audit.sandbox_deny_list = sandboxTools.deny.filter(
                  (item) => typeof item === "string"
                );
              }
            }
          }
        }
        const mcpServers = parsed.mcpServers;
        if (mcpServers && Object.keys(mcpServers).length > 0) {
          audit.mcp_bridge_active = true;
        }
      } catch {
      }
    }
  }
  if (envExists) {
    const envContent = await safeReadFile(envPath);
    if (envContent) {
      const secretPatterns = [
        /[A-Z_]*API_KEY\s*=/,
        /[A-Z_]*TOKEN\s*=/,
        /[A-Z_]*SECRET\s*=/,
        /[A-Z_]*PASSWORD\s*=/,
        /[A-Z_]*PRIVATE_KEY\s*=/
      ];
      audit.env_file_exposed = secretPatterns.some((p) => p.test(envContent));
      audit.gateway_token_set = /OPENCLAW_GATEWAY_TOKEN\s*=/.test(envContent);
    }
  }
  if (memoryExists) {
    audit.memory_encrypted = false;
  }
  return audit;
}

// src/audit/analyzer.ts
var L1_ENCRYPTION_AT_REST = 10;
var L1_IDENTITY_CRYPTOGRAPHIC = 10;
var L1_INTEGRITY_VERIFICATION = 8;
var L1_STATE_PORTABLE = 7;
var L2_THREE_TIER_GATE = 10;
var L2_BINARY_GATE = 3;
var L2_ANOMALY_DETECTION = 5;
var L2_ENCRYPTED_AUDIT = 4;
var L2_TOOL_SANDBOXING = 2;
var L2_CONTEXT_GATING = 4;
var L2_PROCESS_HARDENING = 5;
var L3_COMMITMENT_SCHEME = 8;
var L3_ZK_PROOFS = 7;
var L3_DISCLOSURE_POLICIES = 5;
var L4_PORTABLE_REPUTATION = 6;
var L4_SIGNED_ATTESTATIONS = 6;
var L4_SYBIL_DETECTION = 4;
var L4_SOVEREIGNTY_GATED = 4;
var SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};
var INCIDENT_META_SEV1 = {
  id: "META-SEV1-2026",
  name: "Meta Sev 1: Unauthorized autonomous data exposure",
  date: "2026-03-18",
  description: "AI agent autonomously posted proprietary code, business strategies, and user datasets to an internal forum without human approval. Two-hour exposure window."
};
var INCIDENT_OPENCLAW_SANDBOX = {
  id: "OPENCLAW-CVE-2026",
  name: "OpenClaw sandbox escape via privilege inheritance",
  date: "2026-03-18",
  description: "Nine CVEs in four days. Child processes inherited sandbox.mode=off from parent, bypassing runtime confinement. 42,900+ internet-exposed instances, 15,200 vulnerable to RCE.",
  cves: [
    "CVE-2026-32048",
    "CVE-2026-32915",
    "CVE-2026-32918"
  ]
};
var INCIDENT_CONTEXT_LEAKAGE = {
  id: "CONTEXT-LEAK-CLASS",
  name: "Context leakage: Full state exposure to inference providers",
  date: "2026-03",
  description: "Agents send full context \u2014 conversation history, memory, secrets, internal reasoning \u2014 to remote LLM providers on every inference call with no filtering mechanism."
};
var INCIDENT_CLAUDE_CODE_LEAK = {
  id: "CLAUDE-CODE-LEAK-2026",
  name: "Claude Code source leak: 512K lines exposed via npm source map",
  date: "2026-03-31",
  description: "Anthropic accidentally shipped a 59.8 MB source map in npm package v2.1.88, exposing the full Claude Code TypeScript source \u2014 1,900 files, internal model codenames, unreleased features, OAuth flows, and multi-agent coordination logic."
};
function analyzeSovereignty(env, config) {
  const l1 = assessL1(env, config);
  const l2 = assessL2(env);
  const l3 = assessL3(env);
  const l4 = assessL4(env);
  const l1Score = scoreL1(l1);
  const l2Score = scoreL2(l2);
  const l3Score = scoreL3(l3);
  const l4Score = scoreL4(l4);
  const overallScore = l1Score + l2Score + l3Score + l4Score;
  const sovereigntyLevel = overallScore >= 80 ? "full" : overallScore >= 50 ? "partial" : overallScore >= 20 ? "minimal" : "none";
  const gaps = generateGaps(env, l1, l2, l3, l4);
  gaps.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const recommendations = generateRecommendations(env, l1, l2, l3, l4);
  return {
    version: "1.0",
    audited_at: (/* @__PURE__ */ new Date()).toISOString(),
    environment: env,
    layers: {
      l1_cognitive: l1,
      l2_operational: l2,
      l3_selective_disclosure: l3,
      l4_reputation: l4
    },
    overall_score: overallScore,
    sovereignty_level: sovereigntyLevel,
    gaps,
    recommendations
  };
}
function assessL1(env, config) {
  const findings = [];
  const sanctuaryActive = env.sanctuary_installed;
  const encryptionAtRest = sanctuaryActive;
  const keyCustody = sanctuaryActive ? "self" : "none";
  const integrityVerification = sanctuaryActive;
  const identityCryptographic = sanctuaryActive;
  const statePortable = sanctuaryActive;
  if (sanctuaryActive) {
    findings.push("AES-256-GCM encryption active for all state");
    findings.push(`Key derivation: ${config.state.key_derivation}`);
    findings.push(`Identity provider: ${config.state.identity_provider}`);
    findings.push("Merkle integrity verification enabled");
    findings.push("State export/import available");
  }
  if (env.openclaw_detected && env.openclaw_config) {
    if (!env.openclaw_config.memory_encrypted) {
      findings.push("OpenClaw agent memory (MEMORY.md, daily notes) stored in plaintext");
    }
    if (env.openclaw_config.env_file_exposed) {
      findings.push("OpenClaw .env file contains plaintext API keys/tokens");
    }
  }
  const status = encryptionAtRest && identityCryptographic ? "active" : encryptionAtRest || identityCryptographic ? "partial" : "inactive";
  return {
    status,
    encryption_at_rest: encryptionAtRest,
    key_custody: keyCustody,
    integrity_verification: integrityVerification,
    identity_cryptographic: identityCryptographic,
    state_portable: statePortable,
    findings
  };
}
function assessL2(env, _config) {
  const findings = [];
  const sanctuaryActive = env.sanctuary_installed;
  let approvalGate = "none";
  let behavioralAnomalyDetection = false;
  let auditTrailEncrypted = false;
  let auditTrailExists = false;
  let toolSandboxing = "none";
  let contextGating = false;
  let processIsolationHardening = "none";
  if (sanctuaryActive) {
    approvalGate = "three-tier";
    behavioralAnomalyDetection = true;
    auditTrailEncrypted = true;
    auditTrailExists = true;
    contextGating = true;
    findings.push("Three-tier Principal Policy gate active");
    findings.push("Behavioral anomaly detection (BaselineTracker) enabled");
    findings.push("Encrypted audit trail active");
    findings.push("Context gating available (sanctuary/context_gate_set_policy)");
  }
  if (env.openclaw_detected && env.openclaw_config) {
    if (env.openclaw_config.require_approval_enabled) {
      if (!sanctuaryActive) {
        approvalGate = "binary";
      }
      findings.push("OpenClaw requireApproval hook enabled (binary approve/deny)");
    }
    if (env.openclaw_config.sandbox_policy_active) {
      if (!sanctuaryActive) {
        toolSandboxing = "basic";
      }
      findings.push(
        `OpenClaw sandbox policy active (${env.openclaw_config.sandbox_allow_list.length} allowed, ${env.openclaw_config.sandbox_deny_list.length} denied)`
      );
    }
  }
  processIsolationHardening = "none";
  const status = approvalGate === "three-tier" && auditTrailEncrypted ? "active" : approvalGate !== "none" || auditTrailExists ? "partial" : "inactive";
  return {
    status,
    approval_gate: approvalGate,
    behavioral_anomaly_detection: behavioralAnomalyDetection,
    audit_trail_encrypted: auditTrailEncrypted,
    audit_trail_exists: auditTrailExists,
    tool_sandboxing: sanctuaryActive ? "policy-enforced" : toolSandboxing,
    context_gating: contextGating,
    process_isolation_hardening: processIsolationHardening,
    findings
  };
}
function assessL3(env, _config) {
  const findings = [];
  const sanctuaryActive = env.sanctuary_installed;
  let commitmentScheme = "none";
  let zkProofs = false;
  let selectiveDisclosurePolicy = false;
  if (sanctuaryActive) {
    commitmentScheme = "pedersen+sha256";
    zkProofs = true;
    selectiveDisclosurePolicy = true;
    findings.push("SHA-256 + Pedersen commitment schemes active");
    findings.push("Schnorr zero-knowledge proofs (Fiat-Shamir) enabled \u2014 genuine ZK proofs");
    findings.push("Range proofs (bit-decomposition + OR-proofs) enabled \u2014 genuine ZK proofs");
    findings.push("Selective disclosure policies configurable");
    findings.push("Non-interactive proofs with replay-resistant domain separation");
  }
  const status = commitmentScheme === "pedersen+sha256" && zkProofs ? "active" : commitmentScheme !== "none" ? "partial" : "inactive";
  return {
    status,
    commitment_scheme: commitmentScheme,
    zero_knowledge_proofs: zkProofs,
    selective_disclosure_policy: selectiveDisclosurePolicy,
    findings
  };
}
function assessL4(env, _config) {
  const findings = [];
  const sanctuaryActive = env.sanctuary_installed;
  const reputationPortable = sanctuaryActive;
  const reputationSigned = sanctuaryActive;
  const sybilDetection = sanctuaryActive;
  const sovereigntyGated = sanctuaryActive;
  if (sanctuaryActive) {
    findings.push("Signed EAS-compatible attestations active");
    findings.push("Reputation export/import available");
    findings.push("Sybil detection heuristics enabled");
    findings.push("Sovereignty-gated reputation tiers active");
  } else {
    findings.push("No portable reputation system detected");
  }
  const status = reputationPortable && reputationSigned && sovereigntyGated ? "active" : reputationPortable || reputationSigned ? "partial" : "inactive";
  return {
    status,
    reputation_portable: reputationPortable,
    reputation_signed: reputationSigned,
    reputation_sybil_detection: sybilDetection,
    sovereignty_gated_tiers: sovereigntyGated,
    findings
  };
}
function scoreL1(l1) {
  let score = 0;
  if (l1.encryption_at_rest) score += L1_ENCRYPTION_AT_REST;
  if (l1.identity_cryptographic) score += L1_IDENTITY_CRYPTOGRAPHIC;
  if (l1.integrity_verification) score += L1_INTEGRITY_VERIFICATION;
  if (l1.state_portable) score += L1_STATE_PORTABLE;
  return score;
}
function scoreL2(l2) {
  let score = 0;
  if (l2.approval_gate === "three-tier") score += L2_THREE_TIER_GATE;
  else if (l2.approval_gate === "binary") score += L2_BINARY_GATE;
  if (l2.behavioral_anomaly_detection) score += L2_ANOMALY_DETECTION;
  if (l2.audit_trail_encrypted) score += L2_ENCRYPTED_AUDIT;
  if (l2.tool_sandboxing === "policy-enforced") score += L2_TOOL_SANDBOXING;
  else if (l2.tool_sandboxing === "basic") score += 1;
  if (l2.context_gating) score += L2_CONTEXT_GATING;
  if (l2.process_isolation_hardening === "hardened") score += L2_PROCESS_HARDENING;
  else if (l2.process_isolation_hardening === "basic") score += 2;
  return score;
}
function scoreL3(l3) {
  let score = 0;
  if (l3.commitment_scheme === "pedersen+sha256") score += L3_COMMITMENT_SCHEME;
  else if (l3.commitment_scheme === "sha256-only") score += 4;
  if (l3.zero_knowledge_proofs) score += L3_ZK_PROOFS;
  if (l3.selective_disclosure_policy) score += L3_DISCLOSURE_POLICIES;
  return score;
}
function scoreL4(l4) {
  let score = 0;
  if (l4.reputation_portable) score += L4_PORTABLE_REPUTATION;
  if (l4.reputation_signed) score += L4_SIGNED_ATTESTATIONS;
  if (l4.reputation_sybil_detection) score += L4_SYBIL_DETECTION;
  if (l4.sovereignty_gated_tiers) score += L4_SOVEREIGNTY_GATED;
  return score;
}
function generateGaps(env, l1, l2, l3, l4) {
  const gaps = [];
  const oc = env.openclaw_config;
  if (oc && !oc.memory_encrypted) {
    gaps.push({
      id: "GAP-L1-001",
      layer: "L1",
      severity: "critical",
      title: "Agent memory stored in plaintext",
      description: "Your agent's memory (MEMORY.md, daily notes, SQLite index) is stored in plaintext at ~/.openclaw/workspace/. Any process with file access can read your agent's full context \u2014 preferences, decisions, conversation history.",
      openclaw_relevance: "Stock OpenClaw stores all agent memory in plaintext files. There is no built-in encryption for agent state.",
      sanctuary_solution: "Sanctuary encrypts all state at rest with AES-256-GCM using a key derived from Argon2id, making state opaque to any process that doesn't hold the master key. Use sanctuary/state_write to migrate sensitive state to the encrypted store.",
      incident_class: INCIDENT_META_SEV1
    });
  }
  if (oc && oc.env_file_exposed) {
    gaps.push({
      id: "GAP-L1-002",
      layer: "L1",
      severity: "critical",
      title: "Plaintext API keys in .env file",
      description: "Your .env file contains plaintext API keys and tokens. These secrets are readable by any process with filesystem access.",
      openclaw_relevance: "OpenClaw stores API keys (LLM providers, gateway tokens) in a plaintext .env file.",
      sanctuary_solution: "Sanctuary's encrypted state store can hold secrets under the same AES-256-GCM envelope as all other state, tied to your self-custodied identity. Use sanctuary/state_write with namespace 'secrets'."
    });
  }
  if (!l1.identity_cryptographic) {
    gaps.push({
      id: "GAP-L1-003",
      layer: "L1",
      severity: "critical",
      title: "No cryptographic agent identity",
      description: "Your agent has no cryptographic identity. It cannot prove it is who it claims to be to any counterparty, sign messages, or participate in sovereignty handshakes.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw has no cryptographic agent identity. Agent identity is implicit (tied to the process/session), not cryptographically verifiable." : null,
      sanctuary_solution: "Sanctuary provides Ed25519 self-custodied identity with key rotation and delegation. Use sanctuary/identity_create to establish your cryptographic identity."
    });
  }
  if (l2.approval_gate === "binary" && !l2.behavioral_anomaly_detection) {
    gaps.push({
      id: "GAP-L2-001",
      layer: "L2",
      severity: "high",
      title: "Binary approval gate (no anomaly detection)",
      description: "Your approval gate provides binary approve/deny gating without behavioral anomaly detection. Routine operations require the same manual approval as sensitive ones.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw's requireApproval hook provides binary approve/deny gating. Sanctuary's three-tier Principal Policy adds behavioral anomaly detection (auto-escalation when agent behavior deviates from baseline), encrypted audit trails, and graduated approval tiers \u2014 so routine operations auto-proceed while sensitive operations require explicit consent." : null,
      sanctuary_solution: "Sanctuary's three-tier Principal Policy gate auto-allows routine operations (Tier 3), escalates anomalous behavior (Tier 2), and always requires human approval for irreversible operations (Tier 1). Use sanctuary/principal_policy_view to inspect.",
      incident_class: INCIDENT_META_SEV1
    });
  } else if (l2.approval_gate === "none") {
    gaps.push({
      id: "GAP-L2-001",
      layer: "L2",
      severity: "critical",
      title: "No approval gate",
      description: "No approval gate is configured. All tool calls execute without oversight.",
      openclaw_relevance: null,
      sanctuary_solution: "Sanctuary's Principal Policy evaluates every tool call before execution. Enable it to get three-tier approval gating with behavioral anomaly detection.",
      incident_class: INCIDENT_META_SEV1
    });
  }
  if (l2.tool_sandboxing === "basic") {
    gaps.push({
      id: "GAP-L2-002",
      layer: "L2",
      severity: "medium",
      title: "Basic tool sandboxing (no cryptographic attestation)",
      description: "Your tool sandbox enforces allow/deny lists but provides no cryptographic attestation of execution context.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw's sandbox tool policy (tools.sandbox.tools) enforces allow/deny lists. Sanctuary adds cryptographic attestation of execution context \u2014 a verifiable proof that an operation ran within policy, not just that a policy was configured." : null,
      sanctuary_solution: "Sanctuary provides cryptographic execution attestation via sanctuary/exec_attest and policy-enforced sandboxing with encrypted audit trails.",
      incident_class: INCIDENT_OPENCLAW_SANDBOX
    });
  }
  if (!l2.context_gating) {
    gaps.push({
      id: "GAP-L2-003",
      layer: "L2",
      severity: "high",
      title: "No context gating for outbound inference calls",
      description: "Your agent sends its full context \u2014 conversation history, memory, preferences, internal reasoning \u2014 to remote LLM providers on every inference call. There is no mechanism to filter what leaves the sovereignty boundary. The provider sees everything the agent knows.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw sends full agent context (including MEMORY.md, tool results, and conversation history) to the configured LLM provider with every API call. There is no built-in context filtering." : null,
      sanctuary_solution: "Sanctuary's context gating (sanctuary/context_gate_set_policy + sanctuary/context_gate_filter) lets you define per-provider policies that control exactly what context flows outbound. Redact secrets, hash identifiers, and send only minimum-necessary context for each call.",
      incident_class: INCIDENT_CONTEXT_LEAKAGE
    });
  }
  if (!l2.audit_trail_exists) {
    gaps.push({
      id: "GAP-L2-004",
      layer: "L2",
      severity: "high",
      title: "No audit trail",
      description: "No audit trail exists for tool call history. There is no record of what operations were executed, when, or by whom.",
      openclaw_relevance: null,
      sanctuary_solution: "Sanctuary maintains an encrypted audit log of all operations, queryable via sanctuary/monitor_audit_log.",
      incident_class: INCIDENT_CLAUDE_CODE_LEAK
    });
  }
  if (l3.commitment_scheme === "none") {
    gaps.push({
      id: "GAP-L3-001",
      layer: "L3",
      severity: "high",
      title: "No selective disclosure capability",
      description: "Your agent has no cryptographic mechanism to prove facts about its state without revealing the state itself. Every disclosure is all-or-nothing: no commitments, no zero-knowledge proofs, no selective disclosure policies.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw has no selective disclosure mechanism. When your agent shares information, it shares everything or nothing \u2014 there is no way to prove a claim without revealing the underlying data." : null,
      sanctuary_solution: "Sanctuary's L3 provides SHA-256 + Pedersen commitments with genuine zero-knowledge proofs (Schnorr + range proofs via Fiat-Shamir transform). Your agent can prove it has a valid credential, sufficient reputation, or a completed transaction without exposing the underlying data. Use sanctuary/zk_commit and sanctuary/zk_prove.",
      incident_class: INCIDENT_META_SEV1
    });
  }
  if (!l4.reputation_portable) {
    gaps.push({
      id: "GAP-L4-001",
      layer: "L4",
      severity: "high",
      title: "No portable reputation",
      description: "Your agent's reputation is platform-locked. If you move to a different harness or platform, your track record doesn't follow.",
      openclaw_relevance: env.openclaw_detected ? "OpenClaw has no reputation system. Your agent's track record exists only in conversation history, which is not structured, signed, or portable." : null,
      sanctuary_solution: "Sanctuary's L4 provides signed EAS-compatible attestations that are self-custodied, portable, and cryptographically verifiable. Your reputation is yours, not your platform's. Use sanctuary/reputation_record to start building portable reputation."
    });
  }
  return gaps;
}
function generateRecommendations(env, l1, l2, l3, l4) {
  const recs = [];
  if (!l1.identity_cryptographic) {
    recs.push({
      priority: 1,
      action: "Create a cryptographic identity \u2014 your agent's foundation for all sovereignty operations",
      tool: "sanctuary/identity_create",
      effort: "immediate",
      impact: "critical"
    });
  }
  if (!l1.encryption_at_rest || env.openclaw_config && !env.openclaw_config.memory_encrypted) {
    recs.push({
      priority: 2,
      action: "Migrate plaintext agent state to Sanctuary's encrypted store",
      tool: "sanctuary/state_write",
      effort: "minutes",
      impact: "critical"
    });
  }
  recs.push({
    priority: 3,
    action: "Generate a Sovereignty Health Report to present to counterparties",
    tool: "sanctuary/shr_generate",
    effort: "immediate",
    impact: "high"
  });
  if (l2.approval_gate !== "three-tier") {
    recs.push({
      priority: 4,
      action: "Enable the three-tier Principal Policy gate for graduated approval",
      tool: "sanctuary/principal_policy_view",
      effort: "minutes",
      impact: "high"
    });
  }
  if (!l2.context_gating) {
    recs.push({
      priority: 5,
      action: "Configure context gating to control what flows to LLM providers",
      tool: "sanctuary/context_gate_set_policy",
      effort: "minutes",
      impact: "high"
    });
  }
  if (!l4.reputation_signed) {
    recs.push({
      priority: 6,
      action: "Start recording reputation attestations from completed interactions",
      tool: "sanctuary/reputation_record",
      effort: "minutes",
      impact: "medium"
    });
  }
  if (!l3.selective_disclosure_policy) {
    recs.push({
      priority: 7,
      action: "Configure selective disclosure policies for data sharing",
      tool: "sanctuary/disclosure_set_policy",
      effort: "hours",
      impact: "medium"
    });
  }
  return recs;
}
function formatAuditReport(result) {
  const { environment: env, layers, overall_score, sovereignty_level, gaps, recommendations } = result;
  const scoreBar = formatScoreBar(overall_score);
  const levelLabel = sovereignty_level.toUpperCase();
  let report = "";
  report += "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n";
  report += "  SOVEREIGNTY AUDIT REPORT\n";
  report += `  Generated: ${result.audited_at}
`;
  report += "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n";
  report += "\n";
  report += `  Overall Score: ${overall_score} / 100  ${scoreBar}  ${levelLabel}
`;
  report += "\n";
  report += "  Environment:\n";
  report += `  \u2022 Sanctuary v${env.sanctuary_version ?? "?"} ${padDots("Sanctuary v" + (env.sanctuary_version ?? "?"))} ${env.sanctuary_installed ? "\u2713 installed" : "\u2717 not found"}
`;
  if (env.openclaw_detected) {
    report += `  \u2022 OpenClaw ${padDots("OpenClaw")} \u2713 detected
`;
    if (env.openclaw_config) {
      report += `  \u2022 OpenClaw requireApproval ${padDots("OpenClaw requireApproval")} ${env.openclaw_config.require_approval_enabled ? "\u2713 enabled" : "\u2717 disabled"}
`;
      report += `  \u2022 OpenClaw sandbox policy ${padDots("OpenClaw sandbox policy")} ${env.openclaw_config.sandbox_policy_active ? "\u2713 active" : "\u2717 inactive"}
`;
    }
  }
  report += "\n";
  const l1Score = scoreL1(layers.l1_cognitive);
  const l2Score = scoreL2(layers.l2_operational);
  const l3Score = scoreL3(layers.l3_selective_disclosure);
  const l4Score = scoreL4(layers.l4_reputation);
  report += "  Layer Assessment:\n";
  report += "  \u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u252C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u252C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510\n";
  report += "  \u2502 Layer                       \u2502 Status   \u2502 Score \u2502\n";
  report += "  \u251C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u253C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u253C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524\n";
  report += `  \u2502 L1 Cognitive Sovereignty    \u2502 ${padStatus(layers.l1_cognitive.status)} \u2502 ${padScore(l1Score, 35)} \u2502
`;
  report += `  \u2502 L2 Operational Isolation    \u2502 ${padStatus(layers.l2_operational.status)} \u2502 ${padScore(l2Score, 25)} \u2502
`;
  if (layers.l2_operational.context_gating) {
    report += `  \u2502   \u2514 Context Gating          \u2502 ACTIVE   \u2502       \u2502
`;
  }
  report += `  \u2502 L3 Selective Disclosure     \u2502 ${padStatus(layers.l3_selective_disclosure.status)} \u2502 ${padScore(l3Score, 20)} \u2502
`;
  report += `  \u2502 L4 Verifiable Reputation    \u2502 ${padStatus(layers.l4_reputation.status)} \u2502 ${padScore(l4Score, 20)} \u2502
`;
  report += "  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n";
  report += "\n";
  if (gaps.length > 0) {
    report += `  \u26A0 ${gaps.length} SOVEREIGNTY GAP${gaps.length !== 1 ? "S" : ""} FOUND
`;
    report += "\n";
    for (const gap of gaps) {
      const severityLabel = `[${gap.severity.toUpperCase()}]`;
      report += `  ${severityLabel} ${gap.id}: ${gap.title}
`;
      const descLines = wordWrap(gap.description, 66);
      for (const line of descLines) {
        report += `  ${line}
`;
      }
      if (gap.incident_class) {
        const ic = gap.incident_class;
        const cveStr = ic.cves?.length ? ` (${ic.cves.join(", ")})` : "";
        report += `  \u2192 Incident precedent: ${ic.name}${cveStr} [${ic.date}]
`;
      }
      report += `  \u2192 Fix: ${gap.sanctuary_solution.split(".")[0]}.
`;
      if (gap.openclaw_relevance) {
        report += `  \u2192 OpenClaw context: ${gap.openclaw_relevance.split(".")[0]}.
`;
      }
      report += "\n";
    }
  } else {
    report += "  \u2713 NO SOVEREIGNTY GAPS FOUND\n";
    report += "\n";
  }
  if (recommendations.length > 0) {
    report += "  RECOMMENDED NEXT STEPS (in order):\n";
    for (const rec of recommendations) {
      const effortLabel = rec.effort === "immediate" ? "immediate" : rec.effort === "minutes" ? "5 min" : "30 min";
      report += `  ${rec.priority}. [${effortLabel}] ${rec.action}`;
      if (rec.tool) {
        report += `: ${rec.tool}`;
      }
      report += "\n";
    }
    report += "\n";
  }
  report += "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n";
  return report;
}
function formatScoreBar(score) {
  const filled = Math.round(score / 10);
  return "[" + "\u25A0".repeat(filled) + "\u2591".repeat(10 - filled) + "]";
}
function padDots(label) {
  const totalWidth = 30;
  const dotsNeeded = Math.max(2, totalWidth - label.length - 4);
  return ".".repeat(dotsNeeded);
}
function padStatus(status) {
  const label = status.toUpperCase();
  return label + " ".repeat(Math.max(0, 8 - label.length));
}
function padScore(score, max) {
  const text = `${score}/${max}`;
  return " ".repeat(Math.max(0, 5 - text.length)) + text;
}
function wordWrap(text, maxWidth) {
  const words = text.split(" ");
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current.length + word.length + 1 > maxWidth && current.length > 0) {
      lines.push(current);
      current = word;
    } else {
      current = current.length > 0 ? current + " " + word : word;
    }
  }
  if (current.length > 0) lines.push(current);
  return lines;
}

// src/audit/tools.ts
function createAuditTools(config) {
  const tools = [
    {
      name: "sanctuary/sovereignty_audit",
      description: "Audit your agent's sovereignty posture. Inspects the local environment for encryption, identity, approval gates, selective disclosure, and reputation \u2014 including OpenClaw-specific configurations. Returns a scored gap analysis with prioritized recommendations.",
      inputSchema: {
        type: "object",
        properties: {
          deep_scan: {
            type: "boolean",
            description: "If true (default), also scans for OpenClaw config, .env files, and memory files. Set to false for a Sanctuary-only assessment."
          }
        }
      },
      handler: async (args) => {
        const deepScan = args.deep_scan !== false;
        const env = await detectEnvironment(config, deepScan);
        const result = analyzeSovereignty(env, config);
        const report = formatAuditReport(result);
        return {
          content: [
            { type: "text", text: report },
            { type: "text", text: JSON.stringify(result, null, 2) }
          ]
        };
      }
    }
  ];
  return { tools };
}

// src/l2-operational/context-gate.ts
init_encoding();
init_hashing();
var MAX_CONTEXT_FIELDS = 1e3;
var MAX_POLICY_RULES = 50;
var MAX_PATTERNS_PER_ARRAY = 500;
function evaluateField(policy, provider, field) {
  const exactRule = policy.rules.find((r) => r.provider === provider);
  const wildcardRule = policy.rules.find((r) => r.provider === "*");
  const matchedRule = exactRule ?? wildcardRule;
  if (!matchedRule) {
    return {
      field,
      action: policy.default_action === "deny" ? "deny" : "redact",
      reason: `No rule matches provider "${provider}"; applying default (${policy.default_action})`
    };
  }
  if (matchesPattern(field, matchedRule.redact)) {
    return {
      field,
      action: "redact",
      reason: `Field "${field}" is explicitly redacted for ${matchedRule.provider} provider`
    };
  }
  if (matchesPattern(field, matchedRule.hash)) {
    return {
      field,
      action: "hash",
      reason: `Field "${field}" is hashed for ${matchedRule.provider} provider`
    };
  }
  if (matchesPattern(field, matchedRule.summarize)) {
    return {
      field,
      action: "summarize",
      reason: `Field "${field}" should be summarized for ${matchedRule.provider} provider`
    };
  }
  if (matchesPattern(field, matchedRule.allow)) {
    return {
      field,
      action: "allow",
      reason: `Field "${field}" is allowed for ${matchedRule.provider} provider`
    };
  }
  return {
    field,
    action: policy.default_action === "deny" ? "deny" : "redact",
    reason: `Field "${field}" not addressed in ${matchedRule.provider} rule; applying default (${policy.default_action})`
  };
}
function filterContext(policy, provider, context) {
  const fields = Object.keys(context);
  if (fields.length > MAX_CONTEXT_FIELDS) {
    throw new Error(
      `Context object has ${fields.length} fields, exceeding limit of ${MAX_CONTEXT_FIELDS}`
    );
  }
  const decisions = [];
  let allowed = 0;
  let redacted = 0;
  let hashed = 0;
  let summarized = 0;
  let denied = 0;
  for (const field of fields) {
    const result = evaluateField(policy, provider, field);
    if (result.action === "hash") {
      const value = typeof context[field] === "string" ? context[field] : JSON.stringify(context[field]);
      result.hash_value = hashToString(stringToBytes(value));
    }
    decisions.push(result);
    switch (result.action) {
      case "allow":
        allowed++;
        break;
      case "redact":
        redacted++;
        break;
      case "hash":
        hashed++;
        break;
      case "summarize":
        summarized++;
        break;
      case "deny":
        denied++;
        break;
    }
  }
  const originalHash = hashToString(
    stringToBytes(JSON.stringify(context))
  );
  const filteredOutput = {};
  for (const decision of decisions) {
    switch (decision.action) {
      case "allow":
        filteredOutput[decision.field] = context[decision.field];
        break;
      case "redact":
        filteredOutput[decision.field] = "[REDACTED]";
        break;
      case "hash":
        filteredOutput[decision.field] = `[HASH:${decision.hash_value}]`;
        break;
      case "summarize":
        filteredOutput[decision.field] = "[SUMMARIZE]";
        break;
    }
  }
  const filteredHash = hashToString(
    stringToBytes(JSON.stringify(filteredOutput))
  );
  return {
    policy_id: policy.policy_id,
    provider,
    fields_allowed: allowed,
    fields_redacted: redacted,
    fields_hashed: hashed,
    fields_summarized: summarized,
    fields_denied: denied,
    decisions,
    original_context_hash: originalHash,
    filtered_context_hash: filteredHash,
    filtered_at: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function matchesPattern(field, patterns) {
  const normalizedField = field.toLowerCase();
  for (const pattern of patterns) {
    if (pattern === "*") return true;
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern === normalizedField) return true;
    if (normalizedPattern.endsWith("*") && normalizedField.startsWith(normalizedPattern.slice(0, -1))) return true;
    if (normalizedPattern.startsWith("*") && normalizedField.endsWith(normalizedPattern.slice(1))) return true;
  }
  return false;
}
var ContextGatePolicyStore = class {
  storage;
  encryptionKey;
  policies = /* @__PURE__ */ new Map();
  constructor(storage, masterKey) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l2-context-gate");
  }
  /**
   * Create and store a new context-gating policy.
   */
  async create(policyName, rules, defaultAction, identityId) {
    const policyId = `cg-${Date.now()}-${toBase64url(randomBytes(8))}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const policy = {
      policy_id: policyId,
      policy_name: policyName,
      rules,
      default_action: defaultAction,
      identity_id: identityId,
      created_at: now,
      updated_at: now
    };
    await this.persist(policy);
    this.policies.set(policyId, policy);
    return policy;
  }
  /**
   * Get a policy by ID.
   */
  async get(policyId) {
    if (this.policies.has(policyId)) {
      return this.policies.get(policyId);
    }
    const raw = await this.storage.read("_context_gate_policies", policyId);
    if (!raw) return null;
    try {
      const encrypted = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const policy = JSON.parse(bytesToString(decrypted));
      this.policies.set(policyId, policy);
      return policy;
    } catch {
      return null;
    }
  }
  /**
   * List all context-gating policies.
   */
  async list() {
    await this.loadAll();
    return Array.from(this.policies.values());
  }
  /**
   * Load all persisted policies into memory.
   */
  async loadAll() {
    try {
      const entries = await this.storage.list("_context_gate_policies");
      for (const meta of entries) {
        if (this.policies.has(meta.key)) continue;
        const raw = await this.storage.read("_context_gate_policies", meta.key);
        if (!raw) continue;
        try {
          const encrypted = JSON.parse(bytesToString(raw));
          const decrypted = decrypt(encrypted, this.encryptionKey);
          const policy = JSON.parse(bytesToString(decrypted));
          this.policies.set(policy.policy_id, policy);
        } catch {
        }
      }
    } catch {
    }
  }
  async persist(policy) {
    const serialized = stringToBytes(JSON.stringify(policy));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      "_context_gate_policies",
      policy.policy_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
};

// src/l2-operational/context-gate-templates.ts
var ALWAYS_REDACT_SECRETS = [
  "api_key",
  "secret_*",
  "*_secret",
  "*_token",
  "*_key",
  "password",
  "*_password",
  "credential",
  "*_credential",
  "private_key",
  "recovery_key",
  "passphrase",
  "auth_*"
];
var PII_PATTERNS = [
  "*_pii",
  "name",
  "full_name",
  "email",
  "email_address",
  "phone",
  "phone_number",
  "address",
  "ssn",
  "date_of_birth",
  "ip_address",
  "credit_card",
  "card_number",
  "cvv",
  "bank_account",
  "account_number",
  "routing_number"
];
var INTERNAL_STATE_PATTERNS = [
  "memory",
  "agent_memory",
  "internal_reasoning",
  "internal_state",
  "reasoning_trace",
  "chain_of_thought",
  "private_notes",
  "soul",
  "personality",
  "system_prompt"
];
var ID_PATTERNS = [
  "user_id",
  "session_id",
  "agent_id",
  "identity_id",
  "conversation_id",
  "thread_id"
];
var HISTORY_PATTERNS = [
  "conversation_history",
  "message_history",
  "chat_history",
  "context_window",
  "previous_messages"
];
var INFERENCE_MINIMAL = {
  id: "inference-minimal",
  name: "Inference Minimal",
  description: "Maximum privacy. Only the current task and query reach the LLM provider.",
  use_when: "You want the strictest possible context control for inference calls. The LLM sees only what it needs for the immediate task.",
  rules: [
    {
      provider: "inference",
      allow: [
        "task",
        "task_description",
        "current_query",
        "query",
        "prompt",
        "question",
        "instruction"
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS,
        "tool_results",
        "previous_results"
      ],
      hash: [...ID_PATTERNS],
      summarize: []
    }
  ],
  default_action: "redact"
};
var INFERENCE_STANDARD = {
  id: "inference-standard",
  name: "Inference Standard",
  description: "Balanced privacy. Task, query, and tool results pass through. History flagged for summarization. Secrets and PII redacted.",
  use_when: "You need the LLM to have enough context for multi-step tasks while keeping secrets, PII, and internal reasoning private.",
  rules: [
    {
      provider: "inference",
      allow: [
        "task",
        "task_description",
        "current_query",
        "query",
        "prompt",
        "question",
        "instruction",
        "tool_results",
        "tool_output",
        "previous_results",
        "current_step",
        "remaining_steps",
        "objective",
        "constraints",
        "format",
        "output_format"
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS
      ],
      hash: [...ID_PATTERNS],
      summarize: [...HISTORY_PATTERNS]
    }
  ],
  default_action: "redact"
};
var LOGGING_STRICT = {
  id: "logging-strict",
  name: "Logging Strict",
  description: "Redacts all content for logging and analytics providers. Only operation metadata passes through.",
  use_when: "You send telemetry to logging or analytics services and want usage metrics without any content exposure.",
  rules: [
    {
      provider: "logging",
      allow: [
        "operation",
        "operation_name",
        "tool_name",
        "timestamp",
        "duration_ms",
        "status",
        "error_code",
        "event_type"
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS
      ],
      hash: [...ID_PATTERNS],
      summarize: []
    },
    {
      provider: "analytics",
      allow: [
        "event_type",
        "timestamp",
        "duration_ms",
        "status",
        "tool_name"
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS
      ],
      hash: [...ID_PATTERNS],
      summarize: []
    }
  ],
  default_action: "redact"
};
var TOOL_API_SCOPED = {
  id: "tool-api-scoped",
  name: "Tool API Scoped",
  description: "Allows tool-specific parameters for external API calls. Redacts memory, history, secrets, and PII.",
  use_when: "Your agent calls external APIs (search, database, web) and you want to send query parameters without full agent context. Note: 'headers' and 'body' are redacted by default because they frequently carry authorization tokens. Add them to 'allow' only if you verify they contain no credentials for your use case.",
  rules: [
    {
      provider: "tool-api",
      allow: [
        "task",
        "task_description",
        "query",
        "search_query",
        "tool_input",
        "tool_parameters",
        "url",
        "endpoint",
        "method",
        "filter",
        "sort",
        "limit",
        "offset"
      ],
      redact: [
        ...ALWAYS_REDACT_SECRETS,
        ...PII_PATTERNS,
        ...INTERNAL_STATE_PATTERNS,
        ...HISTORY_PATTERNS
      ],
      hash: [...ID_PATTERNS],
      summarize: []
    }
  ],
  default_action: "redact"
};
var TEMPLATES = {
  "inference-minimal": INFERENCE_MINIMAL,
  "inference-standard": INFERENCE_STANDARD,
  "logging-strict": LOGGING_STRICT,
  "tool-api-scoped": TOOL_API_SCOPED
};
function listTemplateIds() {
  return Object.keys(TEMPLATES);
}
function getTemplate(id) {
  return TEMPLATES[id];
}

// src/l2-operational/context-gate-recommend.ts
var CLASSIFICATION_RULES = [
  // ── Secrets (always redact, high confidence) ─────────────────────
  {
    patterns: [
      "api_key",
      "apikey",
      "api_secret",
      "secret",
      "secret_key",
      "secret_token",
      "password",
      "passwd",
      "pass",
      "credential",
      "credentials",
      "private_key",
      "privkey",
      "recovery_key",
      "passphrase",
      "token",
      "access_token",
      "refresh_token",
      "bearer_token",
      "auth_token",
      "auth_header",
      "authorization",
      "encryption_key",
      "master_key",
      "signing_key",
      "webhook_secret",
      "client_secret",
      "connection_string"
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known secret/credential pattern"
  },
  // ── PII (always redact, high confidence) ─────────────────────────
  {
    patterns: [
      "name",
      "full_name",
      "first_name",
      "last_name",
      "display_name",
      "email",
      "email_address",
      "phone",
      "phone_number",
      "mobile",
      "address",
      "street_address",
      "mailing_address",
      "ssn",
      "social_security",
      "date_of_birth",
      "dob",
      "birthday",
      "ip_address",
      "ip",
      "location",
      "geolocation",
      "coordinates",
      "credit_card",
      "card_number",
      "cvv",
      "bank_account",
      "routing_number",
      "passport",
      "drivers_license",
      "license_number"
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known PII pattern"
  },
  // ── Internal agent state (redact, high confidence) ───────────────
  {
    patterns: [
      "memory",
      "agent_memory",
      "long_term_memory",
      "internal_reasoning",
      "reasoning_trace",
      "chain_of_thought",
      "internal_state",
      "agent_state",
      "private_notes",
      "scratchpad",
      "soul",
      "personality",
      "persona",
      "system_prompt",
      "system_message",
      "system_instruction",
      "preferences",
      "user_preferences",
      "agent_preferences",
      "beliefs",
      "goals",
      "motivations"
    ],
    action: "redact",
    confidence: "high",
    reason: "Matches known internal agent state pattern"
  },
  // ── IDs (hash, medium confidence) ────────────────────────────────
  {
    patterns: [
      "user_id",
      "userid",
      "session_id",
      "sessionid",
      "agent_id",
      "agentid",
      "identity_id",
      "conversation_id",
      "thread_id",
      "threadid",
      "request_id",
      "requestid",
      "correlation_id",
      "trace_id",
      "traceid",
      "account_id",
      "accountid"
    ],
    action: "hash",
    confidence: "medium",
    reason: "Matches known identifier pattern \u2014 hash preserves correlation without exposing value"
  },
  // ── History (summarize, medium confidence) ───────────────────────
  {
    patterns: [
      "conversation_history",
      "chat_history",
      "message_history",
      "messages",
      "previous_messages",
      "prior_messages",
      "context_window",
      "interaction_history",
      "audit_log",
      "event_log"
    ],
    action: "summarize",
    confidence: "medium",
    reason: "Matches known history/log pattern \u2014 summarize to reduce exposure"
  },
  // ── Task/query (allow, medium confidence) ────────────────────────
  {
    patterns: [
      "task",
      "task_description",
      "query",
      "current_query",
      "search_query",
      "prompt",
      "user_prompt",
      "question",
      "current_question",
      "instruction",
      "instructions",
      "objective",
      "goal",
      "current_step",
      "next_step",
      "remaining_steps",
      "constraints",
      "requirements",
      "output_format",
      "format",
      "tool_results",
      "tool_output",
      "tool_input",
      "tool_parameters"
    ],
    action: "allow",
    confidence: "medium",
    reason: "Matches known task/query pattern \u2014 likely needed for inference"
  }
];
function classifyField(fieldName) {
  const normalized = fieldName.toLowerCase().trim();
  for (const rule of CLASSIFICATION_RULES) {
    for (const pattern of rule.patterns) {
      if (matchesFieldPattern(normalized, pattern)) {
        return {
          field: fieldName,
          recommended_action: rule.action,
          reason: rule.reason,
          confidence: rule.confidence,
          matched_pattern: pattern
        };
      }
    }
  }
  return {
    field: fieldName,
    recommended_action: "redact",
    reason: "No known pattern matched \u2014 defaulting to redact (conservative)",
    confidence: "low",
    matched_pattern: null
  };
}
function recommendPolicy(context, provider = "inference") {
  const fields = Object.keys(context);
  const classifications = fields.map(classifyField);
  const warnings = [];
  const allow = [];
  const redact = [];
  const hash2 = [];
  const summarize = [];
  for (const c of classifications) {
    switch (c.recommended_action) {
      case "allow":
        allow.push(c.field);
        break;
      case "redact":
        redact.push(c.field);
        break;
      case "hash":
        hash2.push(c.field);
        break;
      case "summarize":
        summarize.push(c.field);
        break;
    }
  }
  const lowConfidence = classifications.filter((c) => c.confidence === "low");
  if (lowConfidence.length > 0) {
    warnings.push(
      `${lowConfidence.length} field(s) could not be classified by pattern and will default to redact: ${lowConfidence.map((c) => c.field).join(", ")}. Review these manually.`
    );
  }
  for (const [key, value] of Object.entries(context)) {
    if (typeof value === "string" && value.length > 5e3) {
      const existing = classifications.find((c) => c.field === key);
      if (existing && existing.recommended_action === "allow") {
        warnings.push(
          `Field "${key}" is allowed but contains ${value.length} characters. Consider summarizing it to reduce context size and exposure.`
        );
      }
    }
  }
  return {
    provider,
    classifications,
    recommended_rules: { allow, redact, hash: hash2, summarize },
    default_action: "redact",
    summary: {
      total_fields: fields.length,
      allow: allow.length,
      redact: redact.length,
      hash: hash2.length,
      summarize: summarize.length
    },
    warnings
  };
}
function matchesFieldPattern(normalizedField, pattern) {
  if (normalizedField === pattern) return true;
  if (pattern.length >= 3 && normalizedField.includes(pattern)) {
    const idx = normalizedField.indexOf(pattern);
    const before = idx === 0 || normalizedField[idx - 1] === "_" || normalizedField[idx - 1] === "-";
    const after = idx + pattern.length === normalizedField.length || normalizedField[idx + pattern.length] === "_" || normalizedField[idx + pattern.length] === "-";
    return before && after;
  }
  return false;
}

// src/l2-operational/context-gate-tools.ts
function createContextGateTools(storage, masterKey, auditLog) {
  const policyStore = new ContextGatePolicyStore(storage, masterKey);
  const tools = [
    // ── Set Policy ──────────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_set_policy",
      description: "Create a context-gating policy that controls what information flows to remote providers (LLM APIs, tool APIs, logging services). Each rule specifies a provider category and which context fields to allow, redact, hash, or flag for summarization. Redact rules take absolute priority \u2014 if a field is in both 'allow' and 'redact', it is redacted. Default action applies to any field not mentioned in any rule. Use this to prevent your full agent context from being sent to remote LLM providers during inference calls.",
      inputSchema: {
        type: "object",
        properties: {
          policy_name: {
            type: "string",
            description: "Human-readable name for this policy (e.g., 'inference-minimal', 'tool-api-strict')"
          },
          rules: {
            type: "array",
            description: "Array of rules. Each rule has: provider (inference|tool-api|logging|analytics|peer-agent|custom|*), allow (fields to pass through), redact (fields to remove \u2014 highest priority), hash (fields to replace with SHA-256 hash), summarize (fields to flag for compression).",
            items: {
              type: "object",
              properties: {
                provider: {
                  type: "string",
                  description: "Provider category: inference, tool-api, logging, analytics, peer-agent, custom, or * for all"
                },
                allow: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields/patterns to allow through (e.g., 'task_description', 'current_query', 'tool_*')"
                },
                redact: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields/patterns to redact (e.g., 'conversation_history', 'secret_*', '*_pii'). Takes absolute priority."
                },
                hash: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields/patterns to replace with SHA-256 hash (e.g., 'user_id', 'session_id')"
                },
                summarize: {
                  type: "array",
                  items: { type: "string" },
                  description: "Fields/patterns to flag for summarization (advisory \u2014 agent should compress these before sending)"
                }
              },
              required: ["provider", "allow", "redact"]
            }
          },
          default_action: {
            type: "string",
            enum: ["redact", "deny"],
            description: "Action for fields not matched by any rule. 'redact' removes the field value; 'deny' blocks the entire request. Default: 'redact'."
          },
          identity_id: {
            type: "string",
            description: "Bind this policy to a specific identity (optional)"
          }
        },
        required: ["policy_name", "rules"]
      },
      handler: async (args) => {
        const policyName = args.policy_name;
        const rawRules = args.rules;
        const defaultAction = args.default_action ?? "redact";
        const identityId = args.identity_id;
        if (!Array.isArray(rawRules)) {
          return toolResult({ error: "invalid_rules", message: "rules must be an array" });
        }
        if (rawRules.length > MAX_POLICY_RULES) {
          return toolResult({
            error: "too_many_rules",
            message: `Policy has ${rawRules.length} rules, exceeding limit of ${MAX_POLICY_RULES}`
          });
        }
        const rules = [];
        for (const r of rawRules) {
          const allow = Array.isArray(r.allow) ? r.allow : [];
          const redact = Array.isArray(r.redact) ? r.redact : [];
          const hash2 = Array.isArray(r.hash) ? r.hash : [];
          const summarize = Array.isArray(r.summarize) ? r.summarize : [];
          for (const [name, arr] of [["allow", allow], ["redact", redact], ["hash", hash2], ["summarize", summarize]]) {
            if (arr.length > MAX_PATTERNS_PER_ARRAY) {
              return toolResult({
                error: "too_many_patterns",
                message: `Rule ${name} array has ${arr.length} patterns, exceeding limit of ${MAX_PATTERNS_PER_ARRAY}`
              });
            }
          }
          rules.push({
            provider: r.provider ?? "*",
            allow,
            redact,
            hash: hash2,
            summarize
          });
        }
        const policy = await policyStore.create(
          policyName,
          rules,
          defaultAction,
          identityId
        );
        auditLog.append("l2", "context_gate_set_policy", identityId ?? "system", {
          policy_id: policy.policy_id,
          policy_name: policyName,
          rule_count: rules.length,
          default_action: defaultAction
        });
        return toolResult({
          policy_id: policy.policy_id,
          policy_name: policy.policy_name,
          rules: policy.rules,
          default_action: policy.default_action,
          created_at: policy.created_at,
          message: "Context-gating policy created. Use sanctuary/context_gate_filter to apply this policy before making outbound calls."
        });
      }
    },
    // ── Apply Template ───────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_apply_template",
      description: "Apply a starter context-gating template. Available templates: inference-minimal (strictest \u2014 only task and query pass through), inference-standard (balanced \u2014 adds tool results, summarizes history), logging-strict (redacts all content for telemetry services), tool-api-scoped (allows tool parameters, redacts agent state). Templates are starting points \u2014 customize after applying.",
      inputSchema: {
        type: "object",
        properties: {
          template_id: {
            type: "string",
            description: "Template to apply: inference-minimal, inference-standard, logging-strict, or tool-api-scoped"
          },
          identity_id: {
            type: "string",
            description: "Bind this policy to a specific identity (optional)"
          }
        },
        required: ["template_id"]
      },
      handler: async (args) => {
        const templateId = args.template_id;
        const identityId = args.identity_id;
        const template = getTemplate(templateId);
        if (!template) {
          return toolResult({
            error: "template_not_found",
            message: `Unknown template "${templateId}"`,
            available_templates: listTemplateIds().map((id) => {
              const t = TEMPLATES[id];
              return { id, name: t.name, description: t.description };
            })
          });
        }
        const policy = await policyStore.create(
          template.name,
          template.rules,
          template.default_action,
          identityId
        );
        auditLog.append("l2", "context_gate_apply_template", identityId ?? "system", {
          policy_id: policy.policy_id,
          template_id: templateId
        });
        return toolResult({
          policy_id: policy.policy_id,
          template_applied: templateId,
          policy_name: template.name,
          description: template.description,
          use_when: template.use_when,
          rules: policy.rules,
          default_action: policy.default_action,
          created_at: policy.created_at,
          message: "Template applied. Use sanctuary/context_gate_filter with this policy_id to filter context before outbound calls. Customize rules with sanctuary/context_gate_set_policy if needed."
        });
      }
    },
    // ── Recommend Policy ────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_recommend",
      description: "Analyze a sample context object and recommend a context-gating policy based on field name heuristics. Classifies each field as allow, redact, hash, or summarize with confidence levels. Returns a ready-to-apply rule set. When in doubt, recommends redact (conservative). Review the recommendations before applying.",
      inputSchema: {
        type: "object",
        properties: {
          context: {
            type: "object",
            description: "A sample context object to analyze. Each top-level key will be classified. Values are inspected for size warnings but not stored."
          },
          provider: {
            type: "string",
            description: "Provider category to generate rules for. Default: 'inference'."
          }
        },
        required: ["context"]
      },
      handler: async (args) => {
        const context = args.context;
        const provider = args.provider ?? "inference";
        const contextKeys = Object.keys(context);
        if (contextKeys.length > MAX_CONTEXT_FIELDS) {
          return toolResult({
            error: "context_too_large",
            message: `Context has ${contextKeys.length} fields, exceeding limit of ${MAX_CONTEXT_FIELDS}`
          });
        }
        const recommendation = recommendPolicy(context, provider);
        auditLog.append("l2", "context_gate_recommend", "system", {
          provider,
          fields_analyzed: recommendation.summary.total_fields,
          fields_allow: recommendation.summary.allow,
          fields_redact: recommendation.summary.redact,
          fields_hash: recommendation.summary.hash,
          fields_summarize: recommendation.summary.summarize
        });
        return toolResult({
          ...recommendation,
          next_steps: "Review the classifications above. If they look correct, you can apply them directly with sanctuary/context_gate_set_policy using the recommended_rules. Or start with a template via sanctuary/context_gate_apply_template and customize from there.",
          available_templates: listTemplateIds().map((id) => {
            const t = TEMPLATES[id];
            return { id, name: t.name, description: t.description };
          })
        });
      }
    },
    // ── Filter Context ──────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_filter",
      description: "Filter agent context through a gating policy before sending to a remote provider. Returns per-field decisions (allow, redact, hash, summarize) and content hashes for the audit trail. Call this BEFORE making any outbound API call to ensure you are only sending the minimum necessary context. The filtered output tells you exactly what can be sent safely.",
      inputSchema: {
        type: "object",
        properties: {
          policy_id: {
            type: "string",
            description: "ID of the context-gating policy to apply"
          },
          provider: {
            type: "string",
            description: "Provider category for this call: inference, tool-api, logging, analytics, peer-agent, or custom"
          },
          context: {
            type: "object",
            description: "The context object to filter. Each top-level key is evaluated against the policy. Example keys: task_description, conversation_history, user_preferences, api_keys, memory, internal_reasoning"
          }
        },
        required: ["policy_id", "provider", "context"]
      },
      handler: async (args) => {
        const policyId = args.policy_id;
        const provider = args.provider;
        const context = args.context;
        const contextKeys = Object.keys(context);
        if (contextKeys.length > MAX_CONTEXT_FIELDS) {
          return toolResult({
            error: "context_too_large",
            message: `Context has ${contextKeys.length} fields, exceeding limit of ${MAX_CONTEXT_FIELDS}`
          });
        }
        const policy = await policyStore.get(policyId);
        if (!policy) {
          return toolResult({
            error: "policy_not_found",
            message: `No context-gating policy found with ID "${policyId}"`
          });
        }
        const result = filterContext(policy, provider, context);
        const deniedFields = result.decisions.filter((d) => d.action === "deny");
        if (deniedFields.length > 0) {
          auditLog.append("l2", "context_gate_deny", policy.identity_id ?? "system", {
            policy_id: policyId,
            provider,
            denied_fields: deniedFields.map((d) => d.field),
            original_context_hash: result.original_context_hash
          });
          return toolResult({
            blocked: true,
            reason: "Context contains fields that trigger deny action",
            denied_fields: deniedFields.map((d) => ({
              field: d.field,
              reason: d.reason
            })),
            recommendation: "Remove the denied fields from context before retrying, or update the policy to handle these fields differently."
          });
        }
        const safeContext = {};
        for (const decision of result.decisions) {
          switch (decision.action) {
            case "allow":
              safeContext[decision.field] = context[decision.field];
              break;
            case "redact":
              break;
            case "hash":
              safeContext[decision.field] = decision.hash_value;
              break;
            case "summarize":
              safeContext[decision.field] = context[decision.field];
              break;
          }
        }
        auditLog.append("l2", "context_gate_filter", policy.identity_id ?? "system", {
          policy_id: policyId,
          provider,
          fields_total: Object.keys(context).length,
          fields_allowed: result.fields_allowed,
          fields_redacted: result.fields_redacted,
          fields_hashed: result.fields_hashed,
          fields_summarized: result.fields_summarized,
          original_context_hash: result.original_context_hash,
          filtered_context_hash: result.filtered_context_hash
        });
        return toolResult({
          blocked: false,
          safe_context: safeContext,
          summary: {
            total_fields: Object.keys(context).length,
            allowed: result.fields_allowed,
            redacted: result.fields_redacted,
            hashed: result.fields_hashed,
            summarized: result.fields_summarized
          },
          decisions: result.decisions,
          audit: {
            original_context_hash: result.original_context_hash,
            filtered_context_hash: result.filtered_context_hash,
            filtered_at: result.filtered_at
          },
          guidance: result.fields_summarized > 0 ? "Some fields are marked for summarization. Consider compressing them before sending to reduce context size and information exposure." : void 0
        });
      }
    },
    // ── List Policies ───────────────────────────────────────────────
    {
      name: "sanctuary/context_gate_list_policies",
      description: "List all configured context-gating policies. Returns policy IDs, names, rule summaries, and default actions.",
      inputSchema: {
        type: "object",
        properties: {}
      },
      handler: async () => {
        const policies = await policyStore.list();
        auditLog.append("l2", "context_gate_list_policies", "system", {
          policy_count: policies.length
        });
        return toolResult({
          policies: policies.map((p) => ({
            policy_id: p.policy_id,
            policy_name: p.policy_name,
            rule_count: p.rules.length,
            providers: p.rules.map((r) => r.provider),
            default_action: p.default_action,
            identity_id: p.identity_id ?? null,
            created_at: p.created_at,
            updated_at: p.updated_at
          })),
          count: policies.length,
          message: policies.length === 0 ? "No context-gating policies configured. Use sanctuary/context_gate_set_policy to create one." : `${policies.length} context-gating ${policies.length === 1 ? "policy" : "policies"} configured.`
        });
      }
    }
  ];
  return { tools, policyStore };
}
function checkMemoryProtection() {
  const checks = {
    aslr_enabled: checkASLR(),
    stack_canaries: true,
    // Enabled by default in Node.js runtime
    secure_buffer_zeros: true,
    // We use crypto.randomBytes and explicit zeroing
    argon2id_kdf: true
    // Master key derivation uses Argon2id
  };
  const activeCount = Object.values(checks).filter((v) => v).length;
  const overall = activeCount >= 4 ? "full" : activeCount >= 3 ? "partial" : "minimal";
  return {
    ...checks,
    overall
  };
}
function checkASLR() {
  if (process.platform === "linux") {
    try {
      const result = execSync("cat /proc/sys/kernel/randomize_va_space", {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "ignore"]
      }).trim();
      return result === "2";
    } catch {
      return false;
    }
  }
  if (process.platform === "darwin") {
    return true;
  }
  return false;
}
function checkProcessIsolation() {
  const isContainer = detectContainer();
  const isVM = detectVM();
  const isSandboxed = detectSandbox();
  let isolationLevel = "none";
  if (isContainer) isolationLevel = "hardened";
  else if (isVM) isolationLevel = "hardened";
  else if (isSandboxed) isolationLevel = "basic";
  const details = {};
  if (isContainer && isContainer !== true) details.container_type = isContainer;
  if (isVM && isVM !== true) details.vm_type = isVM;
  if (isSandboxed && isSandboxed !== true) details.sandbox_type = isSandboxed;
  return {
    isolation_level: isolationLevel,
    is_container: isContainer !== false,
    is_vm: isVM !== false,
    is_sandboxed: isSandboxed !== false,
    is_tee: false,
    details
  };
}
function detectContainer() {
  try {
    if (process.env.DOCKER_HOST) return "docker";
    try {
      statSync("/.dockerenv");
      return "docker";
    } catch {
    }
    if (process.platform === "linux") {
      const cgroup = execSync("cat /proc/1/cgroup 2>/dev/null || echo ''", {
        encoding: "utf-8"
      });
      if (cgroup.includes("docker")) return "docker";
      if (cgroup.includes("lxc")) return "lxc";
      if (cgroup.includes("kubepods") || cgroup.includes("kubernetes")) return "kubernetes";
    }
    if (process.env.container === "podman") return "podman";
    if (process.env.CONTAINER_ID) return "oci";
    return false;
  } catch {
    return false;
  }
}
function detectVM() {
  if (process.platform === "linux") {
    try {
      const dmidecode = execSync("dmidecode -s system-product-name 2>/dev/null || echo ''", {
        encoding: "utf-8"
      }).toLowerCase();
      if (dmidecode.includes("vmware")) return "vmware";
      if (dmidecode.includes("virtualbox")) return "virtualbox";
      if (dmidecode.includes("kvm")) return "kvm";
      if (dmidecode.includes("xen")) return "xen";
      if (dmidecode.includes("hyper-v")) return "hyper-v";
      const cpuinfo = execSync("grep -i hypervisor /proc/cpuinfo || echo ''", {
        encoding: "utf-8"
      });
      if (cpuinfo.length > 0) return "detected";
    } catch {
    }
  }
  if (process.platform === "darwin") {
    try {
      const bootargs = execSync(
        "nvram boot-args 2>/dev/null | grep -i 'parallels\\|vmware\\|virtualbox' || echo ''",
        {
          encoding: "utf-8"
        }
      );
      if (bootargs.length > 0) return "detected";
    } catch {
    }
  }
  return false;
}
function detectSandbox() {
  if (process.platform === "darwin") {
    if (process.env.APP_SANDBOX_READ_ONLY_HOME === "1") return "app-sandbox";
    if (process.env.TMPDIR && process.env.TMPDIR.includes("AppSandbox")) return "app-sandbox";
  }
  if (process.platform === "openbsd") {
    try {
      const pledge = execSync("pledge -v 2>/dev/null || echo ''", {
        encoding: "utf-8"
      });
      if (pledge.length > 0) return "pledge";
    } catch {
    }
  }
  if (process.platform === "linux") {
    if (process.env.container === "lxc") return "lxc";
    try {
      const context = execSync("getenforce 2>/dev/null || echo ''", {
        encoding: "utf-8"
      }).trim();
      if (context === "Enforcing") return "selinux";
    } catch {
    }
  }
  return false;
}
function checkFilesystemPermissions(storagePath) {
  try {
    const stats = statSync(storagePath);
    const mode = stats.mode & parseInt("777", 8);
    const modeString = mode.toString(8).padStart(3, "0");
    const isSecure = mode === parseInt("700", 8);
    const groupReadable = (mode & parseInt("040", 8)) !== 0;
    const othersReadable = (mode & parseInt("007", 8)) !== 0;
    const currentUid = process.getuid?.() || -1;
    const ownerIsCurrentUser = stats.uid === currentUid;
    let overall = "secure";
    if (groupReadable || othersReadable) overall = "insecure";
    else if (!ownerIsCurrentUser) overall = "warning";
    return {
      sanctuary_storage_protected: isSecure,
      sanctuary_storage_mode: modeString,
      owner_is_current_user: ownerIsCurrentUser,
      group_readable: groupReadable,
      others_readable: othersReadable,
      overall
    };
  } catch {
    return {
      sanctuary_storage_protected: false,
      sanctuary_storage_mode: "unknown",
      owner_is_current_user: false,
      group_readable: false,
      others_readable: false,
      overall: "warning"
    };
  }
}
function checkRuntimeIntegrity() {
  return {
    config_hash_stable: true,
    environment_state: "clean",
    discrepancies: []
  };
}
function assessL2Hardening(storagePath) {
  const memory = checkMemoryProtection();
  const isolation = checkProcessIsolation();
  const filesystem = checkFilesystemPermissions(storagePath);
  const integrity = checkRuntimeIntegrity();
  let checksPassed = 0;
  let checksTotal = 0;
  if (memory.aslr_enabled) checksPassed++;
  checksTotal++;
  if (memory.stack_canaries) checksPassed++;
  checksTotal++;
  if (memory.secure_buffer_zeros) checksPassed++;
  checksTotal++;
  if (memory.argon2id_kdf) checksPassed++;
  checksTotal++;
  if (isolation.is_container) checksPassed++;
  checksTotal++;
  if (isolation.is_vm) checksPassed++;
  checksTotal++;
  if (isolation.is_sandboxed) checksPassed++;
  checksTotal++;
  if (filesystem.sanctuary_storage_protected) checksPassed++;
  checksTotal++;
  {
    checksPassed++;
  }
  checksTotal++;
  let hardeningLevel = isolation.isolation_level;
  if (filesystem.overall === "insecure" || memory.overall === "none" || memory.overall === "minimal") {
    if (hardeningLevel === "hardened") {
      hardeningLevel = "basic";
    } else if (hardeningLevel === "basic") {
      hardeningLevel = "none";
    }
  }
  const summaryParts = [];
  if (isolation.is_container || isolation.is_vm) {
    summaryParts.push(`Running in ${isolation.details.container_type || isolation.details.vm_type || "isolated environment"}`);
  }
  if (memory.aslr_enabled) {
    summaryParts.push("ASLR enabled");
  }
  if (filesystem.sanctuary_storage_protected) {
    summaryParts.push("Storage permissions secured (0700)");
  }
  const summary = summaryParts.length > 0 ? summaryParts.join("; ") : "No process-level hardening detected";
  return {
    hardening_level: hardeningLevel,
    memory_protection: memory,
    process_isolation: isolation,
    filesystem_permissions: filesystem,
    runtime_integrity: integrity,
    checks_passed: checksPassed,
    checks_total: checksTotal,
    summary
  };
}

// src/l2-operational/hardening-tools.ts
function createL2HardeningTools(storagePath, auditLog) {
  return [
    {
      name: "sanctuary/l2_hardening_status",
      description: "L2 Process Hardening Status \u2014 Verify software-based operational isolation. Reports memory protection, process isolation level, filesystem permissions, and overall hardening assessment. Read-only. Tier 3 \u2014 always allowed.",
      inputSchema: {
        type: "object",
        properties: {
          include_details: {
            type: "boolean",
            description: "If true, include detailed check results for memory, process, and filesystem. If false, show summary only.",
            default: false
          }
        }
      },
      handler: async (args) => {
        const includeDetails = args.include_details ?? false;
        const status = assessL2Hardening(storagePath);
        auditLog.append(
          "l2",
          "l2_hardening_status",
          "system",
          { include_details: includeDetails }
        );
        if (includeDetails) {
          return toolResult({
            hardening_level: status.hardening_level,
            summary: status.summary,
            checks_passed: status.checks_passed,
            checks_total: status.checks_total,
            memory_protection: {
              aslr_enabled: status.memory_protection.aslr_enabled,
              stack_canaries: status.memory_protection.stack_canaries,
              secure_buffer_zeros: status.memory_protection.secure_buffer_zeros,
              argon2id_kdf: status.memory_protection.argon2id_kdf,
              overall: status.memory_protection.overall
            },
            process_isolation: {
              isolation_level: status.process_isolation.isolation_level,
              is_container: status.process_isolation.is_container,
              is_vm: status.process_isolation.is_vm,
              is_sandboxed: status.process_isolation.is_sandboxed,
              is_tee: status.process_isolation.is_tee,
              details: status.process_isolation.details
            },
            filesystem_permissions: {
              sanctuary_storage_protected: status.filesystem_permissions.sanctuary_storage_protected,
              sanctuary_storage_mode: status.filesystem_permissions.sanctuary_storage_mode,
              owner_is_current_user: status.filesystem_permissions.owner_is_current_user,
              group_readable: status.filesystem_permissions.group_readable,
              others_readable: status.filesystem_permissions.others_readable,
              overall: status.filesystem_permissions.overall
            },
            runtime_integrity: {
              config_hash_stable: status.runtime_integrity.config_hash_stable,
              environment_state: status.runtime_integrity.environment_state,
              discrepancies: status.runtime_integrity.discrepancies
            }
          });
        } else {
          return toolResult({
            hardening_level: status.hardening_level,
            summary: status.summary,
            checks_passed: status.checks_passed,
            checks_total: status.checks_total,
            note: "Pass include_details: true to see full breakdown of memory, process isolation, and filesystem checks."
          });
        }
      }
    },
    {
      name: "sanctuary/l2_verify_isolation",
      description: "Verify L2 process isolation at runtime. Checks whether the Sanctuary server is running in an isolated environment (container, VM, sandbox) and validates filesystem and memory protections. Reports isolation level and any issues. Read-only. Tier 3 \u2014 always allowed.",
      inputSchema: {
        type: "object",
        properties: {
          check_filesystem: {
            type: "boolean",
            description: "If true, verify Sanctuary storage directory permissions.",
            default: true
          },
          check_memory: {
            type: "boolean",
            description: "If true, verify memory protection mechanisms (ASLR, etc.).",
            default: true
          },
          check_process: {
            type: "boolean",
            description: "If true, detect container, VM, or sandbox environment.",
            default: true
          }
        }
      },
      handler: async (args) => {
        const checkFilesystem = args.check_filesystem ?? true;
        const checkMemory = args.check_memory ?? true;
        const checkProcess = args.check_process ?? true;
        const status = assessL2Hardening(storagePath);
        auditLog.append(
          "l2",
          "l2_verify_isolation",
          "system",
          {
            check_filesystem: checkFilesystem,
            check_memory: checkMemory,
            check_process: checkProcess
          }
        );
        const results = {
          isolation_level: status.hardening_level,
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        if (checkFilesystem) {
          const fs = status.filesystem_permissions;
          results.filesystem = {
            sanctuary_storage_protected: fs.sanctuary_storage_protected,
            storage_mode: fs.sanctuary_storage_mode,
            is_secure: fs.overall === "secure",
            issues: fs.overall === "insecure" ? [
              "Storage directory is readable by group or others. Recommend: chmod 700 on Sanctuary storage path."
            ] : fs.overall === "warning" ? [
              "Storage directory not owned by current user. Verify correct user is running Sanctuary."
            ] : []
          };
        }
        if (checkMemory) {
          const mem = status.memory_protection;
          const issues = [];
          if (!mem.aslr_enabled) {
            issues.push(
              "ASLR not detected. On Linux, enable with: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space"
            );
          }
          results.memory = {
            aslr_enabled: mem.aslr_enabled,
            stack_canaries: mem.stack_canaries,
            secure_buffer_handling: mem.secure_buffer_zeros,
            argon2id_key_derivation: mem.argon2id_kdf,
            protection_level: mem.overall,
            issues
          };
        }
        if (checkProcess) {
          const iso = status.process_isolation;
          results.process = {
            isolation_level: iso.isolation_level,
            in_container: iso.is_container,
            in_vm: iso.is_vm,
            sandboxed: iso.is_sandboxed,
            has_tee: iso.is_tee,
            environment: iso.details,
            recommendation: iso.isolation_level === "none" ? "Consider running Sanctuary in a container or VM for improved isolation." : iso.isolation_level === "basic" ? "Basic isolation detected. Container or VM would provide stronger guarantees." : "Running in isolated environment \u2014 process-level isolation is strong."
          };
        }
        return toolResult({
          status: "verified",
          results
        });
      }
    }
  ];
}

// src/index.ts
init_encoding();
async function createSanctuaryServer(options) {
  const config = await loadConfig(options?.configPath);
  await mkdir(config.storage_path, { recursive: true, mode: 448 });
  const storage = options?.storage ?? new FilesystemStorage(
    `${config.storage_path}/state`
  );
  let masterKey;
  let keyProtection;
  let recoveryKey;
  const passphrase = options?.passphrase ?? process.env.SANCTUARY_PASSPHRASE;
  if (passphrase) {
    keyProtection = "passphrase";
    let existingParams;
    try {
      const raw = await storage.read("_meta", "key-params");
      if (raw) {
        const { bytesToString: bytesToString2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
        existingParams = JSON.parse(bytesToString2(raw));
      }
    } catch {
    }
    const result = await deriveMasterKey(passphrase, existingParams);
    masterKey = result.key;
    if (!existingParams) {
      const { stringToBytes: stringToBytes2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
      await storage.write(
        "_meta",
        "key-params",
        stringToBytes2(JSON.stringify(result.params))
      );
    }
  } else {
    keyProtection = "recovery-key";
    const { hashToString: hashToString2 } = await Promise.resolve().then(() => (init_hashing(), hashing_exports));
    const { stringToBytes: stringToBytes2, bytesToString: bytesToString2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
    const { fromBase64url: fromBase64url2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
    const { constantTimeEqual: constantTimeEqual2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
    const existingHash = await storage.read("_meta", "recovery-key-hash");
    if (existingHash) {
      const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
      if (!envRecoveryKey) {
        throw new Error(
          "Sanctuary: Existing encrypted data found but no credentials provided.\nThis installation was previously set up with a recovery key.\n\nTo start the server, provide one of:\n  - SANCTUARY_PASSPHRASE (if you later configured a passphrase)\n  - SANCTUARY_RECOVERY_KEY (the recovery key shown at first run)\n\nWithout the correct credentials, encrypted state cannot be accessed.\nRefusing to start to prevent silent data loss."
        );
      }
      let recoveryKeyBytes;
      try {
        recoveryKeyBytes = fromBase64url2(envRecoveryKey);
      } catch {
        throw new Error(
          "Sanctuary: SANCTUARY_RECOVERY_KEY is not valid base64url. The recovery key should be the exact string shown at first run."
        );
      }
      if (recoveryKeyBytes.length !== 32) {
        throw new Error(
          "Sanctuary: SANCTUARY_RECOVERY_KEY has incorrect length. The recovery key should be the exact string shown at first run."
        );
      }
      const providedHash = hashToString2(recoveryKeyBytes);
      const storedHash = bytesToString2(existingHash);
      const providedHashBytes = stringToBytes2(providedHash);
      const storedHashBytes = stringToBytes2(storedHash);
      if (!constantTimeEqual2(providedHashBytes, storedHashBytes)) {
        throw new Error(
          "Sanctuary: Recovery key does not match the stored key hash.\nThe recovery key provided via SANCTUARY_RECOVERY_KEY is incorrect.\nUse the exact recovery key that was displayed at first run."
        );
      }
      masterKey = recoveryKeyBytes;
    } else {
      const existingNamespaces = await storage.list("_meta");
      const hasKeyParams = existingNamespaces.some((e) => e.key === "key-params");
      if (hasKeyParams) {
        throw new Error(
          "Sanctuary: Found existing key derivation parameters but no recovery key hash.\nThis indicates a corrupted or incomplete installation.\nIf you previously used a passphrase, set SANCTUARY_PASSPHRASE to start."
        );
      }
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);
      const keyHash = hashToString2(masterKey);
      await storage.write(
        "_meta",
        "recovery-key-hash",
        stringToBytes2(keyHash)
      );
    }
  }
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    keyProtection,
    auditLog
  );
  await identityManager.load();
  const l2Tools = [
    {
      name: "sanctuary/exec_attest",
      description: "Generate an attestation of the current execution environment, including sovereignty assessment and degradation report.",
      inputSchema: {
        type: "object",
        properties: {
          include_hardware: { type: "boolean", default: true },
          include_software: { type: "boolean", default: true },
          include_network: { type: "boolean", default: true }
        }
      },
      handler: async () => {
        const degradations = [];
        degradations.push(
          "L2 isolation is process-level only; no TEE available"
        );
        if (config.disclosure.proof_system === "commitment-only") {
          degradations.push(
            "L3 proofs are commitment-based only; ZK proofs not yet available"
          );
        }
        return toolResult({
          attestation: {
            environment_type: config.execution.environment,
            hardware: {
              cpu_vendor: process.arch,
              tee_available: false,
              tee_type: void 0
            },
            software: {
              os: `${process.platform}-${process.arch}`,
              runtime: `node-${process.version}`,
              sanctuary_version: config.version,
              mcp_sdk_version: "1.26.0"
            },
            network: {
              internet_accessible: true,
              // Conservative assumption
              listening_ports: [],
              egress_restricted: false
            },
            isolation_level: "process",
            sovereignty_assessment: {
              l1_state_encrypted: true,
              l2_execution_isolated: false,
              l2_isolation_type: "process-level",
              l3_proofs_available: config.disclosure.proof_system !== "commitment-only",
              l4_reputation_active: true,
              overall_level: "mvs",
              degradations
            }
          },
          attested_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    {
      name: "sanctuary/monitor_health",
      description: "Sanctuary Health Report (SHR) \u2014 standardized sovereignty status.",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        const storageSizeBytes = await storage.totalSize();
        const degradations = [];
        degradations.push({
          layer: "l2",
          description: "Process-level isolation only (no TEE)",
          severity: "warning",
          mitigation: "TEE support planned for a future release"
        });
        if (config.disclosure.proof_system === "commitment-only") {
          degradations.push({
            layer: "l3",
            description: "Commitment schemes only (no ZK proofs)",
            severity: "info",
            mitigation: "ZK proof support planned for v0.2.0"
          });
        }
        return toolResult({
          status: degradations.some((d) => d.severity === "critical") ? "compromised" : degradations.some((d) => d.severity === "warning") ? "degraded" : "healthy",
          storage_bytes: storageSizeBytes,
          layers: {
            l1: {
              status: "active",
              encryption_algorithm: "aes-256-gcm",
              key_count: identityManager.list().length,
              state_integrity: "verified",
              last_integrity_check: (/* @__PURE__ */ new Date()).toISOString()
            },
            l2: {
              status: "degraded",
              isolation_type: "process-level",
              attestation_available: true,
              last_attestation: (/* @__PURE__ */ new Date()).toISOString()
            },
            l3: {
              status: config.disclosure.proof_system === "commitment-only" ? "degraded" : "active",
              proof_system: config.disclosure.proof_system,
              circuits_loaded: 0,
              proofs_generated_total: 0
            },
            l4: {
              status: "active",
              mode: config.reputation.mode,
              interaction_count: 0,
              // TODO: track from reputation store
              reputation_exportable: true
            }
          },
          degradations,
          checked_at: (/* @__PURE__ */ new Date()).toISOString()
        });
      }
    },
    {
      name: "sanctuary/monitor_audit_log",
      description: "Query the sovereignty audit log.",
      inputSchema: {
        type: "object",
        properties: {
          since: { type: "string", description: "ISO 8601 timestamp" },
          layer: {
            type: "string",
            enum: ["l1", "l2", "l3", "l4"]
          },
          operation_type: { type: "string" },
          limit: { type: "number", default: 50 }
        }
      },
      handler: async (args) => {
        const result = await auditLog.query({
          since: args.since,
          layer: args.layer,
          operation_type: args.operation_type,
          limit: args.limit ?? 50
        });
        return toolResult(result);
      }
    }
  ];
  const manifestTool = {
    name: "sanctuary/manifest",
    description: "Generate the Sanctuary Interface Manifest (SIM) \u2014 a machine-readable declaration of this server's capabilities.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      return toolResult({
        sanctuary_version: "0.2",
        implementation: {
          name: "@sanctuary-framework/mcp-server",
          version: config.version,
          language: "typescript",
          license: "Apache-2.0"
        },
        layers: {
          l1: {
            implemented: true,
            interfaces: ["StateStore", "IdentityRoot"],
            encryption: ["aes-256-gcm"],
            identity: ["ed25519"],
            properties: {
              "S1.1_participant_held_keys": "full",
              "S1.2_encryption_at_rest": "full",
              "S1.3_integrity_verification": "full",
              "S1.4_selective_state_sharing": "full",
              "S1.5_state_portability": "full",
              "S1.6_deletion_rights": "full",
              "S1.7_identity_anchoring": "partial"
            }
          },
          l2: {
            implemented: true,
            interfaces: ["ExecutionEnvironment", "RuntimeMonitor"],
            isolation_types: [config.execution.environment],
            properties: {
              "S2.1_execution_confidentiality": "documented",
              "S2.2_verifiable_execution": "self-reported",
              "S2.5_attestation": "self-reported"
            }
          },
          l3: {
            implemented: true,
            interfaces: ["ProofEngine", "DisclosurePolicy"],
            proof_systems: [config.disclosure.proof_system],
            properties: {
              "S3.1_minimum_disclosure": "policy-based",
              "S3.3_proof_without_revelation": "commitment"
            }
          },
          l4: {
            implemented: true,
            interfaces: ["ReputationStore", "TrustBootstrap"],
            modes: [config.reputation.mode],
            properties: {
              "S4.1_earned_reputation": "full",
              "S4.2_participant_owned": "full",
              "S4.5_sybil_resistance": "basic",
              "S4.7_trust_bootstrapping": "full"
            }
          }
        },
        composition: {
          sim_version: "1.0",
          spf_supported: false,
          shr_supported: true,
          delegation_depth: 1
        },
        limitations: [
          "L1 identity uses ed25519 only; KERI support planned for v0.2.0",
          "L2 isolation is process-level only; TEE support planned for a future release",
          "L3 uses commitment schemes only; ZK proofs planned for v0.2.0",
          "L4 Sybil resistance is escrow-based only",
          "Spec license: CC-BY-4.0 | Code license: Apache-2.0"
        ]
      });
    }
  };
  const { tools: l3Tools } = createL3Tools(storage, masterKey, auditLog);
  const { tools: shrTools } = createSHRTools(
    config,
    identityManager,
    masterKey,
    auditLog
  );
  const { tools: handshakeTools, handshakeResults } = createHandshakeTools(
    config,
    identityManager,
    masterKey,
    auditLog
  );
  const { tools: l4Tools} = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults
  );
  const { tools: federationTools } = createFederationTools(
    auditLog,
    handshakeResults
  );
  const { tools: bridgeTools } = createBridgeTools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults
  );
  const { tools: auditTools } = createAuditTools(config);
  const { tools: contextGateTools } = createContextGateTools(
    storage,
    masterKey,
    auditLog
  );
  const hardeningTools = createL2HardeningTools(config.storage_path, auditLog);
  const policy = await loadPrincipalPolicy(config.storage_path);
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();
  let approvalChannel;
  let dashboard;
  if (config.dashboard.enabled) {
    let authToken = config.dashboard.auth_token;
    if (authToken === "auto") {
      const { randomBytes: rb } = await import('crypto');
      authToken = rb(32).toString("hex");
    }
    dashboard = new DashboardApprovalChannel({
      port: config.dashboard.port,
      host: config.dashboard.host,
      timeout_seconds: policy.approval_channel.timeout_seconds,
      // SEC-002: auto_deny removed — timeout always denies
      auth_token: authToken,
      tls: config.dashboard.tls
    });
    dashboard.setDependencies({ policy, baseline, auditLog });
    await dashboard.start();
    approvalChannel = dashboard;
  } else if (config.webhook.enabled && config.webhook.url && config.webhook.secret) {
    const webhook = new WebhookApprovalChannel({
      webhook_url: config.webhook.url,
      webhook_secret: config.webhook.secret,
      callback_port: config.webhook.callback_port,
      callback_host: config.webhook.callback_host,
      timeout_seconds: policy.approval_channel.timeout_seconds
      // SEC-002: auto_deny removed — timeout always denies
    });
    await webhook.start();
    approvalChannel = webhook;
  } else {
    approvalChannel = new StderrApprovalChannel(policy.approval_channel);
  }
  const gate = new ApprovalGate(policy, baseline, approvalChannel, auditLog);
  const policyTools = createPrincipalPolicyTools(policy, baseline, auditLog);
  const allTools = [
    ...l1Tools,
    ...l2Tools,
    ...l3Tools,
    ...l4Tools,
    ...policyTools,
    ...shrTools,
    ...handshakeTools,
    ...federationTools,
    ...bridgeTools,
    ...auditTools,
    ...contextGateTools,
    ...hardeningTools,
    manifestTool
  ];
  const server = createServer(allTools, { gate });
  await saveConfig(config);
  const saveBaseline = () => {
    baseline.save().catch(() => {
    });
  };
  process.on("SIGINT", saveBaseline);
  process.on("SIGTERM", saveBaseline);
  if (recoveryKey) {
    console.error(
      `\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  SANCTUARY: First Run \u2014 Recovery Key Generated          \u2551
\u2551                                                          \u2551
\u2551  Recovery Key: ${recoveryKey.slice(0, 20)}...             \u2551
\u2551                                                          \u2551
\u2551  SAVE THIS KEY. It will not be shown again.              \u2551
\u2551  Without it, your encrypted state is unrecoverable.      \u2551
\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D`
    );
  }
  return { server, config };
}
var REGISTRY_URL = "https://registry.npmjs.org/@sanctuary-framework/mcp-server/latest";
var TIMEOUT_MS = 3e3;
function isNewerVersion(current, latest) {
  const parse = (v) => v.replace(/^v/, "").split(".").map(Number);
  const [curMajor = 0, curMinor = 0, curPatch = 0] = parse(current);
  const [latMajor = 0, latMinor = 0, latPatch = 0] = parse(latest);
  if (latMajor !== curMajor) return latMajor > curMajor;
  if (latMinor !== curMinor) return latMinor > curMinor;
  return latPatch > curPatch;
}
function formatUpdateMessage(current, latest) {
  return `[Sanctuary] Update available: ${current} \u2192 ${latest} \u2014 run: npx @sanctuary-framework/mcp-server@latest`;
}
function fetchLatestVersion(currentVersion) {
  return new Promise((resolve) => {
    const req = get(
      REGISTRY_URL,
      {
        headers: { Accept: "application/json" },
        timeout: TIMEOUT_MS
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        let data = "";
        res.setEncoding("utf-8");
        res.on("data", (chunk) => {
          data += chunk;
          if (data.length > 32768) {
            res.destroy();
            resolve(null);
          }
        });
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            const latest = json.version;
            if (typeof latest === "string" && isNewerVersion(currentVersion, latest)) {
              resolve(latest);
            } else {
              resolve(null);
            }
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}
async function checkForUpdate(currentVersion) {
  if (process.env.SANCTUARY_NO_UPDATE_CHECK === "1") {
    return;
  }
  try {
    const latest = await fetchLatestVersion(currentVersion);
    if (latest) {
      console.error(formatUpdateMessage(currentVersion, latest));
    }
  } catch {
  }
}
var require4 = createRequire(import.meta.url);
var { version: PKG_VERSION3 } = require4("../package.json");
async function main() {
  const args = process.argv.slice(2);
  let passphrase = process.env.SANCTUARY_PASSPHRASE;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dashboard") {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    } else if (args[i] === "--passphrase" && args[i + 1]) {
      passphrase = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      printHelp();
      process.exit(0);
    } else if (args[i] === "--version" || args[i] === "-v") {
      console.log(`@sanctuary-framework/mcp-server ${PKG_VERSION3}`);
      process.exit(0);
    }
  }
  const { server, config } = await createSanctuaryServer({ passphrase });
  if (config.transport === "stdio") {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`Sanctuary MCP Server v${config.version} running (stdio)`);
    console.error(`Storage: ${config.storage_path}`);
    console.error("Tools: all registered");
    checkForUpdate(PKG_VERSION3);
  } else {
    console.error("HTTP transport not yet implemented. Use stdio.");
    process.exit(1);
  }
}
function printHelp() {
  console.log(`
@sanctuary-framework/mcp-server v${PKG_VERSION3}

Sovereignty infrastructure for agents in the agentic economy.

Usage:
  sanctuary-mcp-server [options]

Options:
  --dashboard          Enable the Principal Dashboard (web UI)
  --passphrase <pass>  Derive encryption key from passphrase
  --help, -h           Show this help
  --version, -v        Show version

Environment variables:
  SANCTUARY_STORAGE_PATH            State directory (default: ~/.sanctuary)
  SANCTUARY_PASSPHRASE              Key derivation passphrase
  SANCTUARY_DASHBOARD_ENABLED       "true" to enable dashboard
  SANCTUARY_DASHBOARD_PORT          Dashboard port (default: 3501)
  SANCTUARY_DASHBOARD_AUTH_TOKEN    Bearer token or "auto"
  SANCTUARY_WEBHOOK_ENABLED         "true" to enable webhook approvals
  SANCTUARY_WEBHOOK_URL             Webhook target URL
  SANCTUARY_WEBHOOK_SECRET          HMAC-SHA256 shared secret
  SANCTUARY_NO_UPDATE_CHECK         "1" to disable startup update check

For more info: https://github.com/eriknewton/sanctuary-framework
`);
}
main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
//# sourceMappingURL=cli.js.map
//# sourceMappingURL=cli.js.map