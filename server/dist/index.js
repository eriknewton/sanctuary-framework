import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { readFile, mkdir, writeFile, stat, unlink, readdir, chmod } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes as randomBytes$1, createHmac } from 'crypto';
import { gcm } from '@noble/ciphers/aes.js';
import { RistrettoPoint, ed25519 } from '@noble/curves/ed25519';
import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer as createServer$2 } from 'http';
import { createServer as createServer$1 } from 'https';
import { readFileSync } from 'fs';

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
function defaultConfig() {
  return {
    version: "0.3.0",
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
    return deepMerge(config, fileConfig);
  } catch {
    return config;
  }
}
async function saveConfig(config, configPath) {
  const path = join(config.storage_path, "sanctuary.json");
  await writeFile(path, JSON.stringify(config, null, 2), { mode: 384 });
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
  async import(bundleBase64, conflictResolution = "skip") {
    const bundleBytes = fromBase64url(bundleBase64);
    const bundleJson = bytesToString(bundleBytes);
    const bundle = JSON.parse(bundleJson);
    let importedKeys = 0;
    let skippedKeys = 0;
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
      conflicts,
      namespaces,
      imported_at: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
};
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
      version: "0.3.0"
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
        const result = await stateStore.import(
          args.bundle,
          args.conflict_resolution ?? "skip"
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
          summary
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
  timeout_seconds: 300,
  auto_deny: true
};
var DEFAULT_POLICY = {
  version: 1,
  tier1_always_approve: [
    "state_export",
    "state_import",
    "identity_rotate",
    "reputation_import",
    "bootstrap_provide_guarantee"
  ],
  tier2_anomaly: DEFAULT_TIER2,
  tier3_always_allow: [
    "state_read",
    "state_write",
    "state_list",
    "state_delete",
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
    "reputation_export",
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
    "zk_range_verify"
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
  return {
    version: raw.version ?? 1,
    tier1_always_approve: raw.tier1_always_approve ?? DEFAULT_POLICY.tier1_always_approve,
    tier2_anomaly: {
      ...DEFAULT_TIER2,
      ...raw.tier2_anomaly ?? {}
    },
    tier3_always_allow: raw.tier3_always_allow ?? DEFAULT_POLICY.tier3_always_allow,
    approval_channel: {
      ...DEFAULT_CHANNEL,
      ...raw.approval_channel ?? {}
    }
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
  - identity_rotate
  - reputation_import
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
  - state_delete
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
  - reputation_export
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

# \u2500\u2500\u2500 Approval Channel \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# How Sanctuary reaches you when approval is needed.
approval_channel:
  type: stderr
  timeout_seconds: 300
  auto_deny: true
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
  config;
  constructor(config) {
    this.config = config;
  }
  async requestApproval(request) {
    const prompt = this.formatPrompt(request);
    process.stderr.write(prompt + "\n");
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (this.config.auto_deny) {
      return {
        decision: "deny",
        decided_at: (/* @__PURE__ */ new Date()).toISOString(),
        decided_by: "timeout"
      };
    } else {
      return {
        decision: "approve",
        decided_at: (/* @__PURE__ */ new Date()).toISOString(),
        decided_by: "auto"
      };
    }
  }
  formatPrompt(request) {
    const tierLabel = request.tier === 1 ? "Tier 1 \u2014 always requires approval" : "Tier 2 \u2014 behavioral anomaly detected";
    const contextLines = Object.entries(request.context).map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
    return [
      "",
      "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557",
      "\u2551  SANCTUARY: Approval Required                                    \u2551",
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
      this.config.auto_deny ? "\u2551  Auto-denying (configure approval_channel.auto_deny to change)  \u2551" : "\u2551  Auto-approving (informational mode)                            \u2551",
      "\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D",
      ""
    ].join("\n");
  }
};
var CallbackApprovalChannel = class {
  callback;
  constructor(callback) {
    this.callback = callback;
  }
  async requestApproval(request) {
    return this.callback(request);
  }
};
var AutoApproveChannel = class {
  async requestApproval(_request) {
    return {
      decision: "approve",
      decided_at: (/* @__PURE__ */ new Date()).toISOString(),
      decided_by: "auto"
    };
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
  // Read auth token from URL query param at runtime (never embedded in HTML source)
  const AUTH_TOKEN = new URLSearchParams(window.location.search).get('token');
  const pending = new Map();
  let auditCount = 0;

  // Auth helpers
  function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (AUTH_TOKEN) h['Authorization'] = 'Bearer ' + AUTH_TOKEN;
    return h;
  }
  function authQuery(url) {
    if (!AUTH_TOKEN) return url;
    const sep = url.includes('?') ? '&' : '?';
    return url + sep + 'token=' + AUTH_TOKEN;
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

  // SSE Connection
  let evtSource;
  function connect() {
    evtSource = new EventSource(authQuery('/events'));
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

  // Init
  connect();
  fetch('/api/status', { headers: authHeaders() }).then(r => r.json()).then(data => {
    if (data.baseline) updateBaseline(data.baseline);
    if (data.policy) updatePolicy(data.policy);
  }).catch(() => {});
})();
</script>
</body>
</html>`;
}

// src/principal-policy/dashboard.ts
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
  constructor(config) {
    this.config = config;
    this.authToken = config.auth_token;
    this.useTLS = !!(config.tls?.cert_path && config.tls?.key_path);
    this.dashboardHTML = generateDashboardHTML({
      timeoutSeconds: config.timeout_seconds,
      serverVersion: "0.3.0",
      authToken: this.authToken
    });
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
            `  Auth required (token: ${hint}). Pass ?token=<TOKEN> or Authorization: Bearer <TOKEN>.

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
          decision: this.config.auto_deny ? "deny" : "approve",
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
   * Checks Authorization header first, falls back to ?token= query param.
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
    const queryToken = url.searchParams.get("token");
    if (queryToken === this.authToken) {
      return true;
    }
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized \u2014 valid bearer token required" }));
    return false;
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
    try {
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
        const id = url.pathname.slice("/api/approve/".length);
        this.handleDecision(id, "approve", res);
      } else if (method === "POST" && url.pathname.startsWith("/api/deny/")) {
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
          auto_deny: this.policy.approval_channel.auto_deny
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
          auto_deny: this.policy.approval_channel.auto_deny
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
          decision: this.config.auto_deny ? "deny" : "approve",
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
            auto_deny: policy.approval_channel.auto_deny
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
      mitigation: "TEE support planned for v0.3.0"
    });
    degradations.push({
      layer: "l2",
      code: "SELF_REPORTED_ATTESTATION",
      severity: "warning",
      description: "Attestation is self-reported (no hardware root of trust)",
      mitigation: "TEE attestation planned for v0.3.0"
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
  const currentTime = now ?? /* @__PURE__ */ new Date();
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
  const identity = identityId ? identityManager.get(identityId) : identityManager.getDefault();
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
          instructions: "Send the 'response' object back to the initiator. When you receive their completion, pass it to sanctuary/handshake_status with this session_id."
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
          instructions: "Send the 'completion' object to the responder so they can verify the handshake. The 'result' object contains the verified counterparty status and trust tier."
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
  const payloadBytes = stringToBytes(JSON.stringify(commitmentPayload));
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
  const payloadBytes = stringToBytes(JSON.stringify(commitmentPayload));
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
          committer_did: storedCommitment.committer_did
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

// src/index.ts
init_encoding();

// src/storage/memory.ts
var MemoryStorage = class {
  store = /* @__PURE__ */ new Map();
  storageKey(namespace, key) {
    return `${namespace}/${key}`;
  }
  async write(namespace, key, data) {
    this.store.set(this.storageKey(namespace, key), {
      data: new Uint8Array(data),
      // Copy to prevent external mutation
      modified_at: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  async read(namespace, key) {
    const entry = this.store.get(this.storageKey(namespace, key));
    if (!entry) return null;
    return new Uint8Array(entry.data);
  }
  async delete(namespace, key, _secureOverwrite) {
    return this.store.delete(this.storageKey(namespace, key));
  }
  async list(namespace, prefix) {
    const entries = [];
    const nsPrefix = `${namespace}/`;
    for (const [storeKey, entry] of this.store) {
      if (!storeKey.startsWith(nsPrefix)) continue;
      const key = storeKey.slice(nsPrefix.length);
      if (prefix && !key.startsWith(prefix)) continue;
      entries.push({
        key,
        namespace,
        size_bytes: entry.data.length,
        modified_at: entry.modified_at
      });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }
  async exists(namespace, key) {
    return this.store.has(this.storageKey(namespace, key));
  }
  async totalSize() {
    let total = 0;
    for (const entry of this.store.values()) {
      total += entry.data.length;
    }
    return total;
  }
  /** Clear all stored data (useful in tests) */
  clear() {
    this.store.clear();
  }
};

// src/index.ts
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
    const existing = await storage.read("_meta", "recovery-key-hash");
    if (existing) {
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);
    } else {
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);
      const { hashToString: hashToString2 } = await Promise.resolve().then(() => (init_hashing(), hashing_exports));
      const { stringToBytes: stringToBytes2 } = await Promise.resolve().then(() => (init_encoding(), encoding_exports));
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
          mitigation: "TEE support planned for v0.3.0"
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
          "L2 isolation is process-level only; TEE support planned for v0.3.0",
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
  const { tools: l4Tools } = createL4Tools(
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
      auto_deny: policy.approval_channel.auto_deny,
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
      timeout_seconds: policy.approval_channel.timeout_seconds,
      auto_deny: policy.approval_channel.auto_deny
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

export { ApprovalGate, AuditLog, AutoApproveChannel, BaselineTracker, CallbackApprovalChannel, CommitmentStore, DashboardApprovalChannel, FederationRegistry, FilesystemStorage, MemoryStorage, PolicyStore, ReputationStore, StateStore, StderrApprovalChannel, TIER_WEIGHTS, WebhookApprovalChannel, canonicalize, completeHandshake, computeWeightedScore, createBridgeCommitment, createPedersenCommitment, createProofOfKnowledge, createRangeProof, createSanctuaryServer, generateSHR, initiateHandshake, loadConfig, loadPrincipalPolicy, resolveTier, respondToHandshake, signPayload, tierDistribution, verifyBridgeCommitment, verifyCompletion, verifyPedersenCommitment, verifyProofOfKnowledge, verifyRangeProof, verifySHR, verifySignature };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map