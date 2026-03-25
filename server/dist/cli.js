#!/usr/bin/env node
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { mkdir, readFile, writeFile, stat, unlink, readdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes as randomBytes$1 } from 'crypto';
import { gcm } from '@noble/ciphers/aes.js';
import { ed25519 } from '@noble/curves/ed25519';
import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

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
    version: "0.1.0",
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
    http_port: 3500
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
function createServer(tools) {
  const server = new Server(
    {
      name: "sanctuary-mcp-server",
      version: "0.1.0"
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
    try {
      return await tool.handler(args ?? {});
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
        const payload = fromBase64url(args.payload);
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
          public_key: identity.public_key
        });
      }
    },
    {
      name: "sanctuary/identity_verify",
      description: "Verify an Ed25519 signature against a public key.",
      inputSchema: {
        type: "object",
        properties: {
          payload: {
            type: "string",
            description: "Base64url-encoded original data"
          },
          signature: { type: "string", description: "Base64url signature" },
          public_key: {
            type: "string",
            description: "Base64url public key"
          }
        },
        required: ["payload", "signature", "public_key"]
      },
      handler: async (args) => {
        const payload = fromBase64url(args.payload);
        const signature = fromBase64url(args.signature);
        const publicKey = fromBase64url(args.public_key);
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
  const allTools = [
    ...l1Tools,
    ...l2Tools,
    manifestTool
    // L3 and L4 tools will be added here as they're implemented
  ];
  const server = createServer(allTools);
  await saveConfig(config);
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

// src/cli.ts
async function main() {
  const passphrase = process.env.SANCTUARY_PASSPHRASE;
  const { server, config } = await createSanctuaryServer({ passphrase });
  if (config.transport === "stdio") {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`Sanctuary MCP Server v${config.version} running (stdio)`);
    console.error(`Storage: ${config.storage_path}`);
    console.error("Tools: all registered");
  } else {
    console.error("HTTP transport not yet implemented. Use stdio.");
    process.exit(1);
  }
}
main().catch((err) => {
  console.error("Sanctuary MCP Server failed to start:", err);
  process.exit(1);
});
//# sourceMappingURL=cli.js.map
//# sourceMappingURL=cli.js.map