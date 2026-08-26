/**
 * Q5C: inert on-disk Ollama manifest and descriptor verifier.
 *
 * No production composition root imports or invokes this module. A caller must
 * explicitly supply a Q5A-validated immune binding, an absolute persisted root,
 * and an injected filesystem adapter before any filesystem read can occur.
 * Residual: real Ollama layer descriptors may carry a `from` key, which this
 * strict parser refuses as `disk_manifest_invalid`; the Q5E disposable-host
 * drill must watch for this as a false-refusal source.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat as nodeLstat,
  open as nodeOpen,
  realpath as nodeRealpath,
  type FileHandle,
} from "node:fs/promises";
import {
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { parseStrictJson } from "../substrate/strict-json.js";
import {
  MODEL_MANIFEST_V2_REGISTRY,
  deriveOllamaManifestRelativePath,
  deriveOllamaRuntimeTag,
  type SignedOllamaIdentityV2,
  type VerifiedLocalBindingV2,
} from "./model-manifest-v2.js";

const KIBIBYTE_BYTES = 1_024;
const MEBIBYTE_BYTES = KIBIBYTE_BYTES * KIBIBYTE_BYTES;
const GIBIBYTE_BYTES = MEBIBYTE_BYTES * KIBIBYTE_BYTES;
const MINUTES_PER_HOUR = 60;
const SECONDS_PER_MINUTE = 60;
const MILLISECONDS_PER_SECOND = 1_000;
const SHA256_BYTES = 32;
const SHA256_HEX_CHARS = SHA256_BYTES * 2;
/** Design section 6.4 requires OCI schemaVersion 2 exactly. */
const OCI_MANIFEST_SCHEMA_VERSION = 2;
/** Each accepted descriptor has exactly mediaType, digest, and size authority. */
const OCI_DESCRIPTOR_REQUIRED_KEY_COUNT = 3;
/** Design section 6.3 permits the first changed read plus one retry. */
const STABLE_FILE_MAX_ATTEMPTS = 2;

/** Design section 6.4: one MiB, with one extra byte read to detect overflow. */
export const IMMUNE_OCI_MANIFEST_MAX_BYTES = MEBIBYTE_BYTES;
export const IMMUNE_OCI_MANIFEST_OVERFLOW_READ_BYTES =
  IMMUNE_OCI_MANIFEST_MAX_BYTES + 1;
/** Design section 6.4: an OCI manifest carries at most 128 layer descriptors. */
export const IMMUNE_OCI_MAX_LAYERS = 128;
/** Design section 6.4: each authenticated descriptor is bounded at 128 GiB. */
export const IMMUNE_OCI_MAX_DESCRIPTOR_BYTES = 128 * GIBIBYTE_BYTES;
/** Design section 6.4: config plus all layers are bounded at 512 GiB. */
export const IMMUNE_OCI_MAX_TOTAL_DESCRIPTOR_BYTES = 512 * GIBIBYTE_BYTES;
/** Design section 6.4 bounds every descriptor media type to 256 ASCII chars. */
export const IMMUNE_OCI_MAX_MEDIA_TYPE_CHARS = 256;
/** Design section 6.5 permits at most four MiB per streaming hash buffer. */
export const IMMUNE_HASH_MAX_BUFFER_BYTES = 4 * MEBIBYTE_BYTES;
/** A smaller fixed buffer remains below the reviewed four-MiB ceiling. */
export const IMMUNE_HASH_BUFFER_BYTES = 64 * KIBIBYTE_BYTES;
/** Design section 7 fixes successful full-verification reuse at six hours. */
export const IMMUNE_FULL_VERIFICATION_CADENCE_MS =
  6 * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
/** Design section 7.3 caps entries at 32; must match LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES in runtime-light-verifier.ts. */
export const IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES = 32;

// Design section 3.2 fixes 64 chars; must match IDENTITY_COMPONENT in model-manifest-v2.ts and OLLAMA_IDENTITY_COMPONENT_MAX_CHARS in runtime-light-verifier.ts.
const OLLAMA_IDENTITY_COMPONENT_MAX_CHARS = 64;
const OLLAMA_IDENTITY_COMPONENT = new RegExp(
  `^[a-z0-9][a-z0-9._-]{0,${OLLAMA_IDENTITY_COMPONENT_MAX_CHARS - 1}}$`,
);
const SHA256_HEX = new RegExp(`^[0-9a-f]{${SHA256_HEX_CHARS}}$`);
const SHA256_DESCRIPTOR = new RegExp(`^sha256:([0-9a-f]{${SHA256_HEX_CHARS}})$`);
const ALL_ZERO_SHA256 = "0".repeat(SHA256_HEX_CHARS);
// Printable US-ASCII excludes control bytes and Unicode-confusable media types.
const ASCII_MEDIA_TYPE = /^[\x20-\x7e]+$/;

export type ImmuneVerificationRefusalReason =
  | "binding_mismatch"
  | "model_root_invalid"
  | "path_escape"
  | "symlink_refused"
  | "disk_manifest_invalid"
  | "disk_manifest_digest_mismatch"
  | "descriptor_bounds_exceeded"
  | "layer_missing"
  | "layer_size_mismatch"
  | "layer_digest_mismatch"
  | "unstable_file"
  | "integrity_io_unavailable"
  | "immune_platform_unsupported";

export type ImmuneVerificationCheckpoint =
  | "selector_load"
  | "first_invocation"
  | "cadence";

export interface ImmuneFileStat {
  readonly device: bigint;
  readonly inode: bigint;
  readonly size: bigint;
  readonly mtimeNanoseconds: bigint;
  readonly isDirectory: boolean;
  readonly isFile: boolean;
  readonly isSymbolicLink: boolean;
}

export interface ImmuneFileHandle {
  stat(): Promise<ImmuneFileStat>;
  read(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}

/** The only I/O seam; implementations provide bytes, never caller-selected hashes. */
export interface ImmuneFileSystemAdapter {
  readonly platform: NodeJS.Platform;
  readonly noFollowFlag: number | null;
  realpath(path: string): Promise<string>;
  lstat(path: string): Promise<ImmuneFileStat>;
  open(path: string, flags: number): Promise<ImmuneFileHandle>;
}

export interface OciDescriptor {
  readonly mediaType: string;
  readonly digest: `sha256:${string}`;
  readonly digestHex: string;
  readonly size: number;
}

export interface ParsedOciManifest {
  readonly config: OciDescriptor;
  readonly layers: readonly OciDescriptor[];
  readonly distinctDescriptors: readonly OciDescriptor[];
  readonly totalDescriptorBytes: number;
}

export interface ImmuneVerificationRequest {
  /** Must be the persisted, already-resolved Q5 root. */
  readonly rootReal: string;
  /** Must come from Q5A armed-state validation and retain immune assurance. */
  readonly binding: VerifiedLocalBindingV2;
  readonly checkpoint: ImmuneVerificationCheckpoint;
}

export type ImmuneVerificationResult =
  | {
    readonly ok: true;
    readonly state: "immune_verified";
    readonly runtimeTag: string;
    readonly expectedManifestDigest: string;
    readonly descriptorCount: number;
    readonly bytesHashed: number;
    readonly verifiedArtifactDigests: readonly string[];
    readonly completedAtMonotonicMs: number;
    readonly cached: boolean;
  }
  | {
    readonly ok: false;
    readonly state: "immune_refused";
    readonly reason: ImmuneVerificationRefusalReason;
  };

export interface ImmuneDiskVerifier {
  verify(request: ImmuneVerificationRequest): Promise<ImmuneVerificationResult>;
}

export interface ImmuneVerificationClock {
  monotonicNow(): number;
  wallNow(): number;
}

export interface CadencedImmuneDiskVerifier extends ImmuneDiskVerifier {
  /** Marks matching entries stale; a pending gate remains single-flight until it settles. */
  invalidate(request?: ImmuneVerificationRequest): void;
  readonly cacheSize: number;
}

class ImmuneRefusal extends Error {
  constructor(readonly reason: ImmuneVerificationRefusalReason) {
    super(reason);
  }
}

function refuse(reason: ImmuneVerificationRefusalReason): never {
  throw new ImmuneRefusal(reason);
}

function failure(reason: ImmuneVerificationRefusalReason): ImmuneVerificationResult {
  return { ok: false, state: "immune_refused", reason };
}

function statFromNode(stats: Awaited<ReturnType<FileHandle["stat"]>>): ImmuneFileStat {
  const bigintStats = stats as unknown as {
    dev: bigint;
    ino: bigint;
    size: bigint;
    mtimeNs: bigint;
    isDirectory(): boolean;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  };
  return {
    device: bigintStats.dev,
    inode: bigintStats.ino,
    size: bigintStats.size,
    mtimeNanoseconds: bigintStats.mtimeNs,
    isDirectory: bigintStats.isDirectory(),
    isFile: bigintStats.isFile(),
    isSymbolicLink: bigintStats.isSymbolicLink(),
  };
}

function wrapNodeHandle(handle: FileHandle): ImmuneFileHandle {
  return {
    async stat() {
      return statFromNode(await handle.stat({ bigint: true }));
    },
    async read(buffer, offset, length, position) {
      return handle.read(buffer, offset, length, position);
    },
    async close() {
      await handle.close();
    },
  };
}

/** Constructing this adapter performs no read; reads begin only in `verify()`. */
export function createNodeImmuneFileSystemAdapter(): ImmuneFileSystemAdapter {
  return {
    platform: process.platform,
    noFollowFlag:
      typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : null,
    async realpath(path) {
      return nodeRealpath(path);
    },
    async lstat(path) {
      return statFromNode(await nodeLstat(path, { bigint: true }));
    },
    async open(path, flags) {
      return wrapNodeHandle(await nodeOpen(path, flags));
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactDescriptorKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value);
  return keys.length === OCI_DESCRIPTOR_REQUIRED_KEY_COUNT &&
    keys.includes("mediaType") && keys.includes("digest") && keys.includes("size");
}

function parseDescriptor(value: unknown): OciDescriptor {
  if (!isRecord(value) || !exactDescriptorKeys(value)) {
    refuse("disk_manifest_invalid");
  }
  if (
    typeof value.mediaType !== "string" || value.mediaType.length === 0 ||
    value.mediaType.length > IMMUNE_OCI_MAX_MEDIA_TYPE_CHARS ||
    !ASCII_MEDIA_TYPE.test(value.mediaType)
  ) {
    refuse("disk_manifest_invalid");
  }
  const match = typeof value.digest === "string"
    ? SHA256_DESCRIPTOR.exec(value.digest)
    : null;
  const digestHex = match?.[1];
  if (digestHex === undefined || digestHex === ALL_ZERO_SHA256) {
    refuse("disk_manifest_invalid");
  }
  if (
    typeof value.size !== "number" || !Number.isSafeInteger(value.size) ||
    value.size < 0 || value.size > IMMUNE_OCI_MAX_DESCRIPTOR_BYTES
  ) {
    refuse("descriptor_bounds_exceeded");
  }
  return {
    mediaType: value.mediaType,
    digest: `sha256:${digestHex}`,
    digestHex,
    size: value.size,
  };
}

/** Parse only authenticated config/layers after the design's byte cap is enforced. */
export function parseBoundedOciManifest(bytes: Uint8Array): ParsedOciManifest {
  if (bytes.byteLength > IMMUNE_OCI_MANIFEST_MAX_BYTES) {
    refuse("disk_manifest_invalid");
  }
  let value: unknown;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    value = parseStrictJson(text);
  } catch {
    refuse("disk_manifest_invalid");
  }
  if (
    !isRecord(value) || value.schemaVersion !== OCI_MANIFEST_SCHEMA_VERSION ||
    !("config" in value) || !Array.isArray(value.layers)
  ) {
    refuse("disk_manifest_invalid");
  }
  if (value.layers.length < 1 || value.layers.length > IMMUNE_OCI_MAX_LAYERS) {
    refuse("descriptor_bounds_exceeded");
  }
  const config = parseDescriptor(value.config);
  const layers = value.layers.map((descriptor) => parseDescriptor(descriptor));
  const allDescriptors = [config, ...layers];
  let totalDescriptorBytes = 0;
  const distinct = new Map<string, OciDescriptor>();
  for (const descriptor of allDescriptors) {
    const nextTotal = totalDescriptorBytes + descriptor.size;
    // Checked addition prevents a future raised per-descriptor cap from wrapping the aggregate.
    if (
      !Number.isSafeInteger(nextTotal) ||
      nextTotal > IMMUNE_OCI_MAX_TOTAL_DESCRIPTOR_BYTES
    ) {
      refuse("descriptor_bounds_exceeded");
    }
    totalDescriptorBytes = nextTotal;
    const prior = distinct.get(descriptor.digestHex);
    if (
      prior !== undefined &&
      (prior.size !== descriptor.size || prior.mediaType !== descriptor.mediaType)
    ) {
      // One content address cannot authenticate two incompatible descriptor meanings.
      refuse("disk_manifest_invalid");
    }
    if (prior === undefined) distinct.set(descriptor.digestHex, descriptor);
  }
  return {
    config,
    layers,
    distinctDescriptors: [...distinct.values()],
    totalDescriptorBytes,
  };
}

function validBinding(binding: VerifiedLocalBindingV2): boolean {
  const identity: SignedOllamaIdentityV2 = binding.ollama_identity;
  return binding.assurance === "immune" &&
    identity.registry === MODEL_MANIFEST_V2_REGISTRY &&
    OLLAMA_IDENTITY_COMPONENT.test(identity.namespace) &&
    OLLAMA_IDENTITY_COMPONENT.test(identity.model) &&
    OLLAMA_IDENTITY_COMPONENT.test(identity.tag) &&
    SHA256_HEX.test(identity.ollama_manifest_sha256) &&
    identity.ollama_manifest_sha256 !== ALL_ZERO_SHA256 &&
    binding.runtime_tag === deriveOllamaRuntimeTag(identity);
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

function sameFileStat(left: ImmuneFileStat, right: ImmuneFileStat): boolean {
  return left.device === right.device && left.inode === right.inode &&
    left.size === right.size &&
    left.mtimeNanoseconds === right.mtimeNanoseconds;
}

function contained(rootReal: string, candidateReal: string): boolean {
  const rel = relative(rootReal, candidateReal);
  if (rel.length === 0 || isAbsolute(rel)) return false;
  return !rel.split(sep).some((component) => component === "..");
}

interface Candidate {
  readonly path: string;
  readonly pathStat: ImmuneFileStat;
}

async function state_ROOT(
  fs: ImmuneFileSystemAdapter,
  requestedRoot: string,
): Promise<string> {
  if (fs.platform === "win32" || fs.noFollowFlag === null) {
    refuse("immune_platform_unsupported");
  }
  if (!isAbsolute(requestedRoot) || resolve(requestedRoot) !== requestedRoot) {
    refuse("model_root_invalid");
  }
  try {
    const lexicalStat = await fs.lstat(requestedRoot);
    if (lexicalStat.isSymbolicLink) refuse("symlink_refused");
    if (!lexicalStat.isDirectory) refuse("model_root_invalid");
    const rootReal = await fs.realpath(requestedRoot);
    // The persisted root is authoritative only when it already names its real directory.
    if (!isAbsolute(rootReal) || rootReal !== requestedRoot) {
      refuse("model_root_invalid");
    }
    const realStat = await fs.lstat(rootReal);
    if (realStat.isSymbolicLink) refuse("symlink_refused");
    if (!realStat.isDirectory) refuse("model_root_invalid");
    return rootReal;
  } catch (error) {
    if (error instanceof ImmuneRefusal) throw error;
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
      refuse("model_root_invalid");
    }
    refuse("integrity_io_unavailable");
  }
}

async function state_PATH_COMPONENTS(
  fs: ImmuneFileSystemAdapter,
  rootReal: string,
  components: readonly string[],
  missingReason: "disk_manifest_invalid" | "layer_missing",
): Promise<Candidate> {
  if (
    components.length === 0 || components.some((component) =>
      component.length === 0 || component === "." || component === ".." ||
      component.includes("/") || component.includes("\\") || component.includes("\0")
    )
  ) {
    refuse("path_escape");
  }
  try {
    const rootStat = await fs.lstat(rootReal);
    if (rootStat.isSymbolicLink) refuse("symlink_refused");
    if (!rootStat.isDirectory) refuse("model_root_invalid");
  } catch (error) {
    if (error instanceof ImmuneRefusal) throw error;
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
      // A vanished/non-directory persisted root is structurally invalid; other
      // re-lstat failures are retryable I/O and must not occupy that slot.
      refuse("model_root_invalid");
    }
    refuse("integrity_io_unavailable");
  }
  let candidate = rootReal;
  let finalStat: ImmuneFileStat | undefined;
  for (let index = 0; index < components.length; index += 1) {
    candidate = join(candidate, components[index]!);
    const lexicalRelative = relative(rootReal, candidate);
    if (
      lexicalRelative.length === 0 || isAbsolute(lexicalRelative) ||
      lexicalRelative.split(sep).some((component) => component === "..")
    ) {
      refuse("path_escape");
    }
    try {
      finalStat = await fs.lstat(candidate);
    } catch (error) {
      if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
        refuse(missingReason);
      }
      refuse("integrity_io_unavailable");
    }
    if (finalStat.isSymbolicLink) refuse("symlink_refused");
    const final = index === components.length - 1;
    if (!final && !finalStat.isDirectory) refuse(missingReason);
    if (final && !finalStat.isFile) refuse(missingReason);
  }
  let candidateReal: string;
  try {
    candidateReal = await fs.realpath(candidate);
  } catch (error) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
      refuse(missingReason);
    }
    refuse("integrity_io_unavailable");
  }
  // Realpath containment catches mount/alias surprises after the lexical component walk.
  if (!contained(rootReal, candidateReal)) {
    refuse("path_escape");
  } else if (candidateReal !== candidate || finalStat === undefined) {
    // Once contained, a different real path still identifies a symlink/alias race.
    refuse("path_escape");
  }
  return { path: candidate, pathStat: finalStat };
}

interface StableRead {
  readonly bytesRead: number;
  readonly bytes?: Uint8Array;
}

interface StableReadOptions {
  readonly components: readonly string[];
  readonly missingReason: "disk_manifest_invalid" | "layer_missing";
  readonly expectedDigest: string;
  readonly digestMismatchReason:
    | "disk_manifest_digest_mismatch"
    | "layer_digest_mismatch";
  readonly expectedSize?: number;
  readonly maxBytes: number;
  readonly collectBytes: boolean;
}

async function readCandidateOnce(
  fs: ImmuneFileSystemAdapter,
  rootReal: string,
  options: StableReadOptions,
): Promise<StableRead | "unstable"> {
  const candidate = await state_PATH_COMPONENTS(
    fs,
    rootReal,
    options.components,
    options.missingReason,
  );
  let handle: ImmuneFileHandle;
  let pendingRefusal: ImmuneRefusal | undefined;
  try {
    // O_NOFOLLOW closes the final-component replacement gap left by the lstat walk.
    handle = await fs.open(
      candidate.path,
      fsConstants.O_RDONLY | (fs.noFollowFlag ?? refuse("immune_platform_unsupported")),
    );
  } catch (error) {
    if (error instanceof ImmuneRefusal) throw error;
    if (errorCode(error) === "ELOOP") refuse("symlink_refused");
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ENOTDIR") {
      refuse(options.missingReason);
    }
    refuse("integrity_io_unavailable");
  }

  try {
    const before = await handle.stat();
    if (!before.isFile || before.isSymbolicLink) refuse(options.missingReason);
    if (!sameFileStat(candidate.pathStat, before)) return "unstable";
    if (
      options.expectedSize !== undefined &&
      before.size !== BigInt(options.expectedSize)
    ) {
      refuse("layer_size_mismatch");
    }
    if (before.size > BigInt(options.maxBytes)) {
      refuse(options.expectedSize === undefined
        ? "disk_manifest_invalid"
        : "layer_size_mismatch");
    }

    const hash = createHash("sha256");
    const buffer = new Uint8Array(IMMUNE_HASH_BUFFER_BYTES);
    const chunks: Uint8Array[] = [];
    let position = 0;
    while (position < options.maxBytes) {
      const remaining = options.maxBytes - position;
      const length = Math.min(buffer.byteLength, remaining);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (!Number.isInteger(bytesRead) || bytesRead < 0 || bytesRead > length) {
        refuse("integrity_io_unavailable");
      }
      if (bytesRead === 0) break;
      const chunk = buffer.slice(0, bytesRead);
      hash.update(chunk);
      if (options.collectBytes) chunks.push(chunk);
      position += bytesRead;
    }

    const after = await handle.stat();
    let candidateAfter: Candidate;
    try {
      // Re-walking the whole chain catches an ancestor swapped after the first lstat pass.
      candidateAfter = await state_PATH_COMPONENTS(
        fs,
        rootReal,
        options.components,
        options.missingReason,
      );
    } catch (error) {
      if (
        error instanceof ImmuneRefusal &&
        error.reason === options.missingReason
      ) {
        return "unstable";
      }
      throw error;
    }
    if (
      !sameFileStat(before, after) ||
      !sameFileStat(after, candidateAfter.pathStat)
    ) {
      return "unstable";
    }
    if (
      options.expectedSize !== undefined &&
      position !== options.expectedSize
    ) {
      refuse("layer_size_mismatch");
    }
    if (options.expectedSize === undefined && position > IMMUNE_OCI_MANIFEST_MAX_BYTES) {
      refuse("disk_manifest_invalid");
    }
    let bytes: Uint8Array | undefined;
    if (options.collectBytes) {
      bytes = new Uint8Array(position);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
    }
    const digestHex = hash.digest("hex");
    if (!constantTimeDigestEqual(digestHex, options.expectedDigest)) {
      refuse(options.digestMismatchReason);
    }
    return bytes === undefined
      ? { bytesRead: position }
      : { bytesRead: position, bytes };
  } catch (error) {
    if (error instanceof ImmuneRefusal) pendingRefusal = error;
    throw error;
  } finally {
    // Descriptor ownership stays local so every success and refusal attempts closure.
    try {
      await handle.close();
    } catch {
      // Invariant: never let close put the wrong failure in the refusal slot.
      if (pendingRefusal === undefined) refuse("integrity_io_unavailable");
    }
  }
}

async function state_STABLE_FILE(
  fs: ImmuneFileSystemAdapter,
  rootReal: string,
  options: StableReadOptions,
): Promise<StableRead> {
  for (let attempt = 0; attempt < STABLE_FILE_MAX_ATTEMPTS; attempt += 1) {
    const result = await readCandidateOnce(fs, rootReal, options);
    if (result !== "unstable") return result;
  }
  refuse("unstable_file");
}

function constantTimeDigestEqual(left: string, right: string): boolean {
  if (!SHA256_HEX.test(left) || !SHA256_HEX.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function manifestComponents(identity: SignedOllamaIdentityV2): readonly string[] {
  const derived = deriveOllamaManifestRelativePath(identity);
  const components = derived.split("/");
  // state_PATH_COMPONENTS enforces every component from the shared Q5A derivation.
  return components;
}

export interface OnDiskImmuneVerifierOptions {
  readonly fs: ImmuneFileSystemAdapter;
  readonly clock?: Pick<ImmuneVerificationClock, "monotonicNow">;
}

/** Create the inert verifier; construction performs no filesystem operation. */
export function createOnDiskImmuneVerifier(
  options: OnDiskImmuneVerifierOptions,
): ImmuneDiskVerifier {
  const monotonicNow = options.clock?.monotonicNow ?? (() => performance.now());
  return {
    async verify(request) {
      try {
        if (!validBinding(request.binding)) refuse("binding_mismatch");
        const rootReal = await state_ROOT(options.fs, request.rootReal);
        const manifest = await state_STABLE_FILE(options.fs, rootReal, {
          components: manifestComponents(request.binding.ollama_identity),
          missingReason: "disk_manifest_invalid",
          expectedDigest: request.binding.ollama_identity.ollama_manifest_sha256,
          digestMismatchReason: "disk_manifest_digest_mismatch",
          maxBytes: IMMUNE_OCI_MANIFEST_OVERFLOW_READ_BYTES,
          collectBytes: true,
        });
        if (manifest.bytes === undefined) refuse("disk_manifest_invalid");
        const parsed = parseBoundedOciManifest(manifest.bytes);
        let bytesHashed = manifest.bytesRead;
        const verifiedArtifactDigests: string[] = [];
        for (const descriptor of parsed.distinctDescriptors) {
          const artifact = await state_STABLE_FILE(options.fs, rootReal, {
            components: ["blobs", `sha256-${descriptor.digestHex}`],
            missingReason: "layer_missing",
            expectedDigest: descriptor.digestHex,
            digestMismatchReason: "layer_digest_mismatch",
            expectedSize: descriptor.size,
            maxBytes: descriptor.size,
            collectBytes: false,
          });
          bytesHashed += artifact.bytesRead;
          verifiedArtifactDigests.push(descriptor.digestHex);
        }
        const completedAtMonotonicMs = monotonicNow();
        if (!Number.isFinite(completedAtMonotonicMs)) {
          refuse("integrity_io_unavailable");
        }
        return {
          ok: true,
          state: "immune_verified",
          runtimeTag: request.binding.runtime_tag,
          expectedManifestDigest:
            request.binding.ollama_identity.ollama_manifest_sha256,
          descriptorCount: parsed.distinctDescriptors.length,
          bytesHashed,
          verifiedArtifactDigests,
          completedAtMonotonicMs,
          cached: false,
        };
      } catch (error) {
        return failure(
          error instanceof ImmuneRefusal
            ? error.reason
            : "integrity_io_unavailable",
        );
      }
    },
  };
}

function verificationTupleKey(request: ImmuneVerificationRequest): string {
  const parts = [
    request.rootReal,
    request.binding.runtime_tag,
    request.binding.ollama_identity.ollama_manifest_sha256,
    request.binding.assurance,
  ];
  // Length-prefixing makes the reviewed four-field tuple collision-free.
  return parts.map((part) => `${part.length}:${part}`).join("");
}

interface CacheEntry {
  promise: Promise<ImmuneVerificationResult>;
  pending: boolean;
  invalidated: boolean;
  lastUsed: number;
  success?: Extract<ImmuneVerificationResult, { ok: true }>;
  completedWallMs?: number;
}

function clocksAreUsable(monotonicMs: number, wallMs: number): boolean {
  return Number.isFinite(monotonicMs) && Number.isFinite(wallMs) &&
    monotonicMs >= 0 && wallMs >= 0;
}

function cacheIsFresh(
  entry: CacheEntry,
  monotonicMs: number,
  wallMs: number,
): boolean {
  if (
    entry.invalidated || entry.success === undefined ||
    entry.completedWallMs === undefined ||
    !clocksAreUsable(monotonicMs, wallMs) ||
    !clocksAreUsable(entry.success.completedAtMonotonicMs, entry.completedWallMs)
  ) {
    return false;
  }
  const elapsed = monotonicMs - entry.success.completedAtMonotonicMs;
  // Clock rollback never extends trust; the next invocation must perform a full check.
  return elapsed >= 0 && wallMs >= entry.completedWallMs &&
    elapsed < IMMUNE_FULL_VERIFICATION_CADENCE_MS;
}

export interface CadencedImmuneVerifierOptions {
  readonly clock?: ImmuneVerificationClock;
}

/** Add reviewed cadence, LRU, invalidation, and per-tuple single-flight semantics. */
export function createCadencedImmuneDiskVerifier(
  delegate: ImmuneDiskVerifier,
  options: CadencedImmuneVerifierOptions = {},
): CadencedImmuneDiskVerifier {
  const clock: ImmuneVerificationClock = options.clock ?? {
    monotonicNow: () => performance.now(),
    wallNow: () => Date.now(),
  };
  const entries = new Map<string, CacheEntry>();
  let useSequence = 0;

  function evictSettledLru(): boolean {
    let oldestKey: string | undefined;
    let oldestUse = Number.POSITIVE_INFINITY;
    for (const [key, entry] of entries) {
      if (!entry.pending && entry.lastUsed < oldestUse) {
        oldestKey = key;
        oldestUse = entry.lastUsed;
      }
    }
    if (oldestKey === undefined) return false;
    entries.delete(oldestKey);
    return true;
  }

  return {
    get cacheSize() {
      return entries.size;
    },
    invalidate(request) {
      if (request === undefined) {
        for (const [key, entry] of entries) {
          entry.invalidated = true;
          if (!entry.pending) entries.delete(key);
        }
        return;
      }
      const key = verificationTupleKey(request);
      const entry = entries.get(key);
      if (entry === undefined) return;
      entry.invalidated = true;
      if (!entry.pending) entries.delete(key);
    },
    verify(request) {
      const key = verificationTupleKey(request);
      const existing = entries.get(key);
      if (existing?.pending) {
        existing.lastUsed = ++useSequence;
        return existing.promise;
      }
      const monotonicMs = clock.monotonicNow();
      const wallMs = clock.wallNow();
      if (
        request.checkpoint === "cadence" && existing !== undefined &&
        cacheIsFresh(existing, monotonicMs, wallMs)
      ) {
        existing.lastUsed = ++useSequence;
        const success = { ...existing.success!, cached: true };
        return Promise.resolve(success);
      }
      if (existing !== undefined) entries.delete(key);
      while (entries.size >= IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES) {
        if (!evictSettledLru()) {
          return Promise.resolve(failure("integrity_io_unavailable"));
        }
      }

      const entry: CacheEntry = {
        promise: Promise.resolve(failure("integrity_io_unavailable")),
        pending: true,
        invalidated: false,
        lastUsed: ++useSequence,
      };
      const pending = Promise.resolve()
        .then(() => delegate.verify(request))
        .catch(() => failure("integrity_io_unavailable"))
        .then((result): ImmuneVerificationResult => {
          entry.pending = false;
          if (entry.invalidated) {
            if (entries.get(key) === entry) entries.delete(key);
            return failure("binding_mismatch");
          }
          if (!result.ok) {
            // Failures never publish a reusable success timestamp.
            if (entries.get(key) === entry) entries.delete(key);
            return result;
          }
          const completedAtMonotonicMs = clock.monotonicNow();
          const completedWallMs = clock.wallNow();
          if (!clocksAreUsable(completedAtMonotonicMs, completedWallMs)) {
            if (entries.get(key) === entry) entries.delete(key);
            return failure("integrity_io_unavailable");
          }
          entry.success = {
            ...result,
            completedAtMonotonicMs,
            cached: false,
          };
          entry.completedWallMs = completedWallMs;
          return entry.success;
        });
      entry.promise = pending;
      entries.set(key, entry);
      return pending;
    },
  };
}
