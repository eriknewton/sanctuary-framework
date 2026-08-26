import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  mkdir,
  mkdtemp,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as intelligence from "../../src/intelligence/index.js";
import {
  IMMUNE_FULL_VERIFICATION_CADENCE_MS,
  IMMUNE_HASH_BUFFER_BYTES,
  IMMUNE_HASH_MAX_BUFFER_BYTES,
  IMMUNE_OCI_MANIFEST_MAX_BYTES,
  IMMUNE_OCI_MAX_DESCRIPTOR_BYTES,
  IMMUNE_OCI_MAX_LAYERS,
  IMMUNE_OCI_MAX_TOTAL_DESCRIPTOR_BYTES,
  IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES,
  createCadencedImmuneDiskVerifier,
  createNodeImmuneFileSystemAdapter,
  createOnDiskImmuneVerifier,
  parseBoundedOciManifest,
  type ImmuneDiskVerifier,
  type ImmuneFileHandle,
  type ImmuneFileSystemAdapter,
  type ImmuneVerificationRequest,
  type ImmuneVerificationResult,
} from "../../src/intelligence/immune-disk-verifier.js";
import type { VerifiedLocalBindingV2 } from "../../src/intelligence/model-manifest-v2.js";

const roots: string[] = [];
const CONFIG_BYTES = Buffer.from('{"model_format":"gguf"}');
const LAYER_A_BYTES = Buffer.from("authenticated-layer-a");
const LAYER_B_BYTES = Buffer.from("authenticated-layer-b");
const SIX_HOURS = IMMUNE_FULL_VERIFICATION_CADENCE_MS;

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function descriptor(bytes: Uint8Array, mediaType: string) {
  return { mediaType, digest: `sha256:${digest(bytes)}`, size: bytes.byteLength };
}

function manifestValue() {
  return {
    schemaVersion: 2,
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    config: descriptor(CONFIG_BYTES, "application/vnd.ollama.image.config"),
    layers: [
      descriptor(LAYER_A_BYTES, "application/vnd.ollama.image.model"),
      descriptor(LAYER_B_BYTES, "application/vnd.ollama.image.adapter"),
    ],
  };
}

function binding(manifestDigest: string): VerifiedLocalBindingV2 {
  return {
    model_id: "qwen2.5-1.5b",
    runtime_tag: "qwen2.5:1.5b",
    ollama_identity: {
      registry: "registry.ollama.ai",
      namespace: "library",
      model: "qwen2.5",
      tag: "1.5b",
      ollama_manifest_sha256: manifestDigest,
    },
    assurance: "immune",
    manifest_version: 9,
  };
}

interface Fixture {
  root: string;
  request: ImmuneVerificationRequest;
  manifestPath: string;
  blobPaths: Map<string, string>;
  manifestBytes: Buffer;
}

async function fixture(
  value: unknown = manifestValue(),
  artifactBytes: ReadonlyMap<string, Uint8Array> = new Map([
    [digest(CONFIG_BYTES), CONFIG_BYTES],
    [digest(LAYER_A_BYTES), LAYER_A_BYTES],
    [digest(LAYER_B_BYTES), LAYER_B_BYTES],
  ]),
): Promise<Fixture> {
  const parent = await mkdtemp(join(tmpdir(), "sanctuary-q5c-"));
  roots.push(parent);
  const root = await createNodeImmuneFileSystemAdapter().realpath(parent);
  const manifestPath = join(
    root,
    "manifests",
    "registry.ollama.ai",
    "library",
    "qwen2.5",
    "1.5b",
  );
  await mkdir(join(manifestPath, ".."), { recursive: true });
  await mkdir(join(root, "blobs"), { recursive: true });
  const manifestBytes = Buffer.from(JSON.stringify(value));
  await writeFile(manifestPath, manifestBytes);
  const blobPaths = new Map<string, string>();
  for (const [artifactDigest, bytes] of artifactBytes) {
    const path = join(root, "blobs", `sha256-${artifactDigest}`);
    await writeFile(path, bytes);
    blobPaths.set(artifactDigest, path);
  }
  return {
    root,
    request: {
      rootReal: root,
      binding: binding(digest(manifestBytes)),
      checkpoint: "selector_load",
    },
    manifestPath,
    blobPaths,
    manifestBytes,
  };
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function verifier(fs = createNodeImmuneFileSystemAdapter()) {
  return createOnDiskImmuneVerifier({ fs, clock: { monotonicNow: () => 42 } });
}

function expectReason(
  result: ImmuneVerificationResult,
  reason: Exclude<ImmuneVerificationResult, { ok: true }>["reason"],
) {
  expect(result).toEqual({ ok: false, state: "immune_refused", reason });
}

function wrapFs(
  base: ImmuneFileSystemAdapter,
  overrides: Partial<ImmuneFileSystemAdapter>,
): ImmuneFileSystemAdapter {
  return {
    platform: overrides.platform ?? base.platform,
    noFollowFlag: overrides.noFollowFlag === undefined
      ? base.noFollowFlag
      : overrides.noFollowFlag,
    realpath: overrides.realpath ?? ((path) => base.realpath(path)),
    lstat: overrides.lstat ?? ((path) => base.lstat(path)),
    open: overrides.open ?? ((path, flags) => base.open(path, flags)),
  };
}

describe("Q5C bounded OCI manifest parser", () => {
  it("exports the inert Q5C surface through the intelligence barrel", () => {
    expect(intelligence.createOnDiskImmuneVerifier).toBe(createOnDiskImmuneVerifier);
    expect(intelligence.createCadencedImmuneDiskVerifier).toBe(
      createCadencedImmuneDiskVerifier,
    );
    expect(IMMUNE_HASH_BUFFER_BYTES).toBeLessThanOrEqual(IMMUNE_HASH_MAX_BUFFER_BYTES);
  });

  it("parses config and layers and deduplicates one identical content address", () => {
    const value = manifestValue();
    value.layers.push({ ...value.config });
    const parsed = parseBoundedOciManifest(Buffer.from(JSON.stringify(value)));
    expect(parsed.layers).toHaveLength(3);
    expect(parsed.distinctDescriptors).toHaveLength(3);
    expect(parsed.totalDescriptorBytes).toBe(
      CONFIG_BYTES.byteLength * 2 + LAYER_A_BYTES.byteLength + LAYER_B_BYTES.byteLength,
    );
  });

  it.each([
    ["missing config", { schemaVersion: 2, layers: [descriptor(LAYER_A_BYTES, "x")] }],
    ["wrong schema", { ...manifestValue(), schemaVersion: 1 }],
    ["malformed descriptor", { ...manifestValue(), config: { digest: `sha256:${digest(CONFIG_BYTES)}`, size: CONFIG_BYTES.length } }],
    ["uppercase digest", { ...manifestValue(), config: { ...descriptor(CONFIG_BYTES, "x"), digest: `sha256:${digest(CONFIG_BYTES).toUpperCase()}` } }],
    ["non-ASCII media type", { ...manifestValue(), config: descriptor(CONFIG_BYTES, "application/☃") }],
    ["descriptor authority extension", { ...manifestValue(), config: { ...descriptor(CONFIG_BYTES, "x"), path: "../../escape" } }],
  ])("refuses %s as disk_manifest_invalid", (_label, value) => {
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify(value))))
      .toThrow("disk_manifest_invalid");
  });

  it("refuses duplicate and prototype keys through the shared strict parser", () => {
    const valid = JSON.stringify(manifestValue());
    expect(() => parseBoundedOciManifest(Buffer.from(
      valid.replace('"schemaVersion":2', '"schemaVersion":2,"schemaVersion":2'),
    ))).toThrow("disk_manifest_invalid");
    expect(() => parseBoundedOciManifest(Buffer.from(
      valid.replace('"schemaVersion":2', '"__proto__":{},"schemaVersion":2'),
    ))).toThrow("disk_manifest_invalid");
  });

  it("accepts an exact-cap manifest and rejects the cap-plus-one byte", () => {
    const encoded = Buffer.from(JSON.stringify(manifestValue()));
    const exactCap = Buffer.concat([
      encoded,
      Buffer.alloc(IMMUNE_OCI_MANIFEST_MAX_BYTES - encoded.byteLength, 0x20),
    ]);
    expect(parseBoundedOciManifest(exactCap).layers).toHaveLength(2);
    expect(() => parseBoundedOciManifest(Buffer.concat([exactCap, Buffer.from(" ")])))
      .toThrow("disk_manifest_invalid");
  });

  it("refuses layer-count, per-descriptor, aggregate, and manifest byte bounds", () => {
    const one = descriptor(new Uint8Array(), "x");
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify({
      schemaVersion: 2,
      config: one,
      layers: [],
    })))).toThrow("descriptor_bounds_exceeded");
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify({
      schemaVersion: 2,
      config: one,
      layers: Array.from({ length: IMMUNE_OCI_MAX_LAYERS + 1 }, () => one),
    })))).toThrow("descriptor_bounds_exceeded");
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify({
      schemaVersion: 2,
      config: { ...one, size: IMMUNE_OCI_MAX_DESCRIPTOR_BYTES + 1 },
      layers: [one],
    })))).toThrow("descriptor_bounds_exceeded");
    const huge = { ...one, size: IMMUNE_OCI_MAX_DESCRIPTOR_BYTES };
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify({
      schemaVersion: 2,
      config: huge,
      layers: Array.from({ length: 4 }, () => huge),
    })))).toThrow("descriptor_bounds_exceeded");
    expect(IMMUNE_OCI_MAX_DESCRIPTOR_BYTES * 5).toBeGreaterThan(
      IMMUNE_OCI_MAX_TOTAL_DESCRIPTOR_BYTES,
    );
    expect(() => parseBoundedOciManifest(
      new Uint8Array(IMMUNE_OCI_MANIFEST_MAX_BYTES + 1),
    )).toThrow("disk_manifest_invalid");
  });

  it("refuses a duplicate digest with conflicting size or media type", () => {
    const value = manifestValue();
    value.layers.push({ ...value.config, size: value.config.size + 1 });
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify(value))))
      .toThrow("disk_manifest_invalid");
    value.layers[value.layers.length - 1] = { ...value.config, mediaType: "other/type" };
    expect(() => parseBoundedOciManifest(Buffer.from(JSON.stringify(value))))
      .toThrow("disk_manifest_invalid");
  });
});

describe("Q5C descriptor-based on-disk verification", () => {
  it("hashes the byte-exact manifest, config, and every distinct real layer", async () => {
    const store = await fixture();
    const base = createNodeImmuneFileSystemAdapter();
    const opened: Array<{ path: string; flags: number }> = [];
    const fs = wrapFs(base, {
      async open(path, flags) {
        opened.push({ path, flags });
        return base.open(path, flags);
      },
    });
    const result = await verifier(fs).verify(store.request);
    expect(result).toMatchObject({
      ok: true,
      descriptorCount: 3,
      cached: false,
      completedAtMonotonicMs: 42,
    });
    expect(result.ok && result.bytesHashed).toBe(
      store.manifestBytes.length + CONFIG_BYTES.length +
        LAYER_A_BYTES.length + LAYER_B_BYTES.length,
    );
    expect(new Set(opened.map(({ path }) => path))).toEqual(new Set([
      store.manifestPath,
      ...store.blobPaths.values(),
    ]));
    expect(opened.every(({ flags }) =>
      (flags & fsConstants.O_NOFOLLOW) !== 0 &&
      (flags & (fsConstants.O_WRONLY | fsConstants.O_RDWR)) === 0
    )).toBe(true);
  });

  it("hashes an identical duplicate descriptor exactly once", async () => {
    const value = manifestValue();
    value.layers.push({ ...value.config });
    const store = await fixture(value);
    const base = createNodeImmuneFileSystemAdapter();
    const opens: string[] = [];
    const result = await verifier(wrapFs(base, {
      async open(path, flags) {
        opens.push(path);
        return base.open(path, flags);
      },
    })).verify(store.request);
    expect(result).toMatchObject({ ok: true, descriptorCount: 3 });
    expect(opens.filter((path) => path === store.blobPaths.get(digest(CONFIG_BYTES))))
      .toHaveLength(1);
  });

  it("refuses byte mutation of the manifest before parsing", async () => {
    const store = await fixture();
    await writeFile(store.manifestPath, Buffer.from(store.manifestBytes.toString().replace(
      "application/vnd.ollama.image.adapter",
      "application/vnd.ollama.image.changed",
    )));
    expectReason(await verifier().verify(store.request), "disk_manifest_digest_mismatch");
  });

  it("refuses one mutated layer under its unchanged digest filename", async () => {
    const store = await fixture();
    const layerPath = store.blobPaths.get(digest(LAYER_A_BYTES))!;
    await writeFile(layerPath, Buffer.from("substituted-layer-aaa"));
    expectReason(await verifier().verify(store.request), "layer_digest_mismatch");
  });

  it("refuses missing descriptors and authenticated size mismatches", async () => {
    const missing = await fixture();
    await unlink(missing.blobPaths.get(digest(LAYER_B_BYTES))!);
    expectReason(await verifier().verify(missing.request), "layer_missing");

    const wrongSize = await fixture();
    await writeFile(wrongSize.blobPaths.get(digest(LAYER_A_BYTES))!, "short");
    expectReason(await verifier().verify(wrongSize.request), "layer_size_mismatch");
  });

  it("refuses a non-regular descriptor and a premature descriptor EOF", async () => {
    const nonRegular = await fixture();
    const nonRegularPath = nonRegular.blobPaths.get(digest(LAYER_A_BYTES))!;
    await rm(nonRegularPath);
    await mkdir(nonRegularPath);
    expectReason(await verifier().verify(nonRegular.request), "layer_missing");

    const premature = await fixture();
    const target = premature.blobPaths.get(digest(LAYER_A_BYTES))!;
    const base = createNodeImmuneFileSystemAdapter();
    const fs = wrapFs(base, {
      async open(path, flags) {
        const handle = await base.open(path, flags);
        if (path !== target) return handle;
        return {
          ...handle,
          async read() {
            return { bytesRead: 0 };
          },
        } satisfies ImmuneFileHandle;
      },
    });
    expectReason(await verifier(fs).verify(premature.request), "layer_size_mismatch");
  });

  it("refuses a manifest larger than one MiB before JSON parsing", async () => {
    const store = await fixture();
    const oversized = Buffer.alloc(IMMUNE_OCI_MANIFEST_MAX_BYTES + 1, 0x20);
    await writeFile(store.manifestPath, oversized);
    store.request.binding.ollama_identity.ollama_manifest_sha256 = digest(oversized);
    expectReason(await verifier().verify(store.request), "disk_manifest_invalid");
  });

  it.each(["..", "/absolute", "with/slash", "with\\backslash", "nul\0byte", "snowman☃", "encoded%2fslash"])(
    "refuses unverified identity component %j before filesystem I/O",
    async (model) => {
      const base = createNodeImmuneFileSystemAdapter();
      const reads = vi.fn(base.lstat);
      const request: ImmuneVerificationRequest = {
        rootReal: "/not-read",
        binding: binding("a".repeat(64)),
        checkpoint: "selector_load",
      };
      request.binding.ollama_identity.model = model;
      expectReason(await verifier(wrapFs(base, { lstat: reads })).verify(request), "binding_mismatch");
      expect(reads).not.toHaveBeenCalled();
    },
  );

  it("refuses invalid roots and unsupported no-follow/platform support before opening", async () => {
    const store = await fixture();
    const base = createNodeImmuneFileSystemAdapter();
    const opens = vi.fn(base.open);
    expectReason(await verifier(wrapFs(base, { platform: "win32", open: opens }))
      .verify(store.request), "immune_platform_unsupported");
    expectReason(await verifier(wrapFs(base, { noFollowFlag: null, open: opens }))
      .verify(store.request), "immune_platform_unsupported");
    expect(opens).not.toHaveBeenCalled();
    expectReason(await verifier().verify({ ...store.request, rootReal: "relative/root" }), "model_root_invalid");
  });

  it("refuses a light binding before any disk read", async () => {
    const store = await fixture();
    const base = createNodeImmuneFileSystemAdapter();
    const reads = vi.fn(base.lstat);
    store.request.binding.assurance = "light";
    expectReason(
      await verifier(wrapFs(base, { lstat: reads })).verify(store.request),
      "binding_mismatch",
    );
    expect(reads).not.toHaveBeenCalled();
  });

  it.each(["root", "intermediate", "manifest", "blob"])(
    "refuses a %s symlink",
    async (kind) => {
      const store = await fixture();
      let request = store.request;
      if (kind === "root") {
        const linked = `${store.root}-link`;
        roots.push(linked);
        await symlink(store.root, linked);
        request = { ...request, rootReal: linked };
      } else if (kind === "intermediate") {
        const manifests = join(store.root, "manifests");
        const moved = join(store.root, "manifests-real");
        await rename(manifests, moved);
        await symlink(moved, manifests);
      } else if (kind === "manifest") {
        const target = `${store.manifestPath}.real`;
        await rename(store.manifestPath, target);
        await symlink(target, store.manifestPath);
      } else {
        const blobPath = store.blobPaths.get(digest(LAYER_A_BYTES))!;
        const target = `${blobPath}.real`;
        await rename(blobPath, target);
        await symlink(target, blobPath);
      }
      expectReason(await verifier().verify(request), "symlink_refused");
    },
  );

  it("refuses a realpath candidate reported outside the root", async () => {
    const store = await fixture();
    const base = createNodeImmuneFileSystemAdapter();
    const fs = wrapFs(base, {
      async realpath(path) {
        if (path === store.manifestPath) return join(store.root, "..", "outside-manifest");
        return base.realpath(path);
      },
    });
    expectReason(await verifier(fs).verify(store.request), "path_escape");
  });

  it("retries once and then refuses repeated final-file replacement as unstable", async () => {
    const store = await fixture();
    const target = store.blobPaths.get(digest(LAYER_A_BYTES))!;
    const base = createNodeImmuneFileSystemAdapter();
    let replacements = 0;
    const fs = wrapFs(base, {
      async open(path, flags) {
        const handle = await base.open(path, flags);
        if (path !== target) return handle;
        let firstRead = true;
        return {
          ...handle,
          async read(buffer, offset, length, position) {
            if (firstRead) {
              firstRead = false;
              replacements += 1;
              const replacement = `${target}.replacement-${replacements}`;
              await writeFile(replacement, LAYER_A_BYTES);
              await rename(replacement, target);
            }
            return handle.read(buffer, offset, length, position);
          },
        } satisfies ImmuneFileHandle;
      },
    });
    expectReason(await verifier(fs).verify(store.request), "unstable_file");
    expect(replacements).toBe(2);
  });

  it("recovers after one stable-file retry when the replacement then stops", async () => {
    const store = await fixture();
    const target = store.blobPaths.get(digest(LAYER_A_BYTES))!;
    const base = createNodeImmuneFileSystemAdapter();
    let replacements = 0;
    const fs = wrapFs(base, {
      async open(path, flags) {
        const handle = await base.open(path, flags);
        if (path !== target || replacements > 0) return handle;
        let firstRead = true;
        return {
          ...handle,
          async read(buffer, offset, length, position) {
            if (firstRead) {
              firstRead = false;
              replacements += 1;
              const replacement = `${target}.one-replacement`;
              await writeFile(replacement, LAYER_A_BYTES);
              await rename(replacement, target);
            }
            return handle.read(buffer, offset, length, position);
          },
        } satisfies ImmuneFileHandle;
      },
    });
    await expect(verifier(fs).verify(store.request)).resolves.toMatchObject({ ok: true });
    expect(replacements).toBe(1);
  });

  it("refuses an intermediate directory changed to a symlink during hashing", async () => {
    const store = await fixture();
    const target = store.blobPaths.get(digest(LAYER_A_BYTES))!;
    const blobs = join(store.root, "blobs");
    const movedBlobs = join(store.root, "blobs-moved-during-read");
    const base = createNodeImmuneFileSystemAdapter();
    let replaced = false;
    const fs = wrapFs(base, {
      async open(path, flags) {
        const handle = await base.open(path, flags);
        if (path !== target) return handle;
        return {
          ...handle,
          async read(buffer, offset, length, position) {
            if (!replaced) {
              replaced = true;
              await rename(blobs, movedBlobs);
              await symlink(movedBlobs, blobs);
            }
            return handle.read(buffer, offset, length, position);
          },
        } satisfies ImmuneFileHandle;
      },
    });
    expectReason(await verifier(fs).verify(store.request), "symlink_refused");
    expect(replaced).toBe(true);
  });

  it("closes descriptors on success, parse refusal, mismatch, and thrown read I/O", async () => {
    for (const mode of ["success", "parse", "mismatch", "timeout"] as const) {
      const store = await fixture();
      if (mode === "parse") {
        const invalid = Buffer.from('{"schemaVersion":2,"config":null,"layers":[null]}');
        await writeFile(store.manifestPath, invalid);
        store.request.binding.ollama_identity.ollama_manifest_sha256 = digest(invalid);
      }
      if (mode === "mismatch") {
        await writeFile(store.blobPaths.get(digest(LAYER_A_BYTES))!, "substituted-layer-aaa");
      }
      const base = createNodeImmuneFileSystemAdapter();
      let opened = 0;
      let closed = 0;
      const fs = wrapFs(base, {
        async open(path, flags) {
          opened += 1;
          const handle = await base.open(path, flags);
          return {
            ...handle,
            async read(buffer, offset, length, position) {
              if (mode === "timeout" && path.includes("/blobs/")) {
                throw new Error("injected timeout");
              }
              return handle.read(buffer, offset, length, position);
            },
            async close() {
              closed += 1;
              await handle.close();
            },
          } satisfies ImmuneFileHandle;
        },
      });
      const result = await verifier(fs).verify(store.request);
      if (mode === "success") expect(result.ok).toBe(true);
      if (mode === "parse") expectReason(result, "disk_manifest_invalid");
      if (mode === "mismatch") expectReason(result, "layer_digest_mismatch");
      if (mode === "timeout") expectReason(result, "integrity_io_unavailable");
      expect(closed, mode).toBe(opened);
    }
  });
});

function successfulResult(runtimeTag = "qwen2.5:1.5b"): ImmuneVerificationResult {
  return {
    ok: true,
    state: "immune_verified",
    runtimeTag,
    expectedManifestDigest: "a".repeat(64),
    descriptorCount: 3,
    bytesHashed: 99,
    verifiedArtifactDigests: ["b".repeat(64)],
    completedAtMonotonicMs: 0,
    cached: false,
  };
}

function cacheRequest(index = 0, checkpoint: ImmuneVerificationRequest["checkpoint"] = "cadence") {
  const request: ImmuneVerificationRequest = {
    rootReal: `/store/${index}`,
    binding: binding("a".repeat(64)),
    checkpoint,
  };
  return request;
}

function deferred<T>() {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

describe("Q5C cadence and single-flight fault schedules", () => {
  it("coalesces concurrent due calls and lets no waiter finish before the hash pass", async () => {
    const gate = deferred<ImmuneVerificationResult>();
    const delegate = { verify: vi.fn(() => gate.promise) };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    const request = cacheRequest(0, "selector_load");
    const calls = Array.from({ length: 12 }, () => cached.verify(request));
    let finished = 0;
    calls.forEach((call) => void call.then(() => { finished += 1; }));
    await Promise.resolve();
    expect(delegate.verify).toHaveBeenCalledTimes(1);
    expect(finished).toBe(0);
    gate.resolve(successfulResult());
    await expect(Promise.all(calls)).resolves.toHaveLength(12);
    expect(finished).toBe(12);
  });

  it("retries after failure and rejected delegates without publishing stale success", async () => {
    const delegate: ImmuneDiskVerifier = {
      verify: vi.fn()
        .mockRejectedValueOnce(new Error("detached failure"))
        .mockResolvedValueOnce(successfulResult()),
    };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    expectReason(await cached.verify(cacheRequest()), "integrity_io_unavailable");
    await expect(cached.verify(cacheRequest())).resolves.toMatchObject({ ok: true });
    expect(delegate.verify).toHaveBeenCalledTimes(2);
  });

  it("reuses only cadence success before six hours and forces named checkpoints", async () => {
    let monotonic = 100;
    let wall = 1_000;
    const delegate = { verify: vi.fn(async () => successfulResult()) };
    const cached = createCadencedImmuneDiskVerifier(delegate, {
      clock: { monotonicNow: () => monotonic, wallNow: () => wall },
    });
    const cadence = cacheRequest();
    await expect(cached.verify(cadence)).resolves.toMatchObject({ cached: false });
    monotonic += SIX_HOURS - 1;
    wall += SIX_HOURS - 1;
    await expect(cached.verify(cadence)).resolves.toMatchObject({ cached: true });
    await cached.verify({ ...cadence, checkpoint: "selector_load" });
    await cached.verify({ ...cadence, checkpoint: "first_invocation" });
    expect(delegate.verify).toHaveBeenCalledTimes(3);
    monotonic += SIX_HOURS;
    wall += SIX_HOURS;
    await expect(cached.verify(cadence)).resolves.toMatchObject({ cached: false });
    expect(delegate.verify).toHaveBeenCalledTimes(4);
  });

  it("makes wall-clock or monotonic rollback and invalid clocks due immediately", async () => {
    let monotonic = 100;
    let wall = 1_000;
    const delegate = { verify: vi.fn(async () => successfulResult()) };
    const cached = createCadencedImmuneDiskVerifier(delegate, {
      clock: { monotonicNow: () => monotonic, wallNow: () => wall },
    });
    const request = cacheRequest();
    await cached.verify(request);
    wall -= 1;
    await cached.verify(request);
    monotonic -= 1;
    wall += 2;
    await cached.verify(request);
    monotonic = Number.NaN;
    expectReason(await cached.verify(request), "integrity_io_unavailable");
    expect(delegate.verify).toHaveBeenCalledTimes(4);
  });

  it("invalidates a delayed completion without detaching or republishing it", async () => {
    const first = deferred<ImmuneVerificationResult>();
    const delegate = { verify: vi.fn()
      .mockImplementationOnce(() => first.promise)
      .mockResolvedValueOnce(successfulResult()) };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    const request = cacheRequest();
    const pending = cached.verify(request);
    await Promise.resolve();
    cached.invalidate(request);
    const concurrent = cached.verify(request);
    expect(delegate.verify).toHaveBeenCalledTimes(1);
    first.resolve(successfulResult());
    expectReason(await pending, "binding_mismatch");
    expectReason(await concurrent, "binding_mismatch");
    await expect(cached.verify(request)).resolves.toMatchObject({ ok: true, cached: false });
    expect(delegate.verify).toHaveBeenCalledTimes(2);
  });

  it("caps 32 pending tuples, then admits repeated waves after settlement", async () => {
    const gates: Array<ReturnType<typeof deferred<ImmuneVerificationResult>>> = [];
    const delegate = { verify: vi.fn(() => {
      const gate = deferred<ImmuneVerificationResult>();
      gates.push(gate);
      return gate.promise;
    }) };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    for (let wave = 0; wave < 3; wave += 1) {
      const offset = wave * IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES;
      const pending = Array.from(
        { length: IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES },
        (_, index) => cached.verify(cacheRequest(offset + index, "selector_load")),
      );
      await Promise.resolve();
      expect(cached.cacheSize).toBe(IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES);
      expectReason(
        await cached.verify(cacheRequest(offset + IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES)),
        "integrity_io_unavailable",
      );
      gates.splice(0).forEach((gate) => gate.resolve(successfulResult()));
      await Promise.all(pending);
    }
    expect(delegate.verify).toHaveBeenCalledTimes(
      3 * IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES,
    );
  });

  it("evicts only settled least-recently-used entries at the 32-entry cap", async () => {
    const delegate = { verify: vi.fn(async () => successfulResult()) };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    for (let index = 0; index < IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES; index += 1) {
      await cached.verify(cacheRequest(index));
    }
    await expect(cached.verify(cacheRequest(0))).resolves.toMatchObject({ cached: true });
    await cached.verify(cacheRequest(IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES));
    expect(cached.cacheSize).toBe(IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES);
    await cached.verify(cacheRequest(1));
    expect(delegate.verify).toHaveBeenCalledTimes(
      IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES + 2,
    );
  });

  it("keys flights on root, runtime tag, expected digest, and assurance", async () => {
    const gates: Array<ReturnType<typeof deferred<ImmuneVerificationResult>>> = [];
    const delegate = { verify: vi.fn(() => {
      const gate = deferred<ImmuneVerificationResult>();
      gates.push(gate);
      return gate.promise;
    }) };
    const cached = createCadencedImmuneDiskVerifier(delegate);
    const base = cacheRequest();
    const changedRoot = { ...base, rootReal: "/other-root" };
    const changedTag = structuredClone(base);
    changedTag.binding.runtime_tag = "other:tag";
    const changedDigest = structuredClone(base);
    changedDigest.binding.ollama_identity.ollama_manifest_sha256 = "b".repeat(64);
    const changedAssurance = structuredClone(base);
    changedAssurance.binding.assurance = "light";
    const pending = [base, changedRoot, changedTag, changedDigest, changedAssurance]
      .map((request) => cached.verify(request));
    await Promise.resolve();
    expect(delegate.verify).toHaveBeenCalledTimes(5);
    gates.forEach((gate) => gate.resolve(successfulResult()));
    await Promise.all(pending);
  });
});
