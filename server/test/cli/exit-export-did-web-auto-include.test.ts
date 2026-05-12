/**
 * WP-V1.x-RECOGNITION-LAYER Path C primary build 3:
 * exit-bundle export CLI auto-inclusion regression suite.
 *
 * Drives `sanctuary exit export` end-to-end against a real
 * FilesystemStorage-backed fortress on disk. Verifies that the
 * fortress-config record persisted by `did-web issue` (build 1) is
 * automatically embedded in the exit-bundle manifest without
 * requiring any --did-web flag.
 *
 * Coverage:
 *   - Auto-include happy path: registered fortress + export with no
 *     did:web flags → manifest carries identity_binding.did_web.
 *   - No record + no flags → manifest carries no did:web binding;
 *     stdout surfaces the "register" hint.
 *   - --no-did-web explicit opt-out: registered fortress + opt-out
 *     → manifest omits did:web binding; stdout reports the opt-out.
 *   - --include-did-web=false legacy opt-out: same outcome as
 *     --no-did-web (forward-compat alias from build 2).
 *   - --did-web CLI override: registered fortress + explicit
 *     identifier → manifest carries the OVERRIDE values, not the
 *     registered ones (CLI flags strictly take precedence).
 *   - Per-fortress isolation: two distinct storage paths carry two
 *     distinct registered identifiers; each export embeds its own
 *     fortress's identifier (no cross-leak).
 *
 * Test discipline:
 *   - Real FilesystemStorage, real Argon2id passphrase derivation,
 *     real Ed25519 identity creation. No mocks.
 *   - SANCTUARY_STORAGE_PATH is set via process.env (the path
 *     loadConfig() reads). Each test isolates its own tmp fortress
 *     and restores the env var in afterEach.
 *   - --yes flag short-circuits the Tier 1 stdin prompt.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";

import { runExitCommand } from "../../src/exit/cli.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  deriveMasterKey,
  derivePurposeKey,
} from "../../src/core/key-derivation.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { createIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/l1-cognitive/tools.js";
import type { FortressDidWebRecord } from "../../src/recognition/did-web.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";

// ── Test scaffolding ─────────────────────────────────────────────────

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

const TEST_PASSPHRASE = "correct-horse-battery-staple-build-3";

interface BootstrappedFortress {
  storagePath: string;
  identityId: string;
}

async function bootstrapFortress(): Promise<BootstrappedFortress> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-cli-build3-"));
  const stateStoragePath = join(storagePath, "state");
  await mkdir(stateStoragePath, { recursive: true, mode: 0o700 });

  const storage = new FilesystemStorage(stateStoragePath);
  const { key: masterKey, params } = await deriveMasterKey(TEST_PASSPHRASE);
  await storage.write(
    "_meta",
    "key-params",
    stringToBytes(JSON.stringify(params)),
  );

  const identityMgr = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { publicIdentity, storedIdentity } = createIdentity(
    "fortress-default",
    identityEncKey,
    "passphrase",
  );
  await identityMgr.save(storedIdentity);

  return { storagePath, identityId: publicIdentity.identity_id };
}

async function writeDidWebRecord(
  storagePath: string,
  record: FortressDidWebRecord,
): Promise<void> {
  const dir = join(storagePath, "recognition");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(join(dir, "did-web.json"), JSON.stringify(record, null, 2));
}

function sampleRecord(opts: {
  did: string;
  authority_host: string;
  fortress_id: string;
}): FortressDidWebRecord {
  return {
    version: 1,
    identifier: {
      did: opts.did,
      created_at: "2026-05-09T12:00:00.000Z",
      authority_host: opts.authority_host,
      fortress_id: opts.fortress_id,
      did_document: {
        "@context": [
          "https://www.w3.org/ns/did/v1",
          "https://w3id.org/security/suites/jws-2020/v1",
        ],
        id: opts.did,
        verificationMethod: [
          {
            id: `${opts.did}#key-1`,
            type: "JsonWebKey2020",
            controller: opts.did,
            publicKeyJwk: {
              kty: "OKP",
              crv: "Ed25519",
              x: "AAAA",
            },
          },
        ],
        authentication: [`${opts.did}#key-1`],
        assertionMethod: [`${opts.did}#key-1`],
      },
    },
    artifact: {
      url: `https://${opts.authority_host}/.well-known/did.json`,
      publish_path: "/.well-known/did.json",
      sha256:
        "0000000000000000000000000000000000000000000000000000000000000000",
    },
  };
}

async function readManifest(bundleDir: string): Promise<ExitBundleManifest> {
  const raw = await readFile(join(bundleDir, "manifest.json"), "utf8");
  return JSON.parse(raw) as ExitBundleManifest;
}

// ── Tests ───────────────────────────────────────────────────────────

describe("sanctuary exit export — did:web auto-inclusion (build 3)", () => {
  let originalEnvStoragePath: string | undefined;
  const cleanup: Array<() => Promise<void>> = [];

  beforeEach(() => {
    originalEnvStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  });

  afterEach(async () => {
    if (originalEnvStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalEnvStoragePath;
    }
    for (const fn of cleanup.splice(0)) {
      await fn();
    }
  });

  function registerCleanup(path: string): void {
    cleanup.push(async () => {
      await rm(path, { recursive: true, force: true });
    });
  }

  it("auto-includes the registered did:web identifier when no flags are passed", async () => {
    const fortress = await bootstrapFortress();
    registerCleanup(fortress.storagePath);
    const record = sampleRecord({
      did: "did:web:alice.example.com",
      authority_host: "alice.example.com",
      fortress_id: fortress.identityId,
    });
    await writeDidWebRecord(fortress.storagePath, record);

    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-auto-"));
    registerCleanup(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["export", "--out", bundleDir, "--yes"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain(
      "did:web: auto-included from fortress config (did:web:alice.example.com)",
    );

    const manifest = await readManifest(bundleDir);
    expect(manifest.body.identity_binding.did_web).toBeDefined();
    expect(manifest.body.identity_binding.did_web?.identifier).toBe(
      "did:web:alice.example.com",
    );
    expect(manifest.body.identity_binding.did_web?.authority_host).toBe(
      "alice.example.com",
    );
    // No published_at because the operator did not assert one.
    expect(manifest.body.identity_binding.did_web?.published_at).toBeUndefined();
  });

  it("surfaces the register hint and omits did:web when no record exists", async () => {
    const fortress = await bootstrapFortress();
    registerCleanup(fortress.storagePath);
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-none-"));
    registerCleanup(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["export", "--out", bundleDir, "--yes"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain("did:web: not included");
    expect(out.text).toContain("sanctuary did-web issue");

    const manifest = await readManifest(bundleDir);
    expect(manifest.body.identity_binding.did_web).toBeUndefined();
  });

  it("--no-did-web explicit opt-out skips auto-inclusion even when a record exists", async () => {
    const fortress = await bootstrapFortress();
    registerCleanup(fortress.storagePath);
    await writeDidWebRecord(
      fortress.storagePath,
      sampleRecord({
        did: "did:web:alice.example.com",
        authority_host: "alice.example.com",
        fortress_id: fortress.identityId,
      }),
    );
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-optout-"));
    registerCleanup(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: ["export", "--out", bundleDir, "--yes", "--no-did-web"],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain(
      "did:web: skipped (operator opt-out via --no-did-web)",
    );

    const manifest = await readManifest(bundleDir);
    expect(manifest.body.identity_binding.did_web).toBeUndefined();
  });

  it("--include-did-web=false legacy flag opts out (same as --no-did-web)", async () => {
    const fortress = await bootstrapFortress();
    registerCleanup(fortress.storagePath);
    await writeDidWebRecord(
      fortress.storagePath,
      sampleRecord({
        did: "did:web:alice.example.com",
        authority_host: "alice.example.com",
        fortress_id: fortress.identityId,
      }),
    );
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-legacy-"));
    registerCleanup(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "export",
        "--out",
        bundleDir,
        "--yes",
        "--include-did-web",
        "false",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    const manifest = await readManifest(bundleDir);
    expect(manifest.body.identity_binding.did_web).toBeUndefined();
  });

  it("--did-web CLI override takes precedence over the registered identifier", async () => {
    const fortress = await bootstrapFortress();
    registerCleanup(fortress.storagePath);
    await writeDidWebRecord(
      fortress.storagePath,
      sampleRecord({
        did: "did:web:alice.example.com",
        authority_host: "alice.example.com",
        fortress_id: fortress.identityId,
      }),
    );
    process.env.SANCTUARY_STORAGE_PATH = fortress.storagePath;

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-bundle-overr-"));
    registerCleanup(bundleDir);

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runExitCommand({
      argv: [
        "export",
        "--out",
        bundleDir,
        "--yes",
        "--did-web",
        "did:web:override.example.com",
        "--did-web-authority-host",
        "override.example.com",
      ],
      out,
      err,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });

    expect(code).toBe(0);
    expect(out.text).toContain(
      "did:web: included via CLI override (did:web:override.example.com)",
    );

    const manifest = await readManifest(bundleDir);
    expect(manifest.body.identity_binding.did_web?.identifier).toBe(
      "did:web:override.example.com",
    );
    expect(manifest.body.identity_binding.did_web?.authority_host).toBe(
      "override.example.com",
    );
  });

  it("isolates per-fortress: two registered fortresses each embed their own identifier", async () => {
    const fortressA = await bootstrapFortress();
    const fortressB = await bootstrapFortress();
    registerCleanup(fortressA.storagePath);
    registerCleanup(fortressB.storagePath);

    await writeDidWebRecord(
      fortressA.storagePath,
      sampleRecord({
        did: "did:web:alice.example.com",
        authority_host: "alice.example.com",
        fortress_id: fortressA.identityId,
      }),
    );
    await writeDidWebRecord(
      fortressB.storagePath,
      sampleRecord({
        did: "did:web:bob.example.com",
        authority_host: "bob.example.com",
        fortress_id: fortressB.identityId,
      }),
    );

    // Export from fortress A.
    process.env.SANCTUARY_STORAGE_PATH = fortressA.storagePath;
    const bundleA = await mkdtemp(join(tmpdir(), "sanctuary-bundle-isoA-"));
    registerCleanup(bundleA);
    const outA = new StringWritable();
    const errA = new StringWritable();
    const codeA = await runExitCommand({
      argv: ["export", "--out", bundleA, "--yes"],
      out: outA,
      err: errA,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });
    expect(codeA).toBe(0);
    const manifestA = await readManifest(bundleA);
    expect(manifestA.body.identity_binding.did_web?.identifier).toBe(
      "did:web:alice.example.com",
    );
    expect(manifestA.body.identity_binding.did_web?.authority_host).toBe(
      "alice.example.com",
    );

    // Export from fortress B.
    process.env.SANCTUARY_STORAGE_PATH = fortressB.storagePath;
    const bundleB = await mkdtemp(join(tmpdir(), "sanctuary-bundle-isoB-"));
    registerCleanup(bundleB);
    const outB = new StringWritable();
    const errB = new StringWritable();
    const codeB = await runExitCommand({
      argv: ["export", "--out", bundleB, "--yes"],
      out: outB,
      err: errB,
      env: { SANCTUARY_PASSPHRASE: TEST_PASSPHRASE },
    });
    expect(codeB).toBe(0);
    const manifestB = await readManifest(bundleB);
    expect(manifestB.body.identity_binding.did_web?.identifier).toBe(
      "did:web:bob.example.com",
    );
    expect(manifestB.body.identity_binding.did_web?.authority_host).toBe(
      "bob.example.com",
    );

    // Cross-check: neither manifest leaks the other fortress's identifier.
    expect(manifestA.body.identity_binding.did_web?.identifier).not.toBe(
      manifestB.body.identity_binding.did_web?.identifier,
    );
  });
});
