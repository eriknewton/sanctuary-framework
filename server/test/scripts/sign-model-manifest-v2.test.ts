/**
 * Round trip of the model-manifest signing tool with an ephemeral key against
 * a loopback registry: placeholder mode, signed mode with the shared verifier,
 * monotonic version refusal, seed checks, and the two build pins.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { toBase64url } from "../../src/core/encoding.js";
import { IMMUNE_OCI_MANIFEST_MAX_BYTES } from "../../src/intelligence/immune-disk-verifier.js";
import {
  parseModelManifestV2Json,
  verifyModelManifestV2WithKey,
} from "../../src/intelligence/model-manifest-v2.js";

const SERVER_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = join(SERVER_ROOT, "scripts", "sign-model-manifest-v2.mjs");
const SOURCE = join(SERVER_ROOT, "model-catalog", "model-manifest-v2.source.json");
const SEED_ENV = "SANCTUARY_MODEL_CATALOG_ROOT_SEED_B64URL";
const SEED = new Uint8Array(32).fill(59);
const SEED_B64URL = toBase64url(SEED);
const PUBLIC_B64URL = toBase64url(ed25519.getPublicKey(SEED));
const FOREIGN_SEED_B64URL = toBase64url(new Uint8Array(32).fill(61));
// 86 = unpadded base64url length of a 64-byte signature; all "A" is all-zero.
const ALL_ZERO_SIGNATURE = "A".repeat(86);
// tsx compiles the tool and its runtime imports on each spawn; generous ceiling.
const TOOL_TIMEOUT_MS = 120_000;

const OVERSIZE_TAG = "oversize";
const OVERSIZE_CHUNK_BYTES = 64 * 1024;
// 16x the cap: far more than loopback socket buffers can absorb before the
// client aborts, so an unfinished response is a real signal of the abort.
const OVERSIZE_TOTAL_BYTES = IMMUNE_OCI_MANIFEST_MAX_BYTES * 16;
let oversizeFinished: boolean | null = null;

const PIN_FILES = [
  ["src/intelligence/packaged-model-manifest.ts", "PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256"],
  ["scripts/copy-model-manifest-v2-asset.mjs", "EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256"],
] as const;

interface ToolRun {
  status: number | null;
  stdout: string;
  stderr: string;
}

function fakeManifest(tag: string): Buffer {
  return Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    config: { mediaType: "application/vnd.docker.container.image.v1+json", digest: `sha256:${"a".repeat(64)}`, size: 400 },
    layers: [{ mediaType: "application/vnd.ollama.image.model", digest: `sha256:${createHash("sha256").update(tag).digest("hex")}`, size: 1 }],
  }));
}

function readPin(root: string, file: string, name: string): string {
  const source = readFileSync(join(root, file), "utf8");
  const match = new RegExp(`${name}\\s*=\\s*\\n?\\s*"([0-9a-f]{64})"`).exec(source);
  expect(match, `${file} declares ${name}`).not.toBeNull();
  return match![1]!;
}

/** Async spawn so the in-process loopback registry can answer the tool. */
function spawnTool(args: string[], env: Record<string, string | undefined>): Promise<ToolRun> {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, ["--import", "tsx/esm", SCRIPT, ...args], {
      cwd: SERVER_ROOT,
      env: { ...process.env, [SEED_ENV]: undefined, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), TOOL_TIMEOUT_MS);
    child.once("error", (error) => { clearTimeout(timer); fail(error); });
    child.once("close", (status) => { clearTimeout(timer); done({ status, stdout, stderr }); });
  });
}

describe("sign-model-manifest-v2 tool", () => {
  let server: Server;
  let origin: string;
  let work: string;
  let out: string;
  const served = new Map<string, Buffer>();

  beforeAll(async () => {
    server = createServer((request, response) => {
      const match = /^\/v2\/library\/qwen3\/manifests\/([a-z0-9]+)$/.exec(request.url ?? "");
      if (!match || request.headers.accept !== "application/vnd.docker.distribution.manifest.v2+json") {
        response.writeHead(404).end();
        return;
      }
      if (match[1] === OVERSIZE_TAG) {
        // No Content-Length (chunked), body far past the cap, written with
        // backpressure so an early client abort leaves the response unfinished.
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        const chunk = Buffer.alloc(OVERSIZE_CHUNK_BYTES, 0x7b);
        let remaining = OVERSIZE_TOTAL_BYTES;
        const pump = () => {
          while (remaining > 0) {
            remaining -= chunk.length;
            if (!response.write(chunk)) {
              response.once("drain", pump);
              return;
            }
          }
          response.end();
        };
        response.once("close", () => { oversizeFinished = response.writableFinished; });
        pump();
        return;
      }
      const body = fakeManifest(match[1]!);
      served.set(match[1]!, body);
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "content-length": String(body.length) });
      response.end(body);
    });
    await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no loopback port");
    origin = `http://127.0.0.1:${address.port}`;
    work = mkdtempSync(join(tmpdir(), "sanctuary-sign-manifest-"));
    out = join(work, "asset", "model-manifest.v2.json");
    mkdirSync(dirname(out), { recursive: true });
    for (const [file] of PIN_FILES) {
      mkdirSync(dirname(join(work, file)), { recursive: true });
      cpSync(join(SERVER_ROOT, file), join(work, file));
    }
  });

  afterAll(async () => {
    await new Promise<void>((done) => server.close(() => done()));
    rmSync(work, { recursive: true, force: true });
  });

  async function run(args: string[], env: Record<string, string | undefined> = {}): Promise<ToolRun> {
    const result = await spawnTool(
      ["--source", SOURCE, "--out", out, "--registry-origin", origin, "--repin-root", work, ...args],
      env,
    );
    expect(result.stderr).not.toContain(SEED_B64URL);
    expect(result.stdout).not.toContain(SEED_B64URL);
    return result;
  }

  it("writes a refused placeholder, then a signed asset the runtime verifier accepts, repinning both constants", async () => {
    const placeholder = await run(["--placeholder", "--test-trust-root-b64url", PUBLIC_B64URL]);
    expect(placeholder.status, placeholder.stderr).toBe(0);
    const placeholderText = readFileSync(out, "utf8");
    const placeholderParsed = parseModelManifestV2Json(placeholderText);
    expect(placeholderParsed.ok && placeholderParsed.value.signature).toBe(ALL_ZERO_SIGNATURE);
    expect(placeholderParsed.ok && placeholderParsed.value.body.manifest_version).toBe(1);
    const placeholderDigest = createHash("sha256").update(placeholderText).digest("hex");
    for (const [file, name] of PIN_FILES) expect(readPin(work, file, name)).toBe(placeholderDigest);
    expect(placeholder.stderr).toContain("mode=PLACEHOLDER");

    const signed = await run(["--test-trust-root-b64url", PUBLIC_B64URL], { [SEED_ENV]: SEED_B64URL });
    expect(signed.status, signed.stderr).toBe(0);
    const signedText = readFileSync(out, "utf8");
    const verified = verifyModelManifestV2WithKey(signedText, ed25519.getPublicKey(SEED));
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;
    expect(verified.body.manifest_version).toBe(1);
    for (const [modelId, model] of Object.entries(verified.body.models)) {
      const bytes = served.get(model.ollama_identity.tag);
      expect(bytes, `registry served ${modelId}`).toBeDefined();
      expect(model.ollama_identity.ollama_manifest_sha256)
        .toBe(createHash("sha256").update(bytes!).digest("hex"));
      expect(model.ollama_identity.registry).toBe("registry.ollama.ai");
    }
    expect(Object.keys(verified.body.models).sort()).toEqual(["qwen3-14b", "qwen3-32b", "qwen3-4b"]);
    const signedDigest = createHash("sha256").update(signedText).digest("hex");
    for (const [file, name] of PIN_FILES) expect(readPin(work, file, name)).toBe(signedDigest);
    expect(signed.stderr).toContain(`asset sha256=${signedDigest}`);
    expect(signed.stderr).toContain("mode=SIGNED");
  }, TOOL_TIMEOUT_MS * 2);

  it("refuses a non-monotonic version against a verified asset, a foreign seed, and a missing seed", async () => {
    const sameVersion = await run(["--test-trust-root-b64url", PUBLIC_B64URL], { [SEED_ENV]: SEED_B64URL });
    expect(sameVersion.status).toBe(1);
    expect(sameVersion.stderr).toContain("is not greater than the verified existing asset version 1");

    const foreign = await run(["--test-trust-root-b64url", PUBLIC_B64URL], { [SEED_ENV]: FOREIGN_SEED_B64URL });
    expect(foreign.status).toBe(1);
    expect(foreign.stderr).toContain("does not derive the compiled model-catalog root public key");

    const unset = await run(["--test-trust-root-b64url", PUBLIC_B64URL]);
    expect(unset.status).toBe(1);
    expect(unset.stderr).toContain(`${SEED_ENV} is not set`);

    // Nothing above rewrote the asset or the pins.
    const text = readFileSync(out, "utf8");
    expect(verifyModelManifestV2WithKey(text, ed25519.getPublicKey(SEED)).ok).toBe(true);
    const digest = createHash("sha256").update(text).digest("hex");
    for (const [file, name] of PIN_FILES) expect(readPin(work, file, name)).toBe(digest);
  }, TOOL_TIMEOUT_MS * 3);

  it("aborts a registry body that exceeds the cap while streaming, before buffering it", async () => {
    const source = JSON.parse(readFileSync(SOURCE, "utf8")) as {
      models: Record<string, { ollama_identity: { tag: string } }>;
    };
    const [firstId, firstModel] = Object.entries(source.models)[0]!;
    // One model whose tag the loopback registry answers with an oversize body.
    const oversizeSource = {
      ...source,
      models: { [firstId]: { ...firstModel, ollama_identity: { ...firstModel.ollama_identity, tag: OVERSIZE_TAG } } },
      tiers: { baseline: [firstId], mid: [firstId], pro: [firstId] },
    };
    const sourcePath = join(work, "oversize-source.json");
    writeFileSync(sourcePath, JSON.stringify(oversizeSource));
    const result = await spawnTool(
      ["--source", sourcePath, "--out", join(work, "oversize-asset.json"), "--registry-origin", origin, "--repin-root", work, "--placeholder"],
      {},
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`exceeded the ${IMMUNE_OCI_MANIFEST_MAX_BYTES}-byte cap while streaming; request aborted`);
    // The server never finished writing: the client aborted mid-stream.
    expect(oversizeFinished).toBe(false);
  }, TOOL_TIMEOUT_MS);

  it("refuses a non-loopback, non-production registry origin before any fetch", async () => {
    const result = await spawnTool(
      ["--source", SOURCE, "--out", join(work, "unused.json"), "--registry-origin", "https://example.invalid", "--placeholder"],
      {},
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--registry-origin must be https://registry.ollama.ai or a loopback http origin");
  }, TOOL_TIMEOUT_MS);
});
