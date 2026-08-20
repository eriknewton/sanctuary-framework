import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Writable } from "node:stream";

import { runManifestPreflight } from "../../src/cli/castle-wall-manifest-preflight.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../../src/castle-wall/constants.js";
import { canonicalize } from "../../src/mesh/canonical-json.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import type { AllowlistManifest, SignedManifest } from "../../src/castle-wall/allowlist/manifest.js";

class CaptureStream extends Writable {
  chunks: string[] = [];

  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }

  text(): string {
    return this.chunks.join("");
  }
}

function signedManifest(entries: AllowlistManifest["rules"]): { envelope: SignedManifest; publicKey: Uint8Array } {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const manifest: AllowlistManifest = {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    fortress_id: "preflight-cli-test",
    issued_at: "2026-08-20T00:00:00.000Z",
    rules: entries,
  };
  return {
    envelope: {
      manifest,
      signature: {
        signature_scheme: CASTLE_WALL_SIGNATURE_SCHEME_V1,
        signing_key_id: "test-key",
        signature_b64url: toBase64url(ed25519.sign(stringToBytes(canonicalize(manifest)), privateKey)),
      },
    },
    publicKey,
  };
}

function sha256Hex(bytes: Uint8Array): string {
  return [...sha256(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("castle-wall manifest-preflight CLI", () => {
  it("reports the complete persisted relation inventory and never reads an unsafe rule filename", async () => {
    const { envelope, publicKey } = signedManifest([
      { rule_id: "bad/id", file: "bad/id.json", sha256: "0".repeat(64) },
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
      { rule_id: "safe-id", file: "safe-id.json", sha256: "0".repeat(64) },
    ]);
    const out = new CaptureStream();
    const requestedPaths: string[] = [];
    const fortress = "/test-fortress";

    const code = await runManifestPreflight(["--fortress", fortress], {
      out,
      env: {},
      readFile: async (path) => {
        requestedPaths.push(path);
        if (path.endsWith("manifest.json")) return Buffer.from(JSON.stringify(envelope));
        if (path.endsWith("castle-pinned-pubkey.bin")) return Buffer.from(publicKey);
        throw new Error(`unexpected rule read: ${path}`);
      },
    });

    const report = JSON.parse(out.text()) as {
      status: string;
      relation_preflight: string;
      rule_bodies_scanned: number;
      issue_count: number;
    };
    expect(code).toBe(1);
    expect(report).toMatchObject({
      status: "incompatible",
      relation_preflight: "failed",
      rule_bodies_scanned: 0,
      issue_count: 3,
    });
    expect(requestedPaths.some((path) => path.includes("/rules/"))).toBe(false);
  });

  it("uses the production fortress-root pin and reports a compatible manifest", async () => {
    const ruleBody = Buffer.from(JSON.stringify({ id: "safe-id" }));
    const { envelope, publicKey } = signedManifest([
      { rule_id: "safe-id", file: "safe-id.json", sha256: sha256Hex(ruleBody) },
    ]);
    const out = new CaptureStream();
    const requestedPaths: string[] = [];
    const fortress = "/test-fortress";

    const code = await runManifestPreflight(["--fortress", fortress], {
      out,
      env: {},
      readFile: async (path) => {
        requestedPaths.push(path);
        if (path === "/test-fortress/policy/egress/manifest.json") {
          return Buffer.from(JSON.stringify(envelope));
        }
        if (path === "/test-fortress/castle-pinned-pubkey.bin") return Buffer.from(publicKey);
        if (path === "/test-fortress/policy/egress/rules/safe-id.json") return ruleBody;
        throw new Error("unexpected path");
      },
    });

    expect(code).toBe(0);
    expect(JSON.parse(out.text())).toMatchObject({
      status: "compatible",
      signature: "verified",
      relation_preflight: "passed",
      rule_bodies_scanned: 1,
      issue_count: 0,
    });
    expect(requestedPaths).toEqual(expect.arrayContaining([
      "/test-fortress/castle-pinned-pubkey.bin",
      "/test-fortress/policy/egress/manifest.json",
      "/test-fortress/policy/egress/rules/safe-id.json",
    ]));
  });

  it("reports an unreadable manifest input without leaking its error path", async () => {
    const out = new CaptureStream();
    const sentinelPath = "/private/sentinel/fortress-manifest.json";

    const code = await runManifestPreflight(["--fortress", "/test-fortress"], {
      out,
      env: {},
      readFile: async () => {
        throw new Error(sentinelPath);
      },
    });

    expect(code).toBe(1);
    expect(JSON.parse(out.text())).toMatchObject({
      status: "unavailable",
      signature: "not_checked",
      relation_preflight: "not_checked",
      rule_bodies_scanned: 0,
      issue_count: 1,
      omitted_issue_count: 0,
      issues: [{ kind: "manifest_input", message: "persisted manifest or pinned key could not be read" }],
    });
    expect(out.text()).not.toContain(sentinelPath);
  });

  it("rejects missing values and extra CLI arguments", async () => {
    for (const argv of [["--fortress"], ["unexpected"]]) {
      const err = new CaptureStream();
      const code = await runManifestPreflight(argv, { err, env: {} });

      expect(code).toBe(2);
      expect(err.text()).toContain("Usage: sanctuary castle-wall manifest-preflight");
    }
  });

  it("is reachable through the production command dispatcher and help", async () => {
    const runCli = promisify(execFile);
    const help = await runCli(process.execPath, ["--import", "tsx/esm", "src/cli.ts", "castle-wall", "--help"], {
      cwd: process.cwd(),
    });
    expect(help.stdout).toContain("manifest-preflight Read the persisted signed egress manifest");

    await expect(
      runCli(
        process.execPath,
        ["--import", "tsx/esm", "src/cli.ts", "castle-wall", "manifest-preflight", "--fortress"],
        { cwd: process.cwd() },
      ),
    ).rejects.toMatchObject({
      code: 2,
      stderr: expect.stringContaining("Usage: sanctuary castle-wall manifest-preflight"),
    });
  });
});
