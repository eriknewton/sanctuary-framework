/**
 * Tests for the surrogate policy FILE: its path, its custody, and the
 * absent-versus-present-and-broken split on load.
 *
 * WHY THE SPLIT MATTERS. An absent policy file is the normal case for every
 * fortress that never used surrogacy, and auditing it would write a chain line on
 * every broker open. A file that IS there and cannot be parsed is a different
 * event: it yields zero bindings, never a partial set, and it gets one audit line
 * carrying a fixed failure class. Collapsing the two is the defect this split
 * closes.
 *
 * Host-free: a temp storage directory per test, no keychain, no `security`
 * subprocess, nothing under the operator's real fortress.
 */

import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  brokerPolicyPath,
  loadSurrogatePolicyDocument,
  saveSurrogatePolicy,
  surrogatePolicyPath,
} from "../../../src/disclosure/broker/open.js";
import { SURROGATE_POLICY_VERSION } from "../../../src/disclosure/broker/policy.js";

let storagePath: string;

const DOCUMENT = {
  surrogate_policy_version: SURROGATE_POLICY_VERSION,
  bindings: [
    {
      secret: "openai-api-key",
      agent: "hermes",
      env: "OPENAI_API_KEY",
      destinations: [{ host: "api.openai.com", port: 443 }],
      header: "Authorization",
    },
  ],
};

beforeEach(async () => {
  storagePath = await mkdtemp(join(tmpdir(), "sanctuary-surrogate-policy-"));
});

afterEach(async () => {
  await rm(storagePath, { recursive: true, force: true });
});

describe("the path is separate from the broker's own policy file", () => {
  it("is surrogate-policy.json beside broker-policy.json, never inside it", () => {
    expect(surrogatePolicyPath(storagePath)).toBe(join(storagePath, "surrogate-policy.json"));
    expect(surrogatePolicyPath(storagePath)).not.toBe(brokerPolicyPath(storagePath));
  });
});

describe("custody", () => {
  it("writes the file owner-only at 0600", async () => {
    await saveSurrogatePolicy(storagePath, DOCUMENT);
    const info = await stat(surrogatePolicyPath(storagePath));
    // eslint-disable-next-line no-bitwise
    expect(info.mode & 0o777).toBe(0o600);
  });

  it("round-trips through the parser, so what is written is what loads", async () => {
    await saveSurrogatePolicy(storagePath, DOCUMENT);
    const result = await loadSurrogatePolicyDocument(storagePath);
    expect(result).toEqual({ outcome: "loaded", document: DOCUMENT });
  });

  it("refuses to persist a document the loader would then refuse", async () => {
    await expect(
      saveSurrogatePolicy(storagePath, {
        ...DOCUMENT,
        bindings: [{ ...DOCUMENT.bindings[0]!, env: "HTTP_PROXY" }],
      }),
    ).rejects.toThrow(/surrogate policy refused/);
    // Nothing was written: a refused save leaves no half-valid file behind.
    await expect(stat(surrogatePolicyPath(storagePath))).rejects.toThrow();
  });

  it("does not touch broker-policy.json", async () => {
    await writeFile(brokerPolicyPath(storagePath), JSON.stringify({ skills: [] }), "utf8");
    const before = await readFile(brokerPolicyPath(storagePath), "utf8");
    await saveSurrogatePolicy(storagePath, DOCUMENT);
    expect(await readFile(brokerPolicyPath(storagePath), "utf8")).toBe(before);
  });
});

describe("absent versus present-and-broken (round-2 finding B2-S6)", () => {
  it("reports absent for ENOENT, the normal no-bindings case, with no failure class", async () => {
    const result = await loadSurrogatePolicyDocument(storagePath);
    expect(result).toEqual({ outcome: "absent" });
  });

  it("reports json_error for a present file that is not JSON", async () => {
    await writeFile(surrogatePolicyPath(storagePath), "{not json", "utf8");
    expect(await loadSurrogatePolicyDocument(storagePath)).toEqual({
      outcome: "failed",
      failureClass: "json_error",
    });
  });

  it("reports bad_version for a present file naming a version this build does not serve", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({ ...DOCUMENT, surrogate_policy_version: 99 }),
      "utf8",
    );
    expect(await loadSurrogatePolicyDocument(storagePath)).toEqual({
      outcome: "failed",
      failureClass: "bad_version",
    });
  });

  it("reports duplicate_binding for two rows naming one secret", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({
        ...DOCUMENT,
        bindings: [DOCUMENT.bindings[0]!, { ...DOCUMENT.bindings[0]!, env: "OTHER", header: "X-Api-Key" }],
      }),
      "utf8",
    );
    expect(await loadSurrogatePolicyDocument(storagePath)).toEqual({
      outcome: "failed",
      failureClass: "duplicate_binding",
    });
  });

  it("reports schema_error for a present file whose binding is ill-formed", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({ ...DOCUMENT, bindings: [{ ...DOCUMENT.bindings[0]!, header: "Host" }] }),
      "utf8",
    );
    expect(await loadSurrogatePolicyDocument(storagePath)).toEqual({
      outcome: "failed",
      failureClass: "schema_error",
    });
  });

  it("reports read_error, not absent, when the path exists but cannot be read", async () => {
    // A directory at the file's path: `readFile` fails with EISDIR, which is a
    // present-and-unreadable policy, not an absent one. The distinction is the
    // whole point of the split.
    await mkdir(surrogatePolicyPath(storagePath));
    expect(await loadSurrogatePolicyDocument(storagePath)).toEqual({
      outcome: "failed",
      failureClass: "read_error",
    });
  });

  it("never returns a partial binding set on any failure", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({
        ...DOCUMENT,
        bindings: [DOCUMENT.bindings[0]!, { ...DOCUMENT.bindings[0]!, secret: "second", env: "BAD env" }],
      }),
      "utf8",
    );
    const result = await loadSurrogatePolicyDocument(storagePath);
    expect(result.outcome).toBe("failed");
    expect(result).not.toHaveProperty("document");
  });

  it("returns no parser message text, so a caller cannot log the document by logging the failure", async () => {
    await writeFile(
      surrogatePolicyPath(storagePath),
      JSON.stringify({ ...DOCUMENT, bindings: [{ ...DOCUMENT.bindings[0]!, secret: "leak-me-$$$" }] }),
      "utf8",
    );
    const result = await loadSurrogatePolicyDocument(storagePath);
    expect(JSON.stringify(result)).not.toContain("leak-me");
  });
});

describe("an empty policy is a valid policy", () => {
  it("loads zero bindings without a failure class", async () => {
    await saveSurrogatePolicy(storagePath, {
      surrogate_policy_version: SURROGATE_POLICY_VERSION,
      bindings: [],
    });
    const result = await loadSurrogatePolicyDocument(storagePath);
    expect(result).toEqual({
      outcome: "loaded",
      document: { surrogate_policy_version: SURROGATE_POLICY_VERSION, bindings: [] },
    });
  });
});
