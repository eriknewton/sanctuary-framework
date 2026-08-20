/**
 * Regression tests for the exact transform/collection classifier shipped in
 * `.githooks/pre-commit`.
 *
 * The local hook and CI must agree that Vite's benign "failed to load source
 * map" warning is not a transform failure, while every real transform,
 * parse, collection, source-load, missing-module, and failed-suite signal
 * remains blocking. These tests extract and execute the shipped shell
 * classifier; they do not reimplement its matching or filtering logic.
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  ".githooks",
  "pre-commit",
);

/** Extract the classifier and its shipped pattern assignment verbatim. */
function extractClassifier(): string {
  const lines = readFileSync(HOOK_PATH, "utf-8").split("\n");
  const patternIndex = lines.findIndex((line) =>
    /^TRANSFORM_ERROR_PATTERNS=/.test(line),
  );
  if (patternIndex === -1) {
    throw new Error("TRANSFORM_ERROR_PATTERNS assignment not found in hook");
  }

  const startIndex = lines.findIndex((line) =>
    /^classify_transform_errors\(\)\s*\{/.test(line),
  );
  if (startIndex === -1) {
    throw new Error("classify_transform_errors() definition not found in hook");
  }

  let endIndex = -1;
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    if (lines[index] === "}") {
      endIndex = index;
      break;
    }
  }
  if (endIndex === -1) {
    throw new Error("classify_transform_errors() closing brace not found in hook");
  }

  return [
    lines[patternIndex],
    ...lines.slice(startIndex, endIndex + 1),
  ].join("\n");
}

/** Execute the exact shipped classifier in a clean bash subprocess. */
function classify(output: string): string {
  const harness = [
    "set -euo pipefail",
    extractClassifier(),
    'classify_transform_errors "$1"',
  ].join("\n");

  return execFileSync("bash", ["-c", harness, "bash", output], {
    encoding: "utf-8",
  });
}

describe("pre-commit transform classifier", () => {
  it("filters the benign source-map warning completely", () => {
    expect(
      classify("[vite] Failed to Load Source Map for /tmp/example.js"),
    ).toBe("");
  });

  it.each([
    "Transform failed with 1 error",
    "transform error in test file",
    "failed to parse module",
    "failed to collect test suite",
    "failed to load source module",
    "Cannot find module './missing'",
    "Failed Suites 1",
  ])("retains real failure: %s", (failure) => {
    expect(classify(failure)).toContain(failure);
  });

  it("filters benign output while retaining a real failure", () => {
    const benign = "Failed to load source map for /tmp/example.js";
    const real = "failed to load source module /tmp/example.js";

    const classified = classify(`${benign}\n${real}`);

    expect(classified).not.toContain(benign);
    expect(classified).toContain(real);
  });
});
