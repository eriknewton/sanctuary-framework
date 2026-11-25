/**
 * Cross-file pin: the verifier's workflow identity names a workflow that
 * exists in this repository, is triggered only by manual dispatch, and uploads
 * the artifact names the verifier expects. The workflow file is read, never
 * edited. Must match PINNED_WORKFLOW_PATH, PINNED_WORKFLOW_IDENTITY and
 * manifestArtifactName in server/src/verify-release/constants.ts.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  PINNED_REF, PINNED_REPOSITORY_URI, PINNED_TRIGGER, PINNED_WORKFLOW_IDENTITY, PINNED_WORKFLOW_PATH, manifestArtifactName,
} from "../../src/verify-release/constants.js";
import { denyAllNetwork } from "./helpers.js";

denyAllNetwork();

const REPO = join(__dirname, "..", "..", "..");

/** Top-level keys of the `on:` block (two-space indentation, as the workflow is written). */
function triggers(workflow: string): string[] {
  const lines = workflow.split("\n");
  const start = lines.findIndex(line => /^on:\s*$/.test(line));
  if (start < 0) throw new Error("workflow has no block-form on: key");
  const keys: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break;
    const match = /^ {2}([A-Za-z_]+):/.exec(line);
    if (match) keys.push(match[1]!);
  }
  return keys;
}

describe("release workflow pin", () => {
  const workflow = readFileSync(join(REPO, PINNED_WORKFLOW_PATH), "utf8");

  it("the pinned workflow identity is the repository, the workflow path and the main ref", () => {
    expect(PINNED_WORKFLOW_IDENTITY).toBe(`${PINNED_REPOSITORY_URI}/${PINNED_WORKFLOW_PATH}@${PINNED_REF}`);
  });

  it("the workflow exists at the pinned path and its only trigger is workflow_dispatch", () => {
    expect(triggers(workflow)).toEqual([PINNED_TRIGGER]);
  });

  it("the workflow uploads release-manifest.json beside the tarball name the manifest must list", () => {
    expect(manifestArtifactName("1.2.3")).toBe("sanctuary-framework-mcp-server-1.2.3.tgz");
    expect(workflow).toContain("sanctuary-framework-mcp-server-${RELEASE_VERSION}.tgz");
    expect(workflow).toContain("release/release-manifest.json");
  });
});
