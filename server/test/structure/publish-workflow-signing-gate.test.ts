/** Structural security gate for the manual npm release workflow. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const workflow = readFileSync(join(repoRoot, ".github", "workflows", "publish-on-tag.yml"), "utf8");

function job(name: string): string {
  const names = ["validate-intent", "build-release", "sign-release", "stage-release", "publish-release", "finalize-release"];
  const position = names.indexOf(name);
  if (position < 0) throw new Error(`unknown job ${name}`);
  const startMarker = `\n  ${name}:\n`;
  const start = workflow.indexOf(startMarker);
  if (start < 0) throw new Error(`job ${name} not found`);
  const nextName = names[position + 1];
  const end = nextName ? workflow.indexOf(`\n  ${nextName}:\n`, start + startMarker.length) : workflow.length;
  return workflow.slice(start + startMarker.length, end);
}

function occurrences(source: string, needle: string): number {
  return source.split(needle).length - 1;
}

function runBodies(source: string): string[] {
  const lines = source.split("\n");
  const bodies: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const match = /^ {8}run:\s*(.*)$/.exec(lines[i]);
    if (!match) continue;
    const body = [match[1]];
    while (i + 1 < lines.length && (lines[i + 1].trim() === "" || /^ {10}/.test(lines[i + 1]))) {
      body.push(lines[++i]);
    }
    bodies.push(body.join("\n"));
  }
  return bodies;
}

describe("publish workflow trust zones", () => {
  const validate = job("validate-intent");
  const build = job("build-release");
  const sign = job("sign-release");
  const stage = job("stage-release");
  const publish = job("publish-release");
  const finalize = job("finalize-release");

  it("parses all six real jobs (anti-vacuity)", () => {
    expect(validate).toContain("Validate version shape without source code");
    expect(build).toContain("Pack once");
    expect(sign).toContain("Sign artifact and prove pinned-key custody");
    expect(stage).toContain("stage private GitHub release");
    expect(publish).toContain("Publish or verify already-published exact tarball");
    expect(finalize).toContain("make signed GitHub release visible");
  });

  it("orders the trust zones through explicit needs edges", () => {
    expect(build).toContain("needs: validate-intent");
    expect(sign).toContain("needs: build-release");
    expect(stage).toContain("needs: [build-release, sign-release]");
    expect(publish).toContain("needs: [build-release, sign-release, stage-release]");
    expect(finalize).toContain("needs: [build-release, publish-release]");
  });

  it("resolves source only through the exact immutable tag namespace", () => {
    expect(build).toContain("ref: refs/tags/v${{ inputs.version }}");
    expect(build).not.toContain("ref: v${{ inputs.version }}");
    expect(build).toContain("persist-credentials: false");
    expect(build).toContain("Checkout executing workflow pin surface");
    expect(build).toContain("ref: ${{ github.workflow_sha }}");
    expect(build).toContain("path: trusted-workflow");
  });

  it("maps the signing secret exactly once and only in the isolated signer", () => {
    expect(occurrences(workflow, "secrets.RELEASE_SIGNING_KEY")).toBe(1);
    expect(sign).toContain("RELEASE_SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}");
    for (const zone of [validate, build, stage, publish, finalize]) {
      expect(zone).not.toContain("RELEASE_SIGNING_KEY");
    }
    expect(sign).not.toMatch(/\bnpm\s+(?:ci|install|exec|run)\b/);
    expect(sign).not.toMatch(/\bpip(?:3)?\s+install\b/);
    expect(sign).not.toContain("uses: ./");
    expect(sign).toContain("persist-credentials: false");
    expect(sign).toContain("scripts/release-artifact-lib.mjs\n            scripts/sign-release-artifact.mjs\n            scripts/verify-release-artifact.mjs");
    expect(sign).toContain("sparse-checkout-cone-mode: false");
    expect(sign).not.toContain("sparse-checkout: scripts\n");
    expect(sign).toContain("Use pinned Node.js for isolated signing");
    expect(sign).toContain("node-version: 24.14.0");
  });

  it("never combines repository-write and npm-OIDC authority", () => {
    for (const zone of [validate, build, sign, stage, publish, finalize]) {
      expect(zone.includes("contents: write") && zone.includes("id-token: write")).toBe(false);
    }
    expect(stage).toContain("contents: write");
    expect(finalize).toContain("contents: write");
    expect(publish).toContain("id-token: write");
    expect(publish).toContain("contents: read");
  });

  it("packs once, then signs and repeatedly verifies the named artifact", () => {
    expect(occurrences(workflow, "npm pack")).toBe(1);
    expect(sign).toContain("sign-release-artifact.mjs");
    expect(occurrences(workflow, "verify-release-artifact.mjs")).toBeGreaterThanOrEqual(5);
    const exactTarball = 'release/sanctuary-framework-mcp-server-${RELEASE_VERSION}.tgz';
    expect(sign).toContain(exactTarball);
    expect(stage).toContain(exactTarball);
    expect(publish).toContain(exactTarball);
    expect(workflow).not.toMatch(/needs\.build-release\.outputs\.(?:tarball|version|dist_tag)/);
    expect(occurrences(workflow, "needs.build-release.outputs.source_sha")).toBe(2);
  });

  it("stages privately before npm and finalizes only after npm", () => {
    expect(stage).toMatch(/gh release create "\$TAG" --draft .*--verify-tag/);
    expect(stage).toContain('--target "$SOURCE_SHA"');
    expect(stage).toContain("release/release-manifest.json");
    expect(stage).toContain('release/sanctuary-framework-mcp-server-${RELEASE_VERSION}.tgz');
    expect(finalize).toContain("gh release edit \"$TAG\" --draft=false");
    expect(finalize).toContain("gh release edit \"$TAG\" --draft=false --latest");
    expect(stage).toContain("expected_assets=");
    expect(stage).toContain("became public while assets were being staged");
    expect(stage).toContain("Use pinned Node.js for staged artifact verification");
    expect(stage).toContain("node-version: 24.14.0");
    expect(finalize).toContain("expected_assets=");
    expect(finalize).toContain("gh release download \"$TAG\"");
    expect(finalize).toContain("Use pinned Node.js for final artifact verification");
    expect(finalize).toContain("node-version: 24.14.0");
    expect(finalize).toContain("node scripts/verify-release-artifact.mjs");
    expect(finalize.indexOf("verify-release-artifact.mjs")).toBeLessThan(finalize.indexOf("gh release edit"));
  });

  it("checks out only the trusted verifier and runs no package lifecycle scripts in the OIDC publisher", () => {
    expect(publish).toContain("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1");
    expect(publish).toContain("ref: ${{ github.workflow_sha }}");
    expect(publish).toContain("persist-credentials: false");
    expect(publish).toContain("scripts/release-artifact-lib.mjs\n            scripts/verify-release-artifact.mjs");
    expect(publish).not.toContain("release/verify-release-artifact.mjs");
    expect(publish).not.toContain("uses: ./");
    expect(publish).toContain("--ignore-scripts");
    expect(publish).toContain("--provenance");
    expect(publish.indexOf("verify-release-artifact.mjs")).toBeLessThan(publish.indexOf("npm publish"));
    expect(occurrences(publish, "npm publish")).toBe(1);
  });

  it("supports both failed-job and all-job reruns without changing artifact identity", () => {
    expect(workflow).not.toContain("github.run_attempt");
    expect(occurrences(workflow, "name: unsigned-release-${{ github.run_id }}")).toBe(2);
    expect(occurrences(workflow, "name: signed-release-${{ github.run_id }}")).toBe(3);
    expect(occurrences(workflow, "overwrite: true")).toBe(2);
  });

  it("does not interpolate dispatch or build output data into a run script", () => {
    const bodies = runBodies(workflow);
    const rawRunKeys = workflow.match(/^\s*run:\s*/gm) ?? [];
    // Exact count is deliberate: adding or removing a shell step requires this
    // security inventory to move with it, so parser coverage cannot drift.
    expect(bodies).toHaveLength(20);
    expect(rawRunKeys).toHaveLength(20);
    expect(bodies).toHaveLength(rawRunKeys.length);
    for (const body of bodies) {
      // Shell expressions are categorically forbidden. This covers direct
      // inputs, github.event.inputs aliases, future event payload aliases, and
      // untrusted outputs without maintaining an attacker-controlled allowlist.
      expect(body).not.toContain("${{");
    }
    expect(validate).toContain('[[ "$RELEASE_VERSION" =~');
  });

  it("pins the hosted runner and release Node runtime", () => {
    expect(workflow).not.toContain("runs-on: ubuntu-latest");
    expect(occurrences(workflow, "runs-on: ubuntu-24.04")).toBe(6);
    expect(occurrences(workflow, "node-version: 24.14.0")).toBe(6);
  });

  it("gates workflow/client release-key parity before signing", () => {
    expect(build).toContain("npm run check:release-key-parity");
    expect(build.indexOf("Release trust checks before dependency execution")).toBeLessThan(build.indexOf("Install dependencies"));
    expect(build).toContain("executing workflow key differs from tagged product key");
    expect(build).toContain("matches.length!==1");
    expect(build).toContain("node trusted-workflow/scripts/check-release-action-pins.mjs --workflows-dir trusted-workflow/.github/workflows");
  });

  it("binds staging and finalization to the exact commit built from the tag", () => {
    expect(build).toContain('echo "sha=$(git rev-parse HEAD)"');
    expect(stage).toContain("SOURCE_SHA: ${{ needs.build-release.outputs.source_sha }}");
    expect(finalize).toContain("SOURCE_SHA: ${{ needs.build-release.outputs.source_sha }}");
    expect(workflow).not.toContain("git ls-remote");
    expect(occurrences(stage, 'gh api "repos/${GH_REPO}/git/ref/tags/${TAG}"')).toBe(2);
    expect(occurrences(finalize, 'gh api "repos/${GH_REPO}/git/ref/tags/${TAG}"')).toBe(2);
    expect(stage).toContain('gh api "repos/${GH_REPO}/git/tags/${resolved}"');
    expect(stage).toContain('gh api "repos/${GH_REPO}/git/tags/${post_stage_sha}"');
    expect(finalize).toContain('gh api "repos/${GH_REPO}/git/tags/${resolved}"');
    expect(finalize).toContain('gh api "repos/${GH_REPO}/git/tags/${final_sha}"');
    expect(occurrences(workflow, '[[ "$object_type" == commit')).toBe(4);
    expect(occurrences(workflow, "::error::GitHub API failed")).toBe(8);
    expect(stage).toContain("moved while the draft release was being staged");
    expect(finalize).toContain('[[ "$final_sha" == "$SOURCE_SHA" ]]');
  });
});
