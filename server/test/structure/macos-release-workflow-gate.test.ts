/** Structural release gate for the signed Castle Wall macOS workflow. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const workflow = readFileSync(
  join(repoRoot, ".github", "workflows", "castle-wall-macos-release.yml"),
  "utf8",
);

function job(name: string, nextName?: string): string {
  const startMarker = `\n  ${name}:\n`;
  const start = workflow.indexOf(startMarker);
  if (start < 0) throw new Error(`job ${name} not found`);
  const end = nextName
    ? workflow.indexOf(`\n  ${nextName}:\n`, start + startMarker.length)
    : workflow.length;
  return workflow.slice(start + startMarker.length, end);
}

describe("Castle Wall macOS release workflow trust boundary", () => {
  const build = job("build-sign-notarize", "stage-app-release");
  const stage = job("stage-app-release");

  it("builds only from the exact requested immutable tag", () => {
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).not.toMatch(/^\s+release:\s*$/m);
    expect(build).toContain("ref: refs/tags/${{ inputs.version_tag }}");
    expect(build).toContain("persist-credentials: false");
    expect(build).toContain('tag_sha=$(git rev-list -n 1 "refs/tags/${RELEASE_TAG}")');
    expect(build).toContain('[[ "v${package_version}" != "$RELEASE_TAG" ]]');
    expect(build).toContain('echo "SANCTUARY_SOURCE_SHA=$source_sha" >> "$GITHUB_ENV"');
    expect(build).not.toContain("github.sha");
    expect(build).not.toContain("GITHUB_SHA");
    expect(build.split("SANCTUARY_SOURCE_SHA").length - 1).toBe(3);
  });

  it("keeps Apple signing secrets out of the repository-write job", () => {
    expect(workflow).toContain("permissions:\n  contents: read");
    expect(build).not.toContain("contents: write");
    expect(stage).toContain("contents: write");
    expect(stage).not.toContain("APPLE_DEVELOPER_ID_P12");
    expect(stage).not.toContain("APPLE_NOTARY_PASSWORD");
    expect(stage).toContain("needs: build-sign-notarize");
  });

  it("moves the verified app bytes into a private exact-tag release", () => {
    expect(stage).toContain("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c");
    expect(stage).toContain('actual_sha256=$(sha256sum "$app_zip"');
    expect(stage).toContain('gh release create "$TAG" --draft');
    expect(stage).toContain('gh release upload "$TAG" "$app_zip" --clobber');
    expect(stage).toContain('uploaded_digest" != "sha256:${ARTIFACT_SHA256}');
    expect(stage).toContain("became public while the app was being staged");
  });

  it("checks remote tag identity before and after release-asset staging", () => {
    expect(stage).toContain("resolve_remote_tag()");
    expect(stage.split("resolved=$(resolve_remote_tag)")).toHaveLength(3);
    expect(stage).toContain("does not name the app source");
    expect(stage).toContain("moved while the app was being staged");
    expect(stage).toContain('test -s "$notes_file"');
  });
});
