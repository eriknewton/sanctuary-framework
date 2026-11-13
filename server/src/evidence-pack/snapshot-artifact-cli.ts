import { lstatSync } from "node:fs";
import { observeArtifactPackageMarker, markerRefusal } from "./snapshot-package-marker.js";
import { ARTIFACT_HELP, ARTIFACT_REFUSED, ARTIFACT_USAGE, CHECK_FLAGS, MAX_ARTIFACT_BYTES, MAX_MANIFEST_BYTES, artifactSuccess, checkArtifact, readBounded } from "./artifact-policy.mjs";
import type { ArtifactMode } from "./artifact-policy.mjs";
interface Output { write(text: string): Promise<void> }
// Completion includes the write callback; asynchronous broken pipes must not turn a refusal or result into success.
const output = (stream: NodeJS.WriteStream): Output => ({ write: text => new Promise((resolve, reject) => {
  const failed = (error: Error) => reject(error);
  stream.once("error", failed);
  try { stream.write(text, error => { if (error) reject(error); else { stream.removeListener("error", failed); resolve(); } }); }
  catch (error) { stream.removeListener("error", failed); reject(error); }
}) });
/** Check caller-pinned artifact bytes. This is independent of evidence-snapshot signature verification. */
export async function runArtifactCommand(args: string[], buildMode: ArtifactMode, stdout: Output = output(process.stdout), stderr: Output = output(process.stderr)): Promise<number> {
  const emit = async (sink: Output, text: string, code: number): Promise<number> => { try { await sink.write(text); return code; } catch { return 1; } };
  if (args.length === 1 && args[0] === "--help") return emit(stdout, ARTIFACT_HELP, 0);
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]!, value = args[index + 1];
    if (!CHECK_FLAGS.includes(key) || values.has(key) || !value || value.startsWith("--")) return emit(stderr, ARTIFACT_USAGE, 2);
    values.set(key, value);
  }
  if (values.size !== CHECK_FLAGS.length || !/^[0-9a-f]{64}$/.test(values.get("--expect-tarball-sha256")!) || !/^[0-9a-f]{64}$/.test(values.get("--expect-manifest-sha256")!) || !/^[0-9a-f]{40}$/.test(values.get("--expect-source-revision")!) || !["release", "fixture"].includes(values.get("--expect-mode")!)) return emit(stderr, ARTIFACT_USAGE, 2);
  try {
    const mode = values.get("--expect-mode")! as ArtifactMode;
    // A fixture-built checker can only report fixture-policy success; this is a compiled policy input.
    if (buildMode !== "release" && (buildMode !== "fixture" || mode !== "fixture")) return emit(stderr, ARTIFACT_REFUSED, 1);
    const checked = checkArtifact(readBounded(values.get("--tarball")!, MAX_ARTIFACT_BYTES), readBounded(values.get("--manifest")!, MAX_MANIFEST_BYTES), { mode, source_revision: values.get("--expect-source-revision")!, tarball_sha256: values.get("--expect-tarball-sha256")!, manifest_sha256: values.get("--expect-manifest-sha256")! });
    if (!checked.ok) return emit(stderr, ARTIFACT_REFUSED, 1);
    return emit(stdout, artifactSuccess(mode), 0);
  } catch { return emit(stderr, ARTIFACT_REFUSED, 1); }
}

/** Installed checker: fixture inspection and help remain available; release checks require observed absence. */
export async function runInstalledArtifactCommand(args: string[], buildMode: ArtifactMode, moduleUrl: string, stdout: Output = output(process.stdout), stderr: Output = output(process.stderr)): Promise<number> {
  try {
    // Must match the loader URL supplied by tsup.evidence-pack.config.ts; fixture policy never grants release authority.
    if (args.some((arg, index) => arg === "--expect-mode" && args[index + 1] === "release")) {
      const refusal = markerRefusal(observeArtifactPackageMarker(moduleUrl, { lstatSync }));
      if (refusal !== undefined) { await stderr.write(refusal); return 1; }
    }
    return await runArtifactCommand(args, buildMode, stdout, stderr);
  } catch { return 1; }
}
