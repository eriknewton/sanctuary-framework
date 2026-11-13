import type { BigIntStats } from "node:fs";
import { fileURLToPath } from "node:url";
import { BIN, NON_RELEASE_MARKER } from "./artifact-policy.mjs";

// Installation-layout budgets: 4096 is Linux PATH_MAX; 256 is the design descriptor budget, independent of evidence input size.
export const MAX_PACKAGE_PATH_BYTES = 4096, MAX_PACKAGE_COMPONENTS = 256;
// Must match the refusal inventory in server/reorg-surface-manifest.md and the recipient instructions.
export const NON_RELEASE_REFUSAL = "NON_RELEASE: this verifier package is not a release artifact.\n";
export const PACKAGE_MARKER_UNAVAILABLE = "PACKAGE_MARKER_UNAVAILABLE: verifier package classification could not be established.\n";
export type MarkerState = { kind: "absent" | "present" | "unknown" };
export interface MarkerFS { lstatSync(path: string, options: { bigint: true }): BigIntStats }

/** Validate an observation at the consumer boundary; malformed results never grant admission. */
export function parseMarkerState(value: unknown): MarkerState {
  if (value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 1 && Object.hasOwn(value, "kind") && "kind" in value) {
    if (value.kind === "absent" || value.kind === "present" || value.kind === "unknown") return { kind: value.kind };
  }
  return { kind: "unknown" };
}

function observe(moduleUrl: string, fsOps: MarkerFS, bin: string): MarkerState {
  try {
    const [dist, entry] = bin.split("/");
    // Validate the unnormalized URL spelling too: URL parsing otherwise erases dot components.
    if (/[\\?#]/.test(moduleUrl) || /%5c/i.test(moduleUrl)) return { kind: "unknown" };
    const raw = decodeURIComponent(moduleUrl);
    // The first three slash-separated fields are file: and the two empty fields in file:///.
    if (!raw.startsWith("file:///") || raw.split("/").slice(3).some(part => part === "." || part === ".." || part === "")) return { kind: "unknown" };
    const path = fileURLToPath(moduleUrl);
    const components = path.slice(1).split("/");
    // At least three components are required: a package root, dist and the entry filename.
    if (!path.startsWith("/") || Buffer.byteLength(path) > MAX_PACKAGE_PATH_BYTES || components.length > MAX_PACKAGE_COMPONENTS || components.some(part => !part || part === "." || part === "..") || components.at(-2) !== dist || components.at(-1) !== entry || components.length < 3) return { kind: "unknown" };
    const root = "/" + components.slice(0, -2).join("/");
    // Ancestors above the package root are not inspected: a symlinked ancestor relocates the whole package, so it cannot substitute a marker. These point-in-time checks require a trusted installation with no concurrent package writers; they do not authenticate a release.
    // With --preserve-symlinks-main, a symlinked bundle observes the link directory; entry links are outside this trusted-installation check.
    // Must match markerPaths and the exact { bigint: true } option check in server/scripts/evidence-pack-drill-isolation.ts.
    const before = fsOps.lstatSync(root, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink()) return { kind: "unknown" };
    let state: MarkerState;
    try {
      // Only the name's no-follow metadata matters; never open its contents or follow a target.
      const marker = fsOps.lstatSync(root + "/" + dist + "/" + NON_RELEASE_MARKER, { bigint: true });
      state = { kind: marker.isFile() ? "present" : "unknown" };
    } catch (error) {
      // Only this final ENOENT can establish absence; other observation failures refuse use.
      state = { kind: (error as NodeJS.ErrnoException)?.code === "ENOENT" ? "absent" : "unknown" };
    }
    const after = fsOps.lstatSync(root, { bigint: true });
    if (!after.isDirectory() || after.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino) return { kind: "unknown" };
    return state;
  } catch { return { kind: "unknown" }; }
}

/** Observe the executing verifier's package before any command or evidence input is consumed. */
export function observePackageMarker(moduleUrl: string, fsOps: MarkerFS): MarkerState {
  return observe(moduleUrl, fsOps, BIN["verify-evidence-pack"]);
}
/** The companion checker uses the same observation with its own fixed loader entry name. */
export function observeArtifactPackageMarker(moduleUrl: string, fsOps: MarkerFS): MarkerState {
  return observe(moduleUrl, fsOps, BIN["check-evidence-pack-artifact"]);
}

/** An absence observation permits the existing command; it is never release authentication. */
export function markerRefusal(value: unknown): string | undefined {
  const state = parseMarkerState(value);
  if (state.kind === "absent") return undefined;
  return state.kind === "present" ? NON_RELEASE_REFUSAL : PACKAGE_MARKER_UNAVAILABLE;
}
