/** Shared name-only capture for the recipient and public descriptor exporter. */
import { lstatSync, type BigIntStats } from "node:fs";
// Must match the subprocess authority allowlist in snapshot-verifier-import-graph.test.ts.
import { execFileSync, spawnSync } from "node:child_process";
import * as C from "./snapshot-contract.js";
// Must match the held-handle calls in snapshot-offline-cli.ts and snapshot-trust-cli.ts.
export const METADATA_OUTPUT_LIMIT = C.MAX_NAME_BYTES * C.MAX_FILES;
export const METADATA_TIMEOUT_MS = 10_000; // Ten seconds bounds each metadata subprocess.
// Must match the exact subprocess policy consumed by evidence-pack-drill-isolation.ts.
export const LINUX_METADATA_PROGRAM = "import os,sys,json; print(json.dumps(os.listxattr(sys.argv[1], follow_symlinks=False)))";
export function metadataNames(path: string, platform: string = process.platform, held?: Pick<BigIntStats, "dev" | "ino">): string[] {
  // Fixed OS paths, closed argv, no stdin and an empty environment prevent metadata enumeration from selecting code or credentials through ambient state.
  const options = { env: { LC_ALL: "C" }, shell: false as const, timeout: METADATA_TIMEOUT_MS, maxBuffer: METADATA_OUTPUT_LIMIT, stdio: ["ignore", "pipe", "ignore"] as ["ignore", "pipe", "ignore"] };
  try {
    // Unsupported hosts cannot establish metadata capture and must report an environment finding.
    C.requireSnapshot(platform === "darwin" || platform === "linux", C.HARD.enumerator_unavailable);
    const recheck = () => {
      if (!held) return;
      let current: BigIntStats;
      try { current = lstatSync(path, { bigint: true }); } catch { throw new C.SnapshotError(C.HARD.snapshot_changed); }
      // Each path enumeration must still name the held inode before its names can be consumed.
      C.requireSnapshot(!current.isSymbolicLink() && current.dev === held.dev && current.ino === held.ino, C.HARD.snapshot_changed);
    };
    const bytes = execFileSync(platform === "darwin" ? "/usr/bin/xattr" : "/usr/bin/python3", platform === "darwin" ? ["-s", path] : ["-I", "-S", "-c", LINUX_METADATA_PROGRAM, path], options);
    recheck();
    const output = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const names: unknown = platform === "darwin" ? (output === "" ? [] : output.split(C.LF).slice(0, output.endsWith(C.LF) ? -1 : undefined)) : C.parseSnapshotJSON(C.utf8(output), METADATA_OUTPUT_LIMIT);
    // Only complete, unique allowed names may leave capture, so malformed labels cannot reach either consumer.
    C.requireSnapshot(Array.isArray(names) && names.every(n => typeof n === "string"), C.HARD.unexpected_metadata);
    C.requireSnapshot(new Set(names).size === names.length && names.every(n => C.OS_ATTACHED_METADATA.includes(n)), C.HARD.unexpected_metadata);
    if (platform === "darwin") for (const name of C.OS_ATTACHED_METADATA) {
      if (!names.includes(name)) continue;
      // Exact fixed-name existence checks disambiguate LF-joined labels while discarding all value bytes inside the OS subprocess.
      const found = spawnSync("/usr/bin/xattr", ["-s", "-p", name, path], { ...options, stdio: "ignore" });
      recheck();
      // An absent lookup executable leaves the local capture prerequisite unsatisfied.
      if ((found.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") throw new C.SnapshotError(C.HARD.enumerator_unavailable);
      C.requireSnapshot(!found.error && found.status === C.EXIT_PASS, C.HARD.unexpected_metadata);
    }
    return names;
  } catch (error) {
    // Only capture-specific findings retain their meaning at the metadata boundary.
    if (error instanceof C.SnapshotError && (error.code === C.HARD.snapshot_changed || error.code === C.HARD.enumerator_unavailable)) throw error;
    // An absent executable is a local capture prerequisite, distinct from observed metadata names.
    throw new C.SnapshotError((error as NodeJS.ErrnoException).code === "ENOENT" ? C.HARD.enumerator_unavailable : C.HARD.unexpected_metadata);
  }
}
