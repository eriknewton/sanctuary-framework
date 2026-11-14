import { lstatSync } from "node:fs";
import { runOfflineCommand, offlineIO, type OfflineIO } from "./snapshot-offline-cli.js";
import { observePackageMarker, markerRefusal } from "./snapshot-package-marker.js";
export { offlineIO };

/** Installed entry: classification precedes help, version, usage and every pin or snapshot read. */
export async function runInstalledOfflineCommand(argv: string[], moduleUrl: string, io: OfflineIO): Promise<number> {
  try {
    // Must match the mandatory loader URL and IO arguments in tsup.evidence-pack.config.ts.
    const refusal = markerRefusal(observePackageMarker(moduleUrl, { lstatSync }));
    if (refusal !== undefined) { await io.stderr(refusal); return 1; }
    return await runOfflineCommand(argv, io);
  } catch { return 1; }
}
