import { join } from "node:path";

import { establishMaster } from "../../src/core/master-custody.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

/**
 * Establish real custody before a test invokes an observation-only verb such
 * as `provision-pin`. Production provisioners must never mint credentials;
 * tests that need a fortress therefore create it explicitly at the same
 * custody API boundary as init/wrap.
 */
export async function initializeTestCustody(
  fortressPath: string,
  credential: { passphrase: string } | { recoveryKey: string },
): Promise<void> {
  const established = await establishMaster({
    storage: new FilesystemStorage(join(fortressPath, "state")),
    ...credential,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
    storagePathHint: fortressPath,
  });
  established.masterKey.fill(0);
  await established.masterWriteBarrier?.release();
}
