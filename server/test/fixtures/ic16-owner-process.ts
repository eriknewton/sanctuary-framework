import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  createPersistentMultiAgentIsolationGuard,
  transferSdwOwnerForOperator,
} from "../../src/sdw/memory-isolation.js";

const [mode, statePath, keyHex, fortressId, first, second] = process.argv.slice(2);
if (!mode || !statePath || !keyHex || !fortressId || !first) process.exit(2);
const storage = new FilesystemStorage(statePath);
const masterKey = new Uint8Array(Buffer.from(keyHex, "hex"));

const result =
  mode === "guard"
    ? await createPersistentMultiAgentIsolationGuard({
        storage,
        masterKey,
        fortressId,
        ownerRef: "fleet-self",
        ownerIdentity: () => first,
      })("memory_count")
    : mode === "transfer" && second
      ? await transferSdwOwnerForOperator({
          storage,
          masterKey,
          fortressId,
          ownerRef: "fleet-self",
          expectedAgentId: first,
          newAgentId: second,
        })
      : { status: "bad_args" };

process.stdout.write(`${JSON.stringify(result)}\n`);
masterKey.fill(0);
