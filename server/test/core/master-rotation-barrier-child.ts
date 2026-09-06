/**
 * Real-process fixture for the shared side of the master-rotation barrier.
 * It unlocks the old master, waits until the parent has bound the exclusive
 * rotation gate, then performs one last ordinary encrypted store write before
 * releasing its shared lease.
 */

import { once } from "node:events";

import { establishMaster } from "../../src/core/master-custody.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const [storagePath, passphrase] = process.argv.slice(2);
if (!storagePath || !passphrase) throw new Error("missing writer fixture arguments");

const storage = new FilesystemStorage(storagePath);
const custody = await establishMaster({ storage, passphrase });
try {
  process.stdout.write("READY\n");
  const [chunk] = await once(process.stdin, "data") as [Buffer];
  if (chunk.toString("utf8").trim() !== "WRITE") {
    throw new Error("unexpected writer fixture command");
  }
  const payload = encrypt(
    stringToBytes(JSON.stringify({ source: "paused-old-master-writer" })),
    derivePurposeKey(custody.masterKey, "l4-reputation"),
  );
  await storage.write(
    "_reputation",
    "late-writer",
    stringToBytes(JSON.stringify(payload)),
  );
  process.stdout.write("WROTE\n");
} finally {
  await custody.masterWriteBarrier?.release();
  custody.masterKey.fill(0);
}
