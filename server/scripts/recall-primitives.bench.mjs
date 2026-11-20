// Primitive cost microbenchmark behind the recall cost model. NOT a CI test; run from server/:
//
//   node scripts/recall-primitives.bench.mjs
//
// It times a strict Ed25519 point check, a strict verify, the full per-signature verification recall performs,
// an AES-GCM decrypt of a passage-sized record, and the file open/stat/read/close a record read costs, then prints
// the per-passage cost of the two signature verifications recall makes per verified passage.
// Failure modes: timings from a busy host are inflated and nothing here detects contention; the file timings
// measure the OS temp directory's filesystem, which may differ from the fortress's; the temporary files are
// removed at the end, but a SIGKILL mid-run leaves a `recall-bench-*` directory in the OS temp directory.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";

const WARMUP = 20; // Twenty untimed calls settle the JIT before each timed loop.
const SIGNED_BYTES = 400; // About the size of a signed provenance body.
const RECORD_BYTES = 1200; // About one short passage's encrypted chunk record.
const FILE_BYTES = 900; // About one encrypted record file on disk.
const FILES = 500; // Five hundred files cycle past small caches.
const ASYNC_READS = 2000; // The corpus ceiling, MEMORY_CORPUS_SCAN_CAP.

function strict(bytes) {
  const point = ed25519.Point.fromBytes(bytes, false);
  if (point.isSmallOrder() || !point.isTorsionFree()) return false;
  return point.toBytes().every((byte, index) => byte === bytes[index]);
}
function time(label, n, fn) {
  for (let i = 0; i < WARMUP; i++) fn();
  const started = process.hrtime.bigint();
  for (let i = 0; i < n; i++) fn();
  const ms = Number(process.hrtime.bigint() - started) / 1e6 / n; // 1e6 nanoseconds per millisecond.
  console.log(label, ms.toFixed(4), "ms");
  return ms;
}

const secret = ed25519.utils.randomPrivateKey ? ed25519.utils.randomPrivateKey() : ed25519.utils.randomSecretKey();
const publicKey = ed25519.getPublicKey(secret);
const message = randomBytes(SIGNED_BYTES);
const signature = ed25519.sign(message, secret);
time("strict point check", 400, () => strict(publicKey));
time("ed25519.verify zip215:false", 400, () => ed25519.verify(signature, message, publicKey, { zip215: false }));
// Ed25519 signatures carry their 32-byte R point first.
const full = time("full strict verify (2 checks + verify)", 300, () => {
  strict(publicKey); strict(signature.subarray(0, 32)); ed25519.verify(signature, message, publicKey, { zip215: false });
});
const key = randomBytes(32), nonce = randomBytes(12), aad = randomBytes(40); // AES-256 key, 96-bit GCM nonce.
const ciphertext = gcm(key, nonce, aad).encrypt(randomBytes(RECORD_BYTES));
time(`aes-gcm decrypt ${RECORD_BYTES} B`, 3000, () => gcm(key, nonce, aad).decrypt(ciphertext));

const dir = fs.mkdtempSync(join(tmpdir(), "recall-bench-"));
const files = [];
try {
  for (let i = 0; i < FILES; i++) { const path = join(dir, `x${i}`); fs.writeFileSync(path, randomBytes(FILE_BYTES)); files.push(path); }
  let k = 0;
  time(`open+fstat+read+close sync ${FILE_BYTES} B`, 5000, () => {
    const fd = fs.openSync(files[k++ % FILES], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    fs.fstatSync(fd); const buffer = Buffer.alloc(FILE_BYTES); fs.readSync(fd, buffer, 0, FILE_BYTES, 0); fs.closeSync(fd);
  });
  const started = process.hrtime.bigint();
  for (let i = 0; i < ASYNC_READS; i++) {
    const handle = await fs.promises.open(files[i % FILES], fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    await handle.stat(); await handle.readFile(); await handle.close();
  }
  console.log("async open+stat+readFile+close", (Number(process.hrtime.bigint() - started) / 1e6 / ASYNC_READS).toFixed(4), "ms");
} finally {
  for (const path of files) fs.unlinkSync(path);
  fs.rmdirSync(dir);
}
console.log("two strict verifications per passage:", (2 * full).toFixed(3), "ms");
