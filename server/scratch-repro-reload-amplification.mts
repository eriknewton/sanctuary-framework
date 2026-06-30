/**
 * Repro: audit-chain reload amplification (the real Slice-M daemon OOM).
 *
 * Seeds a LARGE on-disk audit log (tens of thousands of entries, each with a
 * non-trivial decrypted payload), then drives `verifiedChainView()` repeatedly
 * (the daemon's transparency-emit / periodic re-verify tick) and samples RSS.
 *
 * Before the fix: each call re-decrypts the WHOLE chain into a fresh
 * AuditEntry[] -> per-tick allocation scales with the on-disk log size; RSS
 * spikes far above the steady-state working set.
 *
 * Run:  npx tsx scratch-repro-reload-amplification.mts <numEntries> <payloadBytes> <ticks>
 */
import { AuditLog } from "./src/operational/audit-log.js";
import { MemoryStorage } from "./src/storage/memory.js";
import { generateRandomKey } from "./src/core/random.js";

const numEntries = Number(process.argv[2] ?? 20000);
const payloadBytes = Number(process.argv[3] ?? 512);
const ticks = Number(process.argv[4] ?? 20);

function rssMB(): number {
  return Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10;
}
function heapMB(): number {
  return Math.round((process.memoryUsage().heapUsed / (1024 * 1024)) * 10) / 10;
}

const storage = new MemoryStorage();
const masterKey = generateRandomKey();
// Big disk cap so nothing rotates out; in-memory window stays small.
const log = new AuditLog(storage, masterKey, {
  maxEntries: 1_000_000,
  maxTotalSizeBytes: 10 * 1024 * 1024 * 1024,
  maxInMemoryEntries: 256,
});

const blob = "x".repeat(payloadBytes);

console.log(
  `Seeding ${numEntries} entries, ~${payloadBytes}B payload each, RSS@start=${rssMB()}MB`
);
for (let i = 0; i < numEntries; i++) {
  // Mix egress events so the enforcement recount path also has work.
  const op = i % 2 === 0 ? "egress_allowed" : "egress_blocked";
  await log.append("l1", op, `id-${i % 8}`, {
    rule_id: `rule-${i % 16}`,
    blob,
    i,
  });
  if (i % 5000 === 0 && i > 0) {
    console.log(`  seeded ${i}  RSS=${rssMB()}MB heap=${heapMB()}MB`);
  }
}
// Let the append queue + persist drain.
await new Promise((r) => setTimeout(r, 1000));
const onDisk = (await storage.list("_audit")).length;
console.log(`Seeded. on-disk entries=${onDisk}  RSS=${rssMB()}MB heap=${heapMB()}MB`);

if (global.gc) global.gc();
const baselineRss = rssMB();
const baselineHeap = heapMB();
console.log(`Post-GC baseline: RSS=${baselineRss}MB heap=${baselineHeap}MB`);

let peakRss = baselineRss;
let peakHeap = baselineHeap;
const start = Date.now();
for (let t = 0; t < ticks; t++) {
  const view = await log.verifiedChainView();
  // Touch the view so it is not optimized away; simulate the consumer fold.
  let acc = 0;
  for (const item of view) acc += item.entry.sequence;
  peakRss = Math.max(peakRss, rssMB());
  peakHeap = Math.max(peakHeap, heapMB());
  if (t % 5 === 0) {
    console.log(
      `  tick ${t}: viewLen=${view.length} acc=${acc} RSS=${rssMB()}MB heap=${heapMB()}MB`
    );
  }
}
const elapsed = Date.now() - start;
if (global.gc) global.gc();
const endRss = rssMB();

console.log("\n=== RESULT ===");
console.log(`on-disk entries:        ${onDisk}`);
console.log(`payload bytes/entry:    ${payloadBytes}`);
console.log(`ticks (verifiedChainView calls): ${ticks}  (${elapsed}ms total)`);
console.log(`baseline RSS (post-GC): ${baselineRss}MB`);
console.log(`PEAK RSS during ticks:  ${peakRss}MB   (delta +${Math.round((peakRss - baselineRss) * 10) / 10}MB)`);
console.log(`PEAK heap during ticks: ${peakHeap}MB  (delta +${Math.round((peakHeap - baselineHeap) * 10) / 10}MB)`);
console.log(`post-ticks RSS (post-GC): ${endRss}MB`);
