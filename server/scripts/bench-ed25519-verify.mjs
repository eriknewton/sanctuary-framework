/**
 * Measure what the strict Ed25519 verification profile costs.
 *
 * The strict funnel in `src/core/identity.ts` decodes and subgroup-checks two
 * curve points (the public key A and the signature commitment R) before it
 * calls into @noble, and it pins @noble to the cofactorless equation with
 * `zip215: false`. Every Ed25519 verification in the product pays that, so the
 * number belongs in the PR that introduces it rather than in an estimate.
 *
 * Run:  npx tsx scripts/bench-ed25519-verify.mjs
 * (tsx, not plain node: the "after" arm imports the real TypeScript funnel
 * rather than a re-typed copy of it, so this cannot drift from what ships.)
 *
 * Failure mode to watch for: a run on a busy machine, or one where a laptop is
 * on battery and thermally throttled, reads as a much larger ratio than the
 * real one. Both arms are measured in the same process and interleaved round by
 * round so that drift moves them together; a ratio far outside the reported one
 * means the machine was contended, not that the profile got more expensive.
 */

import { execFileSync } from "node:child_process";
import { ed25519 } from "@noble/curves/ed25519";
import { verify as strictVerify } from "../src/core/identity.js";

const VERIFICATIONS_PER_ROUND = 1000;
const ROUNDS = 3;
/** Distinct keypairs, so no arm can benefit from a single hot decoded point. */
const KEYPAIRS = 32;

/**
 * The "before" arm, byte-for-byte the funnel body on origin/main.
 *
 * Must match the `return ed25519.verify(...)` line in
 * `server/src/core/identity.ts` as it stands on origin/main; `assertBaseline`
 * below fails the run if main no longer contains it, because a baseline that
 * silently stops being main's code turns this benchmark into fiction.
 */
const MAIN_FUNNEL_SOURCE = "return ed25519.verify(signature, payload, publicKey);";

function permissiveVerify(payload, signature, publicKey) {
  try {
    return ed25519.verify(signature, payload, publicKey);
  } catch {
    return false;
  }
}

function assertBaseline() {
  const mainSource = execFileSync(
    "git",
    ["show", "origin/main:server/src/core/identity.ts"],
    { encoding: "utf8" }
  );
  if (!mainSource.includes(MAIN_FUNNEL_SOURCE)) {
    throw new Error(
      "origin/main no longer contains the funnel this benchmark calls the " +
        "baseline; update MAIN_FUNNEL_SOURCE and permissiveVerify together."
    );
  }
}

function buildCorpus() {
  const corpus = [];
  for (let i = 0; i < KEYPAIRS; i++) {
    const priv = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(priv);
    // 64 bytes: a payload the size of a typical signed digest-plus-context
    // blob, so the measurement is dominated by curve work, not by hashing.
    const payload = new Uint8Array(64);
    payload.set(publicKey.subarray(0, 32), 0);
    payload[63] = i;
    corpus.push({ payload, signature: ed25519.sign(payload, priv), publicKey });
  }
  return corpus;
}

function timeRound(fn, corpus) {
  const started = performance.now();
  for (let i = 0; i < VERIFICATIONS_PER_ROUND; i++) {
    const entry = corpus[i % corpus.length];
    if (!fn(entry.payload, entry.signature, entry.publicKey)) {
      throw new Error("a valid signature failed to verify; benchmark invalid");
    }
  }
  return performance.now() - started;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function main() {
  assertBaseline();
  const corpus = buildCorpus();

  // Warm up both arms so JIT compilation lands outside the measured rounds.
  timeRound(permissiveVerify, corpus);
  timeRound(strictVerify, corpus);

  const before = [];
  const after = [];
  for (let round = 0; round < ROUNDS; round++) {
    before.push(timeRound(permissiveVerify, corpus));
    after.push(timeRound(strictVerify, corpus));
  }

  const beforeMedian = median(before);
  const afterMedian = median(after);
  const report = (label, ms) =>
    `${label}: ${ms.toFixed(1)} ms / ${VERIFICATIONS_PER_ROUND} verifications ` +
    `(${((ms * 1000) / VERIFICATIONS_PER_ROUND).toFixed(1)} us each)`;

  process.stdout.write(
    [
      `node ${process.version} on ${process.platform}/${process.arch}`,
      `${ROUNDS} rounds of ${VERIFICATIONS_PER_ROUND}, median reported`,
      report("before (origin/main, permissive)", beforeMedian),
      report("after  (this branch, strict)    ", afterMedian),
      `ratio: ${(afterMedian / beforeMedian).toFixed(2)}x`,
      "",
    ].join("\n")
  );
}

main();
