#!/usr/bin/env node
// check-roadmap-date.mjs: the ROADMAP.md "Last updated:" header must move with the file.
//
// WHY THIS EXISTS (2026-10-02):
// ROADMAP.md carried "Last updated: 2026-08-18" while the file itself changed on
// 2026-10-01. The roadmap-freshness PR gate checked only that a feature PR TOUCHED
// the file, so every edit passed while the header went stale for six weeks, and a
// reader had no way to tell how current the status sections were. This guard makes
// the header a mechanical fact instead of a convention.
//
// Invariant (fails closed, exit 1): when ROADMAP.md differs between BASE and HEAD,
// the HEAD version must contain exactly one "Last updated: YYYY-MM-DD" header, and
// that date must fall within the window [head commit date - LOOKBACK_DAYS,
// head commit date + FUTURE_SKEW_DAYS]. A PR that does not touch ROADMAP.md passes.
//
// LOOKBACK_DAYS = 3: a PR edited on one day and pushed after a weekend still passes;
// a header copied forward from weeks earlier does not. FUTURE_SKEW_DAYS = 1 absorbs
// the author's local timezone being ahead of the UTC commit date; anything further
// ahead is a typo or a fabricated date.
//
// Usage: node scripts/check-roadmap-date.mjs <base-sha> <head-sha>
// Must match the step "Require the ROADMAP.md header date to move with the file"
// in .github/workflows/roadmap-freshness.yml.

import { execFileSync } from "node:child_process";

const LOOKBACK_DAYS = 3;
const FUTURE_SKEW_DAYS = 1;
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const HEADER = /^Last updated: (\d{4}-\d{2}-\d{2})\b/gm;

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" });
}

function fail(msg) {
  console.error(`::error::${msg}`);
  process.exit(1);
}

const [base, head] = process.argv.slice(2);
if (!base || !head) fail("usage: check-roadmap-date.mjs <base-sha> <head-sha>");

const changed = git("diff", "--name-only", base, head).split("\n").includes("ROADMAP.md");
if (!changed) {
  console.log("ROADMAP.md unchanged in this range; header date not checked.");
  process.exit(0);
}

let text;
try {
  text = git("show", `${head}:ROADMAP.md`);
} catch {
  // A deleted roadmap is a reviewable choice, not a stale header.
  console.log("ROADMAP.md removed in this range; header date not checked.");
  process.exit(0);
}

const dates = [...text.matchAll(HEADER)].map((m) => m[1]);
if (dates.length !== 1) {
  fail(`ROADMAP.md must contain exactly one "Last updated: YYYY-MM-DD" line; found ${dates.length}.`);
}

const header = new Date(`${dates[0]}T00:00:00Z`);
if (Number.isNaN(header.getTime())) fail(`ROADMAP.md header date "${dates[0]}" is not a real date.`);

const commitIso = git("show", "-s", "--format=%cI", head).trim();
const commitDay = new Date(`${commitIso.slice(0, 10)}T00:00:00Z`);
const ageDays = Math.round((commitDay - header) / MS_PER_DAY);

if (ageDays > LOOKBACK_DAYS) {
  fail(
    `ROADMAP.md changed in this PR but its header still reads "Last updated: ${dates[0]}", ` +
      `${ageDays} days before the head commit (${commitIso.slice(0, 10)}). Update the header date in the same PR.`,
  );
}
if (ageDays < -FUTURE_SKEW_DAYS) {
  fail(`ROADMAP.md header date ${dates[0]} is ${-ageDays} days after the head commit date; fix the date.`);
}
console.log(`ROADMAP.md header date ${dates[0]} is current (head commit ${commitIso.slice(0, 10)}).`);
