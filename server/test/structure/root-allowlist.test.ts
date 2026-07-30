/**
 * ROOT-ALLOWLIST guard (DoE review L-3).
 *
 * THE RISK: the repo root is the first thing a human or agent sees, and it is
 * where build-thread scratch leaks (historically files like BATCH1_HANDOFF.md,
 * BATCH2_PR_BODY.md, W4_HANDOFF.md, ESLINT_HANDOFF.md). One stray
 * `*_HANDOFF.md` at root reads as unprofessional and buries the real entry
 * points. The 2026-06-14 hygiene pass cleaned the root; nothing enforced it
 * staying clean.
 *
 * This test converts "the coordinator keeps the root tidy by hand" into a
 * CI-failing fact: the COMMITTED repo root may contain ONLY the allowlisted,
 * legitimate set of files/dirs. A new tracked top-level entry -> red, with a
 * message telling the author to either (a) move it into the right subtree, or
 * (b) add it to ALLOWLIST in this PR if it genuinely belongs at root.
 *
 * TRACKED-ONLY (the load-bearing design choice): the check enumerates the root
 * via `git ls-files`, i.e. the COMMITTED tree, NOT a raw `readdir`. Untracked
 * local/CI scratch therefore never trips it — a developer's notes, generated
 * artifacts, or CI state such as `.gnupg-ci` (created by
 * keychain-linux-real-backend.yml at the workspace root) are invisible to the
 * guard. A leaked `*_HANDOFF.md` only fails the build once it is committed,
 * which is exactly when a reviewer should catch it. This both fixes the
 * CI false-RED and makes the guard's contract precise: it gates what is
 * committed, nothing else.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

/**
 * Legitimate top-level entries (the committed, professional repo root). Keep
 * alphabetised. Adding a row is a conscious "this belongs at root" decision —
 * build-thread scratch (`*_HANDOFF.md`, `*_PR_BODY.md`, `W<n>...`, `ESLINT_*`,
 * `BATCH*`) must NOT be added here; move it into a subtree or delete it.
 *
 * This lists tracked top-level entries only. A top-level FILE appears by its
 * name; a top-level DIRECTORY appears by its name (any tracked file beneath it
 * counts the directory as present).
 */
const ALLOWLIST: ReadonlyArray<string> = [
  ".claude",
  ".editorconfig",
  ".gitattributes",
  ".githooks",
  ".github",
  ".gitignore",
  ".gitleaks.toml",
  ".test-baseline",
  ".test-baseline-overrides.log",
  "AGENTS.md",
  "ASSURANCE_MATRIX.md",
  "Archive",
  "CHANGELOG.md",
  "CLAUDE.md",
  "CODEX_BANNER_SUMMARY.md",
  "CODEX_BANNER_VERDICT.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "LICENSE",
  "README.md",
  "ROADMAP.md",
  "SANCTUARY_ARCHITECTURE.md",
  "SECURITY.md",
  "Sanctuary Site",
  "announcements",
  "castle-wall-daemon",
  "castle-wall-macos",
  "castle-wall-vmm",
  "docs",
  "examples",
  "integrations",
  "menubar",
  "package.json",
  "plugin",
  "quickstart",
  "rfcs",
  "sanctuary_framework.md",
  "scripts",
  "server",
  "sidecars",
];

/**
 * The distinct top-level entries in the COMMITTED tree (the first path segment
 * of every tracked path). This is the set the allowlist gates; untracked
 * working-copy noise is intentionally excluded.
 */
function trackedTopLevelEntries(): string[] {
  const out = execFileSync("git", ["-C", REPO_ROOT, "ls-files", "-z"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const top = new Set<string>();
  for (const raw of out.split("\0")) {
    if (!raw) continue;
    const rel = raw.replace(/\\/g, "/");
    const slash = rel.indexOf("/");
    top.add(slash === -1 ? rel : rel.slice(0, slash));
  }
  return [...top].sort();
}

describe("root-allowlist guard (no leaked scratch at repo root)", () => {
  it("the committed repo root contains only allowlisted entries", () => {
    const tracked = trackedTopLevelEntries();

    const allow = new Set(ALLOWLIST);
    const unexpected = tracked.filter((name) => !allow.has(name));
    const missing = ALLOWLIST.filter((name) => !tracked.includes(name));

    // `missing` is ADVISORY, not a failure: the rule is "no UNAPPROVED root
    // entries". A legitimate cleanup/removal PR (deleting a file the allowlist
    // still lists) improves hygiene and must NOT red — it should only prompt a
    // stale-row tidy. So we warn on `missing` and fail only on `unexpected`.
    if (missing.length) {
      console.warn(
        "[root-allowlist] ADVISORY: ALLOWLIST lists entr(ies) no longer " +
          "present at root (a legitimate removal/rename): " +
          missing.join(", ") +
          " — drop the stale row(s) from ALLOWLIST when convenient.",
      );
    }

    expect(
      unexpected,
      "Repo-root hygiene drift (DoE review L-3).\n" +
        "  Unexpected committed top-level entr(ies): " +
        unexpected.join(", ") +
        "\n  -> If this is leaked build/coordinator scratch (e.g. a " +
        "*_HANDOFF.md / *_PR_BODY.md), delete it or move it into a subtree. " +
        "If it genuinely belongs at root, add it to ALLOWLIST in this PR.\n",
    ).toEqual([]);
  });

  it("the allowlist itself has no duplicates and is sorted", () => {
    const dupes = ALLOWLIST.filter((v, i) => ALLOWLIST.indexOf(v) !== i);
    expect(dupes, `duplicate allowlist entries: ${dupes.join(", ")}`).toEqual(
      [],
    );
    const sorted = [...ALLOWLIST].sort();
    expect(
      ALLOWLIST,
      "ALLOWLIST should be kept alphabetically sorted for reviewability.",
    ).toEqual(sorted);
  });
});
