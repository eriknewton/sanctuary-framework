/**
 * Sanctuary Composition v1.0 -- Sidecar requirements.txt Hash-Pin Invariants
 *
 * WP-MVP-10 Follow-up #1 hardening item 2.
 *
 * Acceptance (test-side invariants that enforce the supply-chain posture):
 *  (a) sidecars/concordia/requirements.txt exists and carries --hash=sha256 for
 *      every pinned dependency.
 *  (b) The direct-dep source-of-truth file requirements.in is present and
 *      pins concordia-protocol to the Follow-up #1 baseline version.
 *  (c) Every workflow that installs from requirements.txt uses --require-hashes.
 *      Any new workflow that installs the sidecar MUST be added to the
 *      allow-list before this test will pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

const REPO_ROOT = join(__dirname, "..", "..", "..");
const REQUIREMENTS_TXT = join(
  REPO_ROOT,
  "sidecars",
  "concordia",
  "requirements.txt"
);
const REQUIREMENTS_IN = join(
  REPO_ROOT,
  "sidecars",
  "concordia",
  "requirements.in"
);
const WORKFLOWS_DIR = join(REPO_ROOT, ".github", "workflows");

// -----------------------------------------------------------------------
// File presence
// -----------------------------------------------------------------------

describe("sidecars/concordia/requirements files", () => {
  it("requirements.txt exists", () => {
    expect(existsSync(REQUIREMENTS_TXT)).toBe(true);
  });

  it("requirements.in exists (source of truth for direct deps)", () => {
    expect(existsSync(REQUIREMENTS_IN)).toBe(true);
  });
});

// -----------------------------------------------------------------------
// Hash-pin shape
// -----------------------------------------------------------------------

describe("requirements.txt hash-pin invariants", () => {
  const contents = existsSync(REQUIREMENTS_TXT)
    ? readFileSync(REQUIREMENTS_TXT, "utf-8")
    : "";

  it("carries at least one --hash=sha256: entry", () => {
    expect(contents).toMatch(/--hash=sha256:[0-9a-f]{64}/);
  });

  it("every non-comment non-blank 'package==version' line is followed by at least one --hash=sha256 entry", () => {
    // Walk lines. For every line that begins with "package==version" (possibly
    // followed by a trailing backslash), the logical entry extending across
    // continuation lines MUST contain at least one --hash=sha256:<hex> clause.
    const lines = contents.split("\n");
    const failures: Array<{ pkg: string; lineNo: number }> = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const stripped = line.replace(/\\\s*$/, "").trim();
      if (!stripped || stripped.startsWith("#")) continue;
      const pkgMatch = stripped.match(/^([A-Za-z0-9_.\-]+)==([^\s;]+)/);
      if (!pkgMatch) continue;
      // Collect the logical entry: this line + subsequent continuation lines
      // (previous line ended with \) OR subsequent --hash lines.
      let entry = stripped;
      let j = i;
      while (j < lines.length && lines[j].trimEnd().endsWith("\\")) {
        j++;
        if (j < lines.length) entry += " " + lines[j].trim();
      }
      if (!/--hash=sha256:[0-9a-f]{64}/.test(entry)) {
        failures.push({ pkg: pkgMatch[1], lineNo: i + 1 });
      }
    }
    expect(failures).toEqual([]);
  });

  it("header documents pip-compile + --generate-hashes as the regenerator", () => {
    expect(contents).toMatch(/pip-compile/);
    expect(contents).toMatch(/--generate-hashes/);
  });
});

describe("requirements.in shape", () => {
  const contents = existsSync(REQUIREMENTS_IN)
    ? readFileSync(REQUIREMENTS_IN, "utf-8")
    : "";

  it("pins concordia-protocol to 0.6.0 (the adopted baseline)", () => {
    expect(contents).toMatch(/concordia-protocol==0\.6\.0/);
  });
});

// -----------------------------------------------------------------------
// CI workflow invariant — no un-hashed sidecar install
// -----------------------------------------------------------------------

describe("CI workflows use --require-hashes for the Concordia sidecar install", () => {
  const workflows = existsSync(WORKFLOWS_DIR)
    ? readdirSync(WORKFLOWS_DIR).filter(
        (f) => f.endsWith(".yml") || f.endsWith(".yaml")
      )
    : [];

  it("at least one workflow file is present", () => {
    expect(workflows.length).toBeGreaterThan(0);
  });

  it("every workflow that pip-installs sidecars/concordia/requirements.txt passes --require-hashes", () => {
    const violations: Array<{ workflow: string; lineNo: number; line: string }> = [];
    for (const f of workflows) {
      const body = readFileSync(join(WORKFLOWS_DIR, f), "utf-8");
      const lines = body.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Match a pip install of the sidecar requirements.txt — whether the
        // path uses relative or absolute form.
        if (
          /pip\s+install/.test(line) &&
          /sidecars\/concordia\/requirements\.txt/.test(line)
        ) {
          if (!/--require-hashes/.test(line)) {
            violations.push({ workflow: f, lineNo: i + 1, line: line.trim() });
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
