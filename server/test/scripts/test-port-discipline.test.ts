/**
 * Sigma-6 self-tests for the test-port-discipline regression gate
 * (server/scripts/test-port-discipline.ts).
 *
 * Coverage:
 *   - Detects hardcoded port literals in .listen() calls.
 *   - Allows .listen(0, ...) (ephemeral OS-assigned port).
 *   - Flags variable-port .listen() in files that don't use bindWithRetry.
 *   - Honors a same-line whitelist comment.
 *   - Honors a comment-above whitelist comment.
 *   - Returns zero violations on the actual repo (sanity gate; this
 *     test fails if anyone re-introduces a hardcoded port without an
 *     annotation).
 */

import { describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  scanFile,
  scanRepoTests,
} from "../../scripts/test-port-discipline.js";

/**
 * Vitest invocations may set cwd to either repo root or `server/`
 * depending on the runner; resolve the test dir relative to this
 * file's location so the repo-level check works regardless.
 */
const REPO_TEST_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);

function writeTempTest(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "port-discipline-test-"));
  const path = join(dir, "fixture.test.ts");
  writeFileSync(path, content, "utf-8");
  return path;
}

describe("Sigma-6 test-port-discipline gate — fixture-level checks", () => {
  it("flags a hardcoded port literal", () => {
    // port-discipline: ignore — fixture string for the gate's own self-test
    const fixturePort = "s.listen(36970, \"127.0.0.1\");\n";
    const path = writeTempTest(
      `import { createServer } from "node:http";\n` +
        `const s = createServer();\n` +
        fixturePort,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(1);
    expect(violations[0]!.reason).toContain("36970");
  });

  it("allows .listen(0, ...) (ephemeral port)", () => {
    const path = writeTempTest(
      `import { createServer } from "node:http";\n` +
        `const s = createServer();\n` +
        `s.listen(0, "127.0.0.1");\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  it("flags .listen(<var>) when the file does not import bindWithRetry", () => {
    const path = writeTempTest(
      `import { createServer } from "node:http";\n` +
        `const port = 12345;\n` +
        `const s = createServer();\n` +
        `s.listen(port, "127.0.0.1");\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations[0]!.reason).toContain("bindWithRetry");
  });

  it("allows .listen(<var>) when the file uses bindWithRetry", () => {
    const path = writeTempTest(
      `import { bindWithRetry } from "../util/port-collision-retry.js";\n` +
        `import { createServer } from "node:http";\n` +
        `await bindWithRetry(async () => {\n` +
        `  const port = randomTestPort();\n` +
        `  const s = createServer();\n` +
        `  s.listen(port, "127.0.0.1");\n` +
        `});\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  it("honors same-line whitelist comment", () => {
    // port-discipline: ignore — fixture asserts the whitelist annotation works
    const fixtureLine =
      "s.listen(36970, \"127.0.0.1\"); // port-discipline: ignore - fixture port for unit test\n";
    const path = writeTempTest(
      `import { createServer } from "node:http";\n` +
        `const s = createServer();\n` +
        fixtureLine,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  it("honors comment-above whitelist", () => {
    // port-discipline: ignore — fixture asserts the whitelist annotation works
    const fixtureLine = "s.listen(36970, \"127.0.0.1\");\n";
    const path = writeTempTest(
      `import { createServer } from "node:http";\n` +
        `const s = createServer();\n` +
        `// port-discipline: ignore - fixture port for unit test\n` +
        fixtureLine,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  // Sigma-7: detect local randomPort helpers (the api.test.ts class).
  it("Sigma-7: flags a locally-declared randomPort() function", () => {
    const path = writeTempTest(
      `function randomPort(): number {\n` +
        `  return 10000 + Math.floor(Math.random() * 50000);\n` +
        `}\n` +
        `const port = randomPort();\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations[0]!.reason).toContain("randomTestPort");
  });

  it("Sigma-7: flags a locally-declared randomPort const", () => {
    const path = writeTempTest(
      `const randomPort = () => 10000 + Math.floor(Math.random() * 50000);\n` +
        `const port = randomPort();\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBeGreaterThanOrEqual(1);
    expect(violations[0]!.reason).toContain("randomTestPort");
  });

  it("Sigma-7: allows the canonical randomTestPort import + use", () => {
    const path = writeTempTest(
      `import { bindWithRetry, randomTestPort } from "../util/port-collision-retry.js";\n` +
        `await bindWithRetry(async () => {\n` +
        `  const port = randomTestPort();\n` +
        `});\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  it("Sigma-7: honors whitelist comment above a local randomPort helper", () => {
    const path = writeTempTest(
      `// port-discipline: ignore - fixture-only helper; never binds\n` +
        `function randomPort(): number {\n` +
        `  return 1234;\n` +
        `}\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBe(0);
  });

  it("Sigma-7: bindWithRetry mention in a comment no longer satisfies the .listen(<var>) check", () => {
    // Pre-Sigma-7 a file could pass the gate just by mentioning the word
    // "bindWithRetry" in a comment (e.g. as a TODO). Sigma-7 tightens
    // the recognizer to require an actual call site.
    const path = writeTempTest(
      `// TODO: refactor to bindWithRetry in v1.x housekeeping\n` +
        `import { createServer } from "node:http";\n` +
        `const port = 12345;\n` +
        `const s = createServer();\n` +
        `s.listen(port, "127.0.0.1");\n`,
    );
    const violations = scanFile(path);
    expect(violations.length).toBeGreaterThanOrEqual(1);
  });
});

describe("Sigma-6 test-port-discipline gate — repo-level check", () => {
  it("the live repo passes the gate (catches regressions if a new hardcoded port lands)", () => {
    const violations = scanRepoTests(REPO_TEST_DIR);
    if (violations.length > 0) {
      // Surface what failed so a regression author sees it directly.
      const summary = violations
        .map((v) => `${v.file}:${v.line} — ${v.reason}\n  ${v.text}`)
        .join("\n");
      // eslint-disable-next-line no-console
      console.error("port-discipline violations:\n" + summary);
    }
    expect(violations).toEqual([]);
  });
});
