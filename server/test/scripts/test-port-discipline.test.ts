/**
 * Self-tests for the test-port-discipline regression gate
 * (server/scripts/test-port-discipline.ts).
 *
 * Coverage:
 *   - Detects hardcoded port literals in .listen() calls.
 *   - Allows .listen(0, ...) (ephemeral OS-assigned port).
 *   - Flags variable-port .listen() in files that don't use bindWithRetry.
 *   - Honors a same-line whitelist comment.
 *   - Honors a comment-above whitelist comment.
 *   - Rejects randomTestPort allocations outside retry attempts.
 *   - Returns zero violations on the actual repo (sanity gate; this
 *     test fails if anyone re-introduces a hardcoded port without an
 *     annotation).
 */

import { afterEach, describe, it, expect } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
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

const fixtureDirs: string[] = [];
afterEach(() => {
  for (const dir of fixtureDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function writeTempTest(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "port-discipline-test-"));
  fixtureDirs.push(dir);
  const path = join(dir, "fixture.test.ts");
  writeFileSync(path, content, "utf-8");
  return path;
}

describe("Sigma-6 test-port-discipline gate - fixture-level checks", () => {
  it("flags a hardcoded port literal", () => {
    // port-discipline: ignore - fixture string for the gate's own self-test
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
    // port-discipline: ignore - fixture asserts the whitelist annotation works
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
    // port-discipline: ignore - fixture asserts the whitelist annotation works
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

describe("random port allocation discipline", () => {
  it("flags a bare random port option passed to an internal binder", () => {
    const source = "startServer({ port: randomTestPort() });";
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({
        line: 1, // The allocation is on the only fixture line.
        text: source,
        reason: expect.stringContaining("randomTestPort() outside a bindWithRetry attempt"),
      }),
    ]);
  });

  it("flags a port assigned before a retry and then passed to an internal binder", () => {
    const allocation = "const port = randomTestPort();";
    const source = [
      allocation,
      "await bindWithRetry(async () => startServer({ port }));",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ line: 1, text: allocation }),
    ]);
  });

  it("flags a random option in a sibling callback after a completed retry", () => {
    const source = [
      "await bindWithRetry(async () => { await startServer({ port: randomTestPort() }); });",
      "it('next bind', async () => { await startServer({ port: randomTestPort() }); });",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ line: 2 }), // Only the second fixture line is unsafe.
    ]);
  });

  it("flags an allocation after a retry closes on the same line", () => {
    const source = "await bindWithRetry(async () => {}); startServer({ port: randomTestPort() });";
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ text: source }),
    ]);
  });

  it("flags a random allocation despite retry text in comments and strings", () => {
    const source = [
      "// bindWithRetry(async () => {",
      'const example = "bindWithRetry(async () => {";',
      "startServer({ port: randomTestPort() });",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ text: "startServer({ port: randomTestPort() });" }),
    ]);
  });

  it("flags random allocations in retry options outside the attempt", () => {
    const source = "bindWithRetry(() => startServer(), { jitterMs: randomTestPort() });";
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ text: source }),
    ]);
  });

  it("accepts a random option inside a block attempt despite nested delimiters", () => {
    const source = [
      "await bindWithRetry(async () => {",
      '  const punctuation = "});"; // });',
      "  if (ready) { await startServer({ ports: [randomTestPort()] }); }",
      "});",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("accepts a random option inside an expression attempt", () => {
    const source = "bindWithRetry(() => startServer({ port: randomTestPort() }));";
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("accepts multiline retry and allocation spellings", () => {
    const source = [
      "bindWithRetry(",
      "  async ( ) => {",
      "    return startServer({ port: randomTestPort (",
      "    ) });",
      "  },",
      ");",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("flags a direct random listen argument outside an attempt", () => {
    const source = "server.listen(randomTestPort());";
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ line: 1, text: source }),
    ]);
  });

  const regexCases = [
    { name: "quote", literal: String.raw`/"/` },
    { name: "brace", literal: String.raw`/}/` },
    { name: "comment opener", literal: String.raw`/[/*]/` },
    { name: "escaped slash", literal: String.raw`/a\//` },
  ];
  const positions = ["before", "after", "same line"] as const;
  const regexFixtures = regexCases.flatMap(({ name, literal }) => positions.map((position) => {
    // Pin bare and parenthesized callees together so each case detects an AST
    // regression as well as proving that both spellings have the same result.
    const allocation = "const port = randomTestPort(), wrapped = (randomTestPort)();";
    const regex = `const pattern = ${literal};`;
    const lines = position === "same line" ? [`${regex} ${allocation}`] :
      position === "before" ? [regex, allocation] : [allocation, regex];
    lines.push('const label = "done"; /* terminates misleading comment text */');
    return { name, position, source: lines.join("\n"), line: lines.findIndex((line) => line.includes(allocation)) + 1 };
  }));

  it.each(regexFixtures)("flags allocations with a $name regex $position", ({ source, line }) => {
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ line, text: source.split("\n")[line - 1] }),
      expect.objectContaining({ line, text: source.split("\n")[line - 1] }),
    ]);
  });

  it.each(regexFixtures)("accepts attempt allocations with a $name regex $position", ({ source }) => {
    expect(scanFile("fixture.test.ts", `bindWithRetry(() => {\n${source}\n});`)).toEqual([]);
  });

  const rejectedSyntax = [
    { name: "division outside an attempt", source: "const port = randomTestPort() / divisor + (randomTestPort)() / divisor;", count: 2 }, // Both calls are unprotected.
    { name: "template interpolation outside an attempt", source: "const url = `http://localhost:${randomTestPort()}`;", count: 1 },
    { name: "parenthesized callee outside an attempt", source: "(randomTestPort)();", count: 1 },
    { name: "non-null callee outside an attempt", source: "randomTestPort!();", count: 1 },
    { name: "nested timer callback inside an attempt", source: "bindWithRetry(() => { setTimeout(() => startServer({ port: randomTestPort() }), delay); });", count: 1 },
    { name: "inner function expression inside an attempt", source: "bindWithRetry(() => { consume(function () { return randomTestPort(); }); });", count: 1 },
    { name: "inner method inside an attempt", source: "bindWithRetry(() => { return { later() { return randomTestPort(); } }; });", count: 1 },
    { name: "allocation outside an attempt that only returns a port for a later bind", source: "const port = (randomTestPort)(); const allocated = bindWithRetry(() => port); startServer({ port: allocated });", count: 1 },
    { name: "parenthesized allocation in retry options", source: "bindWithRetry(() => startServer(), { jitterMs: (randomTestPort)() });", count: 1 },
    { name: "annotation text in a string", source: 'const label = "// port-discipline: ignore example"; randomTestPort();', count: 1 },
    { name: "annotation without a reason", source: "randomTestPort(); // port-discipline: ignore", count: 1 },
    { name: "block comment annotation", source: "randomTestPort(); /* port-discipline: ignore example */", count: 1 },
  ];
  it.each(rejectedSyntax)("flags $name", ({ source, count }) => {
    expect(scanFile("fixture.test.ts", source)).toEqual(Array.from({ length: count }, () =>
      expect.objectContaining({ line: 1, text: source, reason: expect.stringContaining("randomTestPort() outside") }),
    ));
  });

  it.each([
    { name: "division", source: "bindWithRetry(() => startServer({ port: randomTestPort() / divisor }));" },
    { name: "template interpolation", source: "bindWithRetry(() => startServer({ url: `http://localhost:${randomTestPort()}` }));" },
    { name: "parenthesized and non-null callees", source: "bindWithRetry(() => { (randomTestPort)(); randomTestPort!(); });" },
    { name: "an arrow return type", source: "bindWithRetry(async (): Promise<Handle> => startServer({ port: randomTestPort() }));" },
    { name: "a generic expression body with a comma", source: "bindWithRetry(() => startServer<Options, Handle>({ port: randomTestPort() }));" },
    { name: "generic retry type arguments", source: "bindWithRetry<Handle>(() => startServer({ port: randomTestPort() }));" },
    { name: "a function expression attempt", source: "bindWithRetry(async function () { return startServer({ port: randomTestPort() }); });" },
    { name: "a parenthesized attempt", source: "bindWithRetry((() => startServer({ port: randomTestPort() })));" },
    { name: "a direct random listen inside an attempt", source: "bindWithRetry(() => server.listen(randomTestPort()));" },
    // The nearest function is the attempt. The AST rule cannot follow the
    // returned value to prove that a later bind is protected by the retry.
    { name: "an attempt that only returns a port for a later bind", source: "const port = await bindWithRetry(async () => randomTestPort()); await startServer({ port });" },
  ])("accepts $name inside the nearest attempt", ({ source }) => {
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("accepts an allocation annotated on the same line", () => {
    const source = "refuse({ port: randomTestPort() }); // port-discipline: ignore refuses before listen";
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("accepts an allocation annotated on the preceding line", () => {
    const source = [
      "// port-discipline: ignore refuses before listen",
      "refuse({ port: randomTestPort() });",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("ignores random allocation examples in comments and quoted strings", () => {
    const source = [
      "// randomTestPort()",
      "/* randomTestPort() */",
      'const example = "randomTestPort()";',
      "const template = `randomTestPort()`;",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([]);
  });

  it("still rejects hardcoded listens inside retry attempts", () => {
    // port-discipline: ignore fixture text verifies the original literal rule.
    const source = "bindWithRetry(async () => { server.listen(12345); });";
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ reason: expect.stringContaining("hardcoded port literal") }),
    ]);
  });

  it("still rejects local randomPort helpers inside retry attempts", () => {
    const source = [
      "bindWithRetry(async () => {",
      "  const randomPort = () => candidatePort;",
      "});",
    ].join("\n");
    expect(scanFile("fixture.test.ts", source)).toEqual([
      expect.objectContaining({ reason: expect.stringContaining("local randomPort helper") }),
    ]);
  });
});

describe("Sigma-6 test-port-discipline gate - repo-level check", () => {
  it("keeps every repo test free of listen, local-helper, and random-allocation violations", () => {
    const violations = scanRepoTests(REPO_TEST_DIR);
    if (violations.length > 0) {
      // Surface what failed so a regression author sees it directly.
      const summary = violations
        .map((v) => `${v.file}:${v.line} - ${v.reason}\n  ${v.text}`)
        .join("\n");
      // eslint-disable-next-line no-console
      console.error("port-discipline violations:\n" + summary);
    }
    expect(violations).toEqual([]);
  });
});
