import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const SRC_ROOT = join(SERVER_ROOT, "src");

function sourceFiles(dir = SRC_ROOT): string[] {
  const files: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) files.push(...sourceFiles(path));
    else if (path.endsWith(".ts")) files.push(path);
  }
  return files;
}

function rel(path: string): string {
  return relative(SRC_ROOT, path).replaceAll("\\", "/");
}

describe("Memory Integrity Slice B — frozen production assembler inventory", () => {
  it("freezes every typed selector invocation site", () => {
    const callsites = sourceFiles()
      .filter((path) => /\.invoke(?:Summarize|Classify|Redact)\s*\(/.test(readFileSync(path, "utf8")))
      .map(rel)
      .sort();
    expect(callsites).toEqual([
      "chat/operator-chat-service.ts",
      "concierge/concierge-service.ts",
      "coordination/context-transfer-extractor.ts",
      "dashboard/v1_1/wiring.ts",
      "honeypot/honeypot-compiler.ts",
      "policy-engine/english-policy-compiler.ts",
      "query-anonymity/intent-classifier.ts",
      "query-anonymity/pii-rewrite.ts",
    ]);
    const sentinelAdapter = readFileSync(
      join(SRC_ROOT, "sentinel/sentinels/suspicious-tool-call-detector.ts"),
      "utf8",
    );
    expect(sentinelAdapter).toContain("selector.invokeClassify as");
    expect(sentinelAdapter).toContain("fn.call(selector");
  });

  it("freezes provider pass-through callsites and rejects direct concierge construction", () => {
    const directClientCalls = sourceFiles()
      .filter((path) => /this\.client\.(?:generate|chat)\s*\(|this\.venice\.complete\s*\(/.test(readFileSync(path, "utf8")))
      .map(rel)
      .sort();
    expect(directClientCalls).toEqual([
      "intelligence/substrates/frontier.ts",
      "intelligence/substrates/local.ts",
      "intelligence/substrates/venice.ts",
    ]);
    const concierge = readFileSync(join(SRC_ROOT, "concierge/concierge-service.ts"), "utf8");
    expect(concierge).not.toContain("VeniceClient");
    expect(concierge).not.toContain("this.venice");
    expect(concierge).toContain('this.selector.invokeSummarize("concierge", {');
  });

  it("requires scan-after-final-assembly and scan-before-provider ordering", () => {
    const selector = readFileSync(join(SRC_ROOT, "intelligence/selector.ts"), "utf8");
    const invoke = selector.slice(selector.indexOf("  private async invoke("), selector.indexOf("  /**\n   * Append a failure entry"));
    expect(invoke.indexOf("compileSubstrateContext(surface, req)")).toBeGreaterThan(-1);
    expect(invoke.indexOf("compileSubstrateContext(surface, req)")).toBeLessThan(invoke.indexOf("this.buildHandle(surface, choice)"));

    const concierge = readFileSync(join(SRC_ROOT, "concierge/concierge-service.ts"), "utf8");
    expect(concierge).toContain(
      "context: JSON.stringify(buildConciergePrompt({ question, context }))",
    );
    expect(concierge).toContain("query: question");
    expect(concierge).not.toContain("compileLegacyConciergeContext");
  });

  it("requires real production reporter wiring at every runtime construction path", () => {
    const main = readFileSync(join(SRC_ROOT, "index.ts"), "utf8");
    expect(main).toContain("createDispatcherWiredCompiledContextScanner");
    expect(main).toContain("dispatcher: sentinelDispatcher");
    expect(main).toContain("setCompiledContextScanner");

    const standalone = readFileSync(join(SRC_ROOT, "dashboard-standalone.ts"), "utf8");
    expect(standalone).toContain("createCompiledContextRuntime");
    expect(standalone).toContain("compiledContextScanner: compiledContextRuntime.scanner");
    expect(standalone).toContain("sentinelFindingStore: compiledContextRuntime.findingStore");

    for (const path of ["cli/concierge.ts", "cli/policy.ts"]) {
      const source = readFileSync(join(SRC_ROOT, path), "utf8");
      expect(source).toContain("createCompiledContextRuntime");
      expect(source).toContain("compiledContextScanner: compiledContextRuntime.scanner");
    }
  });
});
