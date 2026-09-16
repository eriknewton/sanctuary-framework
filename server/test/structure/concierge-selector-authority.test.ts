import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = resolve(process.cwd(), "src");

function source(relativePath: string): string {
  return readFileSync(resolve(SRC, relativePath), "utf8");
}

describe("concierge selector authority structural guard", () => {
  it("keeps the retired standalone Venice client out of the production tree", () => {
    expect(existsSync(resolve(SRC, "concierge/venice-client.ts"))).toBe(false);

    const liveConciergeFiles = [
      "concierge/concierge-service.ts",
      "cli/concierge.ts",
      "hub/hub-service.ts",
      "hub/api-router.ts",
      "dashboard/v1_1/wiring.ts",
    ];
    for (const file of liveConciergeFiles) {
      expect(source(file), `${file} must not construct a provider client`).not.toMatch(
        /new\s+(?:Venice|Frontier|Ollama)Client\s*\(/,
      );
      expect(source(file), `${file} must not import the retired direct client`).not.toContain(
        "concierge/venice-client",
      );
    }
  });

  it("pins both live stateless production composition roots to ConciergeService plus the selector", () => {
    const service = source("concierge/concierge-service.ts");
    const cli = source("cli/concierge.ts");
    const daemon = source("dashboard/v1_1/wiring.ts");

    expect(service).toContain('this.selector.invokeSummarize("concierge"');
    expect(cli).toContain("const selector = new SubstrateSelector({");
    expect(cli).toContain("selector,");
    expect(daemon).toContain("statelessConcierge = new ConciergeService({");
    expect(daemon).toContain("selector: inputs.intelligenceSelector");
    expect(daemon).toContain("concierge: statelessConcierge");
  });

  it("keeps the deterministic empty-context return before selector handle or invocation", () => {
    const service = source("concierge/concierge-service.ts");
    const shortCircuit = service.indexOf("isSummarizationQuery(question) && isEmptyContext(context)");
    const handle = service.indexOf('this.selector.getSubstrate("concierge")');
    const invoke = service.indexOf('this.selector.invokeSummarize("concierge"');

    expect(shortCircuit).toBeGreaterThan(-1);
    expect(handle).toBeGreaterThan(shortCircuit);
    expect(invoke).toBeGreaterThan(handle);
  });
});
