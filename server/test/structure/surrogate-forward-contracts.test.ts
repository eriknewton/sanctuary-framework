/** Capability: forward transport trust and fixed event fields stay confined to their intended seams. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createRequire } from "node:module";
import type * as TypeScript from "typescript";
const ts = createRequire(import.meta.url)("typescript") as typeof TypeScript;
import { describe, expect, it } from "vitest";

const source = (file: string) => readFileSync(resolve("src", file), "utf8");
describe("surrogate forward contracts", () => {
  it("production argv wiring supplies no upstream factory and no custom trust option", () => {
    const gate = source("egress-gate/gate-server.ts"); const daemon = source("egress-gate/gate-daemon.ts");
    expect(gate.includes("options.upstreamRequest ?? https.request")).toBe(true);
    for (const text of [gate, daemon]) {
      expect(/\bca\s*[:?=]/.test(text)).toBe(false);
      expect(/rejectUnauthorized\s*:\s*false/.test(text)).toBe(false);
    }
    const entry = ts.createSourceFile("cli.ts", source("cli.ts"), ts.ScriptTarget.Latest, true);
    const calls: TypeScript.CallExpression[] = [];
    const visit = (node: TypeScript.Node): void => {
      if (ts.isCallExpression(node) && node.expression.getText(entry) === "runEgressGateDaemon") calls.push(node);
      ts.forEachChild(node, visit);
    };
    visit(entry);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.arguments[0]!.getText(entry)).toBe("{ agentUid }");
    expect(gate.includes("checkServerIdentity(target.host, certificate)")).toBe(true);
  });
  it("surrogate event types allow no free-form string field except canonical authority", () => {
    const sf = ts.createSourceFile("gate.ts", source("egress-gate/gate-server.ts"), ts.ScriptTarget.Latest, true);
    const event = sf.statements.find(s => ts.isTypeAliasDeclaration(s) && s.name.text === "SurrogateGateEvent");
    expect(event).toBeDefined();
    const walk = (node: TypeScript.Node): void => {
      if (ts.isPropertySignature(node)) {
        const name = node.name.getText(sf);
        expect(name).not.toBe("message");
        if (name !== "authority") expect(node.type?.kind).not.toBe(ts.SyntaxKind.StringKeyword);
      }
      ts.forEachChild(node, walk);
    };
    walk(event!);
  });
  it("correlation is a validated opaque id on gate and helper event types", () => {
    const helper = source("egress-gate/surrogate-helper-daemon.ts");
    const gate = source("egress-gate/gate-server.ts");
    expect(helper).toContain('kind: "query_answered"; agentUid: number; binding: number; correlationId: SurrogateCorrelationId');
    expect(gate).toContain("correlationId?: SurrogateCorrelationId");
    expect(source("credential-surrogate/forward.ts")).toContain("isSurrogateCorrelationId(value)");
  });
});
