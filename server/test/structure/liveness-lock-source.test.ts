/** Every production recorder constructor must supply the required audit recovery source. */
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";

const sourceRoot = join(__dirname, "../../src");
function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : entry.name.endsWith(".ts") ? [path] : [];
  });
}

it("requires the lock source in the recorder type and every production construction", () => {
  const calls: string[] = [];
  let requiredSource = false;
  for (const path of sourceFiles(sourceRoot)) {
    const file = ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);
    const names = new Set(["LivenessRecorder"]);
    for (const statement of file.statements) {
      if (!ts.isImportDeclaration(statement)) continue;
      const bindings = statement.importClause?.namedBindings;
      if (bindings && ts.isNamedImports(bindings)) {
        for (const binding of bindings.elements) {
          if ((binding.propertyName ?? binding.name).text === "LivenessRecorder") names.add(binding.name.text);
        }
      }
    }
    function visit(node: ts.Node): void {
      if (ts.isInterfaceDeclaration(node) && node.name.text === "LivenessRecorderOptions") {
        const source = node.members.find(member => member.name?.getText(file) === "lockRecovery");
        requiredSource = !!source && ts.isPropertySignature(source) && !source.questionToken;
      }
      if (ts.isNewExpression(node) && names.has(node.expression.getText(file))) {
        const location = relative(sourceRoot, path);
        calls.push(location);
        const options = node.arguments?.[0];
        expect(options && ts.isObjectLiteralExpression(options), location).toBe(true);
        if (options && ts.isObjectLiteralExpression(options)) {
          expect(options.properties.some(property => property.name?.getText(file) === "lockRecovery"), location).toBe(true);
        }
      }
      ts.forEachChild(node, visit);
    }
    visit(file);
  }
  expect(requiredSource, "lockRecovery must be required at the type boundary").toBe(true);
  expect(calls.length, "the production recorder constructor must remain reachable").toBeGreaterThan(0);
});
