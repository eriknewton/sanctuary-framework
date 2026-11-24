import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../../src", import.meta.url));

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sourceFiles(path) : path.endsWith(".ts") ? [path] : [];
  });
}

describe("local task test seams", () => {
  it("no source file other than index.ts names the local task test option", () => {
    const naming = sourceFiles(SRC)
      .filter((path) => readFileSync(path, "utf8").includes("__testLocalTask"))
      .map((path) => relative(SRC, path));
    expect(naming).toEqual(["index.ts"]);
  });

  it("index.ts honours the option only under the test runner", () => {
    const text = readFileSync(join(SRC, "index.ts"), "utf8");
    expect(text).toContain("const testLocalTask = process.env.VITEST ? options?.__testLocalTask : undefined;");
    expect(text.match(/options\?\.__testLocalTask/g)).toHaveLength(1);
  });
});
