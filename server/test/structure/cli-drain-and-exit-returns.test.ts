import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI_ENTRY = join(process.cwd(), "src", "cli.ts");

// drainAndExit schedules the exit on a stdout write callback, so a dispatch branch that calls it without
// returning keeps running main() through the later branches into the default server start before the exit lands.
describe("CLI dispatch ends at drainAndExit", () => {
  it("every drainAndExit call in the CLI entry is returned", async () => {
    const source = await readFile(CLI_ENTRY, "utf8");
    const calls = [...source.matchAll(/^(.*)\bdrainAndExit\(/gm)].filter((m) => !/\bfunction\s+$/.test(m[1]));
    expect(calls.length).toBeGreaterThan(0);
    const bare = calls
      .filter((m) => !/\breturn\s+$/.test(m[1]))
      .map((m) => source.slice(0, m.index).split("\n").length);
    expect(bare).toEqual([]);
  });
});
