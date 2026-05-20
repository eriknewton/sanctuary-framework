import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("dashboard wrapped-agent count surfaces", () => {
  it("derives sidebar, Agents, and Health counts from state.agents", async () => {
    const client = await readFile(
      join(process.cwd(), "src", "dashboard", "v1_1", "client.ts"),
      "utf-8"
    );

    expect(client).toContain("const count = state.agents.length;");
    expect(client).toContain("const totalAgents = state.agents.length;");
    expect(client).toContain(
      "'<section class=\"card\"><h3>Agents (' + state.agents.length + ')"
    );
  });
});
