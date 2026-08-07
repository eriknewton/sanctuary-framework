import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import { runCompletionCommand } from "../../src/cli/completion.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

class Capture extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _enc: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    cb();
  }
  text(): string {
    return this.chunks.join("");
  }
}

describe("sanctuary completion", () => {
  it("emits bash completions from the shared subcommand list", async () => {
    const out = new Capture();
    const code = await runCompletionCommand({ argv: ["bash"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("complete -F _sanctuary_completion");
    for (const command of TOP_LEVEL_SUBCOMMANDS) {
      expect(out.text()).toContain(command);
    }
  });

  it("keeps completion entries for dispatched fleet and agent commands", async () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("agent");
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("fleet");

    for (const shell of ["bash", "zsh", "fish"]) {
      const out = new Capture();
      const code = await runCompletionCommand({ argv: [shell], out });
      expect(code).toBe(0);
      expect(out.text()).toMatch(/\bagent\b/);
      expect(out.text()).toMatch(/\bfleet\b/);
    }
  });

  it("emits zsh completions", async () => {
    const out = new Capture();
    const code = await runCompletionCommand({ argv: ["zsh"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("#compdef sanctuary sanctuary-mcp-server");
    expect(out.text()).toContain("'doctor:sanctuary doctor'");
  });

  it("emits fish completions", async () => {
    const out = new Capture();
    const code = await runCompletionCommand({ argv: ["fish"], out });
    expect(code).toBe(0);
    expect(out.text()).toContain("__fish_use_subcommand");
    expect(out.text()).toContain("audit-chain");
  });

  it("rejects missing or unknown shell", async () => {
    const err = new Capture();
    expect(await runCompletionCommand({ argv: [], err })).toBe(2);
    expect(err.text()).toContain("Usage: sanctuary completion");

    const badErr = new Capture();
    expect(await runCompletionCommand({ argv: ["powershell"], err: badErr })).toBe(2);
    expect(badErr.text()).toContain("Unknown shell: powershell");
  });

  it("uses injected command lists without stale hardcoding", async () => {
    const out = new Capture();
    const code = await runCompletionCommand({
      argv: ["bash"],
      out,
      commands: ["alpha", "omega"],
    });
    expect(code).toBe(0);
    expect(out.text()).toContain("alpha omega");
    expect(out.text()).not.toContain("castle-wall");
  });
});
