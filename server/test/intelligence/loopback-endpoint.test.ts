// fail-before-exempt: new loopback target module; the selector predicate move preserves its behavior.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import dns from "node:dns";
import { describe, expect, it, vi } from "vitest";
import { isLoopbackOllamaEndpoint, resolveLoopbackConnectTarget } from "../../src/intelligence/loopback-endpoint.js";

describe("loopback targets", () => {
  it.each([
    ["http://localhost:1234/", "127.0.0.1", 4],
    ["http://127.0.0.1:1234/", "127.0.0.1", 4],
    ["http://127.4.5.6:1234/", "127.4.5.6", 4],
    ["http://[::1]:1234/", "::1", 6],
  ])("accepts %s", (endpoint, address, family) => {
    expect(resolveLoopbackConnectTarget(String(endpoint))).toEqual({ ok: true, target: { address, family, port: 1234 } });
  });
  it.each(["http://10.0.0.1", "http://example.com", "http://user:pass@localhost", "https://localhost", "http://localhost/path", "http://0.0.0.0", "http://localhost/?a=b", "http://localhost/#hash",
    "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/", "http://[::ffff:169.254.169.254]/", "http://localhost./", "http://a.localhost/", "http://127.0.0.1:0/"])("refuses %s", (endpoint) => {
    expect(resolveLoopbackConnectTarget(endpoint)).toEqual({ ok: false, reason: "not_loopback" });
  });
  it("a target with no port resolves to the HTTP default port", () => {
    const HTTP_DEFAULT_PORT = 80; // the http: scheme's default
    expect(resolveLoopbackConnectTarget("http://127.0.0.1/")).toEqual({ ok: true, target: { address: "127.0.0.1", family: 4, port: HTTP_DEFAULT_PORT } });
  });
  it("localhost resolves without a DNS lookup", () => {
    const lookup = vi.spyOn(dns, "lookup");
    try { expect(resolveLoopbackConnectTarget("http://localhost").ok).toBe(true); expect(lookup).not.toHaveBeenCalled(); }
    finally { lookup.mockRestore(); }
  });
  it("the selector and the client share one loopback predicate", () => {
    const root = join(import.meta.dirname, "../../src");
    const files: string[] = [];
    function visit(dir: string) {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) visit(path);
        else if (entry.name.endsWith(".ts") && /function isLoopbackOllamaEndpoint\(/.test(readFileSync(path, "utf8"))) files.push(path);
      }
    }
    visit(root);
    expect(files).toEqual([join(root, "intelligence/loopback-endpoint.ts")]);
    expect(readFileSync(join(root, "intelligence/selector.ts"), "utf8")).toMatch(/import\s*\{\s*isLoopbackOllamaEndpoint\s*\}\s*from\s*["']\.\/loopback-endpoint\.js["']/);
    expect(isLoopbackOllamaEndpoint("https://localhost/path")).toBe(true);
  });
});
