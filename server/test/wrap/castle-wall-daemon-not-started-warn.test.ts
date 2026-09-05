/** A failed daemon start does not establish the live wall's enforcement state. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { warnCastleWallDaemonNotStarted } from "../../src/wrap/cli.js";

describe("warnCastleWallDaemonNotStarted", () => {
  afterEach(() => vi.restoreAllMocks());

  function capture(err: unknown): string {
    const parts: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      parts.push(args.map(String).join(" "));
    });
    warnCastleWallDaemonNotStarted(err);
    return parts.join("\n");
  }

  it("reports the startup failure and its reason without claiming armed or unarmed", () => {
    const output = capture(new Error("EACCES: permission denied, connect"));
    expect(output).toContain("Castle Wall daemon failed to start");
    expect(output).toContain("EACCES: permission denied, connect");
    expect(output).toMatch(/live enforcement state.*unknown/i);
    expect(output).toContain("Castle Wall panel");
    expect(output).not.toMatch(/NOT armed|traffic.*not.*filtered|enforcement.*active|traffic.*is.*filtered/i);
  });

  it("does not label a persistent signer configuration failure transient", () => {
    const output = capture(new Error("signer helper is unreachable"));
    expect(output).not.toMatch(/transient/i);
    expect(output).toContain("signer helper is unreachable");
    if (process.platform === "darwin") {
      expect(output).toContain("SANCTUARY_CASTLE_SIGNER_CLIENT");
      expect(output).toMatch(/only starts the userspace daemon.*alone does.*NOT mean traffic is being filtered/is);
    }
  });

  it("preserves a non-Error failure reason without inventing an enforcement result", () => {
    const output = capture("socket path unavailable");
    expect(output).toContain("Reason: socket path unavailable");
    expect(output).toMatch(/live enforcement state.*unknown/i);
    expect(output).not.toMatch(/Castle Wall is NOT armed|outbound traffic is NOT filtered/i);
  });
});
