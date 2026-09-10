/**
 * The `re-pin` confirmation exists at BOTH entry points to the anchor
 * migration, and both ask for the same word.
 *
 * Why this test reads source files rather than importing values: one of the two
 * entry points is Swift. `castle-wall-signer-client` is a directly executable
 * binary, and the root helper's caller check authenticates that binary's code
 * signature, not operator presence, so a confirmation that lives only in the
 * TypeScript CLI is not a gate on the operation at all: anything that can exec
 * the bundled shim goes straight past it. The Swift half cannot be imported
 * into vitest, and it also cannot be allowed to drift, so the pin is a
 * source-level parity assertion.
 *
 * Stated bound: this proves the gate is PRESENT in the Swift source and asks
 * for the same word. It does not execute the signed shim, and it does not prove
 * the built binary in a shipped app bundle carries it; that is a drill on a Mac
 * with the app installed, not a unit test.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { RE_PIN_CONFIRMATION_WORD } from "../../src/cli/castle-wall.js";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const swiftShimPath = join(
  repoRoot,
  "castle-wall-macos",
  "Sources",
  "CastleWallSignerClient",
  "main.swift",
);

describe("the re-pin confirmation word is pinned on both sides", () => {
  it("declares the same word in the Swift shim as in the TypeScript CLI", async () => {
    const swift = await readFile(swiftShimPath, "utf8");
    const declared = /let\s+rePinConfirmationWord\s*=\s*"([^"]+)"/.exec(swift);
    expect(
      declared,
      "the Swift shim must declare rePinConfirmationWord; see the cross-file contract on RE_PIN_CONFIRMATION_WORD",
    ).not.toBeNull();
    expect(declared![1]).toBe(RE_PIN_CONFIRMATION_WORD);
  });

  it("gates the Swift re-pin branch before it reaches the helper", async () => {
    const swift = await readFile(swiftShimPath, "utf8");
    // The gate has to run BEFORE the XPC call, or a refusal has already moved
    // the anchor. Asserting the order rather than mere presence is the point:
    // a confirmation placed after `run(.installPin)` would be unreachable, and
    // `run` never returns.
    const branch = /case\s+"re-pin":([\s\S]*?)(?:\ndefault:|\ncase\s+")/.exec(swift);
    expect(branch, "the Swift shim must still have a re-pin mode").not.toBeNull();
    const body = branch![1];
    const gateAt = body.indexOf("confirmRePinOrRefuse()");
    const installAt = body.indexOf("run(.installPin)");
    expect(gateAt, "re-pin must call the confirmation gate").toBeGreaterThanOrEqual(0);
    expect(installAt).toBeGreaterThanOrEqual(0);
    expect(gateAt).toBeLessThan(installAt);
  });

  it("refuses a non-terminal stdin in the Swift gate, with no override", async () => {
    const swift = await readFile(swiftShimPath, "utf8");
    const gate = /func\s+confirmRePinOrRefuse\(\)\s*\{([\s\S]*?)\n\}/.exec(swift);
    expect(gate, "the Swift shim must declare confirmRePinOrRefuse").not.toBeNull();
    const body = gate![1];
    // stdin must be a terminal, so a piped or detached caller cannot answer.
    expect(body).toContain("isatty(FileHandle.standardInput.fileDescriptor)");
    // No escape hatch: an override is exactly the affordance a non-interactive
    // caller would reach for. Matched against CODE, not prose — the gate's own
    // comment says the word "environment", so a bare substring check would
    // fail on its own documentation.
    const code = body.replace(/\/\/[^\n]*/g, "");
    expect(code).not.toMatch(/ProcessInfo\s*\.\s*processInfo/);
    expect(code).not.toMatch(/getenv\s*\(/);
  });
});
