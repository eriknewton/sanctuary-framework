import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf8");
}

describe("state import and checkpoint restore writer-key resolver parity", () => {
  it("routes import, restore, and state_read through the authenticated identity rotation-chain resolver", () => {
    const stateStore = read("src/cognitive/state-store.ts");
    const tools = read("src/cognitive/tools.ts");
    const checkpointCli = read("src/cli/checkpoint.ts");

    expect(stateStore).toContain(
      "for (const key of resolveAuthenticatedIdentityWriterPublicKeys(identity))",
    );
    expect(stateStore).toContain("normalizeImportPublicKeys");
    expect(tools).toContain(
      "resolveAuthenticatedIdentityWriterPublicKeys(identity)",
    );
    expect(checkpointCli).toContain(
      "resolveAuthenticatedIdentityWriterPublicKeys(identity)",
    );
  });
});
