/**
 * `--model-manifest <path>` on the two provisioning entry points (protect and
 * init): parsed as a required path value and handed to the ceremony.
 */

import { describe, expect, it } from "vitest";
import { parseWrapArgs } from "../../src/wrap/cli.js";
import { parseInitArgs } from "../../src/wrap/init.js";

describe("--model-manifest flag", () => {
  it("parses on protect/wrap and requires a path value", () => {
    expect(parseWrapArgs(["--provision-local-intelligence", "--model-manifest", "/tmp/m.json"]))
      .toMatchObject({ provisionLocalIntelligence: true, modelManifestPath: "/tmp/m.json" });
    expect(() => parseWrapArgs(["--model-manifest"])).toThrow("--model-manifest requires a path value");
    expect(() => parseWrapArgs(["--model-manifest", "--dry-run"])).toThrow("--model-manifest requires a path value");
    expect(parseWrapArgs(["--dry-run"]).modelManifestPath).toBeUndefined();
  });

  it("parses on init and requires a path value", () => {
    expect(parseInitArgs(["--provision-local-intelligence", "--model-manifest", "/tmp/m.json"]))
      .toMatchObject({ provisionLocalIntelligence: true, modelManifestPath: "/tmp/m.json" });
    expect(() => parseInitArgs(["--model-manifest"])).toThrow("--model-manifest requires a path value");
    expect(parseInitArgs(["--no-confirm"]).modelManifestPath).toBeUndefined();
  });
});
