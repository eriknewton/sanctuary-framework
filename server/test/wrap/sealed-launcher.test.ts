import { describe, expect, it } from "vitest";

import { resolveSanctuaryCommand } from "../../src/wrap/cli.js";

describe("sealed Castle Wall launcher routing", () => {
  it("writes the absolute launcher with no node/npm/npx arguments", () => {
    const launcher = "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary";
    expect(resolveSanctuaryCommand({ sealedLauncher: launcher })).toEqual({
      command: launcher,
      args: [],
    });
  });
});
