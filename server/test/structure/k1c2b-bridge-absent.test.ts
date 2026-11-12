import {it, expect} from "vitest";
import {readFileSync, readdirSync} from "node:fs";
it("removes the parent-pinned signing transport from production source", () => {
  expect(readFileSync("../castle-wall-daemon/src/business_profile/signer_service.rs", "utf8")).not.toContain("pub fn bridge(");
  for (const root of ["../castle-wall-daemon/src", "src"]) {
    for (const path of readdirSync(root, {recursive: true})) {
      if (typeof path !== "string" || !/\.(rs|ts)$/.test(path)) continue;
      const source = readFileSync(`${root}/${path}`, "utf8");
      expect(source).not.toContain("BRIDGE_READY");
      if (path.includes("sanctuary-business-") || (root === "src" && path.startsWith("signing/"))) {
        expect(source).not.toContain('"--bridge"');
        expect(source).not.toContain('"--test-bridge"');
      }
    }
  }
});
