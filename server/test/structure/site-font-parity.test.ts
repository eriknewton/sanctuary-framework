/** The website and console serve identical licensed faces from their own origins. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
it("the site's font URLs resolve to the console's exact font and license bytes", () => {
  const css = readFileSync(join(root, "docs/assets/css/site.css"), "utf8");
  const faces = [...css.matchAll(/src:\s*url\("\.\.\/fonts\/([^"/]+\.woff2)"\)/g)].map(match => match[1]).sort();
  const families = ["Manrope", "RobotoMono", "SpaceGrotesk"];
  expect(faces).toEqual(families.map(family => `${family}-wght.latin.woff2`));
  for (const family of families) {
    for (const suffix of ["-wght.latin.woff2", "-OFL.txt"]) {
      const file = family + suffix;
      expect(readFileSync(join(root, "docs/assets/fonts", file))).toEqual(
        readFileSync(join(root, "server/assets/fonts", file)),
      );
    }
  }
});
