import {it, expect} from "vitest";
import {mkdtempSync, mkdirSync, writeFileSync, unlinkSync, rmdirSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {BUSINESS_EVIDENCE, isolatedSelectorRoots, selectLinuxProfile, profileRefusalText} from "../../src/linux-business/profile-selection.js";
it("a drain config alone selects business and refuses installed signing", () => {
  const root = mkdtempSync(join(tmpdir(), "drain-inventory-"));
  const etc = join(root, "etc"), sanctuary = join(etc, "sanctuary"), file = join(sanctuary, "business-drain.json");
  try {
    mkdirSync(etc, {mode: 0o700}); mkdirSync(sanctuary, {mode: 0o700}); writeFileSync(file, "{}", {mode: 0o600});
    const result = selectLinuxProfile(isolatedSelectorRoots(root), []);
    expect(result.kind).toBe("Business");
    expect(profileRefusalText(result)).toContain("not enabled");
    expect(BUSINESS_EVIDENCE).toContain("/etc/sanctuary/business-drain.json");
  } finally { unlinkSync(file); rmdirSync(sanctuary); rmdirSync(etc); rmdirSync(root); }
});
