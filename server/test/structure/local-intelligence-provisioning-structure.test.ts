import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";

const source = (path: string) =>
  readFileSync(new URL(`../../src/${path}`, import.meta.url), "utf8");

describe("local intelligence provisioning structural inventory", () => {
  it("keeps protect and init on the one shared ceremony adapter", () => {
    const adapter = source("wrap/local-intelligence.ts");
    const wrap = source("wrap/cli.ts");
    const init = source("wrap/init.ts");
    expect(adapter).toContain("runLocalIntelligenceProvisioning");
    expect(wrap).toContain('from "./local-intelligence.js"');
    expect(init).toContain('from "./local-intelligence.js"');
    expect(wrap).not.toContain('from "../intelligence/provisioning.js"');
    expect(init).not.toContain('from "../intelligence/provisioning.js"');
  });

  it("keeps the consent truth table in one shared predicate, with no second copy", () => {
    const consent = source("intelligence/provisioning-consent.ts");
    const adapter = source("wrap/local-intelligence.ts");
    const sequencer = source("intelligence/provisioning.ts");
    expect(consent).toContain("export function localProvisioningPreflight(");
    // Both stages consume the predicate; neither re-derives "did the operator
    // ask for this" from isTty/preAnswered, which is how "not requested" and
    // "asked for and impossible" collapsed into one refusal.
    for (const consumer of [adapter, sequencer]) {
      expect(consumer).toContain("localProvisioningPreflight(");
      expect(consumer).not.toMatch(/preAnswered\s*===\s*(false|true|undefined)/);
    }
    // The unrequested arm exists on the shared result and on both stages, so a
    // headless run with no flag can end without a refusal.
    expect(consent).toContain('kind: "not-requested"');
    expect(adapter).toContain('kind: "not-requested"');
    expect(sequencer).toContain('kind: "not-requested"');
  });

  it("inventories both flags, both audit ops, and the registry provider category", () => {
    const wrap = source("wrap/cli.ts");
    const init = source("wrap/init.ts");
    const contextGate = source("operational/context-gate.ts");
    for (const flag of [
      "--provision-local-intelligence",
      "--no-provision-local-intelligence",
    ]) {
      expect(wrap).toContain(flag);
      expect(init).toContain(flag);
    }
    expect(INTEL_OPS.MODEL_PULL).toBe("intelligence_model_pull");
    expect(INTEL_OPS.MODEL_PROVISION_REFUSED).toBe(
      "intelligence_model_provision_refused",
    );
    expect(contextGate).toContain('| "model-registry"');
  });

  it("wires the packaged signed-manifest loader as the default and keeps the host installer inert", () => {
    const adapter = source("wrap/local-intelligence.ts");
    const wrap = source("wrap/cli.ts");
    const init = source("wrap/init.ts");
    // The manifest source is the packaged-asset loader, never a null default.
    expect(adapter).toContain("loadPackagedModelManifestV2(");
    expect(adapter).not.toContain("async () => null");
    expect(adapter).toContain("async () => false");
    // No network and no host mutation from the adapter itself.
    expect(adapter).not.toMatch(/https:\/\//);
    expect(adapter).not.toMatch(/execFile|spawn|curl|brew install/);
    // Both production callers take the shared default and only pass the
    // operator path override; neither injects its own manifest source.
    for (const caller of [wrap, init]) {
      expect(caller).not.toContain("loadManifest");
      expect(caller).toContain("--model-manifest");
      expect(caller).toContain("modelManifestPath: options.modelManifestPath");
    }
    // Neither production caller passes a `deps` argument at all, so every
    // test seam (including `modelManifestV2PublicKey`) is unreachable from
    // production: the ceremony runs on its compiled defaults.
    const callSite = (source: string, callee: string) => {
      const match = new RegExp(`await ${callee}\\(\\{[\\s\\S]*?\\n\\s*\\}\\);`).exec(source);
      expect(match, `${callee}({...}) call site present`).not.toBeNull();
      return match![0];
    };
    for (const [source, callee] of [[wrap, "runner"], [init, "localSetup"]] as const) {
      const call = callSite(source, callee);
      expect(call).not.toMatch(/\}\s*,\s*\{/);
      expect(call).not.toMatch(/\}\s*,\s*[A-Za-z_$][\w$]*\s*\)/);
      expect(call).not.toContain("modelManifestV2PublicKey");
    }
  });

  it("pins the packaged asset bytes at build, at load, and in the package exports", () => {
    const loader = source("intelligence/packaged-model-manifest.ts");
    const copyScript = readFileSync(
      new URL("../../scripts/copy-model-manifest-v2-asset.mjs", import.meta.url),
      "utf8",
    );
    const packageJson = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    ) as { exports: Record<string, unknown>; scripts: Record<string, string> };
    const asset = readFileSync(
      new URL("../../src/intelligence/model-manifest/model-manifest.v2.json", import.meta.url),
    );
    const digest = createHash("sha256").update(asset).digest("hex");
    const pin = (text: string, name: string) =>
      new RegExp(`${name}\\s*=\\s*\\n?\\s*"([0-9a-f]{64})"`).exec(text)?.[1];
    expect(pin(loader, "PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256")).toBe(digest);
    expect(pin(copyScript, "EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256")).toBe(digest);
    expect(packageJson.exports["./intelligence/model-manifest/model-manifest.v2.json"])
      .toBe("./dist/intelligence/model-manifest/model-manifest.v2.json");
    expect(packageJson.scripts.build).toContain("copy-model-manifest-v2-asset.mjs --verify-only");
    expect(packageJson.scripts.build.endsWith("node scripts/copy-model-manifest-v2-asset.mjs")).toBe(true);
    // The loader's five refusal states each carry operator copy in the ceremony.
    const provisioning = source("intelligence/provisioning.ts");
    for (const reason of [
      "integrity_asset_absent",
      "integrity_asset_oversize",
      "integrity_asset_unparseable",
      "integrity_asset_signature_invalid",
      "integrity_asset_pin_mismatch",
      "integrity_asset_module_location_unavailable",
    ]) {
      expect(loader).toContain(`"${reason}"`);
      expect(provisioning).toContain(`${reason}:`);
    }
  });
});
