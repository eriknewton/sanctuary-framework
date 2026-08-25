import { describe, expect, it, vi } from "vitest";
import { DEFAULT_PER_SURFACE } from "../../src/intelligence/defaults.js";
import {
  MODEL_REGISTRY_PROVIDER_CATEGORY,
  renderLocalProvisioningPlan,
  runLocalIntelligenceProvisioning,
  type LocalProvisioningOps,
} from "../../src/intelligence/provisioning.js";
import type {
  ModelManifestBody,
  ModelManifestModel,
  ModelManifestRefusalReason,
} from "../../src/intelligence/model-manifest.js";
import type { HardwareCapabilityReport, Surface } from "../../src/intelligence/types.js";

const HASH = "1".repeat(64);
const OTHER_HASH = "2".repeat(64);
const MODEL: ModelManifestModel = {
  model_id: "qwen2.5-1.5b",
  model_name: "Qwen2.5 1.5B",
  model_version: "2.5",
  provider: "Alibaba Cloud",
  runtime: "ollama",
  runtime_tag: "qwen2.5:1.5b",
  registry_source: "ollama://qwen2.5:1.5b",
  weights_sha256: HASH,
  params_b: 1.5,
  license: {
    identifier: "Apache-2.0",
    name: "Apache License 2.0",
    url: "https://www.apache.org/licenses/LICENSE-2.0",
    osi_approved: true,
    redistribution: "permitted",
  },
  open_weights: true,
  open_source: false,
};

const LOCAL_SURFACES = Object.entries(DEFAULT_PER_SURFACE)
  .filter(([, choice]) => choice === "local")
  .map(([surface]) => surface as Surface);

const defaults = Object.fromEntries(
  ["baseline", "mid", "pro"].map((tier) => [
    tier,
    Object.fromEntries(
      Object.keys(DEFAULT_PER_SURFACE).map((surface) => [
        surface,
        surface === "gate-explanation" ? null : MODEL.model_id,
      ]),
    ),
  ]),
) as ModelManifestBody["surface_defaults"];

const BODY: ModelManifestBody = {
  manifest_version: 9,
  models: { [MODEL.model_id]: MODEL },
  tiers: {
    baseline: [MODEL.model_id],
    mid: [MODEL.model_id],
    pro: [MODEL.model_id],
  },
  surface_defaults: defaults,
};

function makeOps(overrides: Partial<LocalProvisioningOps> = {}) {
  const sequence: string[] = [];
  const failures: Array<{ surfaces: readonly Surface[]; snippet: string }> = [];
  let showCalls = 0;
  const ops: LocalProvisioningOps = {
    isTty: true,
    platform: "darwin",
    manifestText: "signed fixture",
    configuredChoices: { ...DEFAULT_PER_SURFACE },
    verifyManifest: () => ({ ok: true, body: BODY }),
    probeHardware: vi.fn(async () => ({
      totalRamGb: 16,
      cpuArch: "apple-silicon-m2",
      tier: "baseline",
      recommendedLocalModel: "gemma-2-2b",
      ollamaReachable: true,
      ollamaModels: [],
    } satisfies HardwareCapabilityReport)),
    installRuntime: vi.fn(async () => {
      sequence.push("install");
      return true;
    }),
    pull: vi.fn(async () => {
      sequence.push("pull");
      return { ok: true, failureClass: null };
    }),
    show: vi.fn(async () => {
      showCalls += 1;
      sequence.push(`show-${showCalls}`);
      return {
        ok: true,
        failureClass: null,
        digest: showCalls === 1 ? OTHER_HASH : HASH,
      };
    }),
    confirm: vi.fn(async () => {
      sequence.push("confirm");
      return true;
    }),
    print: vi.fn(() => sequence.push("print")),
    commitVerified: vi.fn(async () => {
      sequence.push("commit");
    }),
    recordFailure: vi.fn(async (surfaces, _failureClass, snippet) => {
      failures.push({ surfaces, snippet });
    }),
    audit: vi.fn(async () => undefined),
    ...overrides,
  };
  return { ops, sequence, failures };
}

describe("local intelligence provisioning ceremony", () => {
  it("prints the complete verified plan before the first mutation", async () => {
    const { ops, sequence } = makeOps();
    const result = await runLocalIntelligenceProvisioning(ops);
    expect(result.kind).toBe("provisioned");
    expect(sequence.indexOf("print")).toBeLessThan(sequence.indexOf("confirm"));
    expect(sequence.indexOf("confirm")).toBeLessThan(sequence.indexOf("pull"));
    expect(sequence.at(-1)).toBe("commit");
    expect(ops.print).toHaveBeenCalledWith(expect.stringContaining("license Apache-2.0"));
  });

  it("commits provenance and surface tags only after an exact digest match", async () => {
    const { ops } = makeOps();
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toMatchObject({
      kind: "provisioned",
      surfaces: LOCAL_SURFACES,
      models: [MODEL.model_id],
    });
    expect(ops.commitVerified).toHaveBeenCalledOnce();
    const commits = vi.mocked(ops.commitVerified).mock.calls[0]![0];
    expect(commits[0]?.provenance.runtime_manifest_hash).toBe(`sha256:${HASH}`);
    expect(commits[0]?.provenance.weights_hash).toBeUndefined();
    expect(commits[0]?.provenance.serving_surfaces).toEqual(LOCAL_SURFACES);
    expect(commits[0]?.surfaces).toEqual(LOCAL_SURFACES);
  });

  it("refuses a digest mismatch without provenance, fallback, or provisioned state", async () => {
    const { ops, failures } = makeOps({
      show: vi.fn(async () => ({ ok: true, failureClass: null, digest: OTHER_HASH })),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "digest_mismatch",
    });
    expect(ops.commitVerified).not.toHaveBeenCalled();
    expect(failures[0]?.snippet).toContain("did not match");
    expect(ops.configuredChoices).toEqual(DEFAULT_PER_SURFACE);
  });

  it.each([
    "bad_signature",
    "malformed_json",
    "zero_signature",
    "zero_pinned_key",
  ] satisfies ModelManifestRefusalReason[])(
    "refuses %s before probe, plan, or pull",
    async (reason) => {
      const { ops } = makeOps({
        verifyManifest: () => ({ ok: false, reason }),
      });
      await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
        kind: "refused",
        reason: "manifest_invalid",
      });
      expect(ops.probeHardware).not.toHaveBeenCalled();
      expect(ops.pull).not.toHaveBeenCalled();
      expect(ops.print).not.toHaveBeenCalled();
    },
  );

  it("treats an absent manifest as a quiet fail-closed refusal", async () => {
    const { ops, failures } = makeOps({
      verifyManifest: () => ({ ok: false, reason: "absent" }),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "manifest_unavailable",
    });
    expect(ops.print).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(failures[0]?.snippet).toContain("unavailable");
  });

  it("refuses below-baseline hardware before pull", async () => {
    const { ops } = makeOps({
      probeHardware: vi.fn(async () => ({
        totalRamGb: 4,
        cpuArch: "x86_64",
        tier: "below-baseline",
        recommendedLocalModel: null,
        ollamaReachable: false,
        ollamaModels: [],
      } satisfies HardwareCapabilityReport)),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "below_baseline",
    });
    expect(ops.pull).not.toHaveBeenCalled();
  });

  it("explicit decline prints no plan and mutates no runtime", async () => {
    const { ops } = makeOps({ preAnswered: false });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "declined",
    });
    expect(ops.print).not.toHaveBeenCalled();
    expect(ops.installRuntime).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
  });

  it("a positive flag cannot authorize non-TTY mutation", async () => {
    const { ops } = makeOps({ isTty: false, preAnswered: true });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "non_tty",
    });
    expect(ops.probeHardware).not.toHaveBeenCalled();
    expect(ops.installRuntime).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
  });

  it("a negative confirmation preserves local choices and performs no mutation", async () => {
    const { ops } = makeOps({ confirm: vi.fn(async () => false) });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "declined",
    });
    expect(ops.installRuntime).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.configuredChoices["privacy-filter-tier-2"]).toBe("local");
  });

  it("an install failure leaves no provisioned state", async () => {
    const { ops } = makeOps({
      probeHardware: vi.fn(async () => ({
        totalRamGb: 16,
        cpuArch: "apple-silicon-m2",
        tier: "baseline",
        recommendedLocalModel: "gemma-2-2b",
        ollamaReachable: false,
        ollamaModels: [],
      } satisfies HardwareCapabilityReport)),
      installRuntime: vi.fn(async () => false),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "install_failed",
    });
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
  });

  it("prints manual Windows guidance without confirming or installing", async () => {
    const { ops } = makeOps({
      platform: "win32",
      probeHardware: vi.fn(async () => ({
        totalRamGb: 16,
        cpuArch: "x86_64",
        tier: "baseline",
        recommendedLocalModel: "gemma-2-2b",
        ollamaReachable: false,
        ollamaModels: [],
      } satisfies HardwareCapabilityReport)),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "manual_install_required",
    });
    expect(ops.print).toHaveBeenCalledWith(expect.stringContaining("manually on Windows"));
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.installRuntime).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
  });

  it("pull, show, and commit failures each leave no provisioned state", async () => {
    for (const [override, reason] of [
      [{ pull: vi.fn(async () => ({ ok: false, failureClass: "substrate_unavailable" as const })) }, "pull_failed"],
      [{ show: vi.fn(async () => ({ ok: false, failureClass: "substrate_unavailable" as const, digest: null })) }, "show_failed"],
      [{ commitVerified: vi.fn(async () => { throw new Error("persist failed"); }) }, "commit_failed"],
    ] as const) {
      const { ops } = makeOps(override);
      await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
        kind: "refused",
        reason,
      });
      expect(ops.commitVerified).toHaveBeenCalledTimes(reason === "commit_failed" ? 1 : 0);
    }
  });

  it("is idempotent when every installed digest already matches", async () => {
    const { ops } = makeOps({
      show: vi.fn(async () => ({ ok: true, failureClass: null, digest: HASH })),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toMatchObject({
      kind: "already-provisioned",
    });
    expect(ops.print).not.toHaveBeenCalled();
    expect(ops.confirm).not.toHaveBeenCalled();
    expect(ops.pull).not.toHaveBeenCalled();
    expect(ops.commitVerified).not.toHaveBeenCalled();
  });

  it("cannot escape the verified tier/surface references", async () => {
    const closedBody = structuredClone(BODY);
    closedBody.surface_defaults.baseline.concierge = null;
    const { ops } = makeOps({
      verifyManifest: () => ({ ok: true, body: closedBody }),
    });
    await expect(runLocalIntelligenceProvisioning(ops)).resolves.toEqual({
      kind: "refused",
      reason: "manifest_invalid",
    });
    expect(ops.pull).not.toHaveBeenCalled();
  });

  it("classifies registry egress and renders only manifest-sourced values", () => {
    expect(MODEL_REGISTRY_PROVIDER_CATEGORY).toBe("model-registry");
    expect(renderLocalProvisioningPlan({ installRuntime: true, platform: "darwin", models: [MODEL] })).toEqual([
      "Local intelligence setup plan (no changes have been made):",
      "- Install Ollama using the platform adapter after confirmation.",
      "- Pull qwen2.5:1.5b from ollama://qwen2.5:1.5b (1.5B parameters; license Apache-2.0).",
      "- Verify its observed SHA-256 against the signed model manifest before use.",
    ]);
  });
});
