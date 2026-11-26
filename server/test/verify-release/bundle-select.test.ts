/**
 * Bundle selection reads the SIGNED predicateType inside each DSSE payload,
 * never the attestations document's outer label.
 */
import { describe, expect, it } from "vitest";
import { state_BUNDLE_SELECT } from "../../src/verify-release/sigstore.js";
import { attestations184, denyAllNetwork } from "./helpers.js";

denyAllNetwork();

const SLSA = "https://slsa.dev/provenance/v1";
const PUBLISH = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";

describe("bundle selection", () => {
  it("selects the SLSA bundle from the real 1.8.4 document, which also holds the npm publish attestation", () => {
    const document = attestations184();
    expect(document.attestations.map(a => a.predicateType)).toEqual([PUBLISH, SLSA]);
    const result = state_BUNDLE_SELECT(document);
    expect(result.ok).toBe(true);
    expect((result as any).evidence.bundle).toEqual(document.attestations[1]!.bundle);
  });

  it("zero SLSA bundles refuses provenance-absent", () => {
    const document = attestations184();
    document.attestations = document.attestations.filter(a => a.predicateType === PUBLISH);
    expect(state_BUNDLE_SELECT(document)).toEqual({ ok: false, reason: "provenance-absent" });
  });

  it("two SLSA bundles refuses provenance-ambiguous", () => {
    const document = attestations184();
    document.attestations.push(structuredClone(document.attestations[1]!));
    expect(state_BUNDLE_SELECT(document)).toEqual({ ok: false, reason: "provenance-ambiguous" });
  });

  it("an outer label that says SLSA over a payload that signs another predicateType is not selected", () => {
    const document = attestations184();
    const relabelled = { predicateType: SLSA, bundle: document.attestations[0]!.bundle };
    expect(state_BUNDLE_SELECT({ attestations: [relabelled] })).toEqual({ ok: false, reason: "provenance-absent" });
  });

  it("an outer label that says publish over a payload that signs SLSA is selected", () => {
    const document = attestations184();
    const relabelled = { predicateType: PUBLISH, bundle: document.attestations[1]!.bundle };
    expect(state_BUNDLE_SELECT({ attestations: [relabelled] }).ok).toBe(true);
  });

  it.each([
    ["null", null],
    ["no attestations array", { attestations: {} }],
    ["an element without a bundle", { attestations: [{ predicateType: SLSA }] }],
    ["a payload that is not JSON", { attestations: [{ bundle: { dsseEnvelope: { payload: Buffer.from("{").toString("base64") } } }] }],
    ["a payload that is not a string", { attestations: [{ bundle: { dsseEnvelope: { payload: 1 } } }] }],
    ["a predicateType that is not a string", { attestations: [{ bundle: { dsseEnvelope: { payload: Buffer.from("{\"predicateType\":1}").toString("base64") } } }] }],
  ])("%s refuses provenance-absent", (_label, document) => {
    expect(state_BUNDLE_SELECT(document)).toEqual({ ok: false, reason: "provenance-absent" });
  });
});
