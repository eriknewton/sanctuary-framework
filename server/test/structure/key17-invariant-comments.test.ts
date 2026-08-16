import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function around(source: string, anchor: string): string {
  const index = source.indexOf(anchor);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 1_100), index + anchor.length + 700);
}

function expectNear(
  source: string,
  anchor: string,
  snippets: readonly string[]
): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Key 17 invariant comment hygiene", () => {
  it("keeps AP2 verification honest about trusted keys and replay scope", () => {
    const source = read("server/src/key-17/ap2-mandate-signer.ts");

    expectNear(source, "if (opts.trustedPublicKey) {", [
      "trusted-key verify must",
      "cannot echo attacker-chosen key",
    ]);
    expectNear(source, "} else if (opts.trustEmbedded) {", [
      "proves only that this",
      "not that the key belongs to anyone",
    ]);
    expectNear(source, "const freshness = \"not_checked\";", [
      "anti-replay MUST be enforced",
      "future AP2 consumer",
    ]);
    expectNear(source, "const valid = ed25519.verify(signatureBytes, bytes, verificationKey);", [
      "recomputes the canonical mandate bytes",
      "unsigned metadata cannot change what was signed",
    ]);
  });

  it("keeps x402 verification honest about trusted keys and replay scope", () => {
    const source = read("server/src/key-17/x402-signer.ts");

    expectNear(source, "if (opts.trustedPublicKey) {", [
      "trusted-key verify must",
      "cannot echo attacker-chosen key",
    ]);
    expectNear(source, "} else if (opts.trustEmbedded) {", [
      "proves only that this",
      "not that the key belongs to anyone",
    ]);
    expectNear(source, "const freshness = \"not_checked\";", [
      "anti-replay MUST be enforced",
      "future x402 consumer",
    ]);
    expectNear(source, "const valid = ed25519.verify(signatureBytes, bytes, verificationKey);", [
      "recomputes the canonical request bytes",
      "unsigned metadata cannot change what was signed",
    ]);
  });

  it("keeps ERC-8004 self-consistency separate from registry ownership", () => {
    const signer = read("server/src/key-17/erc8004-identity-signer.ts");
    const resolver = read("server/src/key-17/erc8004-resolve.ts");

    expectNear(signer, "const messageBytes = canonicalizeToBytes(unsigned);", [
      "carried public_key is ignored",
      "only key material that can settle this envelope",
    ]);
    expectNear(signer, "return recoveredAddress.toLowerCase() === signer_address.toLowerCase();", [
      "only checked against the recovered key",
      "registry ownership is a separate trust upgrade",
    ]);
    expectNear(resolver, "offlineValid = verifyErc8004Registration(signed);", [
      "self-consistency only",
      "never inferred from the record",
    ]);
    expectNear(resolver, "if (registryConfirmation.status === \"confirmed\") {", [
      "upgraded only after the gated ownerOf read matches",
      "offline self-consistency alone stays offline_verified",
    ]);
  });

  it("keeps signing approval gates ahead of protocol key use", () => {
    const service = read("server/src/key-17/operator-key-interface.ts");
    const tools = read("server/src/key-17/erc8004-tools.ts");
    const policy = read("server/src/key-17/policy-gate.ts");

    expectNear(service, "await this.policyGate.checkApproval({", [
      "no protocol subkey is touched",
      "operator policy has allowed",
    ]);
    expectNear(tools, "await deps.policyGate.checkApproval(approvalRequest);", [
      "last boundary before key use",
      "no branch below may call the",
    ]);
    expectNear(tools, "const signed = signErc8004Registration(", [
      "sign only after the policy",
      "exact registration",
    ]);
    expectNear(policy, "if (!this.config.requestOperatorApproval) {", [
      "Missing approval plumbing is a hard deny",
      "cannot degrade into local key use",
    ]);
  });

  it("keeps ERC-8004 nonce and registry-confirmation boundaries documented", () => {
    const tools = read("server/src/key-17/erc8004-tools.ts");
    const registry = read("server/src/key-17/erc8004-registry-confirm.ts");

    expectNear(tools, "!Number.isFinite(nonce)", [
      "registry nonce is signed into the registration",
      "refused before they can become durable signature input",
    ]);
    expectNear(registry, "throw new Erc8004EgressDeniedError(\"egress_gate_unavailable\");", [
      "without an egress decision",
      "silently opening the network",
    ]);
    expectNear(registry, "await requireEgressAllowed({", [
      "last boundary before the network",
    ]);
    expectNear(registry, "if (ownerAddress.toLowerCase() !== input.signer_address.toLowerCase()) {", [
      "must match the recovered offline signer exactly",
      "refuses registry_confirmed",
    ]);
  });
});
