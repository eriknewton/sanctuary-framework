/**
 * One-shot generator for the S5-4 exclusive-routing manifest parity vector
 * (`manifest-parity-vector-exclusive-routing.json`, written to BOTH the TS
 * fixture dir and the Swift test fixture dir so the two languages verify the
 * SAME bytes). Extends the S5-0 two-uid vector with the S5-4 composition
 * shapes: a provisioned endpoint rule RE-SCOPED to the gate principal
 * (`scope.uids = [601]`) and the derived gate-channel rule bound to the AGENT
 * principal (`scope.uids = [600]`).
 *
 * Deterministic: a fixed test-only Ed25519 seed (this is a parity vector, not
 * a trust anchor; the key exists so both verifiers can check a real
 * signature). Run once via `npx tsx scripts/gen-exclusive-routing-parity-fixture.ts`
 * and commit the output; regeneration produces identical bytes.
 */

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../src/mesh/canonical-json.js";
import { buildProvisionedEgressRules } from "../src/castle-wall/provision/egress.js";
import { deriveGateAllowRule } from "../src/castle-wall/allowlist/gate-derivation.js";
import type { AllowlistRule } from "../src/castle-wall/allowlist/schema.js";

const here = dirname(fileURLToPath(import.meta.url));

// Fixed test-only seed (never a real key).
const seed = Uint8Array.from(
  createHash("sha256").update("s5-4-exclusive-routing-parity-vector").digest(),
);
const publicKey = ed25519.getPublicKey(seed);

const CREATED_AT = "2026-07-16T00:00:00.000Z";

// The S5-4 composition shapes, built by the REAL producers (never hand-typed):
// one provisioned endpoint rule in EXCLUSIVE routing (gate-uid-scoped) + the
// agent-principal-scoped derived gate-channel rule.
const provisioned = buildProvisionedEgressRules(
  {
    harnessId: "hermes",
    endpoints: [
      {
        name: "LLM (Venice)",
        host: "api.venice.ai",
        port: 443,
        protocol: "tcp",
        riskClass: "standard",
      },
    ],
  },
  CREATED_AT,
  { mode: "exclusive", gate_uid: 601 },
);
const gateRule = deriveGateAllowRule(
  { agent_uid: 600, gate_port: 49152 },
  CREATED_AT,
  { scope_to_agent_uid: true },
);
const rules: AllowlistRule[] = [...provisioned, gateRule];

const manifestSignedBody = {
  schema_version: 1,
  fortress_id: "fortress-exclusive-routing-parity",
  issued_at: "2026-07-16T00:00:00.000Z",
  rules: rules.map((rule) => ({
    rule_id: rule.id,
    file: `${rule.id}.json`,
    sha256: createHash("sha256")
      .update(Buffer.from(canonicalize(rule)))
      .digest("hex"),
  })),
  agent_origin: {
    mode: "uid",
    agent_uid: 600,
    gate_uid: 601,
    system_uid_allow_ceiling: 500,
  },
};

const canonical = Buffer.from(canonicalize(manifestSignedBody), "utf8");
const signature = ed25519.sign(canonical, seed);

const fixture = {
  manifest_signed_body: manifestSignedBody,
  rules,
  expected_canonical_json_b64: canonical.toString("base64"),
  expected_canonical_json_hex: canonical.toString("hex"),
  test_public_key_b64url: Buffer.from(publicKey).toString("base64url"),
  test_signature_b64url: Buffer.from(signature).toString("base64url"),
};

const json = `${JSON.stringify(fixture, null, 2)}\n`;
const tsPath = join(here, "../test/castle-wall/fixtures/manifest-parity-vector-exclusive-routing.json");
const swiftPath = join(
  here,
  "../../castle-wall-macos/Tests/CastleWallExtensionTests/Fixtures/manifest-parity-vector-exclusive-routing.json",
);
writeFileSync(tsPath, json);
writeFileSync(swiftPath, json);
console.log(`wrote ${tsPath}`);
console.log(`wrote ${swiftPath}`);
console.log(`canonical sha256: ${createHash("sha256").update(canonical).digest("hex")}`);
