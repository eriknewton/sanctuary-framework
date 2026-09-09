/**
 * One-shot generator for the operator-baseline manifest signature fixture.
 *
 * The fixture is intentionally produced by the real TS manifest publisher and
 * a fixed test-only Ed25519 seed, then consumed by Rust integration tests. This
 * catches typed-struct mirror gaps where Rust deserializes the TS-signed body
 * but drops an additive field before canonicalizing for signature verification.
 *
 * Run via `npx tsx scripts/gen-operator-baseline-manifest-fixture.ts`.
 */

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../src/mesh/canonical-json.js";
import { castleWallSigningKeyId } from "../src/castle-wall/allowlist/parse.js";
import {
  buildSignedManifest,
  type ManifestSigner,
} from "../src/castle-wall/runtime/manifest-publisher.js";
import type {
  OperatorBaseline,
  SignedManifest,
} from "../src/castle-wall/allowlist/manifest.js";

interface FixtureCase {
  name: string;
  signed_manifest: SignedManifest;
  expected_canonical_json_b64: string;
  expected_canonical_json_hex: string;
  test_signature_b64url: string;
}

const here = dirname(fileURLToPath(import.meta.url));

// Fixed test-only seed (never a real key).
const seed = Uint8Array.from(
  createHash("sha256").update("operator-baseline-manifest-cross-lang").digest(),
);
const publicKey = ed25519.getPublicKey(seed);
const signer: ManifestSigner = {
  signingKeyId: castleWallSigningKeyId(publicKey),
  sign(canonicalBytes: Uint8Array): Uint8Array {
    return ed25519.sign(canonicalBytes, seed);
  },
};

async function buildCase(
  name: string,
  operatorBaseline?: OperatorBaseline,
): Promise<FixtureCase> {
  const { signed } = await buildSignedManifest({
    fortressId: `fortress-${name}`,
    issuedAt: "2026-07-20T00:00:00.000Z",
    rules: [],
    signer,
    ...(operatorBaseline !== undefined
      ? { operatorBaseline }
      : {}),
  });
  const canonical = Buffer.from(canonicalize(signed.manifest), "utf8");
  return {
    name,
    signed_manifest: signed,
    expected_canonical_json_b64: canonical.toString("base64"),
    expected_canonical_json_hex: canonical.toString("hex"),
    test_signature_b64url: signed.signature.signature_b64url,
  };
}

const cases = [
  await buildCase("without-operator-baseline"),
  await buildCase("with-operator-baseline", {
    essentials: [
      {
        name: "allfields",
        signing_id: "com.example.operator.allfields",
        team_id: "TEAM123456",
        source_app_identifier: "com.example.operator.source",
      },
      {
        name: "teamonly",
        team_id: "TEAM654321",
      },
    ],
  }),
  await buildCase("empty-operator-baseline", { essentials: [] }),
];

const fixture = {
  _comment:
    "Operator-baseline manifest signature cross-language fixture. Produced by server/scripts/gen-operator-baseline-manifest-fixture.ts using the real TS manifest publisher and a fixed test-only Ed25519 seed. Consumed by server/test/castle-wall/runtime/manifest-parity-vector.test.ts and castle-wall-daemon/tests/integration_manifest_signature_cross_lang.rs.",
  test_public_key_b64url: Buffer.from(publicKey).toString("base64url"),
  cases,
};

const fixturePath = join(
  here,
  "../test/castle-wall/fixtures/manifest-operator-baseline-cross-lang.json",
);
const json = `${JSON.stringify(fixture, null, 2)}\n`;
writeFileSync(fixturePath, json);
console.log(`wrote ${fixturePath}`);
console.log(
  `fixture sha256: ${createHash("sha256").update(json).digest("hex")}`,
);
