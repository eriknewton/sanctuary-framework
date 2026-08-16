/**
 * Generate the O-02 arm-lease canonical-parity fixture consumed by BOTH
 * `server/test/castle-wall/runtime/arm-lease-parity-vector.test.ts` and
 * `castle-wall-macos/Tests/CastleWallExtensionTests/ArmLeaseParityVectorTests.swift`.
 *
 * Run from `server/`:
 *   npx tsx scripts/gen-arm-lease-parity-fixture.ts
 *
 * Writes the SAME bytes to both fixture locations. The private key is a fixed
 * test-only seed (never a real fortress key); the fixture pins the canonical
 * signed-body bytes so a canonicalization divergence between the TS producer
 * and the Swift verifier fails loudly in whichever suite drifted.
 */
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../src/mesh/canonical-json.js";
import { armLeaseSignedBody } from "../src/castle-wall/runtime/macos-ipc-listener.js";
import type { ArmLeaseNotification } from "../src/castle-wall/ipc/messages.js";

const here = dirname(fileURLToPath(import.meta.url));

// Fixed, test-only seed. 32 bytes of 0x42 — obviously synthetic.
const seed = new Uint8Array(32).fill(0x42);
const publicKey = ed25519.getPublicKey(seed);

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// A lease exercising the interesting shape edges: armed, explicit ttl,
// fractional-second stamp, revoked ABSENT on the wire (signed body pins it to
// explicit false), plus a passthrough diagnostic field the signature must NOT
// cover (the CLI's `source`).
const lease: ArmLeaseNotification & { source?: string } = {
  type: "arm_lease",
  armed: true,
  ttl_seconds: 90,
  heartbeat_interval_seconds: 5,
  updated_at: "2026-08-16T00:00:00.000Z",
  source: "castle-wall-cli",
};

const canonicalBytes = new TextEncoder().encode(
  canonicalize(armLeaseSignedBody(lease)),
);
const signature = ed25519.sign(canonicalBytes, seed);

const fixture = {
  arm_lease: {
    ...lease,
    signing_key_id: "parity-test-key",
    lease_signature_b64url: toBase64url(signature),
  },
  expected_canonical_json_b64: Buffer.from(canonicalBytes).toString("base64"),
  expected_canonical_json_hex: Buffer.from(canonicalBytes).toString("hex"),
  test_public_key_b64url: toBase64url(publicKey),
  test_signature_b64url: toBase64url(signature),
};

const json = `${JSON.stringify(fixture, null, 2)}\n`;
const targets = [
  join(here, "../test/castle-wall/fixtures/arm-lease-parity-vector.json"),
  join(
    here,
    "../../castle-wall-macos/Tests/CastleWallExtensionTests/Fixtures/arm-lease-parity-vector.json",
  ),
];
for (const target of targets) {
  await writeFile(target, json, "utf8");
  console.log(`wrote ${target}`);
}
console.log(`canonical: ${new TextDecoder().decode(canonicalBytes)}`);
