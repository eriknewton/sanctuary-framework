/**
 * O-02 arm-lease canonical-parity vector (TS half).
 *
 * The committed fixture pins the canonical signed-body bytes the TS producer
 * (`armLeaseSignedBody` + `canonicalize`) emits for a representative lease.
 * The Swift half (`castle-wall-macos/Tests/CastleWallExtensionTests/
 * ArmLeaseParityVectorTests.swift`) asserts the SAME bytes from the verifier's
 * reconstruction, so a canonicalization divergence between the two sides fails
 * one of the suites loudly instead of surfacing on-device as every lease being
 * rejected. Regenerate BOTH copies with
 * `npx tsx scripts/gen-arm-lease-parity-fixture.ts` if the signed-body shape
 * ever changes (which is a breaking wire change — route it accordingly).
 */
import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { canonicalize } from "../../../src/mesh/canonical-json.js";
import { armLeaseSignedBody } from "../../../src/castle-wall/runtime/macos-ipc-listener.js";
import type { ArmLeaseNotification } from "../../../src/castle-wall/ipc/messages.js";

interface ArmLeaseParityFixture {
  arm_lease: ArmLeaseNotification;
  expected_canonical_json_b64: string;
  expected_canonical_json_hex: string;
  test_public_key_b64url: string;
  test_signature_b64url: string;
}

async function loadFixture(): Promise<ArmLeaseParityFixture> {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(here, "../fixtures/arm-lease-parity-vector.json");
  return JSON.parse(await readFile(fixturePath, "utf8")) as ArmLeaseParityFixture;
}

describe("castle-wall arm-lease canonical parity vector (O-02)", () => {
  it("TS signed-body canonicalization matches the fixture bytes and signature", async () => {
    const fixture = await loadFixture();

    const actualCanonical = new TextEncoder().encode(
      canonicalize(armLeaseSignedBody(fixture.arm_lease)),
    );
    expect(Buffer.from(actualCanonical).toString("hex")).toBe(
      fixture.expected_canonical_json_hex,
    );
    expect(
      Buffer.compare(
        Buffer.from(actualCanonical),
        Buffer.from(fixture.expected_canonical_json_b64, "base64"),
      ),
    ).toBe(0);

    expect(
      ed25519.verify(
        Buffer.from(fixture.test_signature_b64url, "base64url"),
        actualCanonical,
        Buffer.from(fixture.test_public_key_b64url, "base64url"),
      ),
    ).toBe(true);
    expect(fixture.arm_lease.lease_signature_b64url).toBe(
      fixture.test_signature_b64url,
    );
  });

  it("the signed body normalizes wire-optional fields and excludes unconsumed ones", async () => {
    const fixture = await loadFixture();
    const body = armLeaseSignedBody(fixture.arm_lease) as Record<string, unknown>;
    // `revoked` absent on the wire pins to explicit false; the CLI's `source`
    // passthrough and the signature envelope itself stay OUTSIDE the body.
    expect(body.revoked).toBe(false);
    expect(body).not.toHaveProperty("source");
    expect(body).not.toHaveProperty("lease_signature_b64url");
    expect(body).not.toHaveProperty("signing_key_id");
    expect(Object.keys(body).sort()).toEqual([
      "armed",
      "heartbeat_interval_seconds",
      "revoked",
      "ttl_seconds",
      "type",
      "updated_at",
    ]);
  });
});
