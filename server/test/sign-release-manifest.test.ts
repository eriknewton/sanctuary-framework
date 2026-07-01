/**
 * Tests for the signed self-update live-key WIRING (the #818 follow-on).
 *
 * These exercise the sign->verify round trip end-to-end with a GENERATED test
 * keypair (never the placeholder pinned key), mirroring the crypto the release
 * signing script (`scripts/sign-release-manifest.mjs`) performs: it builds the
 * SAME canonical, domain-separated message via `buildReleaseManifestMessage`
 * and signs it with `ed25519.sign(message, seed)`. The runtime verifier
 * (`verifyReleaseManifestWithKey`) must accept that signature and refuse any
 * tamper / wrong-key / absent input.
 *
 * Acceptance (pre-declared, matches the scope doc, N>=3 kinds):
 *   1. A valid manifest (sign->verify) VERIFIES.
 *   2. A flipped body byte -> refused (bad_signature).
 *   3. A wrong-key signature -> refused (bad_signature).
 *   4. A missing/absent manifest -> silent refusal (no advisory).
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../src/core/identity.js";
import { toBase64url } from "../src/core/encoding.js";
import {
  buildReleaseManifestMessage,
  verifyReleaseManifestWithKey,
  type ReleaseManifestBody,
  type SignedReleaseManifest,
} from "../src/release-manifest.js";
import {
  verifyAndAdviseUpdate,
  UPDATE_MANIFEST_REFUSED_OP,
  type UpdateAuditSink,
} from "../src/update-check.js";

/**
 * Reproduce EXACTLY what scripts/sign-release-manifest.mjs does at the crypto
 * seam: build the domain-separated canonical message and sign with the raw
 * Ed25519 seed. If the script's signing ever diverges from the verifier's
 * message construction, this round trip breaks.
 */
function signLikeReleaseScript(
  body: ReleaseManifestBody,
  seed: Uint8Array,
): SignedReleaseManifest {
  const message = buildReleaseManifestMessage(body);
  const signature = ed25519.sign(message, seed);
  return { body, signature: toBase64url(signature) };
}

/** A representative body shaped like the script's output: one tarball hash. */
const BODY: ReleaseManifestBody = {
  version: "1.5.0",
  artifact_hashes: {
    "sanctuary-framework-mcp-server-1.5.0.tgz":
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
};

describe("signed-update wiring: sign->verify round trip", () => {
  it("a valid manifest signed like the release script VERIFIES", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signLikeReleaseScript(BODY, privateKey);

    const result = verifyReleaseManifestWithKey(manifest, publicKey);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.body.version).toBe("1.5.0");
      expect(
        result.body.artifact_hashes[
          "sanctuary-framework-mcp-server-1.5.0.tgz"
        ],
      ).toBe(BODY.artifact_hashes["sanctuary-framework-mcp-server-1.5.0.tgz"]);
    }
  });

  it("a flipped body byte is REFUSED (bad_signature)", () => {
    const { publicKey, privateKey } = generateKeypair();
    const manifest = signLikeReleaseScript(BODY, privateKey);

    // Flip a byte of the signed hash: the signature now covers stale bytes.
    const original =
      BODY.artifact_hashes["sanctuary-framework-mcp-server-1.5.0.tgz"];
    const flipped = `${original.slice(0, -1)}${original.endsWith("0") ? "1" : "0"}`;
    const tampered: SignedReleaseManifest = {
      signature: manifest.signature,
      body: {
        version: BODY.version,
        artifact_hashes: {
          "sanctuary-framework-mcp-server-1.5.0.tgz": flipped,
        },
      },
    };

    const result = verifyReleaseManifestWithKey(tampered, publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  it("a wrong-key signature is REFUSED (bad_signature)", () => {
    const signer = generateKeypair();
    const other = generateKeypair();
    const manifest = signLikeReleaseScript(BODY, signer.privateKey);

    const result = verifyReleaseManifestWithKey(manifest, other.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });
});

describe("signed-update wiring: runtime refusal is silent (no advisory)", () => {
  /** An audit sink that records every appended event for assertions. */
  function recordingSink(): {
    sink: UpdateAuditSink;
    events: Array<{ operation: string; result?: string }>;
  } {
    const events: Array<{ operation: string; result?: string }> = [];
    const sink: UpdateAuditSink = {
      append(_layer, operation, _identityId, _details, result) {
        events.push({ operation, result });
      },
    };
    return { sink, events };
  }

  it("a valid-but-non-pinned manifest is REFUSED by the pinned gate (no advise)", async () => {
    // The runtime gate uses the pinned placeholder, so even a correctly signed
    // manifest from a real key must be refused. This is the inertness contract.
    const { privateKey } = generateKeypair();
    const manifest = signLikeReleaseScript(BODY, privateKey);
    const { sink, events } = recordingSink();

    const out = await verifyAndAdviseUpdate(manifest, sink);
    expect(out.advise).toBe(false);
    expect(events).toHaveLength(1);
    expect(events[0]?.operation).toBe(UPDATE_MANIFEST_REFUSED_OP);
  });

  it("a missing/absent manifest resolves to a silent refusal (advise:false)", async () => {
    // fetchLatestSignedManifest returns null when the asset is absent; the
    // orchestrator treats null as a refusal and never advises. We simulate the
    // null-manifest decision at the verify seam: an empty/absent value is
    // malformed and refused, never advised.
    const out = await verifyAndAdviseUpdate(null);
    expect(out.advise).toBe(false);
    if (!out.advise) expect(typeof out.reason).toBe("string");
  });
});
