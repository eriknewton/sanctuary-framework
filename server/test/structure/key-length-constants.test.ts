/**
 * Key-length constant guard (Hygiene Retrofit PR-4, "no bare magic numbers").
 *
 * Ed25519 key and signature widths used to be written as bare `32` / `64`
 * literals at ~90 comparison sites. That is not a style problem: `32` is ALSO
 * the AES-256 key size, the SHA-256 digest size, the handshake nonce width, and
 * the symmetric fortress master-key size, and `64` is ALSO the legacy
 * `seed || public_key` private-key layout AND the hex character count of a
 * SHA-256 digest. A reader cannot tell which meaning a literal carries, and a
 * mechanical "replace 32 with the key constant" sweep silently mislabels the
 * ones that are not key lengths.
 *
 * PR-4 named the widths at every site that genuinely IS an Ed25519 key or
 * signature length. This test is the durability layer for that work. It makes
 * two assertions:
 *
 *   1. RECONCILIATION: the byte-width constants that must agree across files
 *      actually do. `core/identity.ts` and the standalone offline verifiers
 *      cannot import `core/crypto-suite-registry.ts` (identity.ts because the
 *      registry imports IT, so the reverse edge would close a dependency cycle;
 *      the verifiers because their documented standalone property forbids any
 *      Sanctuary server import). Those files therefore carry literals with a
 *      "must match" pin comment, and this check is what gives the pin teeth.
 *
 *   2. NO REGRESSION: the files PR-4 converted contain no bare-literal Ed25519
 *      key or signature length comparison. A new `pubkey.length !== 32` in any
 *      of them reds here, which is how the convention survives the next editor.
 *
 * Failure mode when this reds: the message names the file and the offending
 * line. The fix is to import the named constant, NOT to add the file to an
 * exclusion list. If a genuinely new 32-or-64-byte value appears that is not an
 * Ed25519 width (say another symmetric key), give it its own named constant or
 * an inline derivation comment and it will not match the patterns below.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(import.meta.url);
// server/test/structure/<file> -> server/
const SERVER_DIR = join(HERE, "..", "..", "..");
const SERVER_SRC = join(SERVER_DIR, "src");

function read(rel: string): string {
  return readFileSync(join(SERVER_SRC, rel), "utf8");
}

/** Value of an `export const NAME = <int>;` or `const NAME = <int>;` declaration. */
function declaredInt(source: string, name: string): number | null {
  const m = new RegExp(
    `(?:export\\s+)?const\\s+${name}\\s*(?::\\s*[^=]+)?=\\s*(\\d+)\\s*;`,
  ).exec(source);
  return m ? Number(m[1]) : null;
}

/**
 * A comparison of some *.length against a bare 32 or 64.
 *
 * Deliberately narrow: it only matches when the compared expression's name
 * looks like Ed25519 key or signature material, so the many legitimate 32s
 * (symmetric keys, digests, nonces) do not produce false reds. Verifying that
 * this pattern actually fires is the job of the self-check test below; a
 * regex guard that cannot match anything is a guard that never protects.
 */
const BARE_ED25519_LENGTH =
  /\b(?:[A-Za-z_$][\w$]*)?(?:[Pp]ub(?:lic)?[Kk]ey|[Pp]ubkey|[Pp]rivate[Kk]ey|[Ss]ignature|[Ss]ig|[Ss]eed)\w*\.length\s*(?:!==|===|!=|==)\s*(?:32|64)\b/;

/**
 * The files PR-4 converted to named constants. Listed explicitly rather than
 * globbed: a glob would silently start covering (or stop covering) files as the
 * tree moves, and the point of this list is that it is a reviewed decision.
 */
const CONVERTED_FILES = [
  "agent-contract/identity-bind.ts",
  "broker-mcp/producer-signature.ts",
  "castle-wall/runtime/helper-signer.ts",
  "castle-wall/runtime/linux-activation-gate.ts",
  "castle-wall/runtime/macos-daemon.ts",
  "castle-wall/runtime/manifest-publisher.ts",
  "castle-wall/runtime/producer-signature.ts",
  "cli/castle-wall-observe.ts",
  "cli/castle-wall.ts",
  "cli/custody-unlock.ts",
  "cli/federation-operator-signing.ts",
  "cli/fleet.ts",
  "cli/transparency.ts",
  "entitlement/activation.ts",
  "entitlement/compliance-attestation.ts",
  "entitlement/token.ts",
  "mesh/federation-joiner-trust-root-store.ts",
  "mesh/federation-rotate-root.ts",
  "mesh/guardian/guardian-roster.ts",
  "mesh/libp2p-transport/peer-id.ts",
  "mesh/lifecycle/node-key-binding.ts",
  "mesh/trust-root-hybrid.ts",
  "recognition/did-web.ts",
  "release-manifest.ts",
  "transparency/emitter.ts",
  "transparency/signer.ts",
  "v1/federation-policy-bundle.ts",
  "v1/federation-revocation.ts",
  "v1/federation-sync-envelope.ts",
  "v1/federation.ts",
  "v1/operator-attestation.ts",
  "v1/session-service.ts",
  "workload-lifecycle/host-attestation.ts",
  "workload-lifecycle/undeclared-finding.ts",
];

describe("Ed25519 byte-width constants", () => {
  const registry = read("core/crypto-suite-registry.ts");

  it("declares the Ed25519 widths the rest of the tree imports", () => {
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_PRIVATE_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
    expect(declaredInt(registry, "ML_DSA_65_PUBLIC_KEY_BYTES")).toBe(1952);
    expect(declaredInt(registry, "ML_DSA_65_SECRET_KEY_BYTES")).toBe(4032);
    expect(declaredInt(registry, "ML_DSA_65_SIGNATURE_BYTES")).toBe(3309);
  });

  it("derives the legacy seed||pubkey width instead of hardcoding 64", () => {
    // The declaration must be an expression over the two named widths, not the
    // literal 64: writing 64 here is what makes it look like a signature length.
    expect(registry).toContain(
      "export const ED25519_LEGACY_SEED_AND_PUBKEY_BYTES =\n" +
        "  ED25519_PRIVATE_KEY_BYTES + ED25519_PUBLIC_KEY_BYTES;",
    );
  });

  it("keeps core/identity.ts's un-importable copy equal to the registry", () => {
    // identity.ts CANNOT import the registry: crypto-suite-registry.ts imports
    // `sign`/`verify` from identity.ts, so the reverse edge would close a
    // dependency cycle. The literal is pinned by comment; this is its teeth.
    const identity = read("core/identity.ts");
    expect(declaredInt(identity, "ED25519_PUBLIC_KEY_LENGTH")).toBe(
      declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES"),
    );
  });

  it("proves core/identity.ts still cannot import the registry", () => {
    // If this ever stops being true the pin above should become a real import.
    // Reading the ACTUAL import list rather than trusting a header comment is
    // deliberate: a "this module imports nothing from X" claim that contradicts
    // the imports is a defect class this repo has hit repeatedly.
    expect(registry).toMatch(/^import .*from "\.\/identity\.js";$/m);
  });

  it("keeps the legacy frozen serializers' literals equal to the registry", () => {
    // `pqc-slice1-additive.test.ts` forbids these two modules from so much as
    // naming the suite registry, so that frozen v1 signatures stay byte-stable.
    // They therefore keep bare literals; this is the reconciliation that makes
    // those literals safe. Verified against that gate's real file list, so the
    // two guards cannot drift into contradicting each other.
    const pqcGate = readFileSync(
      join(SERVER_DIR, "test", "structure", "pqc-slice1-additive.test.ts"),
      "utf8",
    );
    expect(pqcGate).toContain('"server/src/transparency/checkpoint.ts"');
    expect(pqcGate).toContain('"server/src/v1/operator-signed.ts"');

    expect(read("transparency/checkpoint.ts")).toContain(
      "if (keyBytes.length !== 32) return false;",
    );
    expect(read("v1/operator-signed.ts")).toContain(
      "if (signature.length !== 64) return false;",
    );
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
  });

  it("keeps the standalone offline verifier's literals equal to the registry", () => {
    // transparency/verify.ts documents a STANDALONE PROPERTY: it imports only
    // @noble and Node builtins so a third party can compile it alone. Verified
    // against its real import list below, not against its header prose.
    const verify = read("transparency/verify.ts");
    const imports = [...verify.matchAll(/^import[\s\S]*?from\s+["']([^"']+)["'];/gm)].map(
      (m) => m[1]!,
    );
    const sanctuaryImports = imports.filter(
      (spec) => spec.startsWith(".") || spec.startsWith("/"),
    );
    expect(sanctuaryImports).toEqual([]);

    // Its two literals must equal the registry's named widths.
    expect(verify).toContain("if (key.length !== 32) return false;");
    expect(verify).toContain("if (sig.length !== 64) return false;");
    expect(declaredInt(registry, "ED25519_PUBLIC_KEY_BYTES")).toBe(32);
    expect(declaredInt(registry, "ED25519_SIGNATURE_BYTES")).toBe(64);
  });
});

describe("no bare Ed25519 length literals in the converted files", () => {
  it("the scan pattern actually matches a bare literal (self-check)", () => {
    // Mutation-proofs the guard itself: if the regex is broken, this fails
    // before the real assertion can pass vacuously.
    expect(BARE_ED25519_LENGTH.test("if (publicKey.length !== 32) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (signature.length !== 64) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (nodePubkey.length !== 32) {")).toBe(true);
    expect(BARE_ED25519_LENGTH.test("if (seed.length !== 32) {")).toBe(true);
    // ...and does NOT match the symmetric/digest 32s that must stay literals.
    expect(BARE_ED25519_LENGTH.test("if (masterKey.length !== 32) {")).toBe(false);
    expect(BARE_ED25519_LENGTH.test("if (rootHash.length !== 32) return null;")).toBe(
      false,
    );
  });

  for (const rel of CONVERTED_FILES) {
    it(`${rel} names its Ed25519 widths`, () => {
      const offending = read(rel)
        .split("\n")
        .map((line, i) => ({ line, n: i + 1 }))
        // Comments are prose about the numbers, not enforcement; the derivation
        // notes PR-4 added deliberately mention 32 and 64.
        .filter(({ line }) => !/^\s*(\/\/|\*|\/\*)/.test(line))
        .filter(({ line }) => BARE_ED25519_LENGTH.test(line))
        .map(({ line, n }) => `${rel}:${n}: ${line.trim()}`);
      expect(offending).toEqual([]);
    });
  }
});
