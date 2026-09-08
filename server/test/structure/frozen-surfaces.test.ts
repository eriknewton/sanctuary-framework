/**
 * Frozen-surface guard (the Q1 "frozen-token tripwire").
 *
 * The single highest-severity risk in the pending l1-l4 -> named-layer rename:
 * the `l1`..`l4` tokens are doing TWO unrelated jobs that look identical to a
 * find-replace. As DIRECTORY/IMPORT-PATH strings they are safe to rename; as
 * WIRE / CRYPTO / AT-REST / EXPORT / DISPLAY literals they must survive
 * byte-for-byte, or existing fortress data stops decrypting and external
 * consumers break. A careless `s/l2/operational/` sweep would silently corrupt
 * the second kind, and it fails SILENTLY (fresh-install tests still pass).
 *
 * This gate asserts every frozen literal below still EXISTS verbatim in
 * server/src. It is a millisecond-fast tripwire that fires the instant a
 * rename/reorg removes one — long before (and cheaper than) the Phase-0 decrypt
 * fixtures. It is presence-only: it proves a frozen surface was not deleted/
 * renamed, not that its every byte is correct (the fixtures do that).
 *
 * PROVENANCE: the list was curated + verified by a multi-agent workflow
 * (extract from the module map / surface manifest / HKDF registry / a code
 * scan -> verify each occurs verbatim on main -> adversarial completeness
 * critic), 2026-06-14. Each entry was confirmed present at curation time.
 *
 * MAINTENANCE: if an INTENTIONAL change renames/removes one of these (e.g. a
 * deliberate API migration), the gate reds — that is the point. Update this
 * list in that same PR, as a conscious, reviewed decision. Never delete an
 * entry to make a red test pass without confirming the surface really moved.
 *
 * Deliberately EXCLUDED (false-safety as a substring presence-check, per the
 * curation's own "dropped" analysis): bare `L1`..`L4` and `1.0` (match prose/
 * type names everywhere); `audit-log` and `sovereignty-profile` (match the
 * UN-renamed filenames audit-log.ts / sovereignty-profile.ts, so the check can
 * never detect the crypto-purpose string changing); `!` and `.enc` (match
 * `!==` / `.encode` etc.); the `"l1" | "l2" | ...` union-type declarations
 * (whitespace-sensitive). The l-number-EMBEDDING labels below are kept: post-
 * rename their only match is the frozen label, so the guard activates exactly
 * when the rename happens.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  readdirSync,
  readFileSync,
  mkdtempSync,
  mkdirSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  fortressCustodyCredentialServices,
  custodyServiceFor,
  canonicalCustodyServiceFor,
  recoveryKeyServiceFor,
  canonicalRecoveryKeyServiceFor,
} from "../../src/wrap/keychain-custody.js";
import { fortressKeychainReadServices } from "../../src/wrap/passphrase.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

// Frozen literals that must exist verbatim in server/src, grouped by category.
const FROZEN_SURFACES: ReadonlyArray<string> = [
  // --- wire: MCP tool names + basename-dispatched bin aliases ---
  "l2_hardening_status",
  "l2_verify_isolation",
  "reputation_publish",
  "compliance_eu_ai_act_annex_iii_classify",
  "broker/request_token",
  "sanctuary_distress",
  "sovereignty_audit",
  "audit_export_siem",
  "shr_generate",
  "shr_verify",
  "shr_gateway_export",
  "verify-transparency",
  "verify-exit-bundle",
  "import-exit-bundle",

  // --- wire: field values / JSON keys / server names parsed by consumers ---
  "l1_cognitive",
  "l2_operational",
  "l3_selective_disclosure",
  "l4_reputation",
  "l3_disclosure",
  "sanctuary-broker",
  "application/did+json; charset=utf-8",
  "identity.sanctuaryprotocol.ai",
  "privacy-filter-tier-2",
  // federation rotate-root rotation-certificate kind tag (Slice 3a; the joiner
  // adopt side in 3b verifies this exact wire value):
  "federation-root-rotation",
  // C12-REPLAY v2 quorum-input domain separators (design §8 Q5): these ride
  // inside signed bytes AND on NodeRevokePayload.quorum_context.input_schema;
  // every verifier matches them as an EXACT literal, so a byte change silently
  // breaks verification of every existing v2 revoke / device-recovery quorum.
  "sanctuary.guardian-revoke-quorum.v2",
  "sanctuary.guardian-device-recovery-quorum.v2",
  // QI-SIBLING-02: same contract for the master-rotation quorum. It rides on
  // MasterRotationPayload.quorum_context.input_schema.
  "sanctuary.guardian-master-rotation-quorum.v2",

  // --- public TS export symbols (root index.ts surface) ---
  "L1Status",
  "L2Status",
  "L3Status",
  "L4Status",
  "HOSTED_DID_PATH_RE",
  "STATE_ENVELOPE_SCHEMA_VERSION",

  // --- user-visible display / help strings ---
  "Cognitive Sovereignty",
  "Operational Isolation",
  "Selective Disclosure",
  "Verifiable Reputation",
  "Your agent is protected.",
  "hero-copy",

  // --- HKDF / crypto domain-separation labels (the at-rest decryption trap) ---
  // l-number-embedding labels (a layer rename must NOT touch these):
  "l2-context-gate",
  "l3-policies",
  "l3-commitments",
  "l4-reputation",
  "l2-recognition-hosted-did-web-v1",
  "l2-auto-trigger-rules-v1",
  "l2-anomaly-classifier-state-v1",
  "l2-english-policy-activation-v1",
  "l2-approval-aggregator-v1",
  "l2-approval-aggregator-payload-v1",
  "l2-query-anonymity-tier-b-v1",
  "l2-privacy-policies-v1",
  "l2-privacy-placeholders",
  "l2-privacy-placeholder-lookup",
  "l2-honeypot-trap-v1",
  "l2-sentinel-finding-v1",
  "key-17:x402-signer:v1",
  "key-17:erc8004-identity:v1",
  "key-17:ap2-mandate:v1",
  // cross-cutting crypto labels + signing domains:
  "intelligence-substrate-config",
  "sanctuary.model-manifest.v1",
  "sanctuary.model-manifest.v2",
  "sanctuary-fed-v0.1-transport",
  // mesh (Sanctuary Federation Protocol v0.1) libp2p transport wire contract +
  // the remaining federation HKDF domain-separation labels. The transport is
  // parked-but-intended (built + tested, no live caller yet); these strings are
  // still on-wire / at-rest contracts a future mesh peer and existing wrapped
  // payloads depend on. The protocol IDs are template-composed
  // (`${STREAM_PREFIX}/<class>/1.0.0`), so the prefix + each class suffix are
  // frozen separately (the assembled literal never appears verbatim in source).
  // A reorg / "it looks unused, delete it" pass must NEVER touch these.
  "/sanctuary/fed/v0.1",
  "/sync/1.0.0",
  "/agent-state/1.0.0",
  "/unicast/1.0.0",
  "sanctuary-fed-v0.1-audit-chain",
  "sanctuary-fed-v0.1-lifecycle-node-key-wrap",
  "sanctuary-fed-v0.1-lifecycle-agent-state-transfer",
  "cw-audit-producer-v1",
  "sanctuary.enforcement-checkpoint.v1",
  "sanctuary.audit-checkpoint.v1",
  "sanctuary.state-envelope.v1",
  "sanctuary.v1.operator-signed",
  "audit-head-anchor",
  "audit-rotation-anchor",
  "identity-encryption",
  "bridge-commitments",
  "federation-trust-root",
  "federation-joiner-trust-root",
  "federation-bootstrap-nonce-spent-set",
  "federation-operator-cloud-provision-claim-set",
  "federation-sync-state",
  "operator-cloud-joined-node",
  "federation-rotate-root-journal-mac",
  "custody-envelope-mac",
  "custody-sentinel",
  "state-meta-mac",
  "principal-baseline",
  "transparency-counter-floor",
  "distress-inbox",
  "sanctuary-composition-v1",
  "sdw-catalog-v1",
  "sdw-document-corpus-v1",
  "sdw-working-state-v1",
  "sdw-query-history-v1",
  "sdw-vector-memory-v1",
  "sdw-replay-anchors-v1",
  "sdw-source-ref-v1",
  "sdw-memory-passage-content-v1",
  "sdw-replay-anchor-mac",
  "sdw-owner-pin-mac",
  "sanctuary.audit.v1",
  "sanctuary.receipt.v1",
  "sanctuary.transparency.anchor-commitment.v1",
  "sanctuary.meta-record-mac.v1",
  "sanctuary-fortress-mode-v1",
  "operator-chat-store-v1",
  "concierge-memory-store-v1",
  "principal-policy-unified-inbox-v1",
  "principal-policy-unified-inbox-operator-prefs-v1",
  "principal-policy-unified-inbox-retention-policy-v1",

  // --- post-quantum (hybrid Ed25519+ML-DSA-65) signing-suite + cert-version
  // literals (the at-rest/on-wire PQC trap). These tag the bundle/domain and
  // the v2 hybrid fortress-master/principal-cert/node-cert/root-rotation
  // surfaces. Changing a byte breaks verify of existing hybrid certs and
  // decrypt/verify of existing v2 fortresses, and it fails SILENTLY
  // (fresh-install tests still pass). See crypto-suite-registry.ts +
  // mesh/trust-root-hybrid.ts. A vocabulary/reorg sweep must NEVER touch these.
  "sanctuary.signature-bundle.v1",
  "sanctuary.signed-surface.v1",
  "ed25519+ml-dsa-v1",
  "ml-dsa-65-v1",
  "sanctuary.fortress-master.v2.hybrid-ed25519-ml-dsa-65",
  "sanctuary.principal-cert.v2.hybrid-ed25519-ml-dsa-65",
  "sanctuary.node-cert.v2.hybrid-ed25519-ml-dsa-65",
  "sanctuary.root-rotation.v2.hybrid-ed25519-ml-dsa-65",

  // --- persisted at-rest keys / namespaces (renaming orphans on-disk state) ---
  "SANCTUARY_EXIT_BUNDLE_V1",
  "_composition",
  "_intelligence",
  "_bridge",
  "_chat",
  "_recognition_hosted_did_web",
  "_sdw_catalog",
  "_sdw_document_corpus",
  "__custody_epoch_keys",
  "__head_anchor",
  "state-envelope-public-keys-v1",
  "_reputation",
  "_meta",
  "_query_anonymity_tier_b",
  "_query_anonymity_reverse_map",
  "_facade/hidden",
  // federation rotate-root at-rest keys (Slice 3a; renaming orphans an
  // in-progress rotation's staged record / journal):
  "trust-root-v1-next",
  "rotate-root-journal",

  // --- frozen versioned HTTP / served route paths ---
  "/v1/agents/protect",
  "/api/sentinels",
  "/v1.1",
  "/v1/status",
  "/api/console",
  "/api/distress",
];

/** All .ts source under server/src, concatenated once. */
function readServerSrcCorpus(): string {
  const parts: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) {
        parts.push(readFileSync(full, "utf-8"));
      }
    }
  };
  walk(SERVER_SRC);
  return parts.join("\n");
}

describe("frozen-surface guard", () => {
  it("every frozen wire/crypto/at-rest/export/display literal still exists verbatim in server/src", () => {
    const corpus = readServerSrcCorpus();
    // sanity: the walk actually read the tree
    expect(corpus.length).toBeGreaterThan(100_000);

    const missing = FROZEN_SURFACES.filter((literal) => !corpus.includes(literal));

    expect(
      missing,
      "Frozen surface(s) no longer present verbatim in server/src — a reorg or " +
        "layer rename may have changed a wire/crypto/at-rest/export/display literal " +
        "that must survive byte-for-byte (this would silently break decryption of " +
        "existing data or break external consumers). If the change was INTENTIONAL " +
        "(a deliberate API migration), update FROZEN_SURFACES in this same PR as a " +
        "reviewed decision:\n  " + missing.join("\n  "),
    ).toEqual([]);
  });

  it("the frozen-surface list has no duplicates", () => {
    const dupes = FROZEN_SURFACES.filter(
      (v, i) => FROZEN_SURFACES.indexOf(v) !== i,
    );
    expect(dupes, `duplicate entries: ${dupes.join(", ")}`).toEqual([]);
  });
});

/**
 * OS-keyring credential service names (the on-device contract).
 *
 * These names live in the OPERATOR's keyring, not in this repository, so a
 * rename orphans a credential on a machine no release can reach. The
 * presence-only guard above cannot see them: every non-default fortress's name
 * is COMPOSED at runtime as `<prefix>-<16 hex of sha256(canonical path)>`, so a
 * changed prefix, a changed derivation, or a dropped compatibility spelling
 * never removes a literal from the source corpus.
 *
 * This block pins the COMPOSED output of both sides against fixed fixture
 * paths, so it trips when the ENROL side (`wrap/keychain-custody.ts`,
 * `wrap/passphrase.ts`) or the derivation changes, and it pins the cross-file
 * comments that warn an editor of either side before CI has to. The lookup side
 * is `wrap/custody-credential.ts`, the one resolver every verb reads through:
 * the A73 defect was a verb looking somewhere the enrolment never wrote.
 *
 * The expected strings are LITERALS on purpose. Recomputing the hash in the
 * test would assert only that the code agrees with itself, which is exactly the
 * assertion a renamed prefix would still pass.
 */
describe("OS-keyring credential service families (on-device contract)", () => {
  // Fixture paths, not real ones: the parent of the fixture home is `/`, which
  // exists on every platform, so the canonical (realpath-resolved) and lexical
  // spellings coincide and the expected output is stable everywhere.
  const FIXTURE_HOME = "/sanctuary-frozen-surface-fixture-home";
  const DEFAULT_FORTRESS = `${FIXTURE_HOME}/.sanctuary`;
  const NAMED_FORTRESS = `${FIXTURE_HOME}/fortresses/daily`;

  it("composes the frozen custody/recovery service names", () => {
    expect(
      fortressCustodyCredentialServices(DEFAULT_FORTRESS, FIXTURE_HOME),
    ).toEqual(["sanctuary-custody", "sanctuary-recovery"]);
    expect(
      fortressCustodyCredentialServices(NAMED_FORTRESS, FIXTURE_HOME),
    ).toEqual([
      "sanctuary-custody-461e5387cde66977",
      "sanctuary-recovery-461e5387cde66977",
    ]);
  });

  it("composes the frozen passphrase service names, including the legacy read spelling", () => {
    expect(
      fortressKeychainReadServices(DEFAULT_FORTRESS, FIXTURE_HOME),
    ).toEqual(["sanctuary-passphrase"]);
    // The 12-hex entry is the pre-v1.2.3 spelling and stays READABLE forever;
    // dropping it strands a credential on any host installed before that.
    expect(fortressKeychainReadServices(NAMED_FORTRESS, FIXTURE_HOME)).toEqual([
      "sanctuary-passphrase-461e5387cde66977",
      "sanctuary-passphrase-461e5387cde6",
    ]);
  });

  it("both the enrol side and the lookup side carry the cross-file pin", () => {
    const pinned: ReadonlyArray<[string, string]> = [
      ["wrap/keychain-custody.ts", "wrap/custody-credential.ts"],
      ["wrap/passphrase.ts", "wrap/custody-credential.ts"],
      ["wrap/custody-credential.ts", "wrap/keychain-custody.ts"],
      ["wrap/custody-credential.ts", "wrap/passphrase.ts"],
    ];
    const missing = pinned.filter(
      ([file, mustName]) =>
        !readFileSync(join(SERVER_SRC, file), "utf-8").includes(mustName),
    );
    expect(
      missing,
      "A credential service-name file no longer names its counterpart. The " +
        "pin comments are the in-place tripwire that warns whoever edits one " +
        "side that the other must move with it:\n  " +
        missing.map(([file, name]) => `${file} -> ${name}`).join("\n  "),
    ).toEqual([]);
  });
});

/**
 * The block above pins the composed names against a fixture whose canonical
 * and lexical spellings COINCIDE (the fixture home's parent is `/`, which
 * needs no realpath resolution), so a dropped lexical alias in
 * `fortressCustodyCredentialServices` would not trip it: with coincident
 * paths the de-duplication already collapses the four candidates to two, and
 * removing the lexical entries from `ordered` produces that SAME two-entry
 * result. A real symlink is the fixture where the two spellings diverge, so
 * dropping the alias actually changes the composed output and this test can
 * see it.
 */
describe("OS-keyring credential service families on a path that resolves through a symlink", () => {
  let symlinkHome: string;
  let lexicalFortress: string;

  beforeEach(() => {
    symlinkHome = mkdtempSync(join(tmpdir(), "a73-frozen-surface-symlink-"));
    const realFortress = join(symlinkHome, "real-fortress");
    mkdirSync(realFortress, { recursive: true });
    const linkDir = join(symlinkHome, "link-fortress");
    symlinkSync(realFortress, linkDir);
    // The fixture path itself need not exist: `canonicalCredentialStoragePath`
    // walks up to the deepest existing ancestor (the symlink) and resolves it,
    // then rejoins the non-existent tail.
    lexicalFortress = join(linkDir, "daily");
  });

  afterEach(() => {
    rmSync(symlinkHome, { recursive: true, force: true });
  });

  it("composes distinct canonical and lexical names, and the lookup registry carries both", () => {
    const canonicalCustody = canonicalCustodyServiceFor(lexicalFortress, symlinkHome);
    const lexicalCustody = custodyServiceFor(lexicalFortress, symlinkHome);
    const canonicalRecovery = canonicalRecoveryKeyServiceFor(lexicalFortress, symlinkHome);
    const lexicalRecovery = recoveryKeyServiceFor(lexicalFortress, symlinkHome);

    // Sanity check on the fixture: if the two spellings ever coincided again,
    // the assertion below would be vacuous rather than a real pin.
    expect(canonicalCustody).not.toBe(lexicalCustody);
    expect(canonicalRecovery).not.toBe(lexicalRecovery);

    expect(
      fortressCustodyCredentialServices(lexicalFortress, symlinkHome),
    ).toEqual([canonicalCustody, lexicalCustody, canonicalRecovery, lexicalRecovery]);
  });
});

/**
 * Credential help text and the boot-order comments that describe it.
 *
 * `server/reorg-surface-manifest.md` freezes the CLI command surface INCLUDING
 * its help text, because help text is product copy an operator acts on. The
 * A73 credential work changed the behavior underneath it: `protect` stopped
 * minting a passphrase over a fortress that already has custody, and
 * `export-passphrase` stopped being a `sanctuary-passphrase`-only read. The old
 * wording therefore described behavior the code no longer has, which is the one
 * reason frozen text may change — and it changes WITH the manifest row, never
 * around it.
 *
 * These assertions pin the new wording so the next edit is a deliberate one,
 * and pin the two source comments that state the same contract from the other
 * side. A comment that is merely true today is not a contract; a comment a test
 * fails on is.
 */
describe("credential help text and boot-order comments match the shipped behavior", () => {
  const read = (file: string): string =>
    readFileSync(join(SERVER_SRC, file), "utf-8");

  it("no help text still promises that protect auto-generates a passphrase", () => {
    // The exact strings that were false: `protect` opens an existing fortress
    // with the credential this host already holds, and mints only for a
    // fortress with no custody at all.
    const retired = [
      "Auto-generates a passphrase",
      "2. Generates a passphrase (stored in Keychain on macOS",
      "# Print stored passphrase",
      "Print the stored passphrase to stdout after",
    ];
    const survivors = retired.filter(
      (text) => read("cli.ts").includes(text) || read("wrap/cli.ts").includes(text),
    );
    expect(
      survivors,
      "Frozen help text that describes retired behavior is back in the tree. " +
        "If the behavior itself came back, update the CLI-command-surface row " +
        "in server/reorg-surface-manifest.md in the same change:\n  " +
        survivors.join("\n  "),
    ).toEqual([]);
  });

  it("both protect help surfaces describe the enrolled-credential path", () => {
    for (const file of ["cli.ts", "wrap/cli.ts"] as const) {
      expect(read(file)).toContain(
        "generates a passphrase only for a fortress with no custody yet",
      );
    }
    expect(read("cli.ts")).toContain(
      "Opens the fortress with the custody factor already",
    );
  });

  it("export-passphrase help states the passphrase-first order its code runs", () => {
    // Paired with the two resolver calls in `cli/export-passphrase.ts`: the
    // stored passphrase first, the enrolled custody factor only as a fallback.
    // The defect this closes was help and code disagreeing about that order.
    expect(read("cli/export-passphrase.ts")).toContain(
      "Prints the stored fortress passphrase when one unlocks this fortress,",
    );
    expect(read("cli/export-passphrase.ts")).toContain(
      'const stored = await resolveHostLocal(["stored-passphrase"]);',
    );
  });

  it("the wrap MCP-entry comment names the resolver the launched server runs", () => {
    // The launched server resolves its credential through
    // `wrap/custody-credential.ts`, which tries the ENROLLED custody factor
    // before the stored passphrase. The comment used to state the opposite
    // order, which is a boot-order claim an operator would debug against.
    const wrapCli = read("wrap/cli.ts");
    expect(wrapCli).toContain(
      "the SAME\n  // shared resolver this verb runs (wrap/custody-credential.ts)",
    );
    expect(wrapCli).toContain(
      "tries the ENROLLED OS-keyring custody factor before the",
    );
  });

  it("the dashboard help states the host-local credential bound instead of promising a free start", () => {
    // `sanctuary dashboard` starts without a TYPED credential only when this
    // host already holds one (the enrolled OS-keyring custody factor or the
    // stored passphrase). On a host holding neither, an existing fortress
    // refuses to start, so the retired sentence promised a start the code has
    // never performed. Pinned with the manifest's CLI-command-surface row.
    const dashboardHelp = read("cli.ts");
    expect(dashboardHelp).not.toContain("No credential is required to start.");
    expect(dashboardHelp).toContain(
      "No credential has to be TYPED when this host already holds one for the",
    );
    expect(dashboardHelp).toContain(
      "refuses to start without one",
    );
  });

  it("readStoredPassphrase's doc no longer claims export-passphrase as its consumer", () => {
    const passphrase = read("wrap/passphrase.ts");
    expect(passphrase).not.toContain("Used by the `export-passphrase` subcommand");
    expect(passphrase).toContain("It is NOT the fortress credential chain.");
  });
});
