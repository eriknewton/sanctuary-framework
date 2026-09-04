/**
 * Master rotation classifies every `_meta` record the product writes.
 *
 * `classifyMetaKey` in core/master-rotation.ts is the single chokepoint that
 * decides how a `_meta` record is carried across a master rotation (restamp
 * under the new master, keep as-is, or refuse by name). It is a closed switch,
 * so it is total only over the keys its author enumerated (AGENTS.md rule 5:
 * a hand-mirrored registry drifts, and a parity check must cover the WHOLE
 * set, never the first entry). This file therefore checks the inventory two
 * ways, and the two must agree:
 *
 *   1. A MECHANICAL scan of server/src for every `_meta` write site (the
 *      `.write(`, `writeRecordDurable(`, and `saveJsonRecord(` calls whose
 *      namespace argument is the `"_meta"` literal or one of the named
 *      constants bound to it), with each key argument resolved to its string
 *      literal through the defining `const` in the same file or, failing that,
 *      anywhere in the tree.
 *   2. A HAND-TYPED inventory (recognized + deferred) that names each key's
 *      writer, so a reviewer can audit a row without re-running the scan.
 *
 * The scan's set must equal the union of the two hand-typed lists, and every
 * recognized key must classify to a recipe. A new write site that the scan
 * picks up but the lists lack fails here; so does a list row whose writer has
 * disappeared.
 *
 * STATED BLIND SPOT of the scan (capability bound, read before trusting a
 * green): it is a regular-expression pass over source text, not a type-checked
 * call graph. It resolves a key argument that is a string literal, an
 * identifier defined as a string `const` (including `export const` and a
 * definition split across a line break), a `??` fallback chain (the default
 * identifier is taken, and the key OPTIONS that override it, `envelopeKey:` /
 * `sentinelKey:`, are resolved wherever a caller passes them), or a
 * `this.<field>` whose field is initialized to a string literal. It does NOT
 * resolve a key that is a plain lower-case variable
 * flowing through a generic helper (those sites are counted and reported, and
 * the count is pinned so a new one is noticed), and it cannot see a write that
 * reaches `_meta` through a namespace held in a variable it does not know. A
 * write site expressed in a shape outside this list passes the scan silently;
 * extend the scan in the same change that introduces such a shape.
 *
 * It also pins the cross-file contract for the config-security baseline: the
 * key, envelope marker, MAC purpose, and MAC domain are duplicated between
 * core/config-baseline.ts (the writer) and core/master-rotation.ts (the
 * restamp recipe) and must agree byte-for-byte.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  classifyMetaKey,
  PENDING_RECOVERY_KEY,
} from "../../src/core/master-rotation.js";
import { CONFIG_BASELINE_META_KEY } from "../../src/core/config-baseline.js";
import {
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_SENTINEL_KEY,
  ROTATION_JOURNAL_KEY,
  STAGED_CUSTODY_ENVELOPE_KEY,
  STAGED_CUSTODY_SENTINEL_KEY,
} from "../../src/core/master-custody.js";
import {
  EPOCH_WITNESS_META_KEY,
  ROLLBACK_FREEZE_META_KEY,
} from "../../src/core/anti-rollback.js";
import {
  STATE_ENVELOPE_PUBLIC_KEYS_KEY,
  STATE_ENVELOPE_VERSION_ANCHORS_KEY,
} from "../../src/cognitive/state-store.js";
import { TRANSPARENCY_FLOOR_META_KEY } from "../../src/transparency/emitter.js";
import { TRANSPARENCY_ANCHOR_CONFIG_META_KEY } from "../../src/transparency/anchoring.js";
import {
  FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
  FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
} from "../../src/v1/federation-sync-state-store.js";
import { FLEET_ACTIVATION_META_KEY } from "../../src/entitlement/activation.js";
import { DOWNGRADE_LOG_META_KEY } from "../../src/entitlement/downgrade-log.js";
import { REVOCATION_LIST_META_KEY } from "../../src/entitlement/revocation-list.js";
import { REVOCATION_VERSION_ANCHOR_META_KEY } from "../../src/entitlement/revocation-antirollback.js";
import { LEDGER_GENERATION_ANCHOR_META_KEY } from "../../src/entitlement/ledger-antirollback.js";

const HERE = fileURLToPath(import.meta.url);
const SERVER_SRC = join(HERE, "..", "..", "..", "src");

interface MetaKeyWriteSite {
  key: string;
  /** The module that writes it (informational; keeps the inventory auditable). */
  writer: string;
}

/**
 * Every `_meta` key with a rotation recipe. Each entry names its writer so a
 * reviewer can re-derive the row from the source tree.
 */
const ROTATION_RECOGNIZED_META_KEYS: readonly MetaKeyWriteSite[] = [
  // Legacy custody markers (deleted at finalize). Written only by the legacy
  // custody path; today's tree reads and deletes them, so the mechanical scan
  // does not see a writer and they are excluded from the scan comparison below.
  { key: "key-params", writer: "core/master-custody.ts (legacy custody)" },
  { key: "recovery-key-hash", writer: "core/master-custody.ts (legacy custody)" },
  // Custody envelope + sentinel.
  { key: CUSTODY_ENVELOPE_KEY, writer: "core/master-custody.ts" },
  { key: CUSTODY_SENTINEL_KEY, writer: "core/master-custody.ts" },
  // Rotation's own artifacts.
  { key: ROTATION_JOURNAL_KEY, writer: "core/master-rotation.ts" },
  { key: PENDING_RECOVERY_KEY, writer: "core/master-rotation.ts" },
  { key: STAGED_CUSTODY_ENVELOPE_KEY, writer: "core/master-rotation.ts" },
  { key: STAGED_CUSTODY_SENTINEL_KEY, writer: "core/master-rotation.ts" },
  // State-store metadata.
  { key: STATE_ENVELOPE_PUBLIC_KEYS_KEY, writer: "cognitive/state-store.ts" },
  { key: STATE_ENVELOPE_VERSION_ANCHORS_KEY, writer: "cognitive/state-store.ts" },
  // Audit-log durable markers.
  {
    key: "audit-head-anchor-established-v1",
    writer: "operational/audit-log.ts (AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY)",
  },
  {
    key: "audit-store-split-established-v1",
    writer: "operational/audit-log.ts (AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY)",
  },
  // Primary identity pointer.
  {
    key: "primary_identity_id",
    writer: "cognitive/tools.ts + audit/checkpoint-identity.ts",
  },
  // Transparency anchors.
  { key: TRANSPARENCY_ANCHOR_CONFIG_META_KEY, writer: "transparency/anchoring.ts" },
  { key: TRANSPARENCY_FLOOR_META_KEY, writer: "transparency/emitter.ts" },
  // Anti-rollback witness + freeze marker.
  { key: EPOCH_WITNESS_META_KEY, writer: "core/anti-rollback.ts" },
  { key: ROLLBACK_FREEZE_META_KEY, writer: "core/anti-rollback.ts" },
  // Federation guardian records.
  {
    key: FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
    writer: "v1/federation-sync-state-store.ts",
  },
  {
    key: FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
    writer: "v1/federation-sync-state-store.ts",
  },
  // Config-security baseline, written on every MCP-server boot (step "5rc").
  { key: CONFIG_BASELINE_META_KEY, writer: "core/config-baseline.ts" },
  // Recovery-key passphrase rekey journal (refused with a heal remedy).
  {
    key: "custody-rekey-journal",
    writer: "cli/reset-passphrase.ts (REKEY_JOURNAL_KEY)",
  },
];

/**
 * `_meta` keys the product can write whose rotation recipe is still tracked
 * work. Rotation refuses fail-closed on any of these (never a silent skip; the
 * behavioral proof is in master-rotation.test.ts), and they are listed here so
 * the inventory stays total: when a recipe lands, MOVE the key into
 * ROTATION_RECOGNIZED_META_KEYS in the same change, or the pin below fails.
 */
const ROTATION_DEFERRED_META_KEYS: readonly MetaKeyWriteSite[] = [
  // Fleet control-plane records (all master-MAC'd {marker,data,mac} envelopes).
  { key: FLEET_ACTIVATION_META_KEY, writer: "entitlement/activation.ts" },
  { key: DOWNGRADE_LOG_META_KEY, writer: "entitlement/downgrade-log.ts" },
  { key: REVOCATION_LIST_META_KEY, writer: "entitlement/revocation-list.ts" },
  {
    key: REVOCATION_VERSION_ANCHOR_META_KEY,
    writer: "entitlement/revocation-antirollback.ts",
  },
  {
    key: LEDGER_GENERATION_ANCHOR_META_KEY,
    writer: "entitlement/ledger-antirollback.ts",
  },
  // Post-split suffix marker (plaintext "1"), written only on a fortress that
  // also carries the split-established marker, which rotation refuses by name.
  {
    key: "audit-post-split-suffix-established-v1",
    writer: "operational/audit-log.ts (AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY)",
  },
];

/** Keys in the hand-typed inventory that no CURRENT write site produces. */
const LEGACY_KEYS_WITHOUT_A_WRITER: ReadonlySet<string> = new Set([
  "key-params",
  "recovery-key-hash",
]);

// ── Mechanical scan ──────────────────────────────────────────────────────────

/** All .ts source under server/src, read once into a path->contents map. */
function readSrcFiles(): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".ts")) {
        out.set(full, readFileSync(full, "utf-8"));
      }
    }
  };
  walk(SERVER_SRC);
  return out;
}

/** Identifiers that are bound to the `_meta` namespace string somewhere in src. */
function metaNamespaceAliases(files: Map<string, string>): Set<string> {
  const aliases = new Set<string>();
  const re = /\b(?:export\s+)?const\s+([A-Z][A-Z0-9_]*)\s*=\s*"_meta"/g;
  for (const src of files.values()) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) aliases.add(m[1]!);
  }
  return aliases;
}

interface ScanResult {
  keys: Set<string>;
  /** `file:identifier` for key arguments the scan could not resolve. */
  unresolved: string[];
}

/**
 * Find every `_meta` write site and resolve its key argument to a literal.
 * Shapes covered are listed in the file header; anything else is reported in
 * `unresolved` rather than silently dropped.
 */
function scanMetaWriteSites(files: Map<string, string>): ScanResult {
  const aliases = [...metaNamespaceAliases(files)];
  const nsAlt = ['"_meta"', ...aliases].map((a) => a.replace(/[$]/g, "\\$")).join("|");
  // `.write(<ns>, <keyExpr>,` and `writeRecordDurable(<storage>, <ns>, <keyExpr>,`
  const writeCall = new RegExp(
    `\\.write\\(\\s*(?:${nsAlt})\\s*,\\s*([^,]+?)\\s*,`,
    "g"
  );
  const durableCall = new RegExp(
    `writeRecordDurable\\(\\s*[^,]+,\\s*(?:${nsAlt})\\s*,\\s*([^,]+?)\\s*,`,
    "g"
  );
  // state-store's generic `_meta` JSON writer: resolve its callers' first arg.
  const saveJsonCall = /\bsaveJsonRecord\(\s*([A-Za-z_][A-Za-z0-9_]*)/g;
  // master-custody's envelope/sentinel writers take the key as an OPTION
  // (`opts?.envelopeKey ?? CUSTODY_ENVELOPE_KEY`); the `??` default is resolved
  // at the write site, and every caller that overrides it (the rotation engine
  // staging `custody-*-next`) is resolved here.
  const keyOptionPass = /\b(?:envelopeKey|sentinelKey):\s*([A-Z][A-Z0-9_]*)/g;

  const keys = new Set<string>();
  const unresolved: string[] = [];
  const corpus = [...files.values()].join("\n");

  const resolveIdent = (ident: string, src: string): string | null => {
    // `const IDENT = "literal"` (optionally exported, optionally split across a
    // line break); prefer the defining file, fall back to the whole tree.
    const def = new RegExp(
      `\\b(?:export\\s+)?const\\s+${ident}\\s*=\\s*"([^"]+)"`
    );
    const local = def.exec(src);
    if (local) return local[1]!;
    const global = def.exec(corpus);
    if (global) return global[1]!;
    return null;
  };

  const resolveExpr = (rawExpr: string, src: string, file: string): void => {
    const expr = rawExpr.trim();
    const literal = /^"([^"]+)"$/.exec(expr);
    if (literal) {
      keys.add(literal[1]!);
      return;
    }
    // `opts?.envelopeKey ?? CUSTODY_ENVELOPE_KEY`: the default is the real key.
    const fallback = expr.includes("??") ? expr.split("??").pop()!.trim() : expr;
    // `this.metadataKey` -> `metadataKey = "literal"` in the same class.
    const thisField = /^this\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(fallback);
    if (thisField) {
      const init = new RegExp(`\\b${thisField[1]!}\\s*=\\s*"([^"]+)"`).exec(src);
      if (init) {
        keys.add(init[1]!);
        return;
      }
    }
    if (/^[A-Z][A-Z0-9_]*$/.test(fallback)) {
      const value = resolveIdent(fallback, src);
      if (value !== null) {
        keys.add(value);
        return;
      }
    }
    unresolved.push(`${relative(SERVER_SRC, file)}:${expr}`);
  };

  for (const [file, src] of files) {
    for (const re of [writeCall, durableCall]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(src)) !== null) resolveExpr(m[1]!, src, file);
    }
    keyOptionPass.lastIndex = 0;
    let opt: RegExpExecArray | null;
    while ((opt = keyOptionPass.exec(src)) !== null) resolveExpr(opt[1]!, src, file);
    if (relative(SERVER_SRC, file) === join("cognitive", "state-store.ts")) {
      saveJsonCall.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = saveJsonCall.exec(src)) !== null) {
        // Skip the definition itself (`saveJsonRecord(key: string, ...)`).
        if (m[1] === "key") continue;
        resolveExpr(m[1]!, src, file);
      }
    }
  }
  return { keys, unresolved };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("master rotation: `_meta` key classification is total over the tree's write sites", () => {
  const files = readSrcFiles();
  const scan = scanMetaWriteSites(files);
  const inventory = [...ROTATION_RECOGNIZED_META_KEYS, ...ROTATION_DEFERRED_META_KEYS];

  it("the mechanical scan resolves every key argument whose shape it recognizes, and the unresolvable set is exactly the known generic loop variables", () => {
    // Size is covered by the set-equality test below; here only the residue.
    // The generic loop variables the scan cannot resolve (see the header):
    // master-rotation.ts's own `_meta` restamp loop writes `key`, and
    // state-store.ts's saveJsonRecord definition takes `key`. Pinned so a new
    // unresolvable shape is noticed rather than absorbed.
    expect(scan.unresolved.sort()).toEqual(
      [join("core", "master-rotation.ts") + ":key", join("cognitive", "state-store.ts") + ":key"].sort()
    );
  });

  it("the scanned write sites equal the hand-typed inventory (recognized + deferred), minus the legacy keys with no current writer", () => {
    const inventoryKeys = inventory
      .map((site) => site.key)
      .filter((key) => !LEGACY_KEYS_WITHOUT_A_WRITER.has(key))
      .sort();
    const scanned = [...scan.keys].sort();
    expect(
      scanned,
      "a `_meta` write site exists in server/src that the inventory lacks (add it " +
        "to ROTATION_RECOGNIZED_META_KEYS with a classifyMetaKey recipe, or to " +
        "ROTATION_DEFERRED_META_KEYS with a reason), or an inventory row's " +
        "writer is gone"
    ).toEqual(inventoryKeys);
  });

  it("every recognized `_meta` write site classifies to a rotation recipe", () => {
    const unclassified = ROTATION_RECOGNIZED_META_KEYS.filter(
      (site) => classifyMetaKey(site.key) === null
    ).map((site) => `${site.key} (written by ${site.writer})`);
    expect(
      unclassified,
      "`_meta` key(s) with a writer in server/src but no classifyMetaKey case; " +
        "add the recipe in core/master-rotation.ts in the same change:\n  " +
        unclassified.join("\n  ")
    ).toEqual([]);
  });

  it("every deferred `_meta` write site is still unclassified (fail-closed abort, not a silent skip); move it when its recipe lands", () => {
    const nowClassified = ROTATION_DEFERRED_META_KEYS.filter(
      (site) => classifyMetaKey(site.key) !== null
    ).map((site) => site.key);
    expect(
      nowClassified,
      "deferred `_meta` key(s) now have a recipe; move them into " +
        "ROTATION_RECOGNIZED_META_KEYS so the inventory stays honest:\n  " +
        nowClassified.join("\n  ")
    ).toEqual([]);
  });

  it("the inventory has no duplicates and no key in both lists", () => {
    const all = inventory.map((site) => site.key);
    expect(new Set(all).size).toBe(all.length);
  });

  it("an unnamed key classifies to null (the preflight's fail-closed default)", () => {
    expect(classifyMetaKey("mystery-record")).toBeNull();
  });

  it("the config-security baseline key/marker/purpose/domain are byte-identical in the writer and the rotation recipe, and each side pins the other", () => {
    const baseline = readFileSync(join(SERVER_SRC, "core", "config-baseline.ts"), "utf8");
    const rotation = readFileSync(join(SERVER_SRC, "core", "master-rotation.ts"), "utf8");
    // The four literals; the domain's trailing newline is written as the `\n`
    // escape in both files, so it is matched as source text.
    const LITERALS = [
      `CONFIG_BASELINE_META_KEY = "config-security-baseline-v1"`,
      `CONFIG_BASELINE_MARKER = "__sanctuary_config_security_baseline_v1"`,
      `CONFIG_BASELINE_MAC_PURPOSE = "config-security-baseline-mac"`,
      `CONFIG_BASELINE_MAC_DOMAIN = "sanctuary.config-security-baseline.v1\\n"`,
    ];
    for (const literal of LITERALS) {
      expect(baseline, `config-baseline.ts must define ${literal}`).toContain(literal);
      expect(rotation, `master-rotation.ts must duplicate ${literal}`).toContain(literal);
    }
    // The rotation recipe reproduces the writer's MAC input layout
    // (domain prefix + meta key + newline), refuses a marker mismatch rather
    // than leaving it for the next boot, and both sides carry the pin.
    expect(rotation).toContain(
      `CONFIG_BASELINE_MAC_DOMAIN + CONFIG_BASELINE_META_KEY + "\\n"`
    );
    expect(rotation).toContain(`case CONFIG_BASELINE_META_KEY:`);
    expect(rotation).toMatch(
      /case "config-security-baseline":[\s\S]*?onMarkerMismatch: "abort"/
    );
    expect(baseline).toContain("server/src/core/master-rotation.ts");
    expect(baseline).toContain(`onMarkerMismatch: "abort"`);
    expect(rotation).toContain("server/src/core/config-baseline.ts");
  });

  it("the epoch-witness force-write contract is pinned on both sides: anti-rollback names finalize as a force caller, and finalize carries the latches", () => {
    const antiRollback = readFileSync(join(SERVER_SRC, "core", "anti-rollback.ts"), "utf8");
    const rotation = readFileSync(join(SERVER_SRC, "core", "master-rotation.ts"), "utf8");
    // writeEpochWitness's `force` doc names BOTH callers and their carry duty.
    expect(antiRollback).toMatch(/`force`[\s\S]{0,400}core\/master-rotation\.ts/);
    expect(antiRollback).toContain("CARRY INVARIANT");
    // finalize's force write carries the whole prior witness object through
    // advanceEpochWitnessData (override, not allow-list) and names the reason.
    expect(rotation).toContain("CARRY INVARIANT");
    expect(rotation).toMatch(
      /advanceEpochWitnessData\(\s*priorWitness\.status === "valid" \? priorWitness\.data : undefined,[\s\S]{0,300}?\{ force: true \}/
    );
    expect(rotation).toMatch(/return \{ \.\.\.\(prior \?\? \{\}\), \.\.\.advance \};/);
  });
});
