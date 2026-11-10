import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";

// Must match checked in castle-wall-daemon/tests/support/checked_corpus.rs.
export const REQUIRED_CORPORA = ["closure_vectors.json", "generator_vectors.json", "public_vectors.json", "record_join_vectors.json", "role_vectors.json"] as const;
const DEFAULT_ROOT = resolve(fileURLToPath(import.meta.url), "../../../../castle-wall-daemon/src/business_profile");
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const equalKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
function requireCorpus(condition: unknown, reason: string): asserts condition {
  if (!condition) throw new Error(`BUSINESS_CORPUS_REFUSED ${reason}`);
}

export function checkCorpus(manifestBytes: string | Uint8Array, name: string, corpusBytes: string | Uint8Array): unknown {
  const manifest: unknown = JSON.parse(Buffer.from(manifestBytes).toString("utf8"));
  // Only a fully shaped manifest may authorize a corpus; malformed pins cannot remove checks.
  requireCorpus(object(manifest) && equalKeys(manifest, ["version", "contract", "files"]) && manifest.version === 1 && typeof manifest.contract === "string" && object(manifest.files), "manifest shape");
  for (const entry of Object.values(manifest.files)) {
    requireCorpus(object(entry) && equalKeys(entry, ["sha256", "cases"]) && typeof entry.sha256 === "string" && /^[a-f0-9]{64}$/.test(entry.sha256) && object(entry.cases), "manifest entry");
    requireCorpus(Object.values(entry.cases).every(count => Number.isSafeInteger(count) && (count as number) >= 0), "manifest count");
  }
  // Continuing path: the complete required set must be pinned before any corpus can be returned.
  requireCorpus(equalKeys(manifest.files, REQUIRED_CORPORA), "required names");
  const entry = manifest.files[name];
  requireCorpus(object(entry) && object(entry.cases), "unknown corpus");
  // Byte identity prevents a removed witness from disappearing during test collection.
  requireCorpus(createHash("sha256").update(corpusBytes).digest("hex") === entry.sha256, "digest");
  const value: unknown = JSON.parse(Buffer.from(corpusBytes).toString("utf8"));
  requireCorpus(Array.isArray(value) || object(value), "corpus form");
  const groups: Record<string, unknown[]> = Array.isArray(value) ? {$root: value} : Object.fromEntries(Object.entries(value).filter((entry): entry is [string, unknown[]] => Array.isArray(entry[1])));
  // Object groups and array roots have distinct forms, so a pin cannot silently omit a group.
  requireCorpus((Array.isArray(value) || !("$root" in entry.cases)) && equalKeys(entry.cases, Object.keys(groups)), "group form");
  for (const [group, values] of Object.entries(groups)) {
    // Continuing path: every pinned group retains its entire case set, even with an updated digest.
    requireCorpus(values.length === entry.cases[group], `count ${group}`);
  }
  return value;
}

export function loadCheckedCorpus(name: string, {root = DEFAULT_ROOT}: {root?: string} = {}): unknown {
  // The caller cannot turn an unrecognized corpus name into a filesystem lookup outside the root.
  requireCorpus((REQUIRED_CORPORA as readonly string[]).includes(name), "unknown corpus");
  return checkCorpus(readFileSync(resolve(root, "vector_manifest.json")), name, readFileSync(resolve(root, name)));
}
