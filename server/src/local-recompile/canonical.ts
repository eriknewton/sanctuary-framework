/**
 * The one serializer and the one parser for local job records. Both stores,
 * the worker and the job code use only these two functions, so every record
 * is written in one canonical form and read back by one strict grammar.
 */
import { canonicalize } from "../mesh/canonical-json.js";
import { parseStrictJson } from "../substrate/strict-json.js";

export function canonicalLocalJson(value: unknown): string {
  return canonicalize(value);
}

export function parseLocalJson(text: string): unknown {
  return parseStrictJson(text);
}
