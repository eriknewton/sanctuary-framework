import { parseStrictJson } from '../hermes-memory-bridge/strict-json.js';
import { bound } from './constants.js';

/** Parse one bounded UTF-8 JSON document, preserving the A4 numeric and duplicate-name rules. */
export function parseStrict(bytes: Uint8Array, maximum: number = bound('REQ_MAX')): unknown {
  // Size is checked before decoding so an untrusted document cannot allocate beyond its edge budget.
  if (bytes.byteLength > maximum) throw new Error('SMB JSON size');
  // Must match strict_json.rs and vectors/strict-json.json: binary64 magnitude <= MAX_SAFE_INTEGER.
  return parseStrictJson(bytes, bound('JSON_MAX_DEPTH'));
}
