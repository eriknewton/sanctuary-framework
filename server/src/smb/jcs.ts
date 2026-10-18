import { bound } from './constants.js';

/** Encode a JSON value using RFC 8785, with UTF-16 key ordering and ECMAScript numbers. */
export function jcs(value: unknown, depth = 0): string {
  // Must match jcs.rs and server/test/smb/vectors/jcs.json; lone surrogates cannot be signed.
  function string(text: string): string {
    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const low = text.charCodeAt(++i);
        if (!(low >= 0xdc00 && low <= 0xdfff)) throw new Error('SMB Unicode');
      } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('SMB Unicode');
    }
    return JSON.stringify(text);
  }
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return string(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('SMB non-finite number');
    return JSON.stringify(value);
  }
  // The same depth budget as the parser bounds recursive work, including cyclic caller objects.
  if (depth > bound('JSON_MAX_DEPTH')) throw new Error('SMB JSON depth');
  if (Array.isArray(value)) return '[' + value.map(item => jcs(item, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && (Object.getPrototypeOf(value) === null || Object.getPrototypeOf(value) === Object.prototype)) {
    return '{' + Object.keys(value).sort().map(key => string(key) + ':' + jcs((value as Record<string, unknown>)[key], depth + 1)).join(',') + '}';
  }
  throw new Error('SMB non-JSON value');
}
