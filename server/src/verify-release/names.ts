/**
 * Name normalization shared by the archive map and the installed walk. Both
 * sides key on the NFC form, so a name stored as NFD on one filesystem still
 * matches its archive entry; case folding is used only to detect collisions,
 * never to match, so `Foo` against `foo` is one missing and one extra name.
 */

export function nfc(name: string): string {
  return name.normalize("NFC");
}

/** A single code point mapping, or the code point itself when the mapping would expand it. */
function single(mapped: string, original: string): string {
  return [...mapped].length === 1 ? mapped : original;
}

/**
 * Locale-independent case folding for collision detection. Per code point:
 * lowercase, then lowercase of the uppercase, each kept only when it maps to
 * one code point. This follows Unicode simple case folding (`C` and `S`
 * mappings), so `ſ` and `s`, `ς` and `σ`, or the Kelvin sign and `k` collide,
 * while `ß` stays `ß` because its only uppercase is the two-letter `SS`. It
 * may fold slightly more than the table; for collision detection a wider fold
 * refuses more, never less.
 */
export function simpleFold(name: string): string {
  let out = "";
  for (const codePoint of name) {
    const lower = single(codePoint.toLowerCase(), codePoint);
    const upper = single(lower.toUpperCase(), lower);
    out += single(upper.toLowerCase(), lower);
  }
  return out;
}
