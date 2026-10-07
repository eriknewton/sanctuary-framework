/**
 * Credential surrogacy: the placeholder grammar and its single mint.
 *
 * A placeholder is what Sanctuary issues the agent in place of a bound secret.
 * It is not a capability: holding one lets an agent ask the gate to use the
 * value on a bound destination, and nothing else. A placeholder reaching any
 * other surface (a log line, a CONNECT authority, an unbound host) is a
 * detection signal, which is why the grammar is narrow and machine-recognizable
 * rather than opaque.
 *
 * ONE MINT SITE. `mintSurrogatePlaceholder` is called from exactly one place in
 * production, `productionBringUp` in `egress-gate/arming-wiring.ts`, once per
 * binding per committed generation. The boot supervisor, `commitGeneration` and
 * the release-barrier wrapper never mint: a second mint site would let a
 * placeholder exist that root never recorded in the bindings file, and the
 * helper would then refuse it while the agent believed it was live.
 */

import { randomBytes } from "node:crypto";

/** Literal prefix every placeholder carries. Recognizing it is what redaction and misroute detection key on. */
export const SURROGATE_PLACEHOLDER_PREFIX = "sanctuary_surrogate_";

/**
 * Random hex characters after the prefix.
 *
 * Derivation: 128 bits of entropy from `randomBytes(16)`, rendered as 32
 * lowercase hex characters. 128 bits makes guessing a live placeholder for the
 * current generation infeasible, which matters because the gate treats a
 * placeholder it recognizes as a request to use a real credential.
 */
export const SURROGATE_PLACEHOLDER_RANDOM_BYTES = 16;
export const SURROGATE_PLACEHOLDER_HEX_LENGTH = 2 * SURROGATE_PLACEHOLDER_RANDOM_BYTES;

/** Total encoded length: 20 prefix bytes plus 32 hex characters. */
export const SURROGATE_PLACEHOLDER_LENGTH =
  SURROGATE_PLACEHOLDER_PREFIX.length + SURROGATE_PLACEHOLDER_HEX_LENGTH;

/**
 * Anchored match for exactly one placeholder and nothing else.
 *
 * Kept separate from {@link SURROGATE_PLACEHOLDER_SCAN_RE} on purpose: an
 * anchored test is what validates a minted value or a wrapper line, and a
 * global unanchored scan is what redaction needs. Reusing one regex object for
 * both would share `lastIndex` between the two uses.
 */
export const SURROGATE_PLACEHOLDER_RE = new RegExp(
  `^${SURROGATE_PLACEHOLDER_PREFIX}[0-9a-f]{${SURROGATE_PLACEHOLDER_HEX_LENGTH}}$`,
);

/** The same grammar, unanchored and global, for finding placeholders inside a larger string. */
export function surrogatePlaceholderScanRe(): RegExp {
  return new RegExp(
    `${SURROGATE_PLACEHOLDER_PREFIX}[0-9a-f]{${SURROGATE_PLACEHOLDER_HEX_LENGTH}}`,
    "g",
  );
}

/** True only for a complete, correctly shaped placeholder. Lowercase hex only: an uppercase variant is not a placeholder. */
export function isSurrogatePlaceholder(value: unknown): value is string {
  return typeof value === "string" && SURROGATE_PLACEHOLDER_RE.test(value);
}

/**
 * Mint one placeholder. Called once per binding per generation by root inside
 * `productionBringUp` (see the module header: this is the only mint site).
 *
 * `randomBytes` is the synchronous CSPRNG form the rest of this tree uses for
 * unguessable tokens (`gate-credential.ts`, `token-issuer.ts`); a
 * non-cryptographic source here would make a placeholder guessable and so make
 * the gate usable by a process that never received one.
 */
export function mintSurrogatePlaceholder(): string {
  return `${SURROGATE_PLACEHOLDER_PREFIX}${randomBytes(SURROGATE_PLACEHOLDER_RANDOM_BYTES).toString("hex")}`;
}
