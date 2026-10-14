export type LegacyLayerToken = "l1" | "l2" | "l3" | "l4";

// INVARIANT: these legacy pages display the original Health Score layers, not the Castle Wall mechanism names; the `l1`..`l4` tokens stay frozen wire values.
export const LEGACY_LAYER_NAMES: Readonly<Record<LegacyLayerToken, string>> = Object.freeze({
  l1: "Cognitive",
  l2: "Operational",
  l3: "Selective Disclosure",
  l4: "Verifiable Reputation",
});

export function legacyLayerName(token: unknown): string | null {
  return typeof token === "string" && Object.hasOwn(LEGACY_LAYER_NAMES, token)
    ? LEGACY_LAYER_NAMES[token as LegacyLayerToken]
    : null;
}
