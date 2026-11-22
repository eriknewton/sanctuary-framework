import type { SanctuaryConfig } from "../../../src/config.js";
// The v1.9.0-rc.4 body must match TAG_DEEP_MERGE_SHA256 in test/unit/core/tag-config-merge.test.ts.
function deepMerge(base: object, override: object): SanctuaryConfig {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof result[key] === "object" &&
      result[key] !== null
    ) {
      result[key] = deepMerge(
        result[key] as object,
        value as object
      );
    } else {
      result[key] = value;
    }
  }
  return result as unknown as SanctuaryConfig;
}

export { deepMerge };
