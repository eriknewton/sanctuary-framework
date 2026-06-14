/**
 * Sanctuary Wrap - Public surface.
 *
 * Install-time wrap/init custody flows for `sanctuary wrap` and
 * `sanctuary init`: passphrase and OS-keyring custody, recovery-key and
 * passphrase disclosure, the unified wrap custody establishment flow, agent
 * config detection/rewrite (with the legacy wrap-meta constant), the
 * standalone fortress-init entry, the zero-config tool-tier classifier, and
 * harness-schema detection.
 *
 * The wrap CLI entry point (cli.ts) is intentionally NOT re-exported: it is
 * the shebang binary entrypoint whose exports are command-handler internals,
 * not library API. The Fortress View HTML renderer (fortress-view.ts) and
 * the internal config-injection helpers (hermes-yaml.ts,
 * claude-code-allowlist.ts) are likewise excluded as non-library surface.
 */

export * from "./passphrase.js";
export * from "./keychain-custody.js";
export * from "./recovery-key-disclosure.js";
export * from "./custody-flow.js";
export * from "./config-reader.js";
export * from "./init.js";
export * from "./tier-classifier.js";
export * from "./harness-schema.js";
