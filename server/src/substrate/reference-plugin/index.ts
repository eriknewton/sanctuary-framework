/**
 * Reference plugins - first-party, BUNDLED, contract-only implementations that
 * dogfood the Sanctuary plugin vendor contract (slice S5).
 *
 * There is now more than one first-party bundled reference plugin (a bare-domain
 * blocklist and a Pi-hole / hosts-format blocklist), each independently signed with
 * its own key. The plugin BINARIES (e.g. blocklist/bin/blocklist.mjs) import nothing
 * from Sanctuary; this barrel is the HOST-side loader/spawner for them. These are
 * FIRST-PARTY BUNDLED reference plugins, NOT third-party or marketplace plugins;
 * third-party install stays F1-gated.
 */

export {
  REFERENCE_BLOCKLIST_PLUGIN_ID,
  REFERENCE_BLOCKLIST_SIGNER_ID,
  REFERENCE_BLOCKLIST_KEY_ID,
  REFERENCE_BLOCKLIST_ENTRY,
  REFERENCE_SIGNER_PUBKEY_FILENAME,
  type LoadedReferenceBundle,
  referenceBlocklistBundleDir,
  enumerateBundle,
  buildReferenceDescriptor,
  signDescriptor,
  loadReferenceBlocklistBundle,
  readBundledSigner,
  loadBundledReferenceBlocklist,
} from "./blocklist.js";

export {
  FIRST_PARTY_SIGNER_FILENAME,
  type BundledPluginSpec,
  type LoadedBundledPlugin,
  BUNDLED_PLUGINS,
  bundledPluginSpec,
  pinnedSignerFor,
  bundledPluginDir,
  enumerateBundleDir,
  readBundledSignerFrom,
  loadBundledPlugin,
} from "./bundled-plugins.js";

export { type SpawnedPlugin, spawnReferencePlugin } from "./spawn.js";
