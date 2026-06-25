/**
 * Reference plugins — first-party, bundled, contract-only implementations that
 * dogfood the Sanctuary plugin vendor contract (slice S5).
 *
 * The plugin BINARIES (e.g. blocklist/bin/blocklist.mjs) import nothing from
 * Sanctuary; this barrel is the HOST-side loader/spawner for them.
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

export { type SpawnedPlugin, spawnReferencePlugin } from "./spawn.js";
