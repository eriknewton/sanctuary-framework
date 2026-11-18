import { Buffer } from "node:buffer";

import type { IdentityManager } from "../cognitive/tools.js";
import { fromBase64url } from "../core/encoding.js";
import { KnownSignersStore } from "../reputation/known-signers-store.js";
import {
  MemoryProvenanceBadSignerStore,
  type MemoryProvenanceForeignDependencyScan,
} from "../sdw/memory-provenance-bad-signers.js";
import { SdwMemoryProvenanceMigration } from "../sdw/memory-provenance-migration.js";
import {
  createPrimaryMemoryProvenancePublicKeyResolver,
  createPrimaryMemoryProvenanceSigningHandleResolver,
} from "../sdw/memory-provenance-signing.js";
import type { StorageBackend } from "../storage/interface.js";

export interface HermesMemoryAdapterCompositionInput {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
  readonly ownerRef: string;
  /** Already loaded; the composition reads the current primary identity from it on every check. */
  readonly identityManager: IdentityManager;
  /** Clear-time dependency scan for the bad-signer store; only a bad-signer clear ever calls it. */
  readonly scanForeignDependencies: (did: string, fingerprint: string) => Promise<MemoryProvenanceForeignDependencyScan>;
}

/** Everything a Hermes-fortress memory adapter needs except its mode and commit check. */
export interface HermesMemoryAdapterComposition {
  readonly options: {
    readonly storage: StorageBackend;
    readonly masterKey: Uint8Array;
    readonly fortressId: string;
    readonly ownerRef: string;
    readonly resolvePrimarySigningHandle: ReturnType<typeof createPrimaryMemoryProvenanceSigningHandleResolver>;
    readonly resolveSignerPublicKey: (identityId: string, did: string) => Uint8Array | undefined;
    readonly resolveMemoryIntegrityState: () => ReturnType<SdwMemoryProvenanceMigration["getState"]>;
    readonly badSignerAuthority: MemoryProvenanceBadSignerStore;
  };
  readonly migration: SdwMemoryProvenanceMigration;
  readonly knownSigners: KnownSignersStore;
  readonly badSignerStore: MemoryProvenanceBadSignerStore;
}

/**
 * One adapter-option composition for the Hermes fortress: primary resolvers,
 * persisted known signers, bad-signer authority and migration state. The bridge
 * and the owner verbs both build their adapter from this, so a passage the owner
 * reads is verified against exactly the signer set the bridge used to save it;
 * only `mode` and the commit check differ between them.
 */
export async function composeHermesMemoryAdapterOptions(
  input: HermesMemoryAdapterCompositionInput,
): Promise<HermesMemoryAdapterComposition> {
  const { storage, masterKey, fortressId, ownerRef, identityManager } = input;
  const signingHandle = createPrimaryMemoryProvenanceSigningHandleResolver(identityManager, masterKey);
  const signerPublicKey = createPrimaryMemoryProvenancePublicKeyResolver(identityManager);
  // Migration state binds only the primary resolver; persisted foreign signers never complete a migration.
  const migration = new SdwMemoryProvenanceMigration({
    storage,
    masterKey,
    fortressId,
    ownerRef,
    resolvePrimarySigningHandle: signingHandle,
    resolveSignerPublicKey: signerPublicKey,
  });
  const knownSigners = new KnownSignersStore(storage, masterKey, { partition: "memory_provenance" });
  const persistedSigners = new Map((await knownSigners.loadAll()).map((entry) => [entry.did, entry.publicKey]));
  const resolveSignerPublicKey = (identityId: string, did: string) =>
    signerPublicKey(identityId, did) ?? persistedSigners.get(did)?.slice();
  const badSignerStore = new MemoryProvenanceBadSignerStore({
    storage,
    masterKey,
    fortressId,
    resolveSignerPublicKey: (did) => persistedSigners.get(did)?.slice(),
    isLocallyRootedSigner: (did, publicKey) => {
      const current = identityManager.getDefault();
      return current?.did === did && Buffer.from(fromBase64url(current.public_key)).equals(Buffer.from(publicKey));
    },
    scanForeignDependencies: input.scanForeignDependencies,
  });
  return {
    options: {
      storage,
      masterKey,
      fortressId,
      ownerRef,
      resolvePrimarySigningHandle: signingHandle,
      resolveSignerPublicKey,
      resolveMemoryIntegrityState: () => migration.getState(),
      badSignerAuthority: badSignerStore,
    },
    migration,
    knownSigners,
    badSignerStore,
  };
}
