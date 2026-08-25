import { ed25519 } from "@noble/curves/ed25519";
import { hmacSha256 } from "../../src/core/hashing.js";
import { publicKeyToDid } from "../../src/core/identity.js";
import { stringToBytes } from "../../src/core/encoding.js";
import {
  SdwMemoryBackendAdapter,
  type SdwMemoryBackendAdapterOptions,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import type { MemoryProvenanceSigningHandle } from "../../src/sdw/memory-provenance-contract.js";

/** Explicit test fixture. Production code never imports this test-tree module. */
export class TestSdwMemoryBackendAdapter extends SdwMemoryBackendAdapter {
  constructor(options: Omit<SdwMemoryBackendAdapterOptions,
    "resolvePrimarySigningHandle" | "resolveSignerPublicKey" |
    "resolveMemoryIntegrityState" | "testOnlyDefaultProvenanceContext"
  > & {
    readonly resolveMemoryIntegrityState?: SdwMemoryBackendAdapterOptions["resolveMemoryIntegrityState"];
  }) {
    const deps = testMemoryProvenanceDependencies(options.masterKey);
    super({
      ...options,
      ...deps,
      resolveMemoryIntegrityState: options.resolveMemoryIntegrityState ??
        (async () => "state_PRE_MIGRATION"),
      testOnlyDefaultProvenanceContext: memoryInsertIngress(() => "system:test", "system_generated"),
    });
  }
}

export function testMemoryProvenanceDependencies(masterKey: Uint8Array): {
  readonly handle: MemoryProvenanceSigningHandle;
  readonly resolvePrimarySigningHandle: () => MemoryProvenanceSigningHandle;
  readonly resolveSignerPublicKey: (identityId: string, did: string) => Uint8Array | undefined;
} {
  const seed = hmacSha256(masterKey, stringToBytes("test-only-sdw-memory-provenance"));
  const publicKey = ed25519.getPublicKey(seed);
  const handle: MemoryProvenanceSigningHandle = Object.freeze({
    identity_id: "test-primary",
    did: publicKeyToDid(publicKey),
    public_key: publicKey,
    sign: (bytes: Uint8Array) => ed25519.sign(bytes, seed),
  });
  return {
    handle,
    resolvePrimarySigningHandle: () => handle,
    resolveSignerPublicKey: (identityId, did) =>
      identityId === handle.identity_id && did === handle.did ? publicKey : undefined,
  };
}
