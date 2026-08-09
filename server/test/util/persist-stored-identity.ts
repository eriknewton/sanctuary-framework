import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import type { StorageBackend } from "../../src/storage/interface.js";

export async function persistStoredIdentity(
  storage: StorageBackend,
  masterKey: Uint8Array,
  identity: StoredIdentity,
): Promise<void> {
  const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const encrypted = encrypt(
    stringToBytes(JSON.stringify(identity)),
    identityEncryptionKey,
  );
  await storage.write(
    "_identities",
    identity.identity_id,
    stringToBytes(JSON.stringify(encrypted)),
  );
}
