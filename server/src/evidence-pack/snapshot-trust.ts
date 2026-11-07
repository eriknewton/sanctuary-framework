/** Public trust validation only; stored-identity projection belongs to the exporter. */
import { verifyRotationChain } from "../core/rotation-chain.js";
import * as C from "./snapshot-contract.js";
export interface SnapshotPins { packKey: string; descriptorBytes: Uint8Array; expectedManifestDigest: string }
export function validateSnapshotPins(pins: SnapshotPins): C.TrustDescriptor {
  try {
    C.publicKey(pins.packKey);
    const descriptor = C.parseTrustDescriptor(pins.descriptorBytes);
    C.requireSnapshot(descriptor.keys.find(k => k.role === C.PIN_ROLE.pack)!.public_key_base64url === pins.packKey, C.HARD.pin_invalid);
    for (const row of descriptor.keys) validateRotationEvidence(row);
    return descriptor;
  } catch { throw new C.SnapshotError(C.HARD.pin_invalid); }
}
export function validateRotationEvidence(row: C.TrustKey): void {
  const e = row.rotation_evidence;
  if (e.kind !== C.ROTATION.history) return;
  const result = verifyRotationChain({ identityId: e.identity_id, currentPublicKey: e.current_public_key, rotationHistory: e.history });
  // Public history authorizes only explicitly pinned, uncompromised keys in a fully verified chain.
  C.requireSnapshot(result.status === C.INTEGRITY.verified, C.HARD.pin_invalid);
  C.requireSnapshot(row.public_key_base64url === e.current_public_key || result.chain.retired.some(k => k.public_key_base64url === row.public_key_base64url && !k.compromised), C.HARD.pin_invalid);
}
export function bindSnapshotTrust(manifest: C.SnapshotManifest, descriptor: C.TrustDescriptor, delivered: Uint8Array, independent: Uint8Array): void {
  // The delivery cannot replace the independently authenticated key roster even with self-consistent signatures.
  C.requireSnapshot(C.manifestDigest(delivered) === C.manifestDigest(independent), C.HARD.descriptor_mismatch);
  const e = descriptor.keys.find(k => k.role === C.PIN_ROLE.pack)!.rotation_evidence;
  C.requireSnapshot(e.kind === C.ROTATION.history && e.identity_id === manifest.signer.identity_id && e.current_public_key === manifest.signer.public_key_base64url, C.HARD.pin_invalid);
  for (const role of [C.ROLE.audit, C.ROLE.transparency] as const) {
    // Every included component requires an independent role pin before any nested call.
    if (manifest.components[role].state === C.COMPONENT.included) C.requireSnapshot(descriptor.keys.some(k => k.role === C.PIN_ROLE[role]), C.HARD.pin_invalid);
  }
  for (const e of manifest.extensions) for (const role of e.signing_roles) C.requireSnapshot(descriptor.keys.some(k => k.role === role), C.HARD.pin_invalid);
}
