/** Exporter-only public projection, report rendering and manifest production. */
import { sign, type StoredIdentity } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { verifyRotationChain } from "../core/rotation-chain.js";
import { renderMarkdownDocumentsToPdf } from "../compliance/eu_ai_act/pdf.js";
import { SNAPSHOT_RECIPIENT } from "./snapshot-recipient.js";
import { validateSnapshotPins } from "./snapshot-trust.js";
import type { SnapshotGather } from "./snapshot-gather.js";
import { extensionRolesAllowed } from "./snapshot-extensions.js";
import * as C from "./snapshot-contract.js";
export function snapshotJSON(value: unknown): Uint8Array { return C.utf8(JSON.stringify(value, null, 2) + C.LF); }
export function projectIdentity(who: StoredIdentity, role: string, publicKey = who.public_key): C.TrustKey {
  const fingerprint = C.manifestDigest(C.publicKey(publicKey));
  // A positive field allowlist prevents private fields at any nesting depth from entering public evidence.
  const history = who.rotation_history.map(h => ({ old_public_key: h.old_public_key, new_public_key: h.new_public_key, rotation_event: h.rotation_event, rotated_at: h.rotated_at }));
  return { role, key_id: fingerprint, algorithm: C.ALGORITHM, public_key_base64url: publicKey, fingerprint, rotation_evidence: { kind: C.ROTATION.history, identity_id: who.identity_id, current_public_key: who.public_key, history } };
}
export function buildPublicTrust(signer: StoredIdentity, identities: readonly StoredIdentity[], gathered: SnapshotGather): Uint8Array {
  const keys: C.TrustKey[] = [projectIdentity(signer, C.PIN_ROLE.pack)];
  if (gathered.auditBytes) {
    const records = C.parseAuditRecords(gathered.auditBytes);
    const checkpoints = records.filter(r => r.type === C.RECORD.checkpoint || r.type === C.RECORD.legacy);
    const publicKeys = new Set(checkpoints.flatMap(r => typeof r.public_key === "string" ? [r.public_key] : []));
    if (!publicKeys.size) publicKeys.add(signer.public_key);
    for (const key of publicKeys) {
      const owner = identities.find(who => who.public_key === key || who.rotation_history.some(h => h.old_public_key === key));
      C.requireSnapshot(owner, C.HARD.pin_invalid);
      const chain = verifyRotationChain({ identityId: owner.identity_id, currentPublicKey: owner.public_key, rotationHistory: owner.rotation_history });
      C.requireSnapshot(chain.status === C.INTEGRITY.verified, C.HARD.pin_invalid);
      if (key !== owner.public_key) {
        const retired = chain.chain.retired.find(k => k.public_key_base64url === key);
        // A retired audit key is eligible only for uncompromised checkpoints signed no later than its retirement.
        C.requireSnapshot(retired && !retired.compromised && checkpoints.filter(r => r.public_key === key).every(r => typeof r.signed_at === "string" && r.signed_at <= retired.retired_at), C.HARD.pin_invalid);
      }
      keys.push(projectIdentity(owner, C.PIN_ROLE.audit, key));
    }
  }
  if (gathered.transparencyPin) {
    const pin = gathered.transparencyPin, fingerprint = C.manifestDigest(C.publicKey(pin.key));
    keys.push({ role: C.PIN_ROLE.transparency, key_id: fingerprint, algorithm: C.ALGORITHM, public_key_base64url: pin.key, fingerprint, rotation_evidence: { kind: C.ROTATION.castle, path_class: pin.pathClass } });
  }
  keys.sort((a, b) => (a.role + ":" + a.key_id) < (b.role + ":" + b.key_id) ? -1 : 1);
  const bytes = snapshotJSON({ format: C.TRUST_FORMAT, keys });
  validateSnapshotPins({ packKey: signer.public_key, descriptorBytes: bytes, expectedManifestDigest: C.manifestDigest(bytes) });
  return bytes;
}
export function renderSnapshot(exportId: string, generatedAt: string, gathered: SnapshotGather, trust: Uint8Array): Map<string, Uint8Array> {
  const describe = (name: string, component: C.Component<unknown>) => `${name}: ${component.state}. ${component.state === C.COMPONENT.included ? "Extent describes only the supplied records: " + JSON.stringify(component.extent) : "Not included: " + component.reason}.`;
  const report = `# Sanctuary evidence snapshot\n\nExport id: ${exportId}\nGenerated at: ${generatedAt}\n\n${describe("Audit", gathered.audit)}\n\n${describe("Transparency", gathered.transparency)}\n\n${C.NOT_CHECKED.join(" ")}\n\n${SNAPSHOT_RECIPIENT}`;
  // Export id labels the PDF without creating a digest cycle through the signed manifest.
  const pdf = renderMarkdownDocumentsToPdf([{ title: "Sanctuary evidence snapshot", markdown: report }], { footerLabel: "Sanctuary evidence snapshot", footerDigestLabel: "Export id", footerDigest: exportId });
  const files = new Map<string, Uint8Array>([[C.REPORT_FILENAME, C.utf8(report)], [C.PDF_FILENAME, pdf], [C.RECIPIENT_FILENAME, C.utf8(SNAPSHOT_RECIPIENT)], [C.TRUST_FILENAME, trust]]);
  if (gathered.auditBytes) files.set(C.AUDIT_FILENAME, gathered.auditBytes);
  if (gathered.transparencyBytes) files.set(C.TRANSPARENCY_FILENAME, gathered.transparencyBytes);
  return files;
}
export function hashSnapshotFiles(files: Map<string, Uint8Array>): C.SnapshotFile[] {
  // Hash raw bytes so binary PDFs receive the same signed integrity coverage as text files.
  return [...files].map(([filename, bytes]) => {
    const entry = Object.entries(C.FIXED_FILES).find(([, pair]) => pair[0] === filename); C.requireSnapshot(entry);
    return { filename, role: entry[0] as C.SnapshotFile["role"], content_type: entry[1][1], sha256: C.sha256Hex(bytes), size_bytes: bytes.length };
  }).sort((a, b) => a.filename < b.filename ? -1 : 1);
}
export function signSnapshot(manifest: C.SnapshotManifest, signer: StoredIdentity, masterKey: Uint8Array): Uint8Array {
  // Export and verification use the same authority registry, even though v0 generates no extension payloads.
  C.requireSnapshot(manifest.extensions.every(e => extensionRolesAllowed(e.id, e.signing_roles)));
  const key = derivePurposeKey(masterKey, "identity-encryption");
  try { manifest.manifest_signature = Buffer.from(sign(C.manifestSigningBytes(manifest as unknown as Record<string, unknown>), signer.encrypted_private_key, key)).toString("base64url"); }
  finally { key.fill(0); }
  C.parseManifest(manifest);
  return snapshotJSON(manifest);
}
