/** Pure format selection shared by both held-file capture boundaries and the verifier. */
import * as C from "./snapshot-contract.js";
import * as B from "./split-statement-contract.js";
import { validateSnapshotPins,type SnapshotPins } from "./snapshot-trust.js";
import { validateSplitPins } from "./split-statement-verify.js";
/** Inspect a bounded envelope without widening either format's closed parser. */
export function parseManifestEnvelope(bytes:Uint8Array) {
  const value=C.parseSnapshotJSON(bytes,C.MAX_MANIFEST_BYTES);
  C.requireSnapshot(value!==null&&typeof value==="object"&&!Array.isArray(value));
  const format=(value as Record<string,unknown>).format;
  return format===B.FORMAT?B.parseManifestEnvelope(bytes):C.parseManifestEnvelope(bytes);
}
/** Both adapters must match parseManifestEnvelope in this file before opening listed payloads. */
export function parseManifest(raw:Record<string,unknown>) {return raw.format===B.FORMAT?B.parseManifest(raw):C.parseManifest(raw);}
/** Domain selection follows the closed envelope format, never a caller-supplied algorithm. */
export function manifestSigningBytes(raw:Record<string,unknown>){return raw.format===B.FORMAT?B.manifestSigningBytes(raw):C.manifestSigningBytes(raw);}
/** Descriptor format is independently selected, then the verifier rejects cross-format pairing. */
export function validatePins(pins:SnapshotPins){
  let value:unknown;
  try {value=C.parseSnapshotJSON(pins.descriptorBytes,C.MAX_TRUST_BYTES);C.requireSnapshot(value!==null&&typeof value==="object"&&!Array.isArray(value));}
  catch {return validateSnapshotPins(pins);} // V0 owns malformed descriptor mapping before a format can be selected.
  return (value as Record<string,unknown>).format===B.TRUST_FORMAT?validateSplitPins(pins):validateSnapshotPins(pins);
}
/** Authenticated B human output includes basis, coverage and the frozen contract sentences. */
export function humanResult(result:C.VerificationResult|B.Result):string {
  if(result.format===C.RESULT_FORMAT)return C.HUMAN[result.status]+C.LF+[...result.findings.map(f=>f.code),...result.partial_reasons].join(C.LF)+C.LF;
  if(result.snapshot_integrity===C.INTEGRITY.unverified)return C.HUMAN.FAIL+C.LF;
  const rendered=B.renderChains(result.chains);
  return [result.status==="PASS"?B.PASS_SENTENCE:C.HUMAN[result.status],rendered.historical_signatures,...rendered.coverage,...rendered.sentences,...result.findings.map(f=>f.code),...result.partial_reasons].join(C.LF)+C.LF;
}
