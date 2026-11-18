/** Internal non-barrel source registry for split evidence; see the audit row in server/src/README.md. */
import {AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS,AUDIT_CHECKPOINT_REQUIRED_KEYS,AUDIT_CHECKPOINT_OPTIONAL_KEYS} from "./checkpoint-shape.js";
import {AUDIT_ENTRY_KEY_PREFIX,AUDIT_CHECKPOINT_KEY_PREFIXES,AUDIT_RAW_NAME_GRAMMARS,AUDIT_NAMESPACE,AUDIT_CHECKPOINT_NAMESPACE,AUDIT_META_NAMESPACE,AUDIT_INTEGRITY_ALERT_NAMESPACE,AUDIT_ROTATION_ANCHOR_KEY,AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY,AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY,AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY,AUDIT_SPLIT_BOUNDARY_DIRNAME,AUDIT_SPLIT_BOUNDARY_FILENAME,parseCheckpointKeySequence} from "../operational/audit-log.js";
import {AUDIT_DAEMON_NAMESPACE,AUDIT_DAEMON_CHECKPOINT_NAMESPACE,AUDIT_DAEMON_META_NAMESPACE} from "../operational/audit-store-split.js";
import {CUSTODY_WRITE_LOCK_NAMESPACE,MASTER_CUSTODY_RAW_NAME_GRAMMARS} from "../core/master-custody.js";
import {TRANSPARENCY_RAW_NAME_GRAMMARS,TRANSPARENCY_CHECKPOINT_NAMESPACE,TRANSPARENCY_CHECKPOINT_KEY_PREFIX,TRANSPARENCY_FLOOR_META_KEY} from "../transparency/emitter.js";
import {TRANSPARENCY_ANCHOR_CONFIG_META_KEY} from "../transparency/anchoring.js";
import {FILESYSTEM_RAW_NAME_GRAMMARS} from "../storage/filesystem.js";
import {CUSTODY_FS_RAW_NAME_GRAMMARS} from "../storage/custody-fs.js";
// Must match SOURCE_NAMESPACES in evidence-pack/split-statement-contract.ts; whole-set tests compare producer names.
import {SOURCE_NAMESPACES} from "../evidence-pack/split-statement-contract.js";
export {SOURCE_NAMESPACES,AUDIT_CHECKPOINT_REQUIRED_KEYS,AUDIT_CHECKPOINT_OPTIONAL_KEYS};
export const CHAIN_NAMESPACES={operator:{entries:AUDIT_NAMESPACE,checkpoints:AUDIT_CHECKPOINT_NAMESPACE,meta:AUDIT_META_NAMESPACE},daemon:{entries:AUDIT_DAEMON_NAMESPACE,checkpoints:AUDIT_DAEMON_CHECKPOINT_NAMESPACE,meta:AUDIT_DAEMON_META_NAMESPACE}} as const;
export const BOUNDARY={namespace:AUDIT_SPLIT_BOUNDARY_DIRNAME,name:AUDIT_SPLIT_BOUNDARY_FILENAME} as const;
export const META_CONTROLS=[AUDIT_HEAD_ANCHOR_ESTABLISHED_KEY,AUDIT_POST_SPLIT_SUFFIX_ESTABLISHED_KEY,AUDIT_STORE_SPLIT_ESTABLISHED_META_KEY,TRANSPARENCY_FLOOR_META_KEY] as const;
// Must match AUDIT_RAW_NAME_GRAMMARS, TRANSPARENCY_RAW_NAME_GRAMMARS, MASTER_CUSTODY_RAW_NAME_GRAMMARS,
// FILESYSTEM_RAW_NAME_GRAMMARS and CUSTODY_FS_RAW_NAME_GRAMMARS in their imported producer modules.
export const SOURCE_RAW_NAME_PRODUCERS={...AUDIT_RAW_NAME_GRAMMARS,...TRANSPARENCY_RAW_NAME_GRAMMARS,...MASTER_CUSTODY_RAW_NAME_GRAMMARS,...FILESYSTEM_RAW_NAME_GRAMMARS,...CUSTODY_FS_RAW_NAME_GRAMMARS} as const;
export type SourceKind="entry"|"checkpoint"|"control"|"excluded"|"unsupported";
/** Classify the complete raw name set; no unknown audit object is treated as metadata. */
export function sourceKind(namespace:string,key:string):SourceKind {
  if(namespace==="state")return SOURCE_NAMESPACES.includes(key as never)||!key.startsWith("_audit")?"excluded":"unsupported";
  if(namespace===AUDIT_INTEGRITY_ALERT_NAMESPACE)return "excluded";
  if(namespace===BOUNDARY.namespace)return key===BOUNDARY.name?"control":"unsupported";
  if(namespace===AUDIT_META_NAMESPACE||namespace===CHAIN_NAMESPACES.daemon.meta) {
    // Must match TRANSPARENCY_ANCHOR_CONFIG_META_KEY in transparency/anchoring.ts.
    if(key===TRANSPARENCY_ANCHOR_CONFIG_META_KEY)return "excluded";
    if(META_CONTROLS.includes(key as never))return "control";
    return key.startsWith("audit-")||key.startsWith("__audit")||key.startsWith("transparency-")?"unsupported":"excluded";
  }
  if(namespace===TRANSPARENCY_CHECKPOINT_NAMESPACE)return key.startsWith(TRANSPARENCY_CHECKPOINT_KEY_PREFIX)&&Number.isSafeInteger(Number(key.slice(TRANSPARENCY_CHECKPOINT_KEY_PREFIX.length)))?"checkpoint":"unsupported";
  // Must match AUDIT_ENTRY_KEY_PREFIX and AUDIT_CHECKPOINT_KEY_PREFIXES in operational/audit-log.ts; source names retain producer grammar.
  if(Object.values(CHAIN_NAMESPACES).some(n=>n.entries===namespace))return key.startsWith(AUDIT_ENTRY_KEY_PREFIX)?"entry":"unsupported";
  if(Object.values(CHAIN_NAMESPACES).some(n=>n.checkpoints===namespace)) {
    if(AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS.includes(key)||key===AUDIT_ROTATION_ANCHOR_KEY)return "control";
    return Object.values(AUDIT_CHECKPOINT_KEY_PREFIXES).some(prefix=>key.startsWith(prefix))&&parseCheckpointKeySequence(key)!==null?"checkpoint":"unsupported";
  }
  return "unsupported";
}

/** Return the producer's disposition without opening raw lock or residue contents. */
export function producerRawSourceName(namespace:string,rawName:string):"excluded"|"incident"|null {
  for(const grammar of Object.values(SOURCE_RAW_NAME_PRODUCERS)) {
    const applies=grammar.scope==="audit"?Object.values(CHAIN_NAMESPACES).some(n=>n.entries===namespace):grammar.scope==="transparency"?namespace===TRANSPARENCY_CHECKPOINT_NAMESPACE:grammar.scope==="custody"?namespace===CUSTODY_WRITE_LOCK_NAMESPACE:namespace!=="state";
    if(applies&&grammar.pattern.test(rawName))return grammar.disposition;
  }
  return null;
}
/** Exclude only ordinary producer coordination residue; retained incidents remain visible. */
export function excludedRawSourceName(namespace:string,rawName:string):boolean {
  return producerRawSourceName(namespace,rawName)==="excluded";
}
