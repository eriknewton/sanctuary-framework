import {readFileSync, writeFileSync} from 'node:fs';
import {tsImport} from '../server/node_modules/tsx/dist/esm/api/index.mjs';
const root = new URL('../', import.meta.url);
const {LINUX_FIELDS, ROLE_REGISTRY} = await tsImport(new URL('server/src/signing/contract.ts',root).href,import.meta.url);
const read = path => JSON.parse(readFileSync(new URL(path, root), 'utf8'));
const contract = read('server/src/signing/business-append-contract.json');
const schema = read('server/src/signing/linux-business-records.schema.json');
const {ED25519_SIGNATURE_BYTES} = await tsImport(new URL('server/src/core/crypto-suite-registry.ts',root).href,import.meta.url);
// Must match writer_protocol.rs envelope and SIGNATURE_BYTES: producer ownership is checked before either output is written.
const joinCandidate = process.argv.includes('--join-contract-file') ? process.argv[process.argv.indexOf('--join-contract-file') + 1] : new URL('server/src/signing/join-state-contract.json',root);
const join = JSON.parse(readFileSync(joinCandidate,'utf8'));
const producerIndex = [...LINUX_FIELDS.filter(key => !key.endsWith('_digest')), 'machine_id'];
if (JSON.stringify([...join.outer_index].sort()) !== JSON.stringify([...producerIndex].sort())) throw Error('join outer index differs from producer');
if (join.signature_bytes !== ED25519_SIGNATURE_BYTES) throw Error('join signature width differs from producer');
// Each encoding admits ASCII only; quotes contribute two bytes. Union maxima
// deliberately ignore cross-field constraints, giving a conservative bound.
const {BUSINESS_ENCODING_WIDTHS: widths, BUSINESS_SIGNATURE_TEXT_BYTES} = await tsImport(new URL('server/src/signing/business-append-contract.ts',root).href,import.meta.url);
function bound(node) {
  switch (node.type) {
    case 'ref': return bound(schema.definitions[node.name]);
    case 'literal': return Buffer.byteLength(JSON.stringify(node.value));
    case 'enum': return Math.max(...node.values.map(v => Buffer.byteLength(JSON.stringify(v))));
    case 'integer': return String(node.max).length;
    case 'string': if (!(node.encoding in widths)) throw Error('encoding'); return widths[node.encoding] + 2;
    case 'union': return Math.max(...node.branches.map(bound));
    case 'object': return 2 + Math.max(0,Object.keys(node.fields).length-1) + Object.entries(node.fields).reduce((sum,[key,n]) => sum+JSON.stringify(key).length+1+bound(n),0);
    default: throw Error('unbounded schema');
  }
}
const branchBounds = schema.record.branches.map(branch => {
  const keys = [...LINUX_FIELDS.filter(key => !key.endsWith('_digest')), 'machine_id'];
  const outer = {type:'object',fields:Object.fromEntries(keys.map(k=>[k,branch.fields[k]]))};
  outer.fields.signature={type:'literal',value:'A'.repeat(BUSINESS_SIGNATURE_TEXT_BYTES)};
  return bound({type:'object',fields:{body:branch,outer}});
});
const maximum = Math.max(...branchBounds);
// The complete closed state schema owns every key; all free text uses ASCII encodings.
// JSON.stringify charges any escaping in registry literals and field names exactly.
const objectBytes = fields => 2 + Math.max(0,Object.keys(fields).length-1) +
  Object.entries(fields).reduce((sum,[key,size])=>sum+Buffer.byteLength(JSON.stringify(key))+1+size,0);
const arrayBytes = (count,item) => 2 + Math.max(0,count-1) + count*item;
const scalarBounds = {
  role: Math.max(...ROLE_REGISTRY.map(row=>Buffer.byteLength(JSON.stringify(row.role)))),
  kid: widths.kid+2, public_key: Math.ceil(join.public_key_bytes*8/6)+2,
  id: widths.id+2, digest: widths.digest+2, commitment: Math.max(widths.digest, 'GENESIS'.length)+2,
  safe_u64: String(schema.bounds.safe_integer).length, u64_text: widths.u64+2,
};
const vendorBytes = objectBytes({address:widths.ipv4+2,port:bound(schema.definitions.Port)});
const tokenBounds = {...scalarBounds,
  safe_u64_list:arrayBytes(join.policy_agent_uids_max,scalarBounds.safe_u64),
  vendor_list:arrayBytes(join.policy_vendors_max,vendorBytes),
  history:arrayBytes(contract.limits.join_history_max,maximum),
};
const components = Object.fromEntries(Object.entries(join.state_schema).map(([name,fields])=>[name,
  objectBytes(Object.fromEntries(Object.entries(fields).map(([key,token])=>{
    if (!(token in tokenBounds)) throw Error('unbounded join token');
    return [key,tokenBounds[token]];
  })))
]));
const joinMaximum = objectBytes(components);
// The v0 cap is conservative, not attained: 181,481 - 175,337 = 6,144 bytes of slack.
// All 64 history envelopes use the all-branch bound of 2,757 bytes above, while
// the largest valid envelope attains 2,661 bytes: 64 * (2,757 - 2,661) = 6,144.
// The shared maximal-join-state.json fixture attains 175,337 with the longest registered role.
// Must match JOIN_STATE_BYTES_MAX in records.rs and record-joins.ts; both raw parsers consume this cap.
if (process.argv.includes('--check')) {
  if (join.join_state_bytes_max !== joinMaximum) throw Error('join byte bound differs');
} else {
  join.join_state_bytes_max = joinMaximum;
  writeFileSync(joinCandidate,JSON.stringify(join,null,2)+'\n');
}
console.log(JSON.stringify({joinMaximum,components,vendorBytes,historyCount:contract.limits.join_history_max,envelopeMaximum:maximum}));
const bytes = `// Generated by scripts/generate-business-append-contract.mjs; do not edit.\n// Must match business-append-contract.json and the complete record schema.\npub const PRODUCER_ENVELOPE_MAX_BYTES: usize = ${contract.envelope_max_bytes};\npub const CONSERVATIVE_ENVELOPE_MAX_BYTES: usize = ${maximum};\npub const ENVELOPE_BRANCH_BOUNDS: &[usize] = &[${branchBounds.join(', ')}];\n`;
const path = new URL('castle-wall-daemon/src/business_profile/append_contract_constants.rs',root);
// An explicit check candidate lets freshness witnesses avoid mutating tracked output.
const candidate = process.argv.includes('--check-file') ? process.argv[process.argv.indexOf('--check-file') + 1] : path;
if (process.argv.includes('--check')) { if(readFileSync(candidate,'utf8')!==bytes) throw Error('append contract differs'); }
else writeFileSync(path,bytes);
console.log(JSON.stringify({branchBounds,maximum,cap:contract.envelope_max_bytes}));

// Must match join-state-contract.json consumed directly by record-joins.ts.
const joinBytes = `// Generated by scripts/generate-business-append-contract.mjs; do not edit.
// Must match join-state-contract.json and record-joins.ts.
// Versioned v0 policy admission caps, owned by join-state-contract.json.
pub const POLICY_AGENT_UIDS_MAX: usize = ${join.policy_agent_uids_max};
pub const POLICY_VENDORS_MAX: usize = ${join.policy_vendors_max};
// Derived from the closed state schema, scalar encodings, bounded policies and complete envelopes.
pub const JOIN_STATE_BYTES_MAX: usize = ${joinMaximum};
// Fixed schema bytes, safe-integer digits, vendor object bytes, and generated all-branch envelope bytes.
const _: () = assert!(JOIN_STATE_BYTES_MAX == ${joinMaximum-tokenBounds.history-tokenBounds.safe_u64_list-tokenBounds.vendor_list} +
    (2 + (POLICY_AGENT_UIDS_MAX - 1) + POLICY_AGENT_UIDS_MAX * ${scalarBounds.safe_u64}) +
    (2 + (POLICY_VENDORS_MAX - 1) + POLICY_VENDORS_MAX * ${vendorBytes}) +
    (2 + (super::JOIN_HISTORY_MAX - 1) + super::JOIN_HISTORY_MAX * ${maximum}));
// Format widths and the port domain come from the producer and record schema, not policy caps.
pub const PUBLIC_KEY_BYTES: usize = ${join.public_key_bytes};
pub const SIGNATURE_BYTES: usize = ${join.signature_bytes};
pub const PORT_MAX: u64 = ${schema.definitions.Port.max};
pub const OUTER_INDEX: &[&str] = &[${join.outer_index.map(JSON.stringify).join(', ')}];
pub const JOIN_STATE_SCHEMA: &[(&str, &[(&str, &str)])] = &[${Object.entries(join.state_schema).map(([name,fields]) => `(${JSON.stringify(name)}, &[${Object.entries(fields).map(([k,v])=>`(${JSON.stringify(k)}, ${JSON.stringify(v)})`).join(', ')}])`).join(', ')}];
`;
const joinPath = new URL('castle-wall-daemon/src/business_profile/join_state_contract.rs',root);
const joinCheckCandidate = process.argv.includes('--check-join-file') ? process.argv[process.argv.indexOf('--check-join-file') + 1] : joinPath;
if (process.argv.includes('--check')) { if (readFileSync(joinCheckCandidate,'utf8') !== joinBytes) throw Error('join contract differs'); }
else writeFileSync(joinPath,joinBytes);

// Complete checkpoint sizing uses the closed drain and append tables, without elision.
const drain = read('castle-wall-daemon/src/business_profile/drain_schema.json');
const scalarAnchor = {literal1:1, producer:Buffer.byteLength(JSON.stringify(drain.domains.producer)),
  id:widths.id+2,digest:widths.digest+2,commitment:widths.digest+2,boolean:5,
  nullableId:widths.id+2,nullableDigest:widths.digest+2,
  nullableReason:Math.max(4,...drain.domains.reasons.map(s=>Buffer.byteLength(JSON.stringify(s)))),
  safeInteger:scalarBounds.safe_u64,positiveInteger:scalarBounds.safe_u64};
const anchorMaximum=objectBytes(Object.fromEntries(Object.entries(drain.anchor).map(([k,t])=>{
  if (!(t in scalarAnchor)) throw Error('unbounded anchor token'); return [k,scalarAnchor[t]];
})));
const checkpointTokens={safe:scalarBounds.safe_u64,positive:scalarBounds.safe_u64,id:widths.id+2,
  digest:widths.digest+2,commitment:widths.digest+2,u64:widths.u64+2,boolean:5,
  nullable_digest:widths.digest+2,nullable_anchor:anchorMaximum,
  observation_state:Math.max(...contract.observation_states.map(s=>Buffer.byteLength(JSON.stringify(s)))),
  join_state:joinMaximum};
function shapeBytes(name) {
  return objectBytes(Object.fromEntries(Object.entries(contract[name]).map(([key,token])=>{
    if(typeof token!=='string') return [key,Buffer.byteLength(JSON.stringify(token))];
    if(!(token in checkpointTokens)) throw Error('unbounded checkpoint token '+token);
    return [key,checkpointTokens[token]];
  })));
}
const retained=shapeBytes('retained_original');
checkpointTokens.retained_originals=arrayBytes(contract.limits.d_undrained_max,retained);
checkpointTokens.observation=shapeBytes('observation');
checkpointTokens.wal_checkpoint=shapeBytes('wal_checkpoint');
const checkpointMaximum=shapeBytes('checkpoint');
const partBytes=65536; // Must match activation_anchor::MAX_BYTES, pinned by the native const assertion.
const partCount=Math.ceil(checkpointMaximum/partBytes);
const header={v:1,protocol:Buffer.byteLength(JSON.stringify('sanctuary.business-writer.v1')),
  session_id:widths.id+2,request_id:widths.id+2,nonce:widths.id+2};
const partHeader=objectBytes({...header,op:JSON.stringify('CHECKPOINT_PART').length,
  part_index:String(partCount-1).length,part_count:String(partCount).length,
  total_length:String(partCount*partBytes).length,checkpoint_digest:widths.digest+2,
  payload_length:String(partBytes).length});
const challengeHeader=objectBytes({...header,op:JSON.stringify('CHECKPOINT_CHALLENGE').length,
  issued_boottime_ns:widths.u64+2,payload_length:String(4096).length}); // Writer STATUS payload domain.
const checkpointBounds={honest_max_bytes:checkpointMaximum,anchor_max_bytes:anchorMaximum,
  observation_max_bytes:checkpointTokens.observation,retained_row_max_bytes:retained,
  part_bytes:partBytes,part_header_max_bytes:partHeader,challenge_header_max_bytes:challengeHeader};
const checkpointJson=JSON.stringify(checkpointBounds,null,2)+'\n';
const checkpointRs=`// Generated by scripts/generate-business-append-contract.mjs; do not edit.
// Must match checkpoint-bounds.json, the closed append/drain schemas and JOIN_STATE_BYTES_MAX.
pub const CHECKPOINT_HONEST_MAX_BYTES: usize = ${checkpointMaximum};
pub const CHECKPOINT_PART_HEADER_MAX_BYTES: usize = ${partHeader};
pub const CHECKPOINT_CHALLENGE_HEADER_MAX_BYTES: usize = ${challengeHeader};
const _: () = assert!(anchor::MAX_BYTES == ${partBytes});
const _: () = assert!(CHECKPOINT_HONEST_MAX_BYTES == ${checkpointMaximum-checkpointTokens.retained_originals-joinMaximum}
    + records::JOIN_STATE_BYTES_MAX + 2 + (drain_store::D_UNDRAINED_MAX - 1)
    + drain_store::D_UNDRAINED_MAX * ${retained});
`;
for (const [target,output] of [['server/src/signing/checkpoint-bounds.json',checkpointJson],
  ['castle-wall-daemon/src/business_profile/checkpoint_bounds.rs',checkpointRs]]) {
  const path=new URL(target,root);
  if(process.argv.includes('--check')) {if(readFileSync(path,'utf8')!==output) throw Error('checkpoint bound differs');}
  else writeFileSync(path,output);
}
console.log(JSON.stringify(checkpointBounds));
