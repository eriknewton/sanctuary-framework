// Must match business_profile/join_lifecycle.rs; shared vectors pin every transition.
import {advance, joinStateValid, cloneJoinState, plainJoinJson, type JoinRecord, type JoinState} from "./record-joins.js";
import {APPEND_CONTRACT, appendShape, deliveryIdentity, parseBusinessEnvelope, type BusinessDeliveryIdentity} from "./business-append-contract.js";
import {canonicalBytes} from "./contract.js";
export interface JoinLifecycleState {committed: JoinState | null; provisional: {state: JoinState; identity: BusinessDeliveryIdentity; signed: boolean} | null; tombstone: BusinessDeliveryIdentity | null; needs_checkpoint: boolean;}
export const initialLifecycle = (): JoinLifecycleState => ({committed: null, provisional: null, tombstone: null, needs_checkpoint: true});
const equal = (a: unknown,b: unknown) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const closed = (value: unknown, keys: string[]): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key=>Object.hasOwn(value,key));
function lifecycleStateValid(state: unknown): state is JoinLifecycleState {
  // Must match join_lifecycle.rs state_valid: only explicit null is empty, and closed wrappers bound pass-through copies.
  if (!closed(state,["committed","provisional","tombstone","needs_checkpoint"]) || typeof state.needs_checkpoint !== "boolean") return false;
  const identity = (value: unknown) => value === null || appendShape("identity",value);
  return (state.committed === null || joinStateValid(state.committed)) && identity(state.tombstone) &&
    (state.provisional === null || (closed(state.provisional,["state","identity","signed"]) &&
      joinStateValid(state.provisional.state) && identity(state.provisional.identity) && typeof state.provisional.signed === "boolean"));
}
/** Pure model. The caller must authenticate checkpoint and commit evidence before submitting events. */
export function lifecycleStep(state: JoinLifecycleState, event: Record<string, unknown>): {accepted: boolean; state: JoinLifecycleState} {
  const fail = () => ({accepted:false, state});
  try {
  // Data-only snapshots prevent accessor changes between admission and retained copies.
  if (!plainJoinJson(state) || !plainJoinJson(event)) return fail();
  const type = event.type as keyof typeof APPEND_CONTRACT.lifecycle;
  if (!Object.hasOwn(APPEND_CONTRACT.lifecycle,type)) return fail();
  const fields = APPEND_CONTRACT.lifecycle[type];
  if (!fields || !equal(Object.keys(event).sort(), ["type",...fields].sort())) return fail();
  // Caller-supplied lifecycle state cannot carry an unbounded checkpoint through a later event.
  if (!lifecycleStateValid(state)) return fail();
  const next = structuredClone(state);
  if (!lifecycleStateValid(next)) return fail();
  switch (type) {
    case "Checkpoint": {
      const checkpoint = cloneJoinState(event.checkpoint);
      if (!joinStateValid(checkpoint) || state.provisional) return fail();
      // A new checkpoint must account for every owned sequence, not erase it.
      if (state.tombstone && (checkpoint.anchor.sequence !== state.tombstone.sequence || checkpoint.anchor.commitment !== state.tombstone.commitment)) return fail();
      next.committed = structuredClone(checkpoint); next.tombstone=null; next.needs_checkpoint=false; break;
    }
    case "SignAdmitted": {
      if (!state.committed || state.needs_checkpoint || state.provisional || state.tombstone) return fail();
      let record: JoinRecord;
      // Admission uses the same bounded envelope shape as the native identity path.
      try { record = parseBusinessEnvelope(Buffer.from(canonicalBytes(event.record)).toString("base64url")).record; }
      catch { return fail(); }
      const result = advance(state.committed, record);
      if (result.refusal_code) return fail();
      const identity = deliveryIdentity(canonicalBytes(record), record);
      // Each retained identity is independent, matching a JSON round trip with no shared references.
      next.provisional={state:result.final_state,identity,signed:false};next.tombstone=structuredClone(identity); break;
    }
    case "Signed":
      if (!state.provisional || state.provisional.signed || !equal(state.provisional.identity,event.identity)) return fail();
      next.provisional!.signed=true; break;
    case "Committed":
      if (!state.provisional?.signed || !equal(state.provisional.identity,event.identity) || !equal(state.provisional.state,event.checkpoint)) return fail();
      next.committed=next.provisional!.state;next.provisional=null;next.tombstone=null;break;
    case "LostOrUnmatched":next.provisional=null;next.needs_checkpoint=true;break;
    case "NextGrant":next.provisional=null;next.needs_checkpoint=true;break;
    default: return fail();
  }
  return {accepted:true,state:next};
  } catch { return fail(); }
}
